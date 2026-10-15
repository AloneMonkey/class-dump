// Preflight the thin arm64 images used by the native install/verify path.
#pragma once
#import <Foundation/Foundation.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <cstring>
#include <limits>

static int nativeInputError(NSString *path, const char *message, int code = 2) {
    fprintf(stderr, "%s: %s\n", path.fileSystemRepresentation, message);
    return code;
}

static bool nativeRange(uint64_t offset, uint64_t size, uint64_t limit) {
    return offset <= limit && size <= limit - offset;
}

static int nativeValidateImage(NSString *path, const char *payload = nullptr,
                               uint32_t commandType = LC_LOAD_DYLIB) {
    NSError *error = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:&error];
    if (!data) return nativeInputError(path, "cannot read input", 1);
    const uint8_t *bytes = static_cast<const uint8_t *>(data.bytes);
    const uint64_t length = data.length;
    if (length < sizeof(mach_header_64) || length > UINT32_MAX)
        return nativeInputError(path, "truncated or unsupported file size");
    mach_header_64 header;
    memcpy(&header, bytes, sizeof(header));
    if (header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        (header.cpusubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64_ALL)
        return nativeInputError(path, "only thin arm64 is supported; fat and arm64e images require separate validation");
    if (header.filetype != MH_EXECUTE && header.filetype != MH_DYLIB && header.filetype != MH_BUNDLE)
        return nativeInputError(path, "unsupported Mach-O file type");
    if (!nativeRange(sizeof(header), header.sizeofcmds, length) ||
        header.ncmds > header.sizeofcmds / sizeof(load_command))
        return nativeInputError(path, "load command table exceeds input");

    const uint64_t tableEnd = sizeof(header) + uint64_t(header.sizeofcmds);
    uint64_t offset = sizeof(header), firstData = length;
    bool hasText = false, hasSegment = false, alreadyPresent = false;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        if (!nativeRange(offset, sizeof(load_command), tableEnd))
            return nativeInputError(path, "truncated load command");
        load_command command;
        memcpy(&command, bytes + offset, sizeof(command));
        if (command.cmdsize < sizeof(command) || command.cmdsize % 8 ||
            !nativeRange(offset, command.cmdsize, tableEnd))
            return nativeInputError(path, "invalid load command size");
        if (command.cmd == LC_SEGMENT_64) {
            if (command.cmdsize < sizeof(segment_command_64))
                return nativeInputError(path, "truncated segment");
            segment_command_64 segment;
            memcpy(&segment, bytes + offset, sizeof(segment));
            if (segment.nsects > (command.cmdsize - sizeof(segment)) / sizeof(section_64) ||
                !nativeRange(segment.fileoff, segment.filesize, length))
                return nativeInputError(path, "segment or sections exceed input");
            hasSegment = true;
            if (segment.fileoff && segment.filesize) firstData = MIN(firstData, segment.fileoff);
            for (uint32_t n = 0; n < segment.nsects; ++n) {
                section_64 section;
                memcpy(&section, bytes + offset + sizeof(segment) + n * sizeof(section), sizeof(section));
                uint32_t kind = section.flags & SECTION_TYPE;
                bool zeroFill = kind == S_ZEROFILL || kind == S_GB_ZEROFILL || kind == S_THREAD_LOCAL_ZEROFILL;
                if (section.size && !zeroFill) {
                    if (!nativeRange(section.offset, section.size, length) ||
                        section.offset < tableEnd || section.offset < segment.fileoff ||
                        section.offset - segment.fileoff > segment.filesize ||
                        section.size > segment.filesize - (section.offset - segment.fileoff))
                        return nativeInputError(path, "section exceeds segment or overlaps command table");
                    firstData = MIN(firstData, uint64_t(section.offset));
                }
                if (!strncmp(segment.segname, SEG_TEXT, 16) && !strncmp(section.sectname, SECT_TEXT, 16) && section.size && !zeroFill)
                    hasText = true;
            }
        } else if (command.cmd == LC_LOAD_DYLIB || command.cmd == LC_LOAD_WEAK_DYLIB ||
                   command.cmd == LC_REEXPORT_DYLIB || command.cmd == LC_LOAD_UPWARD_DYLIB ||
                   command.cmd == LC_ID_DYLIB) {
            if (command.cmdsize < sizeof(dylib_command)) return nativeInputError(path, "truncated dylib command");
            dylib_command dylib;
            memcpy(&dylib, bytes + offset, sizeof(dylib));
            uint32_t name = dylib.dylib.name.offset;
            if (name < sizeof(dylib) || name >= command.cmdsize ||
                !memchr(bytes + offset + name, 0, command.cmdsize - name))
                return nativeInputError(path, "invalid dylib name");
            if (payload && command.cmd != LC_ID_DYLIB &&
                !strcmp(reinterpret_cast<const char *>(bytes + offset + name), payload)) alreadyPresent = true;
        } else if (command.cmd == LC_ENCRYPTION_INFO_64 || command.cmd == LC_ENCRYPTION_INFO) {
            size_t minimum = command.cmd == LC_ENCRYPTION_INFO_64 ? sizeof(encryption_info_command_64) : sizeof(encryption_info_command);
            if (command.cmdsize < minimum) return nativeInputError(path, "truncated encryption command");
            encryption_info_command encryption;
            memcpy(&encryption, bytes + offset, sizeof(encryption));
            if (!nativeRange(encryption.cryptoff, encryption.cryptsize, length)) return nativeInputError(path, "encrypted range exceeds input");
            if (encryption.cryptid) return nativeInputError(path, "encrypted input is unsupported", 16);
        } else if (command.cmd == LC_SYMTAB) {
            if (command.cmdsize < sizeof(symtab_command)) return nativeInputError(path, "truncated symbol table command");
            symtab_command symbols;
            memcpy(&symbols, bytes + offset, sizeof(symbols));
            if (!nativeRange(symbols.symoff, uint64_t(symbols.nsyms) * sizeof(nlist_64), length) ||
                !nativeRange(symbols.stroff, symbols.strsize, length)) return nativeInputError(path, "symbol table exceeds input");
        } else if (command.cmd == LC_CODE_SIGNATURE || command.cmd == LC_DYLD_CHAINED_FIXUPS ||
                   command.cmd == LC_DYLD_EXPORTS_TRIE || command.cmd == LC_FUNCTION_STARTS ||
                   command.cmd == LC_DATA_IN_CODE) {
            if (command.cmdsize < sizeof(linkedit_data_command)) return nativeInputError(path, "truncated linkedit command");
            linkedit_data_command linkedit;
            memcpy(&linkedit, bytes + offset, sizeof(linkedit));
            if (!nativeRange(linkedit.dataoff, linkedit.datasize, length)) return nativeInputError(path, "linkedit data exceeds input");
        }
        offset += command.cmdsize;
    }
    if (offset != tableEnd || !hasSegment) return nativeInputError(path, "inconsistent command table");
    if (payload) {
        if (!hasText) return nativeInputError(path, "injection requires a file-backed __TEXT,__text section");
        if (!*payload) return nativeInputError(path, "empty dylib path", 13);
        if (commandType != LC_LOAD_DYLIB && commandType != LC_LOAD_WEAK_DYLIB &&
            commandType != LC_REEXPORT_DYLIB && commandType != LC_LOAD_UPWARD_DYLIB)
            return nativeInputError(path, "invalid load command type", 10);
        if (!alreadyPresent) {
            uint64_t needed = (sizeof(dylib_command) + strlen(payload) + 1 + 7) & ~uint64_t(7);
            if (needed > UINT32_MAX || firstData < tableEnd || needed > firstData - tableEnd)
                return nativeInputError(path, "no header space for dylib command", 9);
            for (uint64_t i = tableEnd; i < tableEnd + needed; ++i)
                if (bytes[i]) return nativeInputError(path, "nonzero header padding would be overwritten", 9);
        }
    }
    return 0;
}

static bool nativeLooksLikeImage(NSString *path) {
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!handle) return false;
    NSData *prefix = [handle readDataOfLength:4];
    [handle closeFile];
    uint32_t magic = 0;
    if (prefix.length == sizeof(magic)) memcpy(&magic, prefix.bytes, sizeof(magic));
    return magic == MH_MAGIC || magic == MH_MAGIC_64 || magic == MH_CIGAM ||
           magic == MH_CIGAM_64 || magic == FAT_MAGIC || magic == FAT_CIGAM ||
           magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
}

static int nativeValidateBundle(NSString *executable) {
    int result = nativeValidateImage(executable);
    if (result) return result;
    NSString *root = executable.stringByDeletingLastPathComponent;
    NSDirectoryEnumerator *entries = [[NSFileManager defaultManager] enumeratorAtPath:root];
    for (NSString *relative in entries) {
        NSString *path = [root stringByAppendingPathComponent:relative];
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
        if (![attrs[NSFileType] isEqualToString:NSFileTypeRegular]) continue;
        if (nativeLooksLikeImage(path) && (result = nativeValidateImage(path))) return result;
    }
    return 0;
}
