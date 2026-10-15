// Bounded Objective-C method-symbol reconstruction for thin arm64 Mach-O files.
// Formats follow Apple's objc4 metadata and dyld fixup-chains.h definitions.
#pragma once
#include <mach-o/fixup-chains.h>
#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>
#include <stdexcept>
#include <sys/stat.h>

namespace md_symbols {
struct Pointer { uint64_t value; std::string bind; };
struct Section { section_64 data; uint8_t ordinal; };
struct Symbol { uint64_t address; uint8_t section; std::string name; };

class Image {
public:
    std::vector<uint8_t> bytes;
    std::vector<segment_command_64> segments;
    std::vector<Section> sections;
    std::unordered_map<uint64_t, Pointer> fixups;
    std::vector<std::string> imports;
    std::map<uint64_t, std::string> classNames;
    std::vector<Symbol> recovered;
    std::set<std::pair<uint64_t, std::string>> seen;
    uint64_t base = 0, symCommand = 0, dysymCommand = 0, linkCommand = 0, signatureCommand = 0;
    uint64_t chainedCommand = 0;
    size_t skippedCategories = 0;
    std::string context;

    static void require(bool condition, const char *message) {
        if (!condition) throw std::runtime_error(message);
    }
    template<class T> T get(uint64_t offset) const {
        require(nativeRange(offset, sizeof(T), bytes.size()), "metadata read exceeds input");
        T value; memcpy(&value, bytes.data() + offset, sizeof(T)); return value;
    }
    template<class T> void put(uint64_t offset, const T &value) {
        require(nativeRange(offset, sizeof(T), bytes.size()), "metadata write exceeds output");
        memcpy(bytes.data() + offset, &value, sizeof(T));
    }
    uint64_t fileOffset(uint64_t address, uint64_t count = 1) const {
        for (const auto &segment : segments) {
            if (address >= segment.vmaddr && nativeRange(address - segment.vmaddr, count, segment.filesize))
                return segment.fileoff + address - segment.vmaddr;
        }
        char detail[128]; snprintf(detail, sizeof(detail), "Objective-C address 0x%llx (%llu bytes) is outside file-backed segments", address, count);
        throw std::runtime_error(context + ": " + detail);
    }
    uint64_t remaining(uint64_t address) const {
        for (const auto &segment : segments)
            if (address >= segment.vmaddr && address - segment.vmaddr < segment.filesize)
                return segment.filesize - (address - segment.vmaddr);
        throw std::runtime_error("string address is outside file-backed segments");
    }
    std::string stringAtOffset(uint64_t offset, uint64_t limit) const {
        require(nativeRange(offset, limit, bytes.size()), "string range exceeds input");
        const char *begin = reinterpret_cast<const char *>(bytes.data() + offset);
        const char *end = static_cast<const char *>(memchr(begin, 0, limit));
        require(end != nullptr, "unterminated metadata string");
        return std::string(begin, end);
    }
    std::string stringAt(uint64_t address) const {
        return stringAtOffset(fileOffset(address), std::min<uint64_t>(remaining(address), 1024 * 1024));
    }
    Pointer pointer(uint64_t address) const {
        uint64_t offset = fileOffset(address, 8);
        auto found = fixups.find(offset);
        if (found != fixups.end()) return found->second;
        return {get<uint64_t>(offset), ""};
    }
    uint64_t localPointer(uint64_t address) const {
        Pointer p = pointer(address);
        require(p.bind.empty(), "unexpected external pointer in local Objective-C metadata");
        return p.value;
    }
    void parse() {
        auto header = get<mach_header_64>(0);
        uint64_t offset = sizeof(header);
        uint32_t ordinal = 0;
        for (uint32_t i = 0; i < header.ncmds; ++i) {
            auto command = get<load_command>(offset);
            if (command.cmd == LC_SEGMENT_64) {
                auto segment = get<segment_command_64>(offset);
                segments.push_back(segment);
                if (segment.fileoff == 0 && segment.filesize) base = segment.vmaddr;
                if (!strncmp(segment.segname, SEG_LINKEDIT, 16)) linkCommand = offset;
                for (uint32_t j = 0; j < segment.nsects; ++j) {
                    require(++ordinal <= 255, "too many sections for nlist_64");
                    sections.push_back({get<section_64>(offset + sizeof(segment) + j * sizeof(section_64)), uint8_t(ordinal)});
                }
            } else if (command.cmd == LC_SYMTAB) symCommand = offset;
            else if (command.cmd == LC_DYSYMTAB) {
                require(command.cmdsize >= sizeof(dysymtab_command), "truncated dynamic symbol command");
                dysymCommand = offset;
            }
            else if (command.cmd == LC_CODE_SIGNATURE) signatureCommand = offset;
            else if (command.cmd == LC_DYLD_CHAINED_FIXUPS) chainedCommand = offset;
            offset += command.cmdsize;
        }
        require(symCommand && dysymCommand && linkCommand, "missing symbol/dynamic-symbol/linkedit command");
        if (chainedCommand) parseFixups();
    }
    void parseFixups() {
        auto cmd = get<linkedit_data_command>(chainedCommand);
        uint64_t start = cmd.dataoff, end = start + cmd.datasize;
        require(cmd.datasize >= sizeof(dyld_chained_fixups_header), "truncated chained fixup header");
        auto h = get<dyld_chained_fixups_header>(start);
        require(h.fixups_version == 0 && h.symbols_format == 0, "unsupported chained fixup version or compressed symbols");
        auto inFixups = [&](uint64_t off, uint64_t size) { require(off >= start && nativeRange(off, size, end), "chained fixup range exceeds payload"); };
        inFixups(start + h.symbols_offset, 1);
        size_t importSize = h.imports_format == DYLD_CHAINED_IMPORT ? 4 : h.imports_format == DYLD_CHAINED_IMPORT_ADDEND ? 8 : h.imports_format == DYLD_CHAINED_IMPORT_ADDEND64 ? 16 : 0;
        require(importSize != 0, "unsupported chained import format");
        inFixups(start + h.imports_offset, uint64_t(h.imports_count) * importSize);
        for (uint32_t i = 0; i < h.imports_count; ++i) {
            uint64_t entry = start + h.imports_offset + uint64_t(i) * importSize;
            uint64_t name = h.imports_format == DYLD_CHAINED_IMPORT_ADDEND64 ? get<uint64_t>(entry) >> 32 : get<uint32_t>(entry) >> 9;
            uint64_t off = start + h.symbols_offset + name;
            inFixups(off, 1);
            imports.push_back(stringAtOffset(off, std::min<uint64_t>(end - off, 1024 * 1024)));
        }
        uint64_t starts = start + h.starts_offset;
        inFixups(starts, 4);
        uint32_t count = get<uint32_t>(starts);
        require(count <= segments.size(), "invalid chained segment count");
        inFixups(starts + 4, uint64_t(count) * 4);
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t delta = get<uint32_t>(starts + 4 + 4 * i);
            if (!delta) continue;
            uint64_t info = starts + delta;
            inFixups(info, 22);
            uint32_t size = get<uint32_t>(info);
            inFixups(info, size);
            uint16_t pageSize = get<uint16_t>(info + 4), format = get<uint16_t>(info + 6), pages = get<uint16_t>(info + 20);
            uint64_t segmentOffset = get<uint64_t>(info + 8);
            require(format == DYLD_CHAINED_PTR_64 || format == DYLD_CHAINED_PTR_64_OFFSET, "unsupported chained pointer format (arm64e is not supported)");
            require(pageSize == 0x1000 || pageSize == 0x4000, "unsupported chained page size");
            require(size >= 22 && uint64_t(pages) * 2 <= size - 22, "truncated chained page starts");
            require(segmentOffset <= UINT64_MAX - base && base + segmentOffset == segments[i].vmaddr, "chained segment address mismatch");
            for (uint32_t page = 0; page < pages; ++page) {
                uint16_t first = get<uint16_t>(info + 22 + 2 * page);
                if (first == DYLD_CHAINED_PTR_START_NONE) continue;
                require(!(first & DYLD_CHAINED_PTR_START_MULTI), "multiple chained starts per page are not supported");
                uint64_t within = first;
                for (;;) {
                    require(within + 8 <= pageSize, "chained pointer crosses page boundary");
                    uint64_t address = segments[i].vmaddr + uint64_t(page) * pageSize + within;
                    uint64_t off = fileOffset(address, 8), raw = get<uint64_t>(off);
                    Pointer pointer = {0, ""};
                    if (raw >> 63) {
                        uint32_t index = raw & 0xffffff;
                        require(index < imports.size(), "chained import ordinal exceeds table");
                        pointer.bind = imports[index];
                    } else {
                        uint64_t target = raw & 0xfffffffffULL;
                        uint64_t high = ((raw >> 36) & 0xff) << 56;
                        pointer.value = format == DYLD_CHAINED_PTR_64_OFFSET ? base + target : target;
                        pointer.value |= high;
                    }
                    require(fixups.emplace(off, pointer).second, "overlapping chained fixups");
                    uint64_t next = (raw >> 51) & 0xfff;
                    if (!next) break;
                    within += next * 4;
                }
            }
        }
    }
    std::string className(uint64_t address) {
        auto known = classNames.find(address);
        if (known != classNames.end()) return known->second;
        uint64_t ro = localPointer(address + 32) & ~uint64_t(7);
        std::string name = stringAt(localPointer(ro + 24));
        require(!name.empty(), "empty Objective-C class name");
        classNames[address] = name;
        return name;
    }
    uint8_t codeSection(uint64_t address) const {
        for (const auto &section : sections) {
            auto s = section.data;
            if (address >= s.addr && address - s.addr < s.size &&
                (s.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))) return section.ordinal;
        }
        throw std::runtime_error("method implementation is outside instruction sections");
    }
    void methods(uint64_t address, const std::string &owner, char kind) {
        if (!address) return;
        uint64_t off = fileOffset(address, 8);
        uint32_t flags = get<uint32_t>(off), count = get<uint32_t>(off + 4);
        bool small = flags & 0x80000000, direct = flags & 0x40000000;
        uint32_t stride = flags & 0xfffc;
        require(stride == (small ? 12 : 24), "unsupported Objective-C method entry size");
        fileOffset(address, 8 + uint64_t(count) * stride);
        for (uint32_t i = 0; i < count; ++i) {
            uint64_t entry = address + 8 + uint64_t(i) * stride;
            uint64_t name, imp;
            if (small) {
                int32_t nameDelta = get<int32_t>(fileOffset(entry, 4));
                int32_t impDelta = get<int32_t>(fileOffset(entry + 8, 4));
                name = entry + int64_t(nameDelta);
                if (!direct) name = localPointer(name);
                imp = entry + 8 + int64_t(impDelta);
            } else {
                name = localPointer(entry);
                imp = localPointer(entry + 16);
            }
            if (!imp) continue;
            std::string selector = stringAt(name);
            require(!selector.empty(), "empty Objective-C selector");
            std::string symbol = std::string(1, kind) + "[" + owner + " " + selector + "]";
            if (seen.emplace(imp, symbol).second) recovered.push_back({imp, codeSection(imp), symbol});
        }
    }
    void collect() {
        // Preserve existing names; the operation is idempotent on its own output.
        auto sym = get<symtab_command>(symCommand);
        for (uint32_t i = 0; i < sym.nsyms; ++i) {
            auto n = get<nlist_64>(sym.symoff + uint64_t(i) * sizeof(nlist_64));
            require(n.n_un.n_strx < sym.strsize, "symbol name index exceeds string table");
            if ((n.n_type & N_TYPE) == N_SECT)
                seen.emplace(n.n_value, stringAtOffset(sym.stroff + n.n_un.n_strx, sym.strsize - n.n_un.n_strx));
        }
        for (const auto &section : sections) {
            if (strncmp(section.data.sectname, "__objc_classlist", 16)) continue;
            require(section.data.size % 8 == 0, "misaligned Objective-C class list");
            for (uint64_t i = 0; i < section.data.size; i += 8) {
                uint64_t cls = localPointer(section.data.addr + i);
                if (!cls) continue; // Weak/removed class slots may be null.
                context = "class " + std::to_string(cls);
                std::string name = className(cls);
                context = name;
                uint64_t ro = localPointer(cls + 32) & ~uint64_t(7);
                try { methods(localPointer(ro + 32), name, '-'); } catch (const std::exception &e) { throw std::runtime_error(name + ": " + e.what()); }
                uint64_t meta = localPointer(cls);
                if (meta) {
                    uint64_t metaRO = localPointer(meta + 32) & ~uint64_t(7);
                    try { methods(localPointer(metaRO + 32), name, '+'); } catch (const std::exception &e) { throw std::runtime_error(name + " (meta): " + e.what()); }
                }
            }
        }
        for (const auto &section : sections) {
            if (strncmp(section.data.sectname, "__objc_catlist", 16) && strncmp(section.data.sectname, "__objc_catlist2", 16)) continue;
            require(section.data.size % 8 == 0, "misaligned Objective-C category list");
            for (uint64_t i = 0; i < section.data.size; i += 8) {
                uint64_t category = localPointer(section.data.addr + i);
                if (!category) continue;
                context = "category " + std::to_string(category);
                std::string name = stringAt(localPointer(category)), owner;
                Pointer cls = pointer(category + 8);
                // Swift class stubs (isa == 1) are initialized by runtime code;
                // their final class name is not present in class_ro_t on disk.
                if (cls.value && pointer(cls.value).value == 1) { ++skippedCategories; continue; }
                if (cls.value) owner = className(cls.value);
                else if (cls.bind.find("_OBJC_CLASS_$_") == 0) owner = cls.bind.substr(strlen("_OBJC_CLASS_$_"));
                else { ++skippedCategories; continue; }
                owner += "(" + name + ")";
                context = owner;
                methods(localPointer(category + 16), owner, '-');
                methods(localPointer(category + 24), owner, '+');
            }
        }
    }
    void rebuild() {
        if (recovered.empty()) return;
        auto sym = get<symtab_command>(symCommand);
        auto dyn = get<dysymtab_command>(dysymCommand);
        auto link = get<segment_command_64>(linkCommand);
        require(link.fileoff + link.filesize == bytes.size(), "linkedit must end at the end of the input file");
        require(!dyn.ntoc && !dyn.nmodtab && !dyn.nextrefsyms && !dyn.nextrel && !dyn.nlocrel, "legacy dynamic relocation/module tables are not supported");
        require(dyn.ilocalsym == 0 && dyn.iextdefsym == dyn.nlocalsym &&
                uint64_t(dyn.iundefsym) == uint64_t(dyn.nlocalsym) + dyn.nextdefsym &&
                uint64_t(dyn.iundefsym) + dyn.nundefsym == sym.nsyms, "noncontiguous dynamic symbol partitions are not supported");
        std::vector<nlist_64> table;
        std::vector<uint8_t> strings(bytes.begin() + sym.stroff, bytes.begin() + sym.stroff + sym.strsize);
        require(recovered.size() < UINT32_MAX - sym.nsyms, "too many restored symbols");
        uint32_t added = uint32_t(recovered.size()), insertion = dyn.nlocalsym;
        auto addRecovered = [&]() {
            for (const auto &item : recovered) {
                require(strings.size() + item.name.size() + 1 <= UINT32_MAX, "restored string table is too large");
                nlist_64 n = {}; n.n_type = N_SECT; n.n_sect = item.section;
                n.n_value = item.address; n.n_un.n_strx = uint32_t(strings.size());
                table.push_back(n);
                strings.insert(strings.end(), item.name.begin(), item.name.end()); strings.push_back(0);
            }
        };
        for (uint32_t i = 0; i <= sym.nsyms; ++i) {
            if (i == insertion) addRecovered();
            if (i < sym.nsyms) table.push_back(get<nlist_64>(sym.symoff + uint64_t(i) * sizeof(nlist_64)));
        }
        // The loader's indirect table indexes nlist entries, not byte offsets.
        for (uint32_t i = 0; i < dyn.nindirectsyms; ++i) {
            uint64_t off = dyn.indirectsymoff + uint64_t(i) * 4;
            uint32_t index = get<uint32_t>(off);
            if (!(index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS))) {
                require(index < sym.nsyms, "indirect symbol index exceeds table");
                if (index >= insertion) put<uint32_t>(off, index + added);
            }
        }
        size_t aligned = (bytes.size() + 7) & ~size_t(7);
        uint64_t total = aligned + uint64_t(table.size()) * sizeof(nlist_64) + strings.size();
        require(total <= UINT32_MAX, "restored Mach-O exceeds supported file size");
        bytes.resize(aligned, 0);
        sym.symoff = uint32_t(bytes.size()); sym.nsyms = uint32_t(table.size());
        const uint8_t *raw = reinterpret_cast<const uint8_t *>(table.data());
        bytes.insert(bytes.end(), raw, raw + table.size() * sizeof(nlist_64));
        sym.stroff = uint32_t(bytes.size()); sym.strsize = uint32_t(strings.size());
        bytes.insert(bytes.end(), strings.begin(), strings.end());
        dyn.nlocalsym += added; dyn.iextdefsym += added; dyn.iundefsym += added;
        require(bytes.size() >= link.fileoff, "invalid linkedit file offset");
        link.filesize = bytes.size() - link.fileoff;
        link.vmsize = (link.filesize + 0x3fff) & ~uint64_t(0x3fff);
        put(symCommand, sym); put(dysymCommand, dyn); put(linkCommand, link);
        // Symbols invalidate the old signature. Leave its unreferenced bytes in
        // place, remove only its command; codesign can append a new signature.
        if (signatureCommand) {
            auto header = get<mach_header_64>(0);
            auto signature = get<load_command>(signatureCommand);
            uint64_t commandEnd = sizeof(header) + header.sizeofcmds;
            memmove(bytes.data() + signatureCommand, bytes.data() + signatureCommand + signature.cmdsize,
                    commandEnd - signatureCommand - signature.cmdsize);
            memset(bytes.data() + commandEnd - signature.cmdsize, 0, signature.cmdsize);
            --header.ncmds; header.sizeofcmds -= signature.cmdsize; put(0, header);
        }
    }
};
} // namespace md_symbols

static int nativeRestoreSymbols(NSString *input, NSString *output) {
    int status = nativeValidateImage(input);
    if (status) return status;
    @try {
        try {
            if (output) {
                struct stat a, b;
                if ([input.stringByStandardizingPath isEqualToString:output.stringByStandardizingPath] ||
                    (stat(input.fileSystemRepresentation, &a) == 0 && stat(output.fileSystemRepresentation, &b) == 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino))
                    return nativeInputError(output, "restore output must differ from input");
            }
            NSData *data = [NSData dataWithContentsOfFile:input];
            if (!data) return nativeInputError(input, "cannot read restore input", 1);
            struct stat inputMode;
            if (stat(input.fileSystemRepresentation, &inputMode) != 0)
                return nativeInputError(input, "cannot read restore input permissions", 1);
            md_symbols::Image image;
            const auto *bytes = static_cast<const uint8_t *>(data.bytes);
            image.bytes.assign(bytes, bytes + data.length);
            image.parse(); image.collect(); image.rebuild();
            NSString *destination = output ?: input;
            if (output || !image.recovered.empty()) {
                NSError *error = nil;
                NSData *result = [NSData dataWithBytesNoCopy:image.bytes.data() length:image.bytes.size() freeWhenDone:NO];
                if (![result writeToFile:destination options:NSDataWritingAtomic error:&error])
                    return nativeInputError(destination, "cannot atomically write restored output", 4);
                if (chmod(destination.fileSystemRepresentation, inputMode.st_mode & 0777) != 0)
                    return nativeInputError(destination, "cannot preserve executable permissions", 4);
            }
            fprintf(stdout, "Restored %zu Objective-C method symbols; skipped %zu unresolved/dynamic categories. Re-sign before installation.\n", image.recovered.size(), image.skippedCategories);
            return 0;
        } catch (const std::exception &error) { return nativeInputError(input, error.what()); }
    } @catch (NSException *exception) { return nativeInputError(input, exception.reason.UTF8String); }
}
