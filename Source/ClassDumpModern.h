// Adapt the legacy class-dump reader to modern thin arm64 images, in memory only.
#pragma once
#pragma push_macro("__cmd")
#undef __cmd
#include <string>
#include "NativeInputValidation.h"
#include "NativeSymbolRestore.h"

static NSData *MDPrepareClassDumpImage(NSData *data, NSString *filename, NSDictionary **bindings) {
    if (nativeValidateImage(filename))
        [NSException raise:NSInvalidArgumentException format:@"unsupported or invalid class-dump input: %@", filename];
    try {
        md_symbols::Image image;
        const auto *bytes = static_cast<const uint8_t *>(data.bytes);
        image.bytes.assign(bytes, bytes + data.length);
        image.parse();
        NSMutableDictionary *names = [NSMutableDictionary dictionary];
        // Resolve rebases for the existing absolute-pointer reader. External binds
        // become null pointers and retain their symbol names in a separate map.
        for (const auto &entry : image.fixups) {
            image.put<uint64_t>(entry.first, entry.second.value);
            if (!entry.second.bind.empty()) {
                uint64_t address = 0;
                for (const auto &segment : image.segments) {
                    if (entry.first >= segment.fileoff && entry.first - segment.fileoff < segment.filesize) {
                        address = segment.vmaddr + entry.first - segment.fileoff;
                        break;
                    }
                }
                NSString *symbol = [NSString stringWithUTF8String:entry.second.bind.c_str()];
                if (!symbol) throw std::runtime_error("invalid UTF-8 in chained import");
                names[@(address)] = symbol;
            }
        }
        *bindings = names;
        return [NSData dataWithBytes:image.bytes.data() length:image.bytes.size()];
    } catch (const std::exception &error) {
        [NSException raise:NSInvalidArgumentException format:@"class-dump metadata: %s", error.what()];
    }
    return nil;
}

#pragma pop_macro("__cmd")
