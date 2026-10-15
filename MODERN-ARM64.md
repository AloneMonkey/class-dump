# Apple Silicon / modern Objective-C metadata

The `class-dump` target now builds a native arm64 macOS 14+ tool with current Xcode.
It supports decrypted thin arm64 inputs, relative and absolute Objective-C method
lists, chained pointer formats 64 / 64_OFFSET, external class binds, and ObjC
metadata sections outside the historical __DATA segment.

Build:

```sh
xcodebuild -project class-dump.xcodeproj -target class-dump -configuration Release \
  CODE_SIGNING_ALLOWED=NO SYMROOT="$PWD/build" OBJROOT="$PWD/build-obj"
```

Dump:

```sh
build/Release/class-dump --arch arm64 -H -o /tmp/Headers /path/to/executable
```

The chained pointers are decoded in memory; the input executable is never
rewritten. Unsupported inputs fail with a nonzero status. Header write failures
also fail the command. The old CLI and ObjC type formatter are retained.

Limitations: no pure Swift source recovery, arm64e/PAC, universal input, encrypted
input, compressed chained imports or multi-start chained pages. Categories whose
owning class exists only as a Swift runtime stub are skipped with diagnostics.
Unknown Swift ivar type encodings and some vector method encodings remain
comments in the output, not reconstructed types. Exported headers are analysis
aids and are not guaranteed to compile as a complete SDK.

Regression:

```sh
CLASS_DUMP_BIN="$PWD/build/Release/class-dump" \
  python3 -m unittest discover -s Tests/Modern -p test_class_dump.py -v
```

Validated against a decrypted Bilibili executable: the controller, NSURLSession
BFCTaskIntercept category and BCMReportSession declarations match the methods
previously verified with LLDB. Full header export was also exercised.
