"""Exercise header declarations on modern and classic ObjC metadata."""
import hashlib
import os
import plistlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
def commands(data):
    offset = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, offset)
        yield cmd, offset
        offset += size


def symbols(data):
    offset = next(offset for cmd, offset in commands(data) if cmd == 2)
    symoff, count, stroff, size = struct.unpack_from('<4I', data, offset + 8)
    names = []
    values = {}
    for index in range(count):
        name, kind, section, desc, value = struct.unpack_from('<IBBHQ', data, symoff + index * 16)
        text = data[stroff + name:data.index(b'\0', stroff + name)].decode()
        names.append(text)
        if kind & 14 == 14:
            values[text] = value
    return names, values




ROOT = Path(__file__).resolve().parents[2]
TOOL = Path(os.environ.get('CLASS_DUMP_BIN', ROOT / 'build/Release/class-dump'))

@unittest.skipUnless(Path('/usr/bin/xcrun').exists(), 'requires Xcode')
class ClassDumpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='monkeydev-classdump-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
        cls.inputs = {}
        for name, flags in [('modern', []), ('big-chained', ['-Wl,-no_objc_relative_method_lists']),
                            ('relative-legacy', ['-Wl,-no_fixup_chains']),
                            ('big-legacy', ['-Wl,-no_fixup_chains', '-Wl,-no_objc_relative_method_lists'])]:
            path = cls.root / name
            subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios15.0', '-isysroot', sdk,
                            '-fobjc-arc', '-O0', '-Wl,-no_objc_category_merging', *flags,
                            str(ROOT / 'Tests/Modern/class_dump_fixture.m'), '-framework', 'Foundation',
                            '-o', str(path)], check=True, capture_output=True)
            cls.inputs[name] = path.read_bytes()

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(dir=self.root))
        self.input = self.case / 'input'

    def run_dump(self, *args):
        before = self.input.read_bytes()
        result = subprocess.run([str(TOOL), '--arch', 'arm64', *args, str(self.input)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(hashlib.sha256(before).digest(), hashlib.sha256(self.input.read_bytes()).digest())
        return result

    def test_declarations_across_four_formats(self):
        for name, data in self.inputs.items():
            with self.subTest(name=name):
                self.input.write_bytes(data)
                result = self.run_dump()
                self.assertEqual(result.returncode, 0, result.stderr)
                for declaration in ['@interface MDHeaderFixture : NSObject <MDHeaderProtocol>',
                                    '@protocol MDHeaderProtocol', 'calculate:', '+ (id)marker;',
                                    'NSString *title', '_counter', 'mdHeaderExternal', 'optionalMarker']:
                    self.assertIn(declaration, result.stdout)

    def test_multifile_and_filter(self):
        self.input.write_bytes(self.inputs['modern'])
        output = self.case / 'Headers with spaces'
        result = self.run_dump('-H', '-o', str(output), '-C', '^MDHeaderFixture$')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('calculate:', (output / 'MDHeaderFixture.h').read_text())
        self.assertFalse((output / 'NSObject-MDHeaderExternal.h').exists())

    def test_runtime_initialized_ivar_offset(self):
        data = bytearray(self.inputs['big-legacy'])
        segments = []
        for cmd, off in commands(data):
            if cmd == 0x19:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4Q', data, off + 24)
                segments.append((vmaddr, vmsize, fileoff, filesize))
        nameoff = data.index(b'_counter\0')
        nameaddr = next(vm + nameoff - file for vm, _, file, size in segments if file <= nameoff < file + size)
        field = data.index(struct.pack('<Q', nameaddr)) - 8
        runtime = symbols(data)[1]['_mdRuntimeIvarOffset']
        struct.pack_into('<Q', data, field, runtime)
        self.input.write_bytes(data)
        result = self.run_dump('-a')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('offset initialized at runtime', result.stdout)

    def test_header_write_failure(self):
        self.input.write_bytes(self.inputs['modern'])
        output = self.case / 'Not a directory'
        output.write_text('keep')
        result = self.run_dump('-H', '-o', str(output))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), 'keep')

    def test_invalid_inputs_do_not_emit_headers(self):
        modern = self.inputs['modern']
        encrypted = bytearray(modern)
        enc = next(off for cmd, off in commands(modern) if cmd == 0x2c)
        struct.pack_into('<I', encrypted, enc + 16, 1)
        arm64e = bytearray(modern)
        struct.pack_into('<I', arm64e, 8, 2)
        for data in [b'bad', bytes(encrypted), bytes(arm64e)]:
            with self.subTest(size=len(data)):
                self.input.write_bytes(data)
                output = self.case / 'Rejected'
                result = self.run_dump('-H', '-o', str(output))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())

if __name__ == '__main__':
    unittest.main()
