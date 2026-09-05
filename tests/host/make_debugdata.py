#!/usr/bin/env python3
"""Build the synthetic ELF files the host tests run against.

Each file is a minimal ELF whose only symbol table lives in a compressed
.gnu_debugdata section, which is what a stripped system library looks like.
Finding a symbol in it therefore exercises exactly one path: locating the
section, decompressing the LZMA1 stream, and parsing the ELF that comes out.

Two layouts are produced because Android prepends a four byte CRC32 that the
GNU toolchain leaves out, and the loader has to cope with both:

  <output>-plain.elf  raw LZMA1 "alone" stream
  <output>-crc.elf    four byte CRC32 in front of the stream

Usage: python make_debugdata.py <output-prefix>
"""

import struct
import sys
import zlib

import lzma

# ELF constants, limited to what these files are made of.
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_EXEC = 2
EM_X86_64 = 62

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3

STB_GLOBAL = 1
STT_FUNC = 2
STT_OBJECT = 1

SHN_INDEX = 1

# The symbols the tests look up. The addresses are arbitrary but fixed, so the
# tests can assert on the exact value rather than on "something non-zero".
SYMBOLS = [
    ("zygote_probe_alpha", STT_FUNC, 0x1000, 0x40),
    ("zygote_probe_beta", STT_FUNC, 0x2000, 0x80),
    ("zygote_probe_object", STT_OBJECT, 0x3000, 0x10),
]


def build_string_table(names):
    """A string table starting with the mandatory empty string."""
    blob = bytearray(b"\0")
    offsets = {}

    for name in names:
        offsets[name] = len(blob)
        blob += name.encode() + b"\0"

    return bytes(blob), offsets


def build_inner(names, offsets):
    """The ELF that ends up compressed inside .gnu_debugdata.

    It carries a .symtab with the probe symbols and nothing else: no program
    headers, no other sections, which keeps it small enough to read as a
    fixture while still being a valid ELF the loader can walk.
    """
    strtab, _ = build_string_table(names)

    # Index 0 is the reserved all-zero entry of every symbol table.
    symtab = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))
    for name, kind, value, size in SYMBOLS:
        info = (STB_GLOBAL << 4) | kind
        symtab += struct.pack("<IBBHQQ", offsets[name], info, 0, SHN_INDEX, value, size)

    shstrtab, shstr_offsets = build_string_table([".symtab", ".strtab", ".shstrtab"])

    strtab_offset = 0
    symtab_offset = len(strtab)
    shstrtab_offset = symtab_offset + len(symtab)

    # The section header table sits right after the section contents.
    ehdr_size = 64
    shoff = ehdr_size + len(strtab) + len(symtab) + len(shstrtab)

    def shdr(name, kind, offset, size, link, entsize):
        return struct.pack("<IIQQQQIIQQ",
                           shstr_offsets.get(name, 0), kind, 0, 0,
                           offset, size, link, 0, 1, entsize)

    shdrs = shdr("", SHT_NULL, 0, 0, 0, 0)
    shdrs += shdr(".symtab", SHT_SYMTAB, symtab_offset, len(symtab), 2, 24)
    shdrs += shdr(".strtab", SHT_STRTAB, strtab_offset, len(strtab), 0, 0)
    shdrs += shdr(".shstrtab", SHT_STRTAB, shstrtab_offset, len(shstrtab), 0, 0)

    # e_entry, e_phoff, e_shoff, e_flags, then e_ehsize, e_phentsize,
    # e_phnum, e_shentsize, e_shnum, e_shstrndx.
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([ELFCLASS64, ELFDATA2LSB, EV_CURRENT]) + b"\0" * 9,
        ET_EXEC, EM_X86_64, EV_CURRENT, 0, 0, shoff, 0,
        64, 0, 0, 64, 4, 3,
    )

    return ehdr + strtab + bytes(symtab) + shstrtab + shdrs


# The encoder parameters, written out explicitly so the header built below
# always matches the stream the compressor produces. These are liblzma's
# defaults and the ones LzmaDecode expects unless told otherwise.
LC = 3
LP = 0
PB = 2
DICT_SIZE = 1 << 20


def encode_lzma1_props():
    """The five byte property header of an LZMA1 "alone" stream.

    Built here instead of with lzma.encode_filter_properties, which is missing
    from some Python builds. The layout is the one LzmaDecode reads back:
    one byte packing lc, lp and pb, then the dictionary size.
    """
    return bytes([(PB * 5 + LP) * 9 + LC]) + struct.pack("<I", DICT_SIZE)


def compress_alone(payload):
    """An LZMA1 "alone" stream: props(5), uncompressed size(8), then data.

    Built by hand rather than with FORMAT_ALONE: that writes the size field
    before it can know the length, so it stores the "unknown" marker, which
    the loader rejects on purpose.
    """
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": DICT_SIZE,
                "lc": LC, "lp": LP, "pb": PB}]
    compressor = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filters)
    body = compressor.compress(payload) + compressor.flush()

    return encode_lzma1_props() + struct.pack("<Q", len(payload)) + body


def build_outer(debugdata):
    """A minimal ELF with a single, compressed .gnu_debugdata section."""
    shstrtab, shstr_offsets = build_string_table([".gnu_debugdata", ".shstrtab"])

    ehdr_size = 64
    debugdata_offset = ehdr_size
    shstrtab_offset = debugdata_offset + len(debugdata)
    shoff = shstrtab_offset + len(shstrtab)

    def shdr(name, kind, offset, size, link, entsize):
        return struct.pack("<IIQQQQIIQQ",
                           shstr_offsets.get(name, 0), kind, 0, 0,
                           offset, size, link, 0, 1, entsize)

    shdrs = shdr("", SHT_NULL, 0, 0, 0, 0)
    shdrs += shdr(".gnu_debugdata", SHT_PROGBITS, debugdata_offset, len(debugdata), 0, 0)
    shdrs += shdr(".shstrtab", SHT_STRTAB, shstrtab_offset, len(shstrtab), 0, 0)

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([ELFCLASS64, ELFDATA2LSB, EV_CURRENT]) + b"\0" * 9,
        ET_EXEC, EM_X86_64, EV_CURRENT, 0, 0, shoff, 0,
        64, 0, 0, 64, 3, 2,
    )

    return ehdr + debugdata + shstrtab + shdrs


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: make_debugdata.py <output-prefix>")

    prefix = sys.argv[1]
    names = [name for name, _, _, _ in SYMBOLS]
    _, offsets = build_string_table(names)
    inner = build_inner(names, offsets)
    stream = compress_alone(inner)

    variants = {
        "-plain.elf": stream,
        "-crc.elf": struct.pack("<I", zlib.crc32(inner) & 0xFFFFFFFF) + stream,
    }

    for suffix, payload in variants.items():
        path = prefix + suffix
        with open(path, "wb") as handle:
            handle.write(build_outer(payload))

        print("wrote {} ({} bytes, payload {})".format(path, 64 + len(payload), len(payload)))


if __name__ == "__main__":
    main()
