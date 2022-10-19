use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::Elf32;
use elf_utils::section_hdr::SectionHdr;
use elf_utils::section_hdr::SectionHdrData;
use elf_utils::section_hdr::SectionHdrs;
use elf_utils::section_hdr::SectionHdrsError;
use elf_utils::section_hdr::SectionPos;
use elf_utils::strtab::Strtab;
use elf_utils::strtab::WithStrtab;

const ELF32_SECTION_HDR_BYTES: usize = 920;

const ELF32_NUM_SECTION_HDRS: usize = 23;

const ELF32_SECTION_HDR: [u8; ELF32_SECTION_HDR_BYTES] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
    0x74, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x16, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
    0x8c, 0x01, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x1e, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x6f,
    0x02, 0x00, 0x00, 0x00, 0x3c, 0x03, 0x00, 0x00,
    0x3c, 0x03, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x2b, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xff, 0x6f,
    0x02, 0x00, 0x00, 0x00, 0x74, 0x03, 0x00, 0x00,
    0x74, 0x03, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3a, 0x00, 0x00, 0x00, 0xf6, 0xff, 0xff, 0x6f,
    0x02, 0x00, 0x00, 0x00, 0x70, 0x04, 0x00, 0x00,
    0x70, 0x04, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x44, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
    0x40, 0x05, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x4a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
    0x20, 0x06, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x00, 0x00, 0xf4, 0x07, 0x00, 0x00,
    0xf4, 0x07, 0x00, 0x00, 0xe8, 0x05, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x5b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x32, 0x00, 0x00, 0x00, 0xdc, 0x0d, 0x00, 0x00,
    0xdc, 0x0d, 0x00, 0x00, 0xb0, 0x34, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x8c, 0x42, 0x00, 0x00,
    0x8c, 0x42, 0x00, 0x00, 0xbc, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x71, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x48, 0x43, 0x00, 0x00,
    0x48, 0x43, 0x00, 0x00, 0x74, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0xc0, 0x56, 0x00, 0x00,
    0xc0, 0x46, 0x00, 0x00, 0x05, 0x4d, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x81, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0xc8, 0xb3, 0x01, 0x00,
    0xc8, 0x93, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x8d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0xcc, 0xb3, 0x01, 0x00,
    0xcc, 0x93, 0x01, 0x00, 0x5c, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x28, 0xb6, 0x01, 0x00,
    0x28, 0x96, 0x01, 0x00, 0x88, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0xa3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0xb0, 0xb6, 0x01, 0x00,
    0xb0, 0x96, 0x01, 0x00, 0x60, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x10, 0xc7, 0x01, 0x00,
    0x10, 0x97, 0x01, 0x00, 0x58, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xae, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x68, 0xc7, 0x01, 0x00,
    0x68, 0x97, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb7, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x74, 0xc7, 0x01, 0x00,
    0x74, 0x97, 0x01, 0x00, 0x04, 0x0b, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xbc, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x74, 0x97, 0x01, 0x00, 0xde, 0x11, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xc5, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0xa9, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x6a, 0xa9, 0x01, 0x00, 0xd4, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

const ELF32_STRTAB_BYTES: usize = 212;

const ELF32_STRTAB: [u8; ELF32_STRTAB_BYTES] = [
    0x00, 0x00, 0x2e, 0x73, 0x68, 0x73, 0x74, 0x72,
    0x74, 0x61, 0x62, 0x00, 0x2e, 0x6e, 0x6f, 0x74,
    0x65, 0x2e, 0x74, 0x61, 0x67, 0x00, 0x2e, 0x64,
    0x79, 0x6e, 0x73, 0x79, 0x6d, 0x00, 0x2e, 0x67,
    0x6e, 0x75, 0x2e, 0x76, 0x65, 0x72, 0x73, 0x69,
    0x6f, 0x6e, 0x00, 0x2e, 0x67, 0x6e, 0x75, 0x2e,
    0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f,
    0x64, 0x00, 0x2e, 0x67, 0x6e, 0x75, 0x2e, 0x68,
    0x61, 0x73, 0x68, 0x00, 0x2e, 0x68, 0x61, 0x73,
    0x68, 0x00, 0x2e, 0x64, 0x79, 0x6e, 0x73, 0x74,
    0x72, 0x00, 0x2e, 0x72, 0x65, 0x6c, 0x2e, 0x64,
    0x79, 0x6e, 0x00, 0x2e, 0x72, 0x6f, 0x64, 0x61,
    0x74, 0x61, 0x00, 0x2e, 0x65, 0x68, 0x5f, 0x66,
    0x72, 0x61, 0x6d, 0x65, 0x5f, 0x68, 0x64, 0x72,
    0x00, 0x2e, 0x65, 0x68, 0x5f, 0x66, 0x72, 0x61,
    0x6d, 0x65, 0x00, 0x2e, 0x74, 0x65, 0x78, 0x74,
    0x00, 0x2e, 0x66, 0x69, 0x6e, 0x69, 0x5f, 0x61,
    0x72, 0x72, 0x61, 0x79, 0x00, 0x2e, 0x64, 0x61,
    0x74, 0x61, 0x2e, 0x72, 0x65, 0x6c, 0x2e, 0x72,
    0x6f, 0x00, 0x2e, 0x64, 0x79, 0x6e, 0x61, 0x6d,
    0x69, 0x63, 0x00, 0x2e, 0x67, 0x6f, 0x74, 0x00,
    0x2e, 0x64, 0x61, 0x74, 0x61, 0x00, 0x2e, 0x67,
    0x6f, 0x74, 0x2e, 0x70, 0x6c, 0x74, 0x00, 0x2e,
    0x62, 0x73, 0x73, 0x00, 0x2e, 0x63, 0x6f, 0x6d,
    0x6d, 0x65, 0x6e, 0x74, 0x00, 0x2e, 0x67, 0x6e,
    0x75, 0x5f, 0x64, 0x65, 0x62, 0x75, 0x67, 0x6c,
    0x69, 0x6e, 0x6b, 0x00
];

const ELF32_SECTION_HDR_CONTENTS_BARE: [SectionHdrData<Elf32, u32, u32,
                                                       u32, u32,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>>;
                                        ELF32_NUM_SECTION_HDRS] = [
    SectionHdrData::Null,
    SectionHdrData::Note { name: 12, addr: 0x174, align: 4,
                           note: SectionPos { offset: 0x174, size: 0x18 },
                           alloc: true, write: false, exec: false },
    SectionHdrData::Dynsym { name: 22, addr: 0x18c, align: 4,
                             syms: SectionPos { offset: 0x18c, size: 0x1b0 },
                             strtab: 7, local_end: 1,
                             alloc: true, write: false, exec: false },
    SectionHdrData::Unknown { name: 30, tag: 0x6fffffff, addr: 0x33c,
                              align: 2, offset: 0x33c, size: 0x36, ent_size: 2,
                              link: 2, info: 0, flags: 0x2 },
    SectionHdrData::Unknown { name: 43, tag: 0x6ffffffd, addr: 0x374,
                              align: 4, offset: 0x374, size: 0xfc, ent_size: 0,
                              link: 7, info: 9, flags: 0x2 },
    SectionHdrData::Unknown { name: 58, tag: 0x6ffffff6, addr: 0x470,
                              align: 4, offset: 0x470, size: 0xd0, ent_size: 0,
                              link: 2, info: 0, flags: 0x2 },
    SectionHdrData::Hash { name: 68, addr: 0x540, align: 4,
                           hash: SectionPos { offset: 0x540, size: 0xe0 },
                           symtab: 2, alloc: true, write: false, exec: false },
    SectionHdrData::Strtab { name: 74, addr: 0x620, align: 1,
                             strs: SectionPos { offset: 0x620, size: 0x1d2 } },
    SectionHdrData::Rel { name: 82, addr: 0x7f4, align: 4,
                          rels: SectionPos { offset: 0x7f4, size: 0x5e8 },
                          symtab: 2, target: 0, alloc: true, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: 91, addr: 0xddc, align: 4,
                               data: SectionPos { offset: 0xddc, size: 0x34b0 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: 99, addr: 0x428c, align: 4,
                               data: SectionPos { offset: 0x428c, size: 0xbc },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: 113, addr: 0x4348, align: 4,
                               data: SectionPos { offset: 0x4348, size: 0x374 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: 123, addr: 0x56c0, align: 16,
                               data: SectionPos { offset: 0x46c0,
                                                  size: 0x14d05 },
                               alloc: true, write: false, exec: true },
    SectionHdrData::Unknown { name: 129, tag: 15, addr: 0x1b3c8, align: 4,
                              offset: 0x193c8, size: 4, ent_size: 0, link: 0,
                              info: 0, flags: 0x3 },
    SectionHdrData::ProgBits { name: 141, addr: 0x1b3cc, align: 4,
                               data: SectionPos { offset: 0x193cc,
                                                  size: 0x25c },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Dynamic { name: 154, addr: 0x1b628, align: 4, strtab: 7,
                              dynamic: SectionPos { offset: 0x19628,
                                                    size: 0x88 },
                              alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: 163, addr: 0x1b6b0, align: 4,
                               data: SectionPos { offset: 0x196b0, size: 0x60 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: 168, addr: 0x1c710, align: 4,
                               data: SectionPos { offset: 0x19710, size: 0x58 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: 174, addr: 0x1c768, align: 4,
                               data: SectionPos { offset: 0x19768, size: 0xc },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Nobits { name: 183, addr: 0x1c774, align: 4,
                             offset: 0x19774, size: 0xb04, alloc: true,
                             write: true, exec: false },
    SectionHdrData::ProgBits { name: 188, addr: 0, align: 1,
                               data: SectionPos { offset: 0x19774,
                                                  size: 0x11de },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: 197, addr: 0, align: 1,
                               data: SectionPos { offset: 0x1a952, size: 0x18 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: 2, addr: 0, align: 1,
                             strs: SectionPos { offset: 0x1a96a, size: 0xd4 } }
];

const ELF32_SECTION_HDR_CONTENTS_STRS: [SectionHdrData<Elf32,
                                                       Result<&'static str,
                                                              &'static [u8]>,
                                                       u32,u32, u32,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>,
                                                       SectionPos<u32>>;
                                        ELF32_NUM_SECTION_HDRS] = [
    SectionHdrData::Null,
    SectionHdrData::Note { name: Ok(".note.tag"), addr: 0x174, align: 4,
                           note: SectionPos { offset: 0x174, size: 0x18 },
                           alloc: true, write: false, exec: false },
    SectionHdrData::Dynsym { name: Ok(".dynsym"), addr: 0x18c, align: 4,
                             syms: SectionPos { offset: 0x18c, size: 0x1b0 },
                             strtab: 7, local_end: 1,
                             alloc: true, write: false, exec: false },
    SectionHdrData::Unknown { name: Ok(".gnu.version"), tag: 0x6fffffff,
                              addr: 0x33c, align: 2, offset: 0x33c, size: 0x36,
                              ent_size: 2, link: 2, info: 0, flags: 0x2 },
    SectionHdrData::Unknown { name: Ok(".gnu.version_d"), tag: 0x6ffffffd,
                              addr: 0x374, align: 4, offset: 0x374, size: 0xfc,
                              ent_size: 0, link: 7, info: 9, flags: 0x2 },
    SectionHdrData::Unknown { name: Ok(".gnu.hash"), tag: 0x6ffffff6,
                              addr: 0x470, align: 4, offset: 0x470, size: 0xd0,
                              ent_size: 0, link: 2, info: 0, flags: 0x2 },
    SectionHdrData::Hash { name: Ok(".hash"), addr: 0x540, align: 4,
                           hash: SectionPos { offset: 0x540, size: 0xe0 },
                           symtab: 2, alloc: true, write: false, exec: false },
    SectionHdrData::Strtab { name: Ok(".dynstr"), addr: 0x620, align: 1,
                             strs: SectionPos { offset: 0x620, size: 0x1d2 } },
    SectionHdrData::Rel { name: Ok(".rel.dyn"), addr: 0x7f4, align: 4,
                          rels: SectionPos { offset: 0x7f4, size: 0x5e8 },
                          symtab: 2, target: 0, alloc: true, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: Ok(".rodata"), addr: 0xddc, align: 4,
                               data: SectionPos { offset: 0xddc, size: 0x34b0 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: Ok(".eh_frame_hdr"), addr: 0x428c,
                               align: 4, data: SectionPos { offset: 0x428c,
                                                            size: 0xbc },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: Ok(".eh_frame"), addr: 0x4348, align: 4,
                               data: SectionPos { offset: 0x4348, size: 0x374 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: Ok(".text"), addr: 0x56c0, align: 16,
                               data: SectionPos { offset: 0x46c0,
                                                  size: 0x14d05 },
                               alloc: true, write: false, exec: true },
    SectionHdrData::Unknown { name: Ok(".fini_array"), tag: 15, addr: 0x1b3c8,
                              align: 4, offset: 0x193c8, size: 4, ent_size: 0,
                              link: 0, info: 0, flags: 0x3 },
    SectionHdrData::ProgBits { name: Ok(".data.rel.ro"), addr: 0x1b3cc,
                               align: 4, data: SectionPos { offset: 0x193cc,
                                                            size: 0x25c },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Dynamic { name: Ok(".dynamic"), addr: 0x1b628, align: 4,
                              strtab: 7, dynamic: SectionPos { offset: 0x19628,
                                                               size: 0x88 },
                              alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: Ok(".got"), addr: 0x1b6b0, align: 4,
                               data: SectionPos { offset: 0x196b0, size: 0x60 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: Ok(".data"), addr: 0x1c710, align: 4,
                               data: SectionPos { offset: 0x19710, size: 0x58 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: Ok(".got.plt"), addr: 0x1c768, align: 4,
                               data: SectionPos { offset: 0x19768, size: 0xc },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Nobits { name: Ok(".bss"), addr: 0x1c774, align: 4,
                             offset: 0x19774, size: 0xb04, alloc: true,
                             write: true, exec: false },
    SectionHdrData::ProgBits { name: Ok(".comment"), addr: 0, align: 1,
                               data: SectionPos { offset: 0x19774,
                                                  size: 0x11de },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: Ok(".gnu_debuglink"), addr: 0, align: 1,
                               data: SectionPos { offset: 0x1a952, size: 0x18 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: Ok(".shstrtab"), addr: 0, align: 1,
                             strs: SectionPos { offset: 0x1a96a, size: 0xd4 } }
];

#[test]
fn test_SectionHdrs_from_bytes_just_right() {
    let section_hdr: Result<SectionHdrs<'_, LittleEndian, Elf32>,
                            SectionHdrsError> =
        SectionHdrs::try_from(&ELF32_SECTION_HDR[0..]);

    assert!(section_hdr.is_ok());
}

#[test]
fn test_SectionHdrs_from_bytes_too_small() {
    let section_hdr: Result<SectionHdrs<'_, LittleEndian, Elf32>,
                            SectionHdrsError> =
        SectionHdrs::try_from(&ELF32_SECTION_HDR[0 ..
                                                 ELF32_SECTION_HDR.len() - 1]);

    assert!(section_hdr.is_err());
}

#[test]
fn test_SectionHdrs_from_bytes_num_hdrs() {
    let section_hdr: SectionHdrs<'_, LittleEndian, Elf32> =
        SectionHdrs::try_from(&ELF32_SECTION_HDR[0..])
        .expect("Expected success");

    assert_eq!(section_hdr.num_hdrs(), ELF32_NUM_SECTION_HDRS);
}

#[test]
fn test_SectionHdrs_from_bytes_iter_len() {
    let section_hdr: SectionHdrs<'_, LittleEndian, Elf32> =
        SectionHdrs::try_from(&ELF32_SECTION_HDR[0..])
        .expect("Expected success");
    let mut iter = section_hdr.iter();

    for i in 0 .. ELF32_NUM_SECTION_HDRS {
        assert_eq!(iter.len(), ELF32_NUM_SECTION_HDRS - i);
        assert!(iter.next().is_some());
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_SectionHdrs_from_bytes_just_right_mut() {
    let mut buf = ELF32_SECTION_HDR.clone();
    let section_hdr: Result<SectionHdrs<'_, LittleEndian, Elf32>,
                            SectionHdrsError> =
        SectionHdrs::try_from(&mut buf[0..]);

    assert!(section_hdr.is_ok());
}

#[test]
fn test_SectionHdrs_from_bytes_too_small_mut() {
    let mut buf = ELF32_SECTION_HDR.clone();
    let section_hdr: Result<SectionHdrs<'_, LittleEndian, Elf32>,
                            SectionHdrsError> =
        SectionHdrs::try_from(&mut buf[0 .. ELF32_SECTION_HDR.len() - 1]);

    assert!(section_hdr.is_err());
}

#[test]
fn test_SectionHdrs_from_bytes_num_hdrs_mut() {
    let mut buf = ELF32_SECTION_HDR.clone();
    let section_hdr: SectionHdrs<'_, LittleEndian, Elf32> =
        SectionHdrs::try_from(&mut buf[0..]).expect("Expected success");

    assert_eq!(section_hdr.num_hdrs(), ELF32_NUM_SECTION_HDRS);
}

#[test]
fn test_SectionHdrs_from_bytes_iter_len_mut() {
    let mut buf = ELF32_SECTION_HDR.clone();
    let section_hdr: SectionHdrs<'_, LittleEndian, Elf32> =
        SectionHdrs::try_from(&mut buf[0..]).expect("Expected success");
    let iter = section_hdr.iter();

    assert_eq!(iter.len(), ELF32_NUM_SECTION_HDRS);
}

#[test]
fn test_SectionHdrs_from_bytes_iter() {
    let section_hdr: SectionHdrs<'_, LittleEndian, Elf32> =
        SectionHdrs::try_from(&ELF32_SECTION_HDR[0..])
        .expect("Expected success");
    let mut iter = section_hdr.iter();

    for expect in ELF32_SECTION_HDR_CONTENTS_BARE.iter() {
        let ent = iter.next();

        assert!(ent.is_some());

        let data = ent.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_SectionHdrs_from_bytes_idx() {
    let section_hdr: SectionHdrs<'_, LittleEndian, Elf32> =
        SectionHdrs::try_from(&ELF32_SECTION_HDR[0..])
        .expect("Expected success");
    let mut iter = section_hdr.iter();

    for i in 0 .. ELF32_SECTION_HDR_CONTENTS_BARE.len() {
        let expect = &ELF32_SECTION_HDR_CONTENTS_BARE[i];
        let ent = section_hdr.idx(i);

        assert!(ent.is_some());

        let data = ent.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(section_hdr.idx(ELF32_SECTION_HDR_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_SectionHdrs_with_strtab_iter() {
    let section_hdr: SectionHdrs<'_, LittleEndian, Elf32> =
        SectionHdrs::try_from(&ELF32_SECTION_HDR[0..])
        .expect("Expected success");
    let strtab: Strtab<'_> = Strtab::try_from(&ELF32_STRTAB[0..])
        .expect("Expected success");
    let mut iter = section_hdr.iter();

    for expect in ELF32_SECTION_HDR_CONTENTS_STRS.iter() {
        let ent = iter.next();

        assert!(ent.is_some());

        let data = ent.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SectionHdrData<Elf32, u32, u32, u32, u32,
                                SectionPos<u32>, SectionPos<u32>,
                                SectionPos<u32>, SectionPos<u32>,
                                SectionPos<u32>, SectionPos<u32>,
                                SectionPos<u32>, SectionPos<u32>> =
            data.unwrap();
        let actual: SectionHdrData<Elf32, Result<&'static str, &'static [u8]>,
                                   u32, u32, u32,
                                   SectionPos<u32>, SectionPos<u32>,
                                   SectionPos<u32>, SectionPos<u32>,
                                   SectionPos<u32>, SectionPos<u32>,
                                   SectionPos<u32>, SectionPos<u32>> =
            raw.with_strtab(strtab).unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_SectionHdrs_with_strtab_idx() {
    let section_hdr: SectionHdrs<'_, LittleEndian, Elf32> =
        SectionHdrs::try_from(&ELF32_SECTION_HDR[0..])
        .expect("Expected success");
    let strtab: Strtab<'_> = Strtab::try_from(&ELF32_STRTAB[0..])
        .expect("Expected success");
    let mut iter = section_hdr.iter();

    for i in 0 .. ELF32_SECTION_HDR_CONTENTS_STRS.len() {
        let expect = &ELF32_SECTION_HDR_CONTENTS_STRS[i];
        let ent = section_hdr.idx(i);

        assert!(ent.is_some());

        let data = ent.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SectionHdrData<Elf32, u32, u32, u32, u32,
                                SectionPos<u32>, SectionPos<u32>,
                                SectionPos<u32>, SectionPos<u32>,
                                SectionPos<u32>, SectionPos<u32>,
                                SectionPos<u32>, SectionPos<u32>> =
            data.unwrap();
        let actual: SectionHdrData<Elf32, Result<&'static str, &'static [u8]>,
                                   u32, u32, u32,
                                   SectionPos<u32>, SectionPos<u32>,
                                   SectionPos<u32>, SectionPos<u32>,
                                   SectionPos<u32>, SectionPos<u32>,
                                   SectionPos<u32>, SectionPos<u32>> =
            raw.with_strtab(strtab).unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(section_hdr.idx(ELF32_SECTION_HDR_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_SectionHdrs_create_just_right() {
    let mut buf = [0; ELF32_SECTION_HDR_BYTES];
    let dynamic: Result<(SectionHdrs<'_, LittleEndian, Elf32>,
                         &'_ mut [u8]), ()> =
        SectionHdrs::create_split(&mut buf[0..],
                                  ELF32_SECTION_HDR_CONTENTS_BARE
                                  .iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_SectionHdrs_create_too_big() {
    let mut buf = [0; ELF32_SECTION_HDR_BYTES + 1];
    let dynamic: Result<(SectionHdrs<'_, LittleEndian, Elf32>,
                         &'_ mut [u8]), ()> =
        SectionHdrs::create_split(&mut buf[0..],
                                  ELF32_SECTION_HDR_CONTENTS_BARE
                                  .iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_SectionHdrs_create_too_small() {
    let mut buf = [0; ELF32_SECTION_HDR_BYTES - 1];
    let dynamic: Result<(SectionHdrs<'_, LittleEndian, Elf32>,
                         &'_ mut [u8]), ()> =
        SectionHdrs::create_split(&mut buf[0..],
                                  ELF32_SECTION_HDR_CONTENTS_BARE
                                  .iter().map(|x| *x));

    assert!(dynamic.is_err());
}

#[test]
fn test_SectionHdrs_create_iter() {
    let mut buf = [0; ELF32_SECTION_HDR_BYTES];
    let dynamic: Result<(SectionHdrs<'_, LittleEndian, Elf32>,
                         &'_ mut [u8]), ()> =
        SectionHdrs::create_split(&mut buf[0..],
                                  ELF32_SECTION_HDR_CONTENTS_BARE
                                  .iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = dynamic.iter();

    for expect in ELF32_SECTION_HDR_CONTENTS_BARE.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_SectionHdrs_create_idx() {
    let mut buf = [0; ELF32_SECTION_HDR_BYTES];
    let dynamic: Result<(SectionHdrs<'_, LittleEndian, Elf32>,
                         &'_ mut [u8]), ()> =
        SectionHdrs::create_split(&mut buf[0..],
                                  ELF32_SECTION_HDR_CONTENTS_BARE
                                  .iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF32_SECTION_HDR_CONTENTS_BARE.len() {
        let expect = &ELF32_SECTION_HDR_CONTENTS_BARE[i];
        let sym = dynamic.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(dynamic.idx(ELF32_SECTION_HDR_CONTENTS_BARE.len()).is_none());
}
