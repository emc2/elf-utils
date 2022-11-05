use byteorder::LittleEndian;
use elf_utils::Elf32;
use elf_utils::ElfArch;
use elf_utils::ElfABI;
use elf_utils::ElfHdrData;
use elf_utils::ElfKind;
use elf_utils::ElfTable;
use elf_utils::dynamic::DynamicEntData;
use elf_utils::note::NoteData;
use elf_utils::prog_hdr::ProgHdrData;
use elf_utils::prog_hdr::Segment;
use elf_utils::reloc::x86::X86Rel;
use elf_utils::reloc::x86::X86Rela;
use elf_utils::section_hdr::SectionHdrData;
use elf_utils::section_hdr::SectionPos;
use elf_utils::section_hdr::SymsStrs;
use elf_utils::symtab::SymBase;
use elf_utils::symtab::SymBind;
use elf_utils::symtab::SymData;
use elf_utils::symtab::SymKind;
use std::marker::PhantomData;

pub const PATH: &'static str = "tests/data/relocatable/i386/crt1.o";

const NUM_SECTION_HDRS: usize = 30;

pub const SECTION_HDR_CONTENTS_BARE: [SectionHdrData<Elf32, u32, u32, u32, u32,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>>;
                                      NUM_SECTION_HDRS] = [
    SectionHdrData::Null,
    SectionHdrData::ProgBits { name: 28, addr: 0, align: 16,
                               data: SectionPos { offset: 0x40, size: 0x284 },
                               alloc: true, write: false, exec: true },
    SectionHdrData::Rel { name: 34, addr: 0, align: 4,
                          rels: SectionPos { offset: 0x2c4, size: 0xd0 },
                          symtab: 28, target: 1, alloc: false, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: 44, addr: 0, align: 1,
                               data: SectionPos { offset: 0x394, size: 0x279 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: 53, addr: 0, align: 1,
                               data: SectionPos { offset: 0x60d, size: 0x1 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: 68, addr: 0, align: 4,
                               data: SectionPos { offset: 0x610, size: 0x4 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Rel { name: 74, addr: 0, align: 4,
                          rels: SectionPos { offset: 0x614, size: 0x8 },
                          symtab: 28, target: 5, alloc: false, write: false,
                          exec: false },
    SectionHdrData::Nobits { name: 84, addr: 0, align: 4,
                             offset: 0x61c, size: 0x4, alloc: true,
                             write: true, exec: false },
    SectionHdrData::ProgBits { name: 89, addr: 0, align: 1,
                               data: SectionPos { offset: 0x61c, size: 0x295 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: 100, addr: 0, align: 1,
                               data: SectionPos { offset: 0x8b1, size: 0x1f4 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: 114, addr: 0, align: 1,
                               data: SectionPos { offset: 0xaa5, size: 0x60b },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: 126, addr: 0, align: 4,
                          rels: SectionPos { offset: 0x10b0, size: 0x3d8 },
                          symtab: 28, target: 10, alloc: false, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: 142, addr: 0, align: 1,
                               data: SectionPos { offset: 0x1488, size: 0x30 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: 156, addr: 0, align: 1,
                               data: SectionPos { offset: 0x14b8, size: 0x2a1 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: 167, addr: 0, align: 4,
                               data: SectionPos { offset: 0x175c, size: 0x7c },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: 180, addr: 0, align: 4,
                          rels: SectionPos { offset: 0x17d8, size: 0x30 },
                          symtab: 28, target: 14, alloc: false, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: 197, addr: 0, align: 1,
                               data: SectionPos { offset: 0x1808, size: 0x46c },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: 209, addr: 0, align: 4,
                          rels: SectionPos { offset: 0x1c74, size: 0x10 },
                          symtab: 28, target: 16, alloc: false, write: false,
                          exec: false },
    SectionHdrData::Unknown { name: 225, tag: 0x6fff4c03, addr: 0,
                              align: 1, offset: 0x1c84, size: 0xa, ent_size: 0,
                              link: 0, info: 0, flags: 0x80000000 },
    SectionHdrData::ProgBits { name: 239, addr: 0, align: 4,
                               data: SectionPos { offset: 0x1c90, size: 0x34 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::Rel { name: 249, addr: 0, align: 4,
                          rels: SectionPos { offset: 0x1cc4, size: 0x8 },
                          symtab: 28, target: 19, alloc: false, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: 263, addr: 0, align: 1,
                               data: SectionPos { offset: 0x1ccc, size: 0x20 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: 278, addr: 0, align: 4,
                          rels: SectionPos { offset: 0x1cec, size: 0x10 },
                          symtab: 28, target: 21, alloc: false, write: false,
                          exec: false },
    SectionHdrData::Unknown { name: 297, tag: 0x11, addr: 0,
                              align: 4, offset: 0x1cfc, size: 0x8, ent_size: 4,
                              link: 28, info: 72, flags: 0 },
    SectionHdrData::Note { name: 304, addr: 0, align: 4,
                           note: SectionPos { offset: 0x1d04, size: 0x18 },
                           alloc: true, write: false, exec: false },
    SectionHdrData::Note { name: 304, addr: 0, align: 4,
                           note: SectionPos { offset: 0x1d1c, size: 0x30 },
                           alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: 314, addr: 0, align: 1,
                               data: SectionPos { offset: 0x1d4c, size: 0x0 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: 18, addr: 0, align: 1,
                             strs: SectionPos { offset: 0x239c, size: 0x14a } },
    SectionHdrData::Symtab { name: 2, addr: 0, align: 4,
                             syms: SectionPos { offset: 0x1d4c, size: 0x650 },
                             strtab: 29, local_end: 83,
                             alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: 10, addr: 0, align: 1,
                             strs: SectionPos { offset: 0x24e6, size: 0x121 } }
];

pub const SECTION_HDR_CONTENTS_STRS: [SectionHdrData<Elf32, &'static str,
                                                     u32, u32, u32,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>,
                                                     SectionPos<u32>>;
                                      NUM_SECTION_HDRS] = [
    SectionHdrData::Null,
    SectionHdrData::ProgBits { name: ".text", addr: 0, align: 16,
                               data: SectionPos { offset: 0x40, size: 0x284 },
                               alloc: true, write: false, exec: true },
    SectionHdrData::Rel { name: ".rel.text", addr: 0, align: 4,
                          rels: SectionPos { offset: 0x2c4, size: 0xd0 },
                          symtab: 28, target: 1, alloc: false, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: ".comment", addr: 0, align: 1,
                               data: SectionPos { offset: 0x394, size: 0x279 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".rodata.str1.1", addr: 0, align: 1,
                               data: SectionPos { offset: 0x60d, size: 0x1 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".data", addr: 0, align: 4,
                               data: SectionPos { offset: 0x610, size: 0x4 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Rel { name: ".rel.data", addr: 0, align: 4,
                          rels: SectionPos { offset: 0x614, size: 0x8 },
                          symtab: 28, target: 5, alloc: false, write: false,
                          exec: false },
    SectionHdrData::Nobits { name: ".bss", addr: 0, align: 4,
                             offset: 0x61c, size: 0x4, alloc: true,
                             write: true, exec: false },
    SectionHdrData::ProgBits { name: ".debug_loc", addr: 0, align: 1,
                               data: SectionPos { offset: 0x61c, size: 0x295 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_abbrev", addr: 0, align: 1,
                               data: SectionPos { offset: 0x8b1, size: 0x1f4 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_info", addr: 0, align: 1,
                               data: SectionPos { offset: 0xaa5, size: 0x60b },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.debug_info", addr: 0, align: 4,
                          rels: SectionPos { offset: 0x10b0, size: 0x3d8 },
                          symtab: 28, target: 10, alloc: false, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: ".debug_ranges", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1488, size: 0x30 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_str", addr: 0, align: 1,
                               data: SectionPos { offset: 0x14b8, size: 0x2a1 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_frame", addr: 0, align: 4,
                               data: SectionPos { offset: 0x175c, size: 0x7c },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.debug_frame", addr: 0, align: 4,
                          rels: SectionPos { offset: 0x17d8, size: 0x30 },
                          symtab: 28, target: 14, alloc: false, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: ".debug_line", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1808, size: 0x46c },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.debug_line", addr: 0, align: 4,
                          rels: SectionPos { offset: 0x1c74, size: 0x10 },
                          symtab: 28, target: 16, alloc: false, write: false,
                          exec: false },
    SectionHdrData::Unknown { name: ".llvm_addrsig", tag: 0x6fff4c03, addr: 0,
                              align: 1, offset: 0x1c84, size: 0xa, ent_size: 0,
                              link: 0, info: 0, flags: 0x80000000 },
    SectionHdrData::ProgBits { name: ".eh_frame", addr: 0, align: 4,
                               data: SectionPos { offset: 0x1c90, size: 0x34 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.eh_frame", addr: 0, align: 4,
                          rels: SectionPos { offset: 0x1cc4, size: 0x8 },
                          symtab: 28, target: 19, alloc: false, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: ".debug_aranges", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1ccc, size: 0x20 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.debug_aranges", addr: 0, align: 4,
                          rels: SectionPos { offset: 0x1cec, size: 0x10 },
                          symtab: 28, target: 21, alloc: false, write: false,
                          exec: false },
    SectionHdrData::Unknown { name: ".group", tag: 0x11, addr: 0,
                              align: 4, offset: 0x1cfc, size: 0x8, ent_size: 4,
                              link: 28, info: 72, flags: 0 },
    SectionHdrData::Note { name: ".note.tag", addr: 0, align: 4,
                           note: SectionPos { offset: 0x1d04, size: 0x18 },
                           alloc: true, write: false, exec: false },
    SectionHdrData::Note { name: ".note.tag", addr: 0, align: 4,
                           note: SectionPos { offset: 0x1d1c, size: 0x30 },
                           alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".note.GNU-stack", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1d4c, size: 0x0 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: ".shstrtab", addr: 0, align: 1,
                             strs: SectionPos { offset: 0x239c, size: 0x14a } },
    SectionHdrData::Symtab { name: ".symtab", addr: 0, align: 4,
                             syms: SectionPos { offset: 0x1d4c, size: 0x650 },
                             strtab: 29, local_end: 83,
                             alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: ".strtab", addr: 0, align: 1,
                             strs: SectionPos { offset: 0x24e6, size: 0x121 } }
];

pub const HEADER_DATA: ElfHdrData<LittleEndian, Elf32, ElfTable<Elf32>,
                                  ElfTable<Elf32>, u16> =
    ElfHdrData {
        byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
        kind: ElfKind::Relocatable, arch: ElfArch::I386,
        entry: 0, flags: 0, section_hdr_strtab: 27, prog_hdrs: None,
        section_hdrs: ElfTable { offset: 9736, num_ents: 30 }
    };

const NUM_NOTES1: usize = 1;
const NUM_NOTES2: usize = 2;

const NOTE_1_NAME: [u8; 8] = [
    0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
];
const NOTE_1_DESC: [u8; 4] = [
    0x9b, 0xd6, 0x13, 0x00
];
const NOTE_2_NAME: [u8; 8] = [
    0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
];
const NOTE_2_DESC: [u8; 4] = [
    0x00, 0x00, 0x00, 0x00
];
const NOTE_3_NAME: [u8; 8] = [
    0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
];
const NOTE_3_DESC: [u8; 4] = [
    0x00, 0x00, 0x00, 0x00
];

pub const NOTES1_CONTENTS: [NoteData<'static>; NUM_NOTES1] = [
    NoteData { kind: 1, name: &NOTE_1_NAME, desc: &NOTE_1_DESC },
];

pub const NOTES2_CONTENTS: [NoteData<'static>; NUM_NOTES2] = [
    NoteData { kind: 4, name: &NOTE_2_NAME, desc: &NOTE_2_DESC },
    NoteData { kind: 2, name: &NOTE_3_NAME, desc: &NOTE_3_DESC },
];

const SHSTRTAB_NUM_STRS: usize = 30;

pub const SHSTRTAB_CONTENTS: [(&'static str, usize); SHSTRTAB_NUM_STRS] = [
    ("", 0),
    ("", 1),
    (".symtab", 2),
    (".strtab", 10),
    (".shstrtab", 18),
    (".text", 28),
    (".rel.text", 34),
    (".comment", 44),
    (".rodata.str1.1", 53),
    (".data", 68),
    (".rel.data", 74),
    (".bss", 84),
    (".debug_loc", 89),
    (".debug_abbrev", 100),
    (".debug_info", 114),
    (".rel.debug_info", 126),
    (".debug_ranges", 142),
    (".debug_str", 156),
    (".debug_frame", 167),
    (".rel.debug_frame", 180),
    (".debug_line", 197),
    (".rel.debug_line", 209),
    (".llvm_addrsig", 225),
    (".eh_frame", 239),
    (".rel.eh_frame", 249),
    (".debug_aranges", 263),
    (".rel.debug_aranges", 278),
    (".group", 297),
    (".note.tag", 304),
    (".note.GNU-stack", 314)
];

const STRTAB_NUM_STRS: usize = 25;

pub const STRTAB_CONTENTS: [(&'static str, usize); STRTAB_NUM_STRS] = [
    ("", 0),
    ("crt1_c.c", 1),
    (".L.str", 10),
    ("finalizer", 17),
    ("handle_static_init", 27),
    (".freebsd.noteG", 46),
    ("_start1", 61),
    ("_DYNAMIC", 69),
    ("__fini_array_end", 78),
    ("__fini_array_start", 95),
    ("__init_array_end", 114),
    ("__init_array_start", 131),
    ("__preinit_array_end", 150),
    ("__preinit_array_start", 170),
    ("__progname", 192),
    ("__rel_iplt_end", 203),
    ("__rel_iplt_start", 218),
    ("_fini", 235),
    ("_init", 241),
    ("_init_tls", 247),
    ("atexit", 257),
    ("environ", 264),
    ("exit", 272),
    ("main", 277),
    ("_start", 282)
];

const SYMTAB_NUM_SYMS: usize = 101;

pub const SYMTAB_CONTENTS: [SymData<&'static str, u16, Elf32>;
                            SYMTAB_NUM_SYMS] = [
    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Undef },
    SymData { name: Some("crt1_c.c"), value: 0, size: 0,
              kind: SymKind::File, bind: SymBind::Local,
              section: SymBase::Absolute },
    SymData { name: None, value: 504, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 485, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 68, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 480, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 275, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 6, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 442, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 447, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 132, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 512, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 166, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 16, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 155, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 338, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 496, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 141, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 356, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 102, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 419, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 317, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 343, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 467, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 398, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 71, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 620, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 281, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 286, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 197, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 235, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 638, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 456, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 365, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 328, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 410, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 113, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 428, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 239, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 199, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 654, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 458, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 625, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 298, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 255, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 614, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 460, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 373, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 215, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 379, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 477, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 120, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 439, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 290, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 666, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 388, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 83, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 454, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: Some(".L.str"), value: 0, size: 1,
              kind: SymKind::Object, bind: SymBind::Local,
              section: SymBase::Index(4) },
    SymData { name: Some("finalizer"), value: 544, size: 69,
              kind: SymKind::Function, bind: SymBind::Local,
              section: SymBase::Index(1) },
    SymData { name: Some("handle_static_init"), value: 304, size: 238,
              kind: SymKind::Function, bind: SymBind::Local,
              section: SymBase::Index(1) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(1) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(5) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(7) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(8) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(9) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(10) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(12) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(14) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(16) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(18) },
    SymData { name: Some(".freebsd.noteG"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Local,
              section: SymBase::Index(23) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(23) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(24) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(3) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(4) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(19) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(21) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(25) },
    SymData { name: Some("_start1"), value: 0, size: 303,
              kind: SymKind::Function, bind: SymBind::Local,
              section: SymBase::Index(1) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(26) },
    SymData { name: Some("_DYNAMIC"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Weak,
              section: SymBase::Undef },
    SymData { name: Some("__fini_array_end"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some("__fini_array_start"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some("__init_array_end"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some("__init_array_start"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some("__preinit_array_end"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some("__preinit_array_start"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some("__progname"), value: 0, size: 4,
              kind: SymKind::Object, bind: SymBind::Global,
              section: SymBase::Index(5) },
    SymData { name: Some("__rel_iplt_end"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Weak,
              section: SymBase::Undef },
    SymData { name: Some("__rel_iplt_start"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Weak,
              section: SymBase::Undef },
    SymData { name: Some("_fini"), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some("_init"), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some("_init_tls"), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some("atexit"), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some("environ"), value: 0, size: 4,
              kind: SymKind::Object, bind: SymBind::Global,
              section: SymBase::Index(7) },
    SymData { name: Some("exit"), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some("main"), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some("_start"), value: 616, size: 25,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(1) },
];

const REL_TEXT_NUM_RELS: usize = 26;

const REL_TEXT_RELS_CONTENTS_X86: [X86Rel<SymData<&'static str, u16, Elf32>>;
                                   REL_TEXT_NUM_RELS] = [
    X86Rel::Abs32 {
        sym: SymData { name: Some("environ"), value: 0, size: 4,
                       kind: SymKind::Object, bind: SymBind::Global,
                       section: SymBase::Index(7) },
        offset: 0x15
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("environ"), value: 0, size: 4,
                       kind: SymKind::Object, bind: SymBind::Global,
                       section: SymBase::Index(7) },
        offset: 0x1e
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("_DYNAMIC"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Weak,
                       section: SymBase::Undef },
        offset: 0x2d

    },
    X86Rel::PC32 {
        sym: SymData { name: Some("atexit"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x39
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__progname"), value: 0, size: 4,
                       kind: SymKind::Object, bind: SymBind::Global,
                       section: SymBase::Index(5) },
        offset: 0x51
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__rel_iplt_start"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Weak,
                       section: SymBase::Undef },
        offset: 0x69
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__rel_iplt_end"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Weak,
                       section: SymBase::Undef },
        offset: 0x6f
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__rel_iplt_end"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Weak,
                       section: SymBase::Undef },
        offset: 0xfc
    },
    X86Rel::PC32 {
        sym: SymData { name: Some("_init_tls"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x107
    },
    X86Rel::PC32 {
        sym: SymData { name: Some("main"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x122
    },
    X86Rel::PC32 {
        sym: SymData { name: Some("exit"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x12b
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("_DYNAMIC"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Weak,
                       section: SymBase::Undef },
        offset: 0x140
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x14d
    },
    X86Rel::PC32 {
        sym: SymData { name: Some("atexit"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x152
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__preinit_array_start"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x15a
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__preinit_array_end"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x15f
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__preinit_array_start"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x198
    },
    X86Rel::PC32 {
        sym: SymData { name: Some("_init"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x1b7
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__init_array_start"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x1bc
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__init_array_end"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x1c1
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__init_array_start"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x1f8
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__fini_array_start"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x225
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__fini_array_end"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x22a
    },
    X86Rel::PC32 {
        sym: SymData { name: Some("_fini"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x242
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__fini_array_start"), value: 0, size: 0,
                       kind: SymKind::None, bind: SymBind::Global,
                       section: SymBase::Undef },
        offset: 0x257
    },
    X86Rel::PC32 {
        sym: SymData { name: Some("_start1"), value: 0, size: 303,
                       kind: SymKind::Function, bind: SymBind::Local,
                       section: SymBase::Index(1) },
        offset: 0x27c
    },
];

const REL_DATA_NUM_RELS: usize = 1;

const REL_DATA_RELS_CONTENTS_X86: [X86Rel<SymData<&'static str, u16, Elf32>>;
                                   REL_DATA_NUM_RELS] = [
    X86Rel::Abs32 {
        sym: SymData { name: Some(".L.str"), value: 0, size: 1,
                       kind: SymKind::Object, bind: SymBind::Local,
                       section: SymBase::Index(4) },
        offset: 0
    },
];

const REL_DEBUG_INFO_NUM_RELS: usize = 123;

const REL_DEBUG_INFO_RELS_CONTENTS_X86: [X86Rel<SymData<&'static str,
                                                          u16, Elf32>>;
                                         REL_DEBUG_INFO_NUM_RELS] = [
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(9) },
        offset: 0x6
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 512, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0xc
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 166, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x12
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(16) },
        offset: 0x16
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 16, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1a
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x1e
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 155, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x27
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("__progname"), value: 0, size: 4,
                       kind: SymKind::Object, bind: SymBind::Global,
                       section: SymBase::Index(5) },
        offset: 0x33
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 338, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x42
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 496, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x49
    },
    X86Rel::Abs32 {
        sym: SymData { name: Some("environ"), value: 0, size: 4,
                       kind: SymKind::Object, bind: SymBind::Global,
                       section: SymBase::Index(7) },
        offset: 0x55
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 141, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x65
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 356, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x75
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 102, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x80
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 419, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x8b
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 317, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x96
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 343, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x9d
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 467, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0xc7
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 398, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0xd2
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 71, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0xd9
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 620, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0xe1
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 281, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0xec
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 286, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0xf7
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 197, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x102
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 235, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x10e
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 638, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x115
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 456, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x11d
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 365, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x137
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 328, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x142
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 410, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x14d
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 113, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x159
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 428, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x16a
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 239, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x171
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 456, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x179
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 199, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x184
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 654, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x18f
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 458, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x19a
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 625, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1a5
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 298, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1b0
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 255, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1bb
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 614, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1c6
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 460, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1d1
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 373, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1e1
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 215, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1f4
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 379, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x1fb
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 477, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x203
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 458, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x20e
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 120, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x21f
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 477, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x227
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 439, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x232
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 458, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x23d
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x249
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 290, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x253
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 504, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x25d
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 620, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x26b
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 281, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x279
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x284
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 286, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x288
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(12) },
        offset: 0x297
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x29f
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x2a8
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x2b1
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x2c4
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x2d0
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x2dd
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x2e9
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x2f2
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x2fb
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x304
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x30d
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x316
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x31f
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x328
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x331
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x33e
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x35a
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x366
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(12) },
        offset: 0x379
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x381
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x38a
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x39f
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x3a6
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x3af
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x3b8
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x3ce
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 666, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x3d4
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 388, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x3eb
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x3f2
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 83, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x3fc
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x403
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 620, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x407
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x412
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 281, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x416
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 286, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x424
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x42f
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 454, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x433
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 485, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x43e
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x449
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 68, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x44d
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x45c
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x463
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x46c
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x473
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 480, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x479
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 275, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x494
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x49b
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 6, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x4a5
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x4ac
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 454, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x4b0
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 485, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x4bb
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(8) },
        offset: 0x4c6
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 68, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x4ca
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x4d9
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x4e0
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x4e6
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 442, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x4f1
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 447, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x4fc
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 132, size: 0, kind: SymKind::None,
                       bind: SymBind::Local, section: SymBase::Index(13) },
        offset: 0x507
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(9) },
        offset: 0x52a
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(16) },
        offset: 0x530
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x534
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x538
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x606
    }
];

const REL_DEBUG_FRAME_NUM_RELS: usize = 6;

const REL_DEBUG_FRAME_RELS_CONTENTS_X86: [X86Rel<SymData<&'static str,
                                                           u16, Elf32>>;
                                          REL_DEBUG_FRAME_NUM_RELS] = [
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(14) },
        offset: 0x18
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x1c
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(14) },
        offset: 0x38
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x3c
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(14) },
        offset: 0x5c
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x60
    }
];

const REL_DEBUG_LINE_NUM_RELS: usize = 2;

const REL_DEBUG_LINE_RELS_CONTENTS_X86: [X86Rel<SymData<&'static str,
                                                          u16, Elf32>>;
                                         REL_DEBUG_LINE_NUM_RELS] = [
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x1b8
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x37e
    },
];

const REL_EH_FRAME_NUM_RELS: usize = 1;

const REL_EH_FRAME_RELS_CONTENTS_X86: [X86Rel<SymData<&'static str,
                                                        u16, Elf32>>;
                                       REL_EH_FRAME_NUM_RELS] = [
    X86Rel::PC32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x20
    },
];

const REL_DEBUG_ARANGES_NUM_RELS: usize = 2;

const REL_DEBUG_ARANGES_RELS_CONTENTS_X86: [X86Rel<SymData<&'static str,
                                                             u16, Elf32>>;
                                            REL_DEBUG_ARANGES_NUM_RELS] = [
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(10) },
        offset: 0x6
    },
    X86Rel::Abs32 {
        sym: SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
                       bind: SymBind::Local, section: SymBase::Index(1) },
        offset: 0x10
    },
];

pub const EXPECTED: [SectionHdrData<Elf32, &'static str,
                                    u32,
                                    SymsStrs<&'static [SymData<&'static str,
                                                               u16, Elf32>],
                                             &'static [(&'static str, usize)]>,
                                    &'static [(&'static str, usize)],
                                    SectionPos<u32>,
                                    &'static [SymData<&'static str,
                                                      u16, Elf32>],
                                    &'static [(&'static str, usize)],
                                    &'static [X86Rel<SymData<&'static str,
                                                             u16, Elf32>>],
                                    &'static [X86Rela<SymData<&'static str,
                                                              u16, Elf32>>],
                                    SectionPos<u32>,
                                    &'static [DynamicEntData<&'static str,
                                                             u32, Elf32>],
                                    &'static [NoteData<'static>]>;
                     NUM_SECTION_HDRS] = [
    SectionHdrData::Null,
    SectionHdrData::ProgBits { name: ".text", addr: 0, align: 16,
                               data: SectionPos { offset: 0x40,
                                                  size: 0x284 },
                               alloc: true, write: false, exec: true },
    SectionHdrData::Rel { name: ".rel.text", addr: 0, align: 4,
                          rels: &REL_TEXT_RELS_CONTENTS_X86,
                          symtab: SymsStrs { syms: &SYMTAB_CONTENTS,
                                             strs: &STRTAB_CONTENTS },
                          target: 1, alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".comment", addr: 0, align: 1,
                               data: SectionPos { offset: 0x394,
                                                  size: 0x279 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".rodata.str1.1", addr: 0, align: 1,
                               data: SectionPos { offset: 0x60d,
                                                  size: 0x1 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".data", addr: 0, align: 4,
                               data: SectionPos { offset: 0x610,
                                                  size: 0x4 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Rel { name: ".rel.data", addr: 0, align: 4,
                          rels: &REL_DATA_RELS_CONTENTS_X86,
                          symtab: SymsStrs { syms: &SYMTAB_CONTENTS,
                                             strs: &STRTAB_CONTENTS },
                          target: 5, alloc: false, write: false, exec: false },
    SectionHdrData::Nobits { name: ".bss", addr: 0, align: 4,
                             offset: 0x61c, size: 0x4, alloc: true,
                             write: true, exec: false },
    SectionHdrData::ProgBits { name: ".debug_loc", addr: 0, align: 1,
                               data: SectionPos { offset: 0x61c,
                                                  size: 0x295 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_abbrev", addr: 0, align: 1,
                               data: SectionPos { offset: 0x8b1,
                                                  size: 0x1f4 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_info", addr: 0, align: 1,
                               data: SectionPos { offset: 0xaa5,
                                                  size: 0x60b },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.debug_info", addr: 0, align: 4,
                          rels: &REL_DEBUG_INFO_RELS_CONTENTS_X86,
                          symtab: SymsStrs { syms: &SYMTAB_CONTENTS,
                                             strs: &STRTAB_CONTENTS },
                          target: 10, alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_ranges", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1488,
                                                  size: 0x30 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_str", addr: 0, align: 1,
                               data: SectionPos { offset: 0x14b8,
                                                  size: 0x2a1 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_frame", addr: 0, align: 4,
                               data: SectionPos { offset: 0x175c,
                                                  size: 0x7c },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.debug_frame", addr: 0, align: 4,
                          rels: &REL_DEBUG_FRAME_RELS_CONTENTS_X86,
                          symtab: SymsStrs { syms: &SYMTAB_CONTENTS,
                                             strs: &STRTAB_CONTENTS },
                          target: 14, alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_line", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1808,
                                                  size: 0x46c },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.debug_line", addr: 0, align: 4,
                          rels: &REL_DEBUG_LINE_RELS_CONTENTS_X86,
                          symtab: SymsStrs { syms: &SYMTAB_CONTENTS,
                                             strs: &STRTAB_CONTENTS },
                          target: 16, alloc: false, write: false, exec: false },
    SectionHdrData::Unknown { name: ".llvm_addrsig", tag: 0x6fff4c03,
                              addr: 0, align: 1, offset: 0x1c84, size: 0xa,
                              ent_size: 0, link: 0, info: 0,
                              flags: 0x80000000 },
    SectionHdrData::ProgBits { name: ".eh_frame", addr: 0, align: 4,
                               data: SectionPos { offset: 0x1c90,
                                                  size: 0x34 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.eh_frame", addr: 0, align: 4,
                          rels: &REL_EH_FRAME_RELS_CONTENTS_X86,
                          symtab: SymsStrs { syms: &SYMTAB_CONTENTS,
                                             strs: &STRTAB_CONTENTS },
                          target: 19, alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".debug_aranges", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1ccc,
                                                  size: 0x20 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Rel { name: ".rel.debug_aranges", addr: 0, align: 4,
                          rels: &REL_DEBUG_ARANGES_RELS_CONTENTS_X86,
                          symtab: SymsStrs { syms: &SYMTAB_CONTENTS,
                                             strs: &STRTAB_CONTENTS },
                          target: 21, alloc: false, write: false, exec: false },
    SectionHdrData::Unknown { name: ".group", tag: 0x11, addr: 0,
                              align: 4, offset: 0x1cfc, size: 0x8,
                              ent_size: 4, link: 28, info: 72, flags: 0 },
    SectionHdrData::Note { name: ".note.tag", addr: 0, align: 4,
                           note: &NOTES1_CONTENTS,
                           alloc: true, write: false, exec: false },
    SectionHdrData::Note { name: ".note.tag", addr: 0, align: 4,
                           note: &NOTES2_CONTENTS,
                           alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".note.GNU-stack", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1d4c,
                                                  size: 0x0 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: ".shstrtab", addr: 0, align: 1,
                             strs: &SHSTRTAB_CONTENTS },
    SectionHdrData::Symtab { name: ".symtab", addr: 0, align: 4,
                             syms: &SYMTAB_CONTENTS,
                             strtab: &STRTAB_CONTENTS, local_end: 83,
                             alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: ".strtab", addr: 0, align: 1,
                             strs: &STRTAB_CONTENTS }
];
