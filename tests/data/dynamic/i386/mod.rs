use byteorder::LittleEndian;
use elf_utils::Elf32;
use elf_utils::ElfArch;
use elf_utils::ElfABI;
use elf_utils::ElfHdrData;
use elf_utils::ElfKind;
use elf_utils::ElfTable;
use elf_utils::note::NoteData;
use elf_utils::dynamic::DynamicEntData;
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

pub const PATH: &'static str = "tests/data/dynamic/i386/ld-elf32.so.1";

const NUM_PROG_HDRS: usize = 10;

pub const PROG_HDR_CONTENTS: [ProgHdrData<Elf32, Segment<u32>,
                                          Segment<u32>, Segment<u32>>;
                          NUM_PROG_HDRS] = [
    ProgHdrData::ProgHdr { virt_addr: 0x34, phys_addr: 0x34,
                           content: Segment { offset: 0x34, size: 0x140 } },
    ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
                        mem_size: 0x46bc, align: 0x1000,
                        read: true, write: false, exec: false,
                        content: Segment { offset: 0, size: 0x46bc } },
    ProgHdrData::Load { virt_addr: 0x56c0, phys_addr: 0x56c0,
                        mem_size: 0x14d05, align: 0x1000,
                        read: true, write: false, exec: true,
                        content: Segment { offset: 0x46c0, size: 0x14d05 } },
    ProgHdrData::Load { virt_addr: 0x1b3c8, phys_addr: 0x1b3c8,
                        mem_size: 0x348, align: 4096,
                        read: true, write: true, exec: false,
                        content: Segment { offset: 0x193c8, size: 0x348 } },
    ProgHdrData::Load { virt_addr: 0x1c710, phys_addr: 0x1c710,
                        mem_size: 0xb68, align: 4096,
                        read: true, write: true, exec: false,
                        content: Segment { offset: 0x19710, size: 0x64 } },
    ProgHdrData::Dynamic { virt_addr: 0x1b628, phys_addr: 0x1b628,
                           content: Segment { offset: 0x19628, size: 0x88 } },
    ProgHdrData::Unknown { tag: 0x6474e552, flags: 4, offset: 0x193c8,
                           file_size: 0x348, mem_size: 0x348,
                           phys_addr: 0x1b3c8, virt_addr: 0x1b3c8, align: 1 },
    ProgHdrData::Unknown { tag: 0x6474e550, flags: 4, offset: 0x428c,
                           file_size: 0xbc, mem_size: 0xbc,
                           phys_addr: 0x428c, virt_addr: 0x428c, align: 4 },
    ProgHdrData::Unknown { tag: 0x6474e551, flags: 6, offset: 0,
                           file_size: 0, mem_size: 0,
                           phys_addr: 0, virt_addr: 0, align: 0 },
    ProgHdrData::Note { virt_addr: 0x174, phys_addr: 0x174,
                        content: Segment { offset: 0x174, size: 0x18 } },
];

const NUM_SECTION_HDRS: usize = 23;

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
    SectionHdrData::Note { name: ".note.tag", addr: 0x174, align: 4,
                           note: SectionPos { offset: 0x174, size: 0x18 },
                           alloc: true, write: false, exec: false },
    SectionHdrData::Dynsym { name: ".dynsym", addr: 0x18c, align: 4,
                             syms: SectionPos { offset: 0x18c, size: 0x1b0 },
                             strtab: 7, local_end: 1,
                             alloc: true, write: false, exec: false },
    SectionHdrData::Unknown { name: ".gnu.version", tag: 0x6fffffff,
                              addr: 0x33c, align: 2, offset: 0x33c, size: 0x36,
                              ent_size: 2, link: 2, info: 0, flags: 0x2 },
    SectionHdrData::Unknown { name: ".gnu.version_d", tag: 0x6ffffffd,
                              addr: 0x374, align: 4, offset: 0x374, size: 0xfc,
                              ent_size: 0, link: 7, info: 9, flags: 0x2 },
    SectionHdrData::Unknown { name: ".gnu.hash", tag: 0x6ffffff6, addr: 0x470,
                              align: 4, offset: 0x470, size: 0xd0, ent_size: 0,
                              link: 2, info: 0, flags: 0x2 },
    SectionHdrData::Hash { name: ".hash", addr: 0x540, align: 4,
                           hash: SectionPos { offset: 0x540, size: 0xe0 },
                           symtab: 2, alloc: true, write: false, exec: false },
    SectionHdrData::Strtab { name: ".dynstr", addr: 0x620, align: 1,
                             strs: SectionPos { offset: 0x620, size: 0x1d2 } },
    SectionHdrData::Rel { name: ".rel.dyn", addr: 0x7f4, align: 4,
                          rels: SectionPos { offset: 0x7f4, size: 0x5e8 },
                          symtab: 2, target: 0, alloc: true, write: false,
                          exec: false },
    SectionHdrData::ProgBits { name: ".rodata", addr: 0xddc, align: 4,
                               data: SectionPos { offset: 0xddc, size: 0x34b0 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".eh_frame_hdr", addr: 0x428c, align: 4,
                               data: SectionPos { offset: 0x428c, size: 0xbc },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".eh_frame", addr: 0x4348, align: 4,
                               data: SectionPos { offset: 0x4348, size: 0x374 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".text", addr: 0x56c0, align: 16,
                               data: SectionPos { offset: 0x46c0,
                                                  size: 0x14d05 },
                               alloc: true, write: false, exec: true },
    SectionHdrData::Unknown { name: ".fini_array", tag: 15, addr: 0x1b3c8,
                              align: 4, offset: 0x193c8, size: 4, ent_size: 0,
                              link: 0, info: 0, flags: 0x3 },
    SectionHdrData::ProgBits { name: ".data.rel.ro", addr: 0x1b3cc, align: 4,
                               data: SectionPos { offset: 0x193cc,
                                                  size: 0x25c },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Dynamic { name: ".dynamic", addr: 0x1b628, align: 4,
                              strtab: 7,dynamic: SectionPos { offset: 0x19628,
                                                              size: 0x88 },
                              alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: ".got", addr: 0x1b6b0, align: 4,
                               data: SectionPos { offset: 0x196b0, size: 0x60 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: ".data", addr: 0x1c710, align: 4,
                               data: SectionPos { offset: 0x19710, size: 0x58 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: ".got.plt", addr: 0x1c768, align: 4,
                               data: SectionPos { offset: 0x19768, size: 0xc },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Nobits { name: ".bss", addr: 0x1c774, align: 4,
                             offset: 0x19774, size: 0xb04, alloc: true,
                             write: true, exec: false },
    SectionHdrData::ProgBits { name: ".comment", addr: 0, align: 1,
                               data: SectionPos { offset: 0x19774,
                                                  size: 0x11de },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".gnu_debuglink", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1a952, size: 0x18 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: ".shstrtab", addr: 0, align: 1,
                             strs: SectionPos { offset: 0x1a96a, size: 0xd4 } }
];

pub const HEADER_DATA: ElfHdrData<LittleEndian, Elf32, ElfTable<Elf32>,
                                  ElfTable<Elf32>, u16> =
    ElfHdrData {
        byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
        kind: ElfKind::Dynamic, arch: ElfArch::I386,
        entry: 0x56c0, flags: 0, section_hdr_strtab: 22,
        prog_hdrs: Some(ElfTable { offset: 52, num_ents: 10 }),
        section_hdrs: ElfTable { offset: 109120, num_ents: 23 }
    };

const NUM_NOTES: usize = 1;

const NOTE_1_NAME: [u8; 8] = [
    0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
];
const NOTE_1_DESC: [u8; 4] = [
    0x9b, 0xd6, 0x13, 0x00
];

pub const NOTES_CONTENTS: [NoteData<'static>; NUM_NOTES] = [
    NoteData { kind: 1, name: &NOTE_1_NAME, desc: &NOTE_1_DESC },
];

const DYNSYM_NUM_SYMS: usize = 27;

pub const DYNSYM_CONTENTS: [SymData<&'static str, u16, Elf32>;
                            DYNSYM_NUM_SYMS] = [
    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Undef },
    SymData { name: Some("_rtld_allocate_tls"), value: 0xbdf0, size: 138,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_get_stack_prot"), value: 0xbf50, size: 23,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dllockinit"), value: 0x9ed0, size: 62,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dlsym"), value: 0xa110, size: 38,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dlvsym"), value: 0xa9d0, size: 121,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_addr_phdr"), value: 0xaa50, size: 213,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_version__FreeBSD_version"), value: 0x1c738,
              size: 4, kind: SymKind::Object, bind: SymBind::Global,
              section: SymBase::Index(17) },
    SymData { name: Some("_rtld_version_laddr_offset"), value: 0x1cba4,
              size: 1, kind: SymKind::Object, bind: SymBind::Global,
              section: SymBase::Index(19) },
    SymData { name: Some("dl_iterate_phdr"), value: 0xb010, size: 743,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dlerror"), value: 0x9650, size: 33,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dlopen"), value: 0x9f10, size: 38,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("r_debug_state"), value: 0x8a50, size: 5,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dladdr"), value: 0xab30, size: 299,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_thread_init"), value: 0x10960, size: 497,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("__tls_get_addr"), value: 0x6130, size: 46,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_r_debug_postinit"), value: 0x9130, size: 5,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_is_dlopened"), value: 0xbf70, size: 217,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dlclose"), value: 0x9c20, size: 77,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("fdlopen"), value: 0xa0e0, size: 35,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("___tls_get_addr"), value: 0x6100, size: 43,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_atfork_pre"), value: 0x10b60, size: 153,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_error"), value: 0x8330, size: 224,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_free_tls"), value: 0xbe80, size: 197,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dlfunc"), value: 0xa9a0, size: 38,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("dlinfo"), value: 0xac60, size: 938,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
    SymData { name: Some("_rtld_atfork_post"), value: 0x10c00, size: 170,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(12) },
];

const REL_DYN_NUM_RELS: usize = 189;

const REL_DYN_RELS_CONTENTS_X86: [X86Rel<SymData<&'static str, u16, Elf32>>;
                                   REL_DYN_NUM_RELS] = [
    X86Rel::Relative { offset: 0x1b3c8 },
    X86Rel::Relative { offset: 0x1b3cc },
    X86Rel::Relative { offset: 0x1b3d0 },
    X86Rel::Relative { offset: 0x1b3d4 },
    X86Rel::Relative { offset: 0x1b3d8 },
    X86Rel::Relative { offset: 0x1b3dc },
    X86Rel::Relative { offset: 0x1b3e0 },
    X86Rel::Relative { offset: 0x1b3e4 },
    X86Rel::Relative { offset: 0x1b3e8 },
    X86Rel::Relative { offset: 0x1b3ec },
    X86Rel::Relative { offset: 0x1b3f0 },
    X86Rel::Relative { offset: 0x1b3f4 },
    X86Rel::Relative { offset: 0x1b3f8 },
    X86Rel::Relative { offset: 0x1b3fc },
    X86Rel::Relative { offset: 0x1b400 },
    X86Rel::Relative { offset: 0x1b404 },
    X86Rel::Relative { offset: 0x1b408 },
    X86Rel::Relative { offset: 0x1b40c },
    X86Rel::Relative { offset: 0x1b410 },
    X86Rel::Relative { offset: 0x1b414 },
    X86Rel::Relative { offset: 0x1b418 },
    X86Rel::Relative { offset: 0x1b41c },
    X86Rel::Relative { offset: 0x1b420 },
    X86Rel::Relative { offset: 0x1b424 },
    X86Rel::Relative { offset: 0x1b428 },
    X86Rel::Relative { offset: 0x1b42c },
    X86Rel::Relative { offset: 0x1b430 },
    X86Rel::Relative { offset: 0x1b434 },
    X86Rel::Relative { offset: 0x1b438 },
    X86Rel::Relative { offset: 0x1b43c },
    X86Rel::Relative { offset: 0x1b440 },
    X86Rel::Relative { offset: 0x1b444 },
    X86Rel::Relative { offset: 0x1b448 },
    X86Rel::Relative { offset: 0x1b44c },
    X86Rel::Relative { offset: 0x1b450 },
    X86Rel::Relative { offset: 0x1b454 },
    X86Rel::Relative { offset: 0x1b458 },
    X86Rel::Relative { offset: 0x1b45c },
    X86Rel::Relative { offset: 0x1b460 },
    X86Rel::Relative { offset: 0x1b464 },
    X86Rel::Relative { offset: 0x1b468 },
    X86Rel::Relative { offset: 0x1b46c },
    X86Rel::Relative { offset: 0x1b470 },
    X86Rel::Relative { offset: 0x1b474 },
    X86Rel::Relative { offset: 0x1b478 },
    X86Rel::Relative { offset: 0x1b47c },
    X86Rel::Relative { offset: 0x1b480 },
    X86Rel::Relative { offset: 0x1b484 },
    X86Rel::Relative { offset: 0x1b488 },
    X86Rel::Relative { offset: 0x1b48c },
    X86Rel::Relative { offset: 0x1b490 },
    X86Rel::Relative { offset: 0x1b494 },
    X86Rel::Relative { offset: 0x1b498 },
    X86Rel::Relative { offset: 0x1b49c },
    X86Rel::Relative { offset: 0x1b4a0 },
    X86Rel::Relative { offset: 0x1b4a4 },
    X86Rel::Relative { offset: 0x1b4a8 },
    X86Rel::Relative { offset: 0x1b4ac },
    X86Rel::Relative { offset: 0x1b4b0 },
    X86Rel::Relative { offset: 0x1b4b4 },
    X86Rel::Relative { offset: 0x1b4b8 },
    X86Rel::Relative { offset: 0x1b4bc },
    X86Rel::Relative { offset: 0x1b4c0 },
    X86Rel::Relative { offset: 0x1b4c4 },
    X86Rel::Relative { offset: 0x1b4c8 },
    X86Rel::Relative { offset: 0x1b4cc },
    X86Rel::Relative { offset: 0x1b4d0 },
    X86Rel::Relative { offset: 0x1b4d4 },
    X86Rel::Relative { offset: 0x1b4d8 },
    X86Rel::Relative { offset: 0x1b4dc },
    X86Rel::Relative { offset: 0x1b4e0 },
    X86Rel::Relative { offset: 0x1b4e4 },
    X86Rel::Relative { offset: 0x1b4e8 },
    X86Rel::Relative { offset: 0x1b4ec },
    X86Rel::Relative { offset: 0x1b4f0 },
    X86Rel::Relative { offset: 0x1b4f4 },
    X86Rel::Relative { offset: 0x1b4f8 },
    X86Rel::Relative { offset: 0x1b4fc },
    X86Rel::Relative { offset: 0x1b500 },
    X86Rel::Relative { offset: 0x1b504 },
    X86Rel::Relative { offset: 0x1b508 },
    X86Rel::Relative { offset: 0x1b50c },
    X86Rel::Relative { offset: 0x1b510 },
    X86Rel::Relative { offset: 0x1b514 },
    X86Rel::Relative { offset: 0x1b518 },
    X86Rel::Relative { offset: 0x1b51c },
    X86Rel::Relative { offset: 0x1b520 },
    X86Rel::Relative { offset: 0x1b524 },
    X86Rel::Relative { offset: 0x1b528 },
    X86Rel::Relative { offset: 0x1b52c },
    X86Rel::Relative { offset: 0x1b530 },
    X86Rel::Relative { offset: 0x1b534 },
    X86Rel::Relative { offset: 0x1b538 },
    X86Rel::Relative { offset: 0x1b53c },
    X86Rel::Relative { offset: 0x1b540 },
    X86Rel::Relative { offset: 0x1b544 },
    X86Rel::Relative { offset: 0x1b548 },
    X86Rel::Relative { offset: 0x1b54c },
    X86Rel::Relative { offset: 0x1b550 },
    X86Rel::Relative { offset: 0x1b554 },
    X86Rel::Relative { offset: 0x1b558 },
    X86Rel::Relative { offset: 0x1b55c },
    X86Rel::Relative { offset: 0x1b560 },
    X86Rel::Relative { offset: 0x1b564 },
    X86Rel::Relative { offset: 0x1b568 },
    X86Rel::Relative { offset: 0x1b56c },
    X86Rel::Relative { offset: 0x1b570 },
    X86Rel::Relative { offset: 0x1b574 },
    X86Rel::Relative { offset: 0x1b578 },
    X86Rel::Relative { offset: 0x1b57c },
    X86Rel::Relative { offset: 0x1b580 },
    X86Rel::Relative { offset: 0x1b584 },
    X86Rel::Relative { offset: 0x1b588 },
    X86Rel::Relative { offset: 0x1b58c },
    X86Rel::Relative { offset: 0x1b590 },
    X86Rel::Relative { offset: 0x1b594 },
    X86Rel::Relative { offset: 0x1b598 },
    X86Rel::Relative { offset: 0x1b59c },
    X86Rel::Relative { offset: 0x1b5a0 },
    X86Rel::Relative { offset: 0x1b5a4 },
    X86Rel::Relative { offset: 0x1b5a8 },
    X86Rel::Relative { offset: 0x1b5ac },
    X86Rel::Relative { offset: 0x1b5b0 },
    X86Rel::Relative { offset: 0x1b5b4 },
    X86Rel::Relative { offset: 0x1b5b8 },
    X86Rel::Relative { offset: 0x1b5bc },
    X86Rel::Relative { offset: 0x1b5c0 },
    X86Rel::Relative { offset: 0x1b5c4 },
    X86Rel::Relative { offset: 0x1b5c8 },
    X86Rel::Relative { offset: 0x1b5cc },
    X86Rel::Relative { offset: 0x1b5d0 },
    X86Rel::Relative { offset: 0x1b5d4 },
    X86Rel::Relative { offset: 0x1b5d8 },
    X86Rel::Relative { offset: 0x1b5dc },
    X86Rel::Relative { offset: 0x1b5e0 },
    X86Rel::Relative { offset: 0x1b5e4 },
    X86Rel::Relative { offset: 0x1b5e8 },
    X86Rel::Relative { offset: 0x1b5ec },
    X86Rel::Relative { offset: 0x1b5f0 },
    X86Rel::Relative { offset: 0x1b5f4 },
    X86Rel::Relative { offset: 0x1b5f8 },
    X86Rel::Relative { offset: 0x1b5fc },
    X86Rel::Relative { offset: 0x1b600 },
    X86Rel::Relative { offset: 0x1b604 },
    X86Rel::Relative { offset: 0x1b608 },
    X86Rel::Relative { offset: 0x1b60c },
    X86Rel::Relative { offset: 0x1b610 },
    X86Rel::Relative { offset: 0x1b614 },
    X86Rel::Relative { offset: 0x1b618 },
    X86Rel::Relative { offset: 0x1b61c },
    X86Rel::Relative { offset: 0x1b620 },
    X86Rel::Relative { offset: 0x1b624 },
    X86Rel::Relative { offset: 0x1b6b0 },
    X86Rel::Relative { offset: 0x1b6b4 },
    X86Rel::Relative { offset: 0x1b6b8 },
    X86Rel::Relative { offset: 0x1b6bc },
    X86Rel::Relative { offset: 0x1b6c0 },
    X86Rel::Relative { offset: 0x1b6c4 },
    X86Rel::Relative { offset: 0x1b6c8 },
    X86Rel::Relative { offset: 0x1b6cc },
    X86Rel::Relative { offset: 0x1b6d0 },
    X86Rel::Relative { offset: 0x1b6d4 },
    X86Rel::Relative { offset: 0x1b6d8 },
    X86Rel::Relative { offset: 0x1b6dc },
    X86Rel::Relative { offset: 0x1b6e0 },
    X86Rel::Relative { offset: 0x1b6e4 },
    X86Rel::Relative { offset: 0x1b6e8 },
    X86Rel::Relative { offset: 0x1b6ec },
    X86Rel::Relative { offset: 0x1b6f0 },
    X86Rel::Relative { offset: 0x1b6f4 },
    X86Rel::Relative { offset: 0x1b6f8 },
    X86Rel::Relative { offset: 0x1b6fc },
    X86Rel::Relative { offset: 0x1b700 },
    X86Rel::Relative { offset: 0x1b704 },
    X86Rel::Relative { offset: 0x1b708 },
    X86Rel::Relative { offset: 0x1b70c },
    X86Rel::Relative { offset: 0x1c718 },
    X86Rel::Relative { offset: 0x1c71c },
    X86Rel::Relative { offset: 0x1c720 },
    X86Rel::Relative { offset: 0x1c724 },
    X86Rel::Relative { offset: 0x1c728 },
    X86Rel::Relative { offset: 0x1c734 },
    X86Rel::Relative { offset: 0x1c740 },
    X86Rel::Relative { offset: 0x1c748 },
    X86Rel::Relative { offset: 0x1c74c },
    X86Rel::Relative { offset: 0x1c750 },
    X86Rel::Relative { offset: 0x1c754 },
    X86Rel::Relative { offset: 0x1c75c },
    X86Rel::Relative { offset: 0x1c764 },
];

const STRTAB_NUM_STRS: usize = 36;

pub const STRTAB_CONTENTS: [(&'static str, usize); STRTAB_NUM_STRS] = [
    ("", 0),
    ("___tls_get_addr", 1),
    ("__tls_get_addr", 17),
    ("_rtld_error", 32),
    ("_r_debug_postinit", 44),
    ("_rtld_addr_phdr", 62),
    ("_rtld_allocate_tls", 78),
    ("_rtld_free_tls", 97),
    ("_rtld_get_stack_prot", 112),
    ("_rtld_is_dlopened", 133),
    ("_rtld_version__FreeBSD_version", 151),
    ("_rtld_version_laddr_offset", 182),
    ("dl_iterate_phdr", 209),
    ("dladdr", 225),
    ("dlclose", 232),
    ("dlerror", 240),
    ("dlfunc", 248),
    ("dlinfo", 255),
    ("dllockinit", 262),
    ("dlopen", 273),
    ("dlsym", 280),
    ("dlvsym", 286),
    ("fdlopen", 293),
    ("r_debug_state", 301),
    ("_rtld_atfork_post", 315),
    ("_rtld_atfork_pre", 333),
    ("_rtld_thread_init", 350),
    ("ld-elf32.so.1.full", 368),
    ("FBSD_1.0", 387),
    ("FBSD_1.1", 396),
    ("FBSD_1.2", 405),
    ("FBSD_1.3", 414),
    ("FBSD_1.4", 423),
    ("FBSD_1.5", 432),
    ("FBSD_1.6", 441),
    ("FBSDprivate_1.0", 450)
];

const SHSTRTAB_NUM_STRS: usize = 24;

pub const SHSTRTAB_CONTENTS: [(&'static str, usize); SHSTRTAB_NUM_STRS] = [
    ("", 0),
    ("", 1),
    (".shstrtab", 2),
    (".note.tag", 12),
    (".dynsym", 22),
    (".gnu.version", 30),
    (".gnu.version_d", 43),
    (".gnu.hash", 58),
    (".hash", 68),
    (".dynstr", 74),
    (".rel.dyn", 82),
    (".rodata", 91),
    (".eh_frame_hdr", 99),
    (".eh_frame", 113),
    (".text", 123),
    (".fini_array", 129),
    (".data.rel.ro", 141),
    (".dynamic", 154),
    (".got", 163),
    (".data", 168),
    (".got.plt", 174),
    (".bss", 183),
    (".comment", 188),
    (".gnu_debuglink", 197),
];

const NUM_DYNAMIC_ENTS: usize = 17;

const DYNAMIC_ENTS: [DynamicEntData<&'static str, u32, Elf32>;
                     NUM_DYNAMIC_ENTS] = [
    DynamicEntData::Flags { flags: 0x2 },
    DynamicEntData::Rel { tab: 0x7f4 },
    DynamicEntData::RelSize { size: 1512 },
    DynamicEntData::RelEntSize { size: 8 },
    DynamicEntData::Unknown { tag: 0x6ffffffa, info: 189 },
    DynamicEntData::Symtab { tab: 0x18c },
    DynamicEntData::SymtabEntSize { size: 16 },
    DynamicEntData::Strtab { tab: 0x620 },
    DynamicEntData::StrtabSize { size: 466 },
    DynamicEntData::Unknown { tag: 0x6ffffef5, info: 0x470 },
    DynamicEntData::Hash { tab: 0x540 },
    DynamicEntData::FiniArray { arr: 0x1b3c8 },
    DynamicEntData::FiniArraySize { size: 4 },
    DynamicEntData::Unknown { tag: 0x6ffffff0, info: 0x33c },
    DynamicEntData::Unknown { tag: 0x6ffffffc, info: 0x374 },
    DynamicEntData::Unknown { tag: 0x6ffffffd, info: 0x9 },
    DynamicEntData::None
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
    SectionHdrData::Note { name: ".note.tag", addr: 0x174, align: 4,
                           note: &NOTES_CONTENTS, alloc: true,
                           write: false, exec: false },
    SectionHdrData::Dynsym { name: ".dynsym", addr: 0x18c, align: 4,
                             syms: &DYNSYM_CONTENTS,
                             strtab: &STRTAB_CONTENTS, local_end: 1,
                             alloc: true, write: false, exec: false },
    SectionHdrData::Unknown { name: ".gnu.version", tag: 0x6fffffff,
                              addr: 0x33c, align: 2, offset: 0x33c,
                              size: 0x36, ent_size: 2, link: 2, info: 0,
                              flags: 0x2 },
    SectionHdrData::Unknown { name: ".gnu.version_d", tag: 0x6ffffffd,
                              addr: 0x374, align: 4, offset: 0x374,
                              size: 0xfc, ent_size: 0, link: 7, info: 9,
                              flags: 0x2 },
    SectionHdrData::Unknown { name: ".gnu.hash", tag: 0x6ffffff6,
                              addr: 0x470, align: 4, offset: 0x470,
                              size: 0xd0, ent_size: 0, link: 2,
                              info: 0, flags: 0x2 },
    SectionHdrData::Hash { name: ".hash", addr: 0x540, align: 4,
                           hash: SectionPos { offset: 0x540, size: 0xe0 },
                           symtab: SymsStrs { syms: &DYNSYM_CONTENTS,
                                              strs: &STRTAB_CONTENTS },
                           alloc: true, write: false, exec: false },
    SectionHdrData::Strtab { name: ".dynstr", addr: 0x620, align: 1,
                             strs: &STRTAB_CONTENTS },
    SectionHdrData::Rel { name: ".rel.dyn", addr: 0x7f4, align: 4,
                          rels: &REL_DYN_RELS_CONTENTS_X86,
                          symtab: SymsStrs { syms: &DYNSYM_CONTENTS,
                                             strs: &STRTAB_CONTENTS },
                          target: 0, alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".rodata", addr: 0xddc, align: 4,
                               data: SectionPos { offset: 0xddc,
                                                  size: 0x34b0 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".eh_frame_hdr", addr: 0x428c,
                               align: 4, data: SectionPos { offset: 0x428c,
                                                            size: 0xbc },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".eh_frame", addr: 0x4348, align: 4,
                               data: SectionPos { offset: 0x4348,
                                                  size: 0x374 },
                               alloc: true, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".text", addr: 0x56c0, align: 16,
                               data: SectionPos { offset: 0x46c0,
                                                  size: 0x14d05 },
                               alloc: true, write: false, exec: true },
    SectionHdrData::Unknown { name: ".fini_array", tag: 15, addr: 0x1b3c8,
                              align: 4, offset: 0x193c8, size: 4,
                              ent_size: 0, link: 0, info: 0, flags: 0x3 },
    SectionHdrData::ProgBits { name: ".data.rel.ro", addr: 0x1b3cc,
                               align: 4, data: SectionPos { offset: 0x193cc,
                                                            size: 0x25c },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Dynamic { name: ".dynamic", addr: 0x1b628, align: 4,
                              strtab: &STRTAB_CONTENTS, dynamic: &DYNAMIC_ENTS,
                              alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: ".got", addr: 0x1b6b0, align: 4,
                               data: SectionPos { offset: 0x196b0,
                                                  size: 0x60 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: ".data", addr: 0x1c710, align: 4,
                               data: SectionPos { offset: 0x19710,
                                                  size: 0x58 },
                               alloc: true, write: true, exec: false },
    SectionHdrData::ProgBits { name: ".got.plt", addr: 0x1c768, align: 4,
                               data: SectionPos { offset: 0x19768,
                                                  size: 0xc },
                               alloc: true, write: true, exec: false },
    SectionHdrData::Nobits { name: ".bss", addr: 0x1c774, align: 4,
                             offset: 0x19774, size: 0xb04, alloc: true,
                             write: true, exec: false },
    SectionHdrData::ProgBits { name: ".comment", addr: 0, align: 1,
                               data: SectionPos { offset: 0x19774,
                                                  size: 0x11de },
                               alloc: false, write: false, exec: false },
    SectionHdrData::ProgBits { name: ".gnu_debuglink", addr: 0, align: 1,
                               data: SectionPos { offset: 0x1a952,
                                                  size: 0x18 },
                               alloc: false, write: false, exec: false },
    SectionHdrData::Strtab { name: ".shstrtab", addr: 0, align: 1,
                             strs: &SHSTRTAB_CONTENTS }
];
