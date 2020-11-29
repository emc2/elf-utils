use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::Elf64;
use elf_utils::strtab::Strtab;
use elf_utils::strtab::WithStrtab;
use elf_utils::symtab::SymBase;
use elf_utils::symtab::SymBind;
use elf_utils::symtab::SymData;
use elf_utils::symtab::SymKind;
use elf_utils::symtab::Symtab;
use elf_utils::symtab::SymtabCreate;
use elf_utils::symtab::SymtabError;
use elf_utils::symtab::SymtabIter;
use elf_utils::symtab::SymtabMut;
use elf_utils::symtab::SymtabMutOps;

const ELF64_SYMTAB_BYTES: usize = 936;

const ELF64_SYMTAB: [u8; ELF64_SYMTAB_BYTES] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x07, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x09, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0e, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x12, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x13, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x15, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x36, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3f, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x74, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x87, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb1, 0x00, 0x00, 0x00, 0x11, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xbc, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xcc, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xde, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe4, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xea, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf4, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xfb, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x01, 0x00, 0x00, 0x11, 0x00, 0x07, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

const ELF64_STRTAB: [u8; 276] = [
    0x00, 0x63, 0x72, 0x74,
    0x31, 0x5f, 0x63, 0x2e, 0x63, 0x00, 0x66, 0x69,
    0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x72, 0x00,
    0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x5f, 0x73,
    0x74, 0x61, 0x74, 0x69, 0x63, 0x5f, 0x69, 0x6e,
    0x69, 0x74, 0x00, 0x2e, 0x66, 0x72, 0x65, 0x65,
    0x62, 0x73, 0x64, 0x2e, 0x6e, 0x6f, 0x74, 0x65,
    0x47, 0x00, 0x5f, 0x44, 0x59, 0x4e, 0x41, 0x4d,
    0x49, 0x43, 0x00, 0x5f, 0x5f, 0x66, 0x69, 0x6e,
    0x69, 0x5f, 0x61, 0x72, 0x72, 0x61, 0x79, 0x5f,
    0x65, 0x6e, 0x64, 0x00, 0x5f, 0x5f, 0x66, 0x69,
    0x6e, 0x69, 0x5f, 0x61, 0x72, 0x72, 0x61, 0x79,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x5f,
    0x5f, 0x69, 0x6e, 0x69, 0x74, 0x5f, 0x61, 0x72,
    0x72, 0x61, 0x79, 0x5f, 0x65, 0x6e, 0x64, 0x00,
    0x5f, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x5f, 0x61,
    0x72, 0x72, 0x61, 0x79, 0x5f, 0x73, 0x74, 0x61,
    0x72, 0x74, 0x00, 0x5f, 0x5f, 0x70, 0x72, 0x65,
    0x69, 0x6e, 0x69, 0x74, 0x5f, 0x61, 0x72, 0x72,
    0x61, 0x79, 0x5f, 0x65, 0x6e, 0x64, 0x00, 0x5f,
    0x5f, 0x70, 0x72, 0x65, 0x69, 0x6e, 0x69, 0x74,
    0x5f, 0x61, 0x72, 0x72, 0x61, 0x79, 0x5f, 0x73,
    0x74, 0x61, 0x72, 0x74, 0x00, 0x5f, 0x5f, 0x70,
    0x72, 0x6f, 0x67, 0x6e, 0x61, 0x6d, 0x65, 0x00,
    0x5f, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x5f, 0x69,
    0x70, 0x6c, 0x74, 0x5f, 0x65, 0x6e, 0x64, 0x00,
    0x5f, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x5f, 0x69,
    0x70, 0x6c, 0x74, 0x5f, 0x73, 0x74, 0x61, 0x72,
    0x74, 0x00, 0x5f, 0x66, 0x69, 0x6e, 0x69, 0x00,
    0x5f, 0x69, 0x6e, 0x69, 0x74, 0x00, 0x5f, 0x69,
    0x6e, 0x69, 0x74, 0x5f, 0x74, 0x6c, 0x73, 0x00,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x61,
    0x74, 0x65, 0x78, 0x69, 0x74, 0x00, 0x65, 0x6e,
    0x76, 0x69, 0x72, 0x6f, 0x6e, 0x00, 0x65, 0x78,
    0x69, 0x74, 0x00, 0x6d, 0x61, 0x69, 0x6e, 0x00
];

const ELF64_SYMTAB_CONTENTS_BARE: [SymData<u32, u16, Elf64>; 39] = [
    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Undef },
    SymData { name: Some(1), value: 0, size: 0, kind: SymKind::File,
              bind: SymBind::Local, section: SymBase::Absolute },
    SymData { name: Some(10), value: 560, size: 90, kind: SymKind::Function,
              bind: SymBind::Local, section: SymBase::Index(1) },
    SymData { name: Some(20), value: 272, size: 282, kind: SymKind::Function,
              bind: SymBind::Local, section: SymBase::Index(1) },
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
    SymData { name: Some(39), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(19) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(19) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(20) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(3) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(4) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(21) },
    SymData { name: Some(54), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Weak, section: SymBase::Undef },
    SymData { name: Some(63), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(80), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(99), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(116), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(135), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(155), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(177), value: 0, size: 8, kind: SymKind::Object,
              bind: SymBind::Global, section: SymBase::Index(5)},
    SymData { name: Some(188), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Weak, section: SymBase::Undef },
    SymData { name: Some(204), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Weak, section: SymBase::Undef },
    SymData { name: Some(222), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(228), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(234), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(244), value: 0, size: 262, kind: SymKind::Function,
              bind: SymBind::Global, section: SymBase::Index(1) },
    SymData { name: Some(251), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(258), value: 0, size: 8, kind: SymKind::Object,
              bind: SymBind::Global, section: SymBase::Index(7) },
    SymData { name: Some(266), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(271), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef }
];

const ELF64_SYMTAB_CONTENTS: [SymData<Result<&'static str, &'static [u8]>,
                                              u16, Elf64>; 39] = [
    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Undef },
    SymData { name: Some(Ok("crt1_c.c")), value: 0, size: 0,
              kind: SymKind::File, bind: SymBind::Local,
              section: SymBase::Absolute },
    SymData { name: Some(Ok("finalizer")), value: 560, size: 90,
              kind: SymKind::Function, bind: SymBind::Local,
              section: SymBase::Index(1) },
    SymData { name: Some(Ok("handle_static_init")), value: 272, size: 282,
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
    SymData { name: Some(Ok(".freebsd.noteG")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Local,
              section: SymBase::Index(19) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(19) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(20) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(3) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(4) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(13) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(21) },
    SymData { name: Some(Ok("_DYNAMIC")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Weak,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__fini_array_end")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__fini_array_start")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__init_array_end")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__init_array_start")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__preinit_array_end")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__preinit_array_start")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__progname")), value: 0, size: 8,
              kind: SymKind::Object, bind: SymBind::Global,
              section: SymBase::Index(5)},
    SymData { name: Some(Ok("__rela_iplt_end")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Weak,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__rela_iplt_start")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Weak,
              section: SymBase::Undef },
    SymData { name: Some(Ok("_fini")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("_init")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("_init_tls")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some(Ok("_start")), value: 0, size: 262,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(1) },
    SymData { name: Some(Ok("atexit")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("environ")), value: 0, size: 8,
              kind: SymKind::Object, bind: SymBind::Global,
              section: SymBase::Index(7) },
    SymData { name: Some(Ok("exit")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("main")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef }
];

#[test]
fn test_Symtab_from_bytes_just_right() {
    let symtab: Result<Symtab<'_, LittleEndian, Elf64>, SymtabError> =
        Symtab::try_from(&ELF64_SYMTAB[0..]);

    assert!(symtab.is_ok());
}

#[test]
fn test_Symtab_from_bytes_too_small() {
    let symtab: Result<Symtab<'_, LittleEndian, Elf64>, SymtabError> =
        Symtab::try_from(&ELF64_SYMTAB[0 .. ELF64_SYMTAB.len() - 1]);

    assert!(symtab.is_err());
}

#[test]
fn test_Symtab_from_bytes_num_syms() {
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF64_SYMTAB[0..]).expect("Expected success");

    assert_eq!(symtab.num_syms(), 39);
}

#[test]
fn test_Symtab_from_bytes_iter_len() {
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF64_SYMTAB[0..]).expect("Expected success");
    let iter = symtab.iter();

    assert_eq!(iter.len(), 39);
}

#[test]
fn test_Symtab_from_bytes_just_right_mut() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: Result<Symtab<'_, LittleEndian, Elf64>, SymtabError> =
        Symtab::try_from(&mut buf[0..]);

    assert!(symtab.is_ok());
}

#[test]
fn test_Symtab_from_bytes_too_small_mut() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: Result<Symtab<'_, LittleEndian, Elf64>, SymtabError> =
        Symtab::try_from(&mut buf[0 .. ELF64_SYMTAB.len() - 1]);

    assert!(symtab.is_err());
}

#[test]
fn test_Symtab_from_bytes_num_syms_mut() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&mut buf[0..]).expect("Expected success");

    assert_eq!(symtab.num_syms(), 39);
}

#[test]
fn test_Symtab_from_bytes_iter_len_mut() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&mut buf[0..]).expect("Expected success");
    let iter = symtab.iter();

    assert_eq!(iter.len(), 39);
}

#[test]
fn test_Symtab_from_bytes_iter() {
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF64_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for expect in ELF64_SYMTAB_CONTENTS_BARE.iter() {
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
fn test_Symtab_from_bytes_idx() {
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF64_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for i in 0 .. ELF64_SYMTAB_CONTENTS_BARE.len() {
        let expect = &ELF64_SYMTAB_CONTENTS_BARE[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(symtab.idx(ELF64_SYMTAB_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_Symtab_from_bytes_iter_with_strtab() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF64_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF64_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for expect in ELF64_SYMTAB_CONTENTS.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SymData<u32, u16, Elf64> = data.unwrap();
        let actual: Result<SymData<Result<&'static str, &'static [u8]>,
                                          u16, Elf64>, u32> =
            raw.with_strtab(strtab);

        assert!(actual.is_ok());

        assert_eq!(expect, &actual.unwrap())
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Symtab_from_bytes_idx_with_strtab() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF64_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF64_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for i in 0 .. ELF64_SYMTAB_CONTENTS.len() {
        let expect = &ELF64_SYMTAB_CONTENTS[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SymData<u32, u16, Elf64> = data.unwrap();
        let actual: Result<SymData<Result<&'static str, &'static [u8]>,
                                          u16, Elf64>, u32> =
            raw.with_strtab(strtab);

        assert!(actual.is_ok());

        assert_eq!(expect, &actual.unwrap())
    }

    assert!(symtab.idx(ELF64_SYMTAB_CONTENTS.len()).is_none());
}
#[test]
fn test_Symtab_create_just_right() {
    let mut buf = [0; ELF64_SYMTAB_BYTES];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_Symtab_create_too_big() {
    let mut buf = [0; ELF64_SYMTAB_BYTES + 1];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_Symtab_create_too_small() {
    let mut buf = [0; ELF64_SYMTAB_BYTES - 1];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_err());
}

#[test]
fn test_Symtab_create_iter() {
    let mut buf = [0; ELF64_SYMTAB_BYTES];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = symtab.iter();

    for expect in ELF64_SYMTAB_CONTENTS_BARE.iter() {
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
fn test_Symtab_create_idx() {
    let mut buf = [0; ELF64_SYMTAB_BYTES];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF64_SYMTAB_CONTENTS_BARE.len() {
        let expect = &ELF64_SYMTAB_CONTENTS_BARE[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(symtab.idx(ELF64_SYMTAB_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_SymtabMut_from_bytes_just_right_mut() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: Result<SymtabMut<'_, LittleEndian, Elf64>, SymtabError> =
        SymtabMut::try_from(&mut buf[0..]);

    assert!(symtab.is_ok());
}

#[test]
fn test_SymtabMut_from_bytes_too_small_mut() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: Result<SymtabMut<'_, LittleEndian, Elf64>, SymtabError> =
        SymtabMut::try_from(&mut buf[0 .. ELF64_SYMTAB.len() - 1]);

    assert!(symtab.is_err());
}

#[test]
fn test_SymtabMut_from_bytes_num_syms_mut() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: SymtabMut<'_, LittleEndian, Elf64> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");

    assert_eq!(symtab.num_syms(), 39);
}

#[test]
fn test_SymtabMut_from_bytes_iter_len_mut() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: SymtabMut<'_, LittleEndian, Elf64> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let iter = symtab.iter();

    assert_eq!(iter.len(), 39);
}

#[test]
fn test_SymtabMut_from_bytes_iter() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: SymtabMut<'_, LittleEndian, Elf64> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for expect in ELF64_SYMTAB_CONTENTS_BARE.iter() {
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
fn test_SymtabMut_from_bytes_idx() {
    let mut buf = ELF64_SYMTAB.clone();
    let symtab: SymtabMut<'_, LittleEndian, Elf64> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for i in 0 .. ELF64_SYMTAB_CONTENTS_BARE.len() {
        let expect = &ELF64_SYMTAB_CONTENTS_BARE[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(symtab.idx(ELF64_SYMTAB_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_SymtabMut_from_bytes_iter_with_strtab() {
    let mut buf = ELF64_SYMTAB.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF64_STRTAB[0..]).expect("Expected success");
    let symtab: SymtabMut<'_, LittleEndian, Elf64> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for expect in ELF64_SYMTAB_CONTENTS.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SymData<u32, u16, Elf64> = data.unwrap();
        let actual: Result<SymData<Result<&'static str, &'static [u8]>,
                                          u16, Elf64>, u32> =
            raw.with_strtab(strtab);

        assert!(actual.is_ok());

        assert_eq!(expect, &actual.unwrap())
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_SymtabMut_from_bytes_idx_with_strtab() {
    let mut buf = ELF64_SYMTAB.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF64_STRTAB[0..]).expect("Expected success");
    let symtab: SymtabMut<'_, LittleEndian, Elf64> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for i in 0 .. ELF64_SYMTAB_CONTENTS.len() {
        let expect = &ELF64_SYMTAB_CONTENTS[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SymData<u32, u16, Elf64> = data.unwrap();
        let actual: Result<SymData<Result<&'static str, &'static [u8]>,
                                          u16, Elf64>, u32> =
            raw.with_strtab(strtab);

        assert!(actual.is_ok());

        assert_eq!(expect, &actual.unwrap())
    }

    assert!(symtab.idx(ELF64_SYMTAB_CONTENTS.len()).is_none());
}

#[test]
fn test_SymtabMut_create_just_right() {
    let mut buf = [0; ELF64_SYMTAB_BYTES];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_SymtabMut_create_too_big() {
    let mut buf = [0; ELF64_SYMTAB_BYTES + 1];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_SymtabMut_create_too_small() {
    let mut buf = [0; ELF64_SYMTAB_BYTES - 1];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_err());
}

#[test]
fn test_SymtabMut_create_iter() {
    let mut buf = [0; ELF64_SYMTAB_BYTES];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = symtab.iter();

    for expect in ELF64_SYMTAB_CONTENTS_BARE.iter() {
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
fn test_SymtabMut_create_idx() {
    let mut buf = [0; ELF64_SYMTAB_BYTES];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF64_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF64_SYMTAB_CONTENTS_BARE.len() {
        let expect = &ELF64_SYMTAB_CONTENTS_BARE[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(symtab.idx(ELF64_SYMTAB_CONTENTS_BARE.len()).is_none());
}
