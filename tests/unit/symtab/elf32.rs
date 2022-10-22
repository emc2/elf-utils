use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::Elf32;
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

const ELF32_SYMTAB_BYTES: usize = 1616;

const ELF32_SYMTAB: [u8; ELF32_SYMTAB_BYTES] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xe5, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x13, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa6, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x9b, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x52, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa3, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x3d, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x57, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xd3, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x8e, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x6c, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x19, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x1e, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xeb, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x7e, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x6d, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x9a, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x71, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xef, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x8e, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xca, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x71, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x2a, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x66, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xcc, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x75, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xd7, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x7b, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xdd, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb7, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x22, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x9a, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x84, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc6, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00,
    0x11, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0x45, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x1b, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00,
    0xee, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x07, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x09, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0e, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x12, 0x00,
    0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x17, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x18, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x13, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x15, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x19, 0x00,
    0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2f, 0x01, 0x00, 0x00, 0x02, 0x02, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x1a, 0x00,
    0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0x96, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x11, 0x00, 0x05, 0x00,
    0xcb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0xda, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0xf1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00,
    0xf7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x11, 0x00, 0x07, 0x00,
    0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x1a, 0x01, 0x00, 0x00, 0x68, 0x02, 0x00, 0x00,
    0x19, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x00
];

const ELF32_STRTAB: [u8; 289] = [
    0x00, 0x63,
    0x72, 0x74, 0x31, 0x5f, 0x63, 0x2e, 0x63, 0x00,
    0x2e, 0x4c, 0x2e, 0x73, 0x74, 0x72, 0x00, 0x66,
    0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x72,
    0x00, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x5f,
    0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x5f, 0x69,
    0x6e, 0x69, 0x74, 0x00, 0x2e, 0x66, 0x72, 0x65,
    0x65, 0x62, 0x73, 0x64, 0x2e, 0x6e, 0x6f, 0x74,
    0x65, 0x47, 0x00, 0x5f, 0x73, 0x74, 0x61, 0x72,
    0x74, 0x31, 0x00, 0x5f, 0x44, 0x59, 0x4e, 0x41,
    0x4d, 0x49, 0x43, 0x00, 0x5f, 0x5f, 0x66, 0x69,
    0x6e, 0x69, 0x5f, 0x61, 0x72, 0x72, 0x61, 0x79,
    0x5f, 0x65, 0x6e, 0x64, 0x00, 0x5f, 0x5f, 0x66,
    0x69, 0x6e, 0x69, 0x5f, 0x61, 0x72, 0x72, 0x61,
    0x79, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00,
    0x5f, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x5f, 0x61,
    0x72, 0x72, 0x61, 0x79, 0x5f, 0x65, 0x6e, 0x64,
    0x00, 0x5f, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x5f,
    0x61, 0x72, 0x72, 0x61, 0x79, 0x5f, 0x73, 0x74,
    0x61, 0x72, 0x74, 0x00, 0x5f, 0x5f, 0x70, 0x72,
    0x65, 0x69, 0x6e, 0x69, 0x74, 0x5f, 0x61, 0x72,
    0x72, 0x61, 0x79, 0x5f, 0x65, 0x6e, 0x64, 0x00,
    0x5f, 0x5f, 0x70, 0x72, 0x65, 0x69, 0x6e, 0x69,
    0x74, 0x5f, 0x61, 0x72, 0x72, 0x61, 0x79, 0x5f,
    0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x5f, 0x5f,
    0x70, 0x72, 0x6f, 0x67, 0x6e, 0x61, 0x6d, 0x65,
    0x00, 0x5f, 0x5f, 0x72, 0x65, 0x6c, 0x5f, 0x69,
    0x70, 0x6c, 0x74, 0x5f, 0x65, 0x6e, 0x64, 0x00,
    0x5f, 0x5f, 0x72, 0x65, 0x6c, 0x5f, 0x69, 0x70,
    0x6c, 0x74, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x5f, 0x66, 0x69, 0x6e, 0x69, 0x00, 0x5f,
    0x69, 0x6e, 0x69, 0x74, 0x00, 0x5f, 0x69, 0x6e,
    0x69, 0x74, 0x5f, 0x74, 0x6c, 0x73, 0x00, 0x61,
    0x74, 0x65, 0x78, 0x69, 0x74, 0x00, 0x65, 0x6e,
    0x76, 0x69, 0x72, 0x6f, 0x6e, 0x00, 0x65, 0x78,
    0x69, 0x74, 0x00, 0x6d, 0x61, 0x69, 0x6e, 0x00,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00
];

const ELF32_SYMTAB_CONTENTS_BARE: [SymData<u32, u16, Elf32>; 101] = [
    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Undef },
    SymData { name: Some(1), value: 0, size: 0, kind: SymKind::File,
              bind: SymBind::Local, section: SymBase::Absolute },
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
    SymData { name: Some(10), value: 0, size: 1, kind: SymKind::Object,
              bind: SymBind::Local, section: SymBase::Index(4) },
    SymData { name: Some(17), value: 544, size: 69, kind: SymKind::Function,
              bind: SymBind::Local, section: SymBase::Index(1) },
    SymData { name: Some(27), value: 304, size: 238, kind: SymKind::Function,
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
    SymData { name: Some(46), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Index(23) },
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
    SymData { name: Some(61), value: 0, size: 303, kind: SymKind::Function,
              bind: SymBind::Local, section: SymBase::Index(1) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(26) },
    SymData { name: Some(69), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Weak, section: SymBase::Undef },
    SymData { name: Some(78), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(95), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(114), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(131), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(150), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(170), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(192), value: 0, size: 4, kind: SymKind::Object,
              bind: SymBind::Global, section: SymBase::Index(5) },
    SymData { name: Some(203), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Weak, section: SymBase::Undef },
    SymData { name: Some(218), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Weak, section: SymBase::Undef },
    SymData { name: Some(235), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(241), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(247), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(257), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(264), value: 0, size: 4, kind: SymKind::Object,
              bind: SymBind::Global, section: SymBase::Index(7) },
    SymData { name: Some(272), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(277), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(282), value: 616, size: 25, kind: SymKind::Function,
              bind: SymBind::Global, section: SymBase::Index(1) },
];

const ELF32_SYMTAB_CONTENTS: [SymData<Result<&'static str, &'static [u8]>,
                                             u16, Elf32>; 101] = [
    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Local, section: SymBase::Undef },
    SymData { name: Some(Ok("crt1_c.c")), value: 0, size: 0,
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
    SymData { name: Some(Ok(".L.str")), value: 0, size: 1,
              kind: SymKind::Object, bind: SymBind::Local,
              section: SymBase::Index(4) },
    SymData { name: Some(Ok("finalizer")), value: 544, size: 69,
              kind: SymKind::Function, bind: SymBind::Local,
              section: SymBase::Index(1) },
    SymData { name: Some(Ok("handle_static_init")), value: 304, size: 238,
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
    SymData { name: Some(Ok("_start1")), value: 0, size: 303,
              kind: SymKind::Function, bind: SymBind::Local,
              section: SymBase::Index(1) },
    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
              bind: SymBind::Local, section: SymBase::Index(26) },
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
    SymData { name: Some(Ok("__progname")), value: 0, size: 4,
              kind: SymKind::Object, bind: SymBind::Global,
              section: SymBase::Index(5) },
    SymData { name: Some(Ok("__rel_iplt_end")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Weak,
              section: SymBase::Undef },
    SymData { name: Some(Ok("__rel_iplt_start")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Weak,
              section: SymBase::Undef },
    SymData { name: Some(Ok("_fini")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("_init")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("_init_tls")), value: 0, size: 0,
              kind: SymKind::None, bind: SymBind::Global,
              section: SymBase::Undef },
    SymData { name: Some(Ok("atexit")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("environ")), value: 0, size: 4,
              kind: SymKind::Object, bind: SymBind::Global,
              section: SymBase::Index(7) },
    SymData { name: Some(Ok("exit")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("main")), value: 0, size: 0, kind: SymKind::None,
              bind: SymBind::Global, section: SymBase::Undef },
    SymData { name: Some(Ok("_start")), value: 616, size: 25,
              kind: SymKind::Function, bind: SymBind::Global,
              section: SymBase::Index(1) },
];

#[test]
fn test_Symtab_from_bytes_just_right() {
    let symtab: Result<Symtab<'_, LittleEndian, Elf32>, SymtabError> =
        Symtab::try_from(&ELF32_SYMTAB[0..]);

    assert!(symtab.is_ok());
}

#[test]
fn test_Symtab_from_bytes_too_small() {
    let symtab: Result<Symtab<'_, LittleEndian, Elf32>, SymtabError> =
        Symtab::try_from(&ELF32_SYMTAB[0 .. ELF32_SYMTAB.len() - 1]);

    assert!(symtab.is_err());
}

#[test]
fn test_Symtab_from_bytes_num_syms() {
    let symtab: Symtab<'_, LittleEndian, Elf32> =
        Symtab::try_from(&ELF32_SYMTAB[0..]).expect("Expected success");

    assert_eq!(symtab.num_syms(), 101);
}

#[test]
fn test_Symtab_from_bytes_iter_len() {
    let symtab: Symtab<'_, LittleEndian, Elf32> =
        Symtab::try_from(&ELF32_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for i in 0 .. 101 {
        assert_eq!(iter.len(), 101 - i);
        assert!(iter.next().is_some());
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Symtab_from_bytes_just_right_mut() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: Result<Symtab<'_, LittleEndian, Elf32>, SymtabError> =
        Symtab::try_from(&mut buf[0..]);

    assert!(symtab.is_ok());
}

#[test]
fn test_Symtab_from_bytes_too_small_mut() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: Result<Symtab<'_, LittleEndian, Elf32>, SymtabError> =
        Symtab::try_from(&mut buf[0 .. ELF32_SYMTAB.len() - 1]);

    assert!(symtab.is_err());
}

#[test]
fn test_Symtab_from_bytes_num_syms_mut() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: Symtab<'_, LittleEndian, Elf32> =
        Symtab::try_from(&mut buf[0..]).expect("Expected success");

    assert_eq!(symtab.num_syms(), 101);
}

#[test]
fn test_Symtab_from_bytes_iter_len_mut() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: Symtab<'_, LittleEndian, Elf32> =
        Symtab::try_from(&mut buf[0..]).expect("Expected success");
    let iter = symtab.iter();

    assert_eq!(iter.len(), 101);
}

#[test]
fn test_Symtab_from_bytes_iter() {
    let symtab: Symtab<'_, LittleEndian, Elf32> =
        Symtab::try_from(&ELF32_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for expect in ELF32_SYMTAB_CONTENTS_BARE.iter() {
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
    let symtab: Symtab<'_, LittleEndian, Elf32> =
        Symtab::try_from(&ELF32_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for i in 0 .. ELF32_SYMTAB_CONTENTS_BARE.len() {
        let expect = &ELF32_SYMTAB_CONTENTS_BARE[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(symtab.idx(ELF32_SYMTAB_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_Symtab_from_bytes_iter_with_strtab() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF32_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf32> =
        Symtab::try_from(&ELF32_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for expect in ELF32_SYMTAB_CONTENTS.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SymData<u32, u16, Elf32> = data.unwrap();
        let actual: Result<SymData<Result<&'static str, &'static [u8]>,
                                          u16, Elf32>, u32> =
            raw.with_strtab(strtab);

        assert!(actual.is_ok());

        assert_eq!(expect, &actual.unwrap())
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Symtab_from_bytes_idx_with_strtab() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF32_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf32> =
        Symtab::try_from(&ELF32_SYMTAB[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for i in 0 .. ELF32_SYMTAB_CONTENTS.len() {
        let expect = &ELF32_SYMTAB_CONTENTS[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SymData<u32, u16, Elf32> = data.unwrap();
        let actual: Result<SymData<Result<&'static str, &'static [u8]>,
                                          u16, Elf32>, u32> =
            raw.with_strtab(strtab);

        assert!(actual.is_ok());

        assert_eq!(expect, &actual.unwrap())
    }

    assert!(symtab.idx(ELF32_SYMTAB_CONTENTS.len()).is_none());
}

#[test]
fn test_Symtab_create_just_right() {
    let mut buf = [0; ELF32_SYMTAB_BYTES];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_Symtab_create_too_big() {
    let mut buf = [0; ELF32_SYMTAB_BYTES + 1];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_Symtab_create_too_small() {
    let mut buf = [0; ELF32_SYMTAB_BYTES - 1];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_err());
}

#[test]
fn test_Symtab_create_iter() {
    let mut buf = [0; ELF32_SYMTAB_BYTES];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = symtab.iter();

    for expect in ELF32_SYMTAB_CONTENTS_BARE.iter() {
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
    let mut buf = [0; ELF32_SYMTAB_BYTES];
    let symtab: Result<(Symtab<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Symtab::create_split(&mut buf[0..], ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF32_SYMTAB_CONTENTS_BARE.len() {
        let expect = &ELF32_SYMTAB_CONTENTS_BARE[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(symtab.idx(ELF32_SYMTAB_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_SymtabMut_from_bytes_just_right_mut() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: Result<SymtabMut<'_, LittleEndian, Elf32>, SymtabError> =
        SymtabMut::try_from(&mut buf[0..]);

    assert!(symtab.is_ok());
}

#[test]
fn test_SymtabMut_from_bytes_too_small_mut() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: Result<SymtabMut<'_, LittleEndian, Elf32>, SymtabError> =
        SymtabMut::try_from(&mut buf[0 .. ELF32_SYMTAB.len() - 1]);

    assert!(symtab.is_err());
}

#[test]
fn test_SymtabMut_from_bytes_num_syms_mut() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: SymtabMut<'_, LittleEndian, Elf32> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");

    assert_eq!(symtab.num_syms(), 101);
}

#[test]
fn test_SymtabMut_from_bytes_iter_len_mut() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: SymtabMut<'_, LittleEndian, Elf32> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let iter = symtab.iter();

    assert_eq!(iter.len(), 101);
}

#[test]
fn test_SymtabMut_from_bytes_iter() {
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: SymtabMut<'_, LittleEndian, Elf32> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for expect in ELF32_SYMTAB_CONTENTS_BARE.iter() {
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
    let mut buf = ELF32_SYMTAB.clone();
    let symtab: SymtabMut<'_, LittleEndian, Elf32> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for i in 0 .. ELF32_SYMTAB_CONTENTS_BARE.len() {
        let expect = &ELF32_SYMTAB_CONTENTS_BARE[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(symtab.idx(ELF32_SYMTAB_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_SymtabMut_from_bytes_iter_with_strtab() {
    let mut buf = ELF32_SYMTAB.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF32_STRTAB[0..]).expect("Expected success");
    let symtab: SymtabMut<'_, LittleEndian, Elf32> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");
    let mut iter = symtab.iter();

    for expect in ELF32_SYMTAB_CONTENTS.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SymData<u32, u16, Elf32> = data.unwrap();
        let actual: Result<SymData<Result<&'static str, &'static [u8]>,
                                          u16, Elf32>, u32> =
            raw.with_strtab(strtab);

        assert!(actual.is_ok());

        assert_eq!(expect, &actual.unwrap())
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_SymtabMut_from_bytes_idx_with_strtab() {
    let mut buf = ELF32_SYMTAB.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF32_STRTAB[0..]).expect("Expected success");
    let symtab: SymtabMut<'_, LittleEndian, Elf32> =
        SymtabMut::try_from(&mut buf[0..]).expect("Expected success");

    for i in 0 .. ELF32_SYMTAB_CONTENTS.len() {
        let expect = &ELF32_SYMTAB_CONTENTS[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let raw: SymData<u32, u16, Elf32> = data.unwrap();
        let actual: Result<SymData<Result<&'static str, &'static [u8]>,
                                          u16, Elf32>, u32> =
            raw.with_strtab(strtab);

        assert!(actual.is_ok());

        assert_eq!(expect, &actual.unwrap())
    }

    assert!(symtab.idx(ELF32_SYMTAB_CONTENTS.len()).is_none());
}

#[test]
fn test_SymtabMut_create_just_right() {
    let mut buf = [0; ELF32_SYMTAB_BYTES];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_SymtabMut_create_too_big() {
    let mut buf = [0; ELF32_SYMTAB_BYTES + 1];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_SymtabMut_create_too_small() {
    let mut buf = [0; ELF32_SYMTAB_BYTES - 1];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_err());
}

#[test]
fn test_SymtabMut_create_iter() {
    let mut buf = [0; ELF32_SYMTAB_BYTES];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = symtab.iter();

    for expect in ELF32_SYMTAB_CONTENTS_BARE.iter() {
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
    let mut buf = [0; ELF32_SYMTAB_BYTES];
    let symtab: Result<(SymtabMut<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        SymtabMut::create_split(&mut buf[0..],
                                ELF32_SYMTAB_CONTENTS_BARE.iter());

    assert!(symtab.is_ok());

    let (symtab, buf) = symtab.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF32_SYMTAB_CONTENTS_BARE.len() {
        let expect = &ELF32_SYMTAB_CONTENTS_BARE[i];
        let sym = symtab.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(symtab.idx(ELF32_SYMTAB_CONTENTS_BARE.len()).is_none());
}
