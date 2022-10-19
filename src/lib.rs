//! Crate for parsing, creating, and loading Executable Linkable
//! Format (ELF) binary data.
//!
//! This crate is built for handling architectures, word sizes, and
//! byte-orders other than the native.
//!
//! # Traversing ELF Data
//!
//! ELF data stored in a `&[u8]` can be parsed by obtaining an [Elf]
//! using the [TryFrom](core::convert::TryFrom), which will parse only
//! the ELF header.  The program header table
//! ([ProgHdrs](crate::prog_hdr::ProgHdrs)) and the section header
//! table ([SectionHdrs](crate::section_hdr::SectionHdrs)) can then be
//! obtained using the [WithElfData](crate::elf::WithElfData)
//! instance, which can be used to traverse the rest of the ELF data.
//!
//! Individual ELF structures can generally be parsed directly,
//! without needing the entire ELF data.  These structures can be
//! augmented using instances like
//! [WithElfData](crate::elf::WithElfData),
//! [WithStrtab](crate::strtab::WithStrtab),
//! [WithSymtab](crate::symtab::WithSymtab), etc.

#![no_std]

extern crate byteorder;

#[cfg(feature = "alloc")]
extern crate alloc;

mod elf;

pub mod dynamic;
pub mod hash;
pub mod note;
pub mod prog_hdr;
pub mod reloc;
pub mod section_hdr;
pub mod strtab;
pub mod symtab;

pub use elf::Elf;
pub use elf::Elf32;
pub use elf::Elf64;
pub use elf::ElfClass;
pub use elf::ElfMut;
pub use elf::ElfMux;
pub use elf::ElfABI;
pub use elf::ElfArch;
pub use elf::ElfByteOrder;
pub use elf::ElfKind;
pub use elf::ElfError;
pub use elf::ElfHdrData;
pub use elf::ElfHdrDataBufs;
pub use elf::ElfHdrDataError;
pub use elf::ElfHdrDataHdrs;
pub use elf::ElfHdrDataRaw;
pub use elf::ElfHdrOffsets;
pub use elf::ElfTable;
pub use elf::WithElfData;
