//! ELF note section header functionality.
//!
//! This module provides a [SectionHdrs] type which acts as a wrapper
//! around ELF section header data.
//!
//! # Examples
//!
//! A `SectionHdrs` can be created from any slice containing binary data
//! that contains a properly-formatted ELF section header table:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf32;
//! use elf_utils::section_hdr::SectionHdrs;
//!
//! const SECTION_HDR: [u8; 200] = [
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0c, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
//!     0x74, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x16, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
//!     0x8c, 0x01, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00,
//!     0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
//!     0x44, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
//!     0x40, 0x05, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x4a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
//!     0x20, 0x06, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let hdrs: Result<SectionHdrs<'_, LittleEndian, Elf32>, ()> =
//!     SectionHdrs::try_from(&SECTION_HDR[0..]);
//!
//! assert!(hdrs.is_ok());
//! ```
//!
//! Indexing into a `SectionHdrs` with [idx](SectionHdrs::idx) will give a
//! [SectionHdr], which is itself a handle on a single ELF section header:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf32;
//! use elf_utils::section_hdr::SectionHdrs;
//!
//! const SECTION_HDR: [u8; 200] = [
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0c, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
//!     0x74, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x16, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
//!     0x8c, 0x01, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00,
//!     0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
//!     0x44, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
//!     0x40, 0x05, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x4a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
//!     0x20, 0x06, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let hdrs: SectionHdrs<'_, LittleEndian, Elf32> =
//!     SectionHdrs::try_from(&SECTION_HDR[0..]).unwrap();
//!
//! assert!(hdrs.idx(0).is_some());
//! assert!(hdrs.idx(6).is_none());
//! ```
//!
//! A [SectionHdr] can be projected to a [SectionHdrData] with the
//! [TryFrom](core::convert::TryFrom) instance:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use core::convert::TryInto;
//! use elf_utils::Elf32;
//! use elf_utils::section_hdr::SectionHdrs;
//! use elf_utils::section_hdr::SectionHdrData;
//! use elf_utils::section_hdr::SectionPos;
//!
//! const SECTION_HDR: [u8; 200] = [
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0c, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
//!     0x74, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x16, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
//!     0x8c, 0x01, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00,
//!     0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
//!     0x44, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
//!     0x40, 0x05, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x4a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
//!     0x20, 0x06, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let hdrs: SectionHdrs<'_, LittleEndian, Elf32> =
//!     SectionHdrs::try_from(&SECTION_HDR[0..]).unwrap();
//! let ent = hdrs.idx(2).unwrap();
//! let data: SectionHdrData<Elf32, u32, u32, u32, u32, SectionPos<u32>,
//!                          SectionPos<u32>, SectionPos<u32>, SectionPos<u32>,
//!                          SectionPos<u32>, SectionPos<u32>, SectionPos<u32>,
//!                          SectionPos<u32>> =
//!     ent.try_into().unwrap();
//!
//! assert_eq!(data, SectionHdrData::Dynsym { name: 22, addr: 0x18c, align: 4,
//!                                           syms: SectionPos { offset: 0x18c,
//!                                                              size: 0x1b0 },
//!                                           strtab: 7, local_end: 1,
//!                                           alloc: true, write: false,
//!                                           exec: false });
//! ```
use byteorder::ByteOrder;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use crate::dynamic::Dynamic;
use crate::dynamic::DynamicOffsets;
use crate::elf::Elf32;
use crate::elf::Elf64;
use crate::elf::ElfClass;
use crate::elf::WithElfData;
use crate::hash::Hashtab;
use crate::hash::HashtabError;
use crate::note::Notes;
use crate::reloc::Rels;
use crate::reloc::Relas;
use crate::reloc::RelOffsets;
use crate::reloc::RelaOffsets;
use crate::symtab::Symtab;
use crate::strtab::Strtab;
use crate::strtab::StrtabError;
use crate::strtab::WithStrtab;
use crate::symtab::SymOffsets;

/// Offsets for ELF section headers.
///
/// This contains the various offsets for fields in an ELF section
/// header table entry for a given ELF class.
pub trait SectionHdrOffsets: SymOffsets + RelaOffsets + DynamicOffsets {
    /// Start of the ELF section header name field.
    const SH_NAME_START: usize = 0;
    /// Size of the ELF section header name field.
    const SH_NAME_SIZE: usize = Self::WORD_SIZE;
    /// End of the ELF section header name field.
    const SH_NAME_END: usize = Self::SH_NAME_START + Self::SH_NAME_SIZE;

    /// Start of the ELF section header type field.
    const SH_KIND_START: usize = Self::SH_NAME_END;
    /// Size of the ELF section header type field.
    const SH_KIND_SIZE: usize = Self::WORD_SIZE;
    /// End of the ELF section header type field.
    const SH_KIND_END: usize = Self::SH_KIND_START + Self::SH_KIND_SIZE;

    /// Start of the ELF section header flags field.
    const SH_FLAGS_START: usize = Self::SH_KIND_END;
    /// Size of the ELF section header flags field.
    const SH_FLAGS_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF section header flags field.
    const SH_FLAGS_END: usize = Self::SH_FLAGS_START + Self::SH_FLAGS_SIZE;

    /// Start of the ELF section header addr field.
    const SH_ADDR_START: usize = Self::SH_FLAGS_END;
    /// Size of the ELF section header addr field.
    const SH_ADDR_SIZE: usize = Self::ADDR_SIZE;
    /// End of the ELF section header addr field.
    const SH_ADDR_END: usize = Self::SH_ADDR_START + Self::SH_ADDR_SIZE;

    /// Start of the ELF section header offset field.
    const SH_OFFSET_START: usize = Self::SH_ADDR_END;
    /// Size of the ELF section header offset field.
    const SH_OFFSET_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF section header offset field.
    const SH_OFFSET_END: usize = Self::SH_OFFSET_START + Self::SH_OFFSET_SIZE;

    /// Start of the ELF section header size field.
    const SH_SIZE_START: usize = Self::SH_OFFSET_END;
    /// Size of the ELF section header size field.
    const SH_SIZE_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF section header size field.
    const SH_SIZE_END: usize = Self::SH_SIZE_START + Self::SH_SIZE_SIZE;

    /// Start of the ELF section header link field.
    const SH_LINK_START: usize = Self::SH_SIZE_END;
    /// Size of the ELF section header link field.
    const SH_LINK_SIZE: usize = Self::WORD_SIZE;
    /// End of the ELF section header link field.
    const SH_LINK_END: usize = Self::SH_LINK_START + Self::SH_LINK_SIZE;

    /// Start of the ELF section header info field.
    const SH_INFO_START: usize = Self::SH_LINK_END;
    /// Size of the ELF section header info field.
    const SH_INFO_SIZE: usize = Self::WORD_SIZE;
    /// End of the ELF section header info field.
    const SH_INFO_END: usize = Self::SH_INFO_START + Self::SH_INFO_SIZE;

    /// Start of the ELF section header align field.
    const SH_ALIGN_START: usize = Self::SH_INFO_END;
    /// Size of the ELF section header align field.
    const SH_ALIGN_SIZE: usize = Self::ADDR_SIZE;
    /// End of the ELF section header align field.
    const SH_ALIGN_END: usize = Self::SH_ALIGN_START + Self::SH_ALIGN_SIZE;

    /// Start of the ELF section header entry size field.
    const SH_ENT_SIZE_START: usize = Self::SH_ALIGN_END;
    /// Size of the ELF section header entry size field.
    const SH_ENT_SIZE_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF section header entry size field.
    const SH_ENT_SIZE_END: usize = Self::SH_ENT_SIZE_START +
                                   Self::SH_ENT_SIZE_SIZE;

    /// Size of a section header entry.
    const SECTION_HDR_SIZE: usize = Self::SH_ENT_SIZE_END;
    /// Size of a section header entry as a `Half`.
    const SECTION_HDR_SIZE_HALF: Self::Half;
}

/// Trait for things that can be converted from one type to another
/// with the use of a [SectionHdrs].
///
/// This is typically used with objects such as symbols, dynamic
/// linking entries, etc. that contain a section index.  It can also
/// be used to convert iterators and other objects to produce data
/// that contains section references.
pub trait WithSectionHdrs<'a, B: ByteOrder, Offsets: SectionHdrOffsets> {
    /// Result of conversion.
    type Result;
    /// Errors that can occur (typically derived from a `StrtabError`).
    type Error;

    /// Consume the caller to convert it using `section_hdrs`.
    fn with_section_hdrs(self, section_hdrs: SectionHdrs<'a, B, Offsets>) ->
        Result<Self::Result, Self::Error>;
}

/// In-place read-only ELF section header table.
///
/// An ELF section header table is an array of data objects that
/// provide information about each section in the ELF data.  They are
/// used primarily for static and dynamic linking.
///
/// A `SectionHdrs` is essentially a 'handle' for raw ELF data.  It
/// can be used to convert an index into a [SectionHdr] using the
/// [idx](SectionHdrs::idx) function, or iterated over with
/// [iter](SectionHdrs::iter).
///
/// A `SectionHdrs` can be created from raw data using the [TryFrom]
/// instance.
///
/// New `SectionHdrs` can be created from an iterator over
/// [SectionHdrData] with [create](SectionHdrs::create) or
/// [create_split](SectionHdrs::create_split).
///
/// # Examples
///
/// ```
/// extern crate elf_utils;
///
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf32;
/// use elf_utils::section_hdr::SectionHdrs;
/// use elf_utils::section_hdr::SectionHdrData;
/// use elf_utils::section_hdr::SectionPos;
///
/// const SECTION_HDR: [u8; 200] = [
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0c, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
///     0x74, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x16, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
///     0x8c, 0x01, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00,
///     0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
///     0x44, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
///     0x40, 0x05, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x4a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
///     0x20, 0x06, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
///
/// const SECTION_HDR_CONTENTS: [SectionHdrData<Elf32, u32, u32, u32, u32,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>>; 5] = [
///     SectionHdrData::Null,
///     SectionHdrData::Note { name: 12, addr: 0x174, align: 4,
///                            note: SectionPos { offset: 0x174, size: 0x18 },
///                            alloc: true, write: false, exec: false },
///     SectionHdrData::Dynsym { name: 22, addr: 0x18c, align: 4,
///                              syms: SectionPos { offset: 0x18c,
///                                                 size: 0x1b0 },
///                              strtab: 7, local_end: 1,
///                              alloc: true, write: false, exec: false },
///     SectionHdrData::Hash { name: 68, addr: 0x540, align: 4,
///                            hash: SectionPos { offset: 0x540, size: 0xe0 },
///                            symtab: 2, alloc: true, write: false,
///                            exec: false },
///     SectionHdrData::Strtab { name: 74, addr: 0x620, align: 1,
///                              strs: SectionPos { offset: 0x620,
///                                                 size: 0x1d2 } }
/// ];
///
/// let hdrs: SectionHdrs<'_, LittleEndian, Elf32> =
///     SectionHdrs::try_from(&SECTION_HDR[0..]).unwrap();
///
/// for i in 0 .. 5 {
///     let ent = hdrs.idx(i).unwrap();
///     let data: SectionHdrData<Elf32, u32, u32, u32, u32, SectionPos<u32>,
///                              SectionPos<u32>, SectionPos<u32>,
///                              SectionPos<u32>, SectionPos<u32>,
///                              SectionPos<u32>, SectionPos<u32>,
///                              SectionPos<u32>> =
///         ent.try_into().unwrap();
///
///     assert_eq!(data, SECTION_HDR_CONTENTS[i]);
/// }
/// ```
#[derive(Copy, Clone)]
pub struct SectionHdrs<'a, B, Offsets: SectionHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    hdrs: &'a [u8]
}

/// In-place read-only ELF section header table entry.
///
/// An ELF section header table entry is a union of many different
/// kinds of information.  See [SectionHdrData] for more information.
///
/// A `SectionHdr` is essentially a 'handle' for raw ELF data.  Note that
/// this data may not be in host byte order, and may not even have the
/// same word size.  In order to directly manipulate the section
/// header data, it must be projected into a [SectionHdrData] using the
/// [TryFrom](core::convert::TryFrom) instance in order to access the
/// section header table entry's information directly.
///
/// # Examples
///
/// ```
/// extern crate elf_utils;
///
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf32;
/// use elf_utils::section_hdr::SectionHdrs;
/// use elf_utils::section_hdr::SectionHdrData;
/// use elf_utils::section_hdr::SectionPos;
///
/// const SECTION_HDR: [u8; 200] = [
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0c, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
///     0x74, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x16, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
///     0x8c, 0x01, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00,
///     0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
///     0x44, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
///     0x40, 0x05, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x4a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
///     0x20, 0x06, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
///
/// let hdrs: SectionHdrs<'_, LittleEndian, Elf32> =
///     SectionHdrs::try_from(&SECTION_HDR[0..]).unwrap();
/// let ent = hdrs.idx(2).unwrap();
/// let data: SectionHdrData<Elf32, u32, u32, u32, u32, SectionPos<u32>,
///                          SectionPos<u32>, SectionPos<u32>, SectionPos<u32>,
///                          SectionPos<u32>, SectionPos<u32>, SectionPos<u32>,
///                          SectionPos<u32>> =
///     ent.try_into().unwrap();
///
/// assert_eq!(data, SectionHdrData::Dynsym { name: 22, addr: 0x18c, align: 4,
///                                           syms: SectionPos { offset: 0x18c,
///                                                              size: 0x1b0 },
///                                           strtab: 7, local_end: 1,
///                                           alloc: true, write: false,
///                                           exec: false });
/// ```
#[derive(Copy, Clone)]
pub struct SectionHdr<'a, B: ByteOrder, Offsets: SectionHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    ent: &'a [u8]
}

pub struct SectionHdrMut<'a, B: ByteOrder, Offsets: SectionHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    ent: &'a mut [u8]
}

/// Iterator for [SectionHdrs].
///
/// This iterator produces [SectionHdr]s referenceding the program header
/// table entries defined in an underlying `SectionHdrs`.
///
/// # Examples
///
/// ```
/// extern crate elf_utils;
///
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf32;
/// use elf_utils::section_hdr::SectionHdrs;
/// use elf_utils::section_hdr::SectionHdrData;
/// use elf_utils::section_hdr::SectionHdrIter;
/// use elf_utils::section_hdr::SectionPos;
///
/// const SECTION_HDR: [u8; 200] = [
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0c, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
///     0x74, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x16, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
///     0x8c, 0x01, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00,
///     0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
///     0x44, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
///     0x40, 0x05, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x4a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
///     0x20, 0x06, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
///
/// const SECTION_HDR_CONTENTS: [SectionHdrData<Elf32, u32, u32, u32, u32,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>>; 5] = [
///     SectionHdrData::Null,
///     SectionHdrData::Note { name: 12, addr: 0x174, align: 4,
///                            note: SectionPos { offset: 0x174, size: 0x18 },
///                            alloc: true, write: false, exec: false },
///     SectionHdrData::Dynsym { name: 22, addr: 0x18c, align: 4,
///                              syms: SectionPos { offset: 0x18c,
///                                                 size: 0x1b0 },
///                              strtab: 7, local_end: 1,
///                              alloc: true, write: false, exec: false },
///     SectionHdrData::Hash { name: 68, addr: 0x540, align: 4,
///                            hash: SectionPos { offset: 0x540, size: 0xe0 },
///                            symtab: 2, alloc: true, write: false,
///                            exec: false },
///     SectionHdrData::Strtab { name: 74, addr: 0x620, align: 1,
///                              strs: SectionPos { offset: 0x620,
///                                                 size: 0x1d2 } }
/// ];
///
/// let hdrs: SectionHdrs<'_, LittleEndian, Elf32> =
///     SectionHdrs::try_from(&SECTION_HDR[0..]).unwrap();
/// let mut iter = hdrs.iter();
///
/// for i in 0 .. 5 {
///     let ent = iter.next().unwrap();
///     let data: SectionHdrData<Elf32, u32, u32, u32, u32, SectionPos<u32>,
///                              SectionPos<u32>, SectionPos<u32>,
///                              SectionPos<u32>, SectionPos<u32>,
///                              SectionPos<u32>, SectionPos<u32>,
///                              SectionPos<u32>> =
///         ent.try_into().unwrap();
///
///     assert_eq!(data, SECTION_HDR_CONTENTS[i]);
/// }
/// ```
#[derive(Clone)]
pub struct SectionHdrIter<'a, B: ByteOrder, Offsets: SectionHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    hdrs: &'a [u8],
    idx: usize
}

/// Projected ELF section header data.
///
/// This is a representation of an ELF section header table entry
/// projected into a form that can be directly manipulated.  This data
/// can also be used to create a new [SectionHdrs] using
/// [create](SectionHdrs::create) or
/// [create_split](SectionHdrs::create_split).
///
/// The instance of [WithSectionHdrs] allows a `SectionHdrData` to be
/// interpreted using its own host `SectionHdrs` to convert associated
/// sections references from an index into a `SectionHdr`.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum SectionHdrData<Offsets: SectionHdrOffsets, Str, HdrRef, SymsRef,
                        StrsRef, Data, Syms, Strs, Rels, Relas, Hash,
                        Dynamic, Note> {
    /// Null section.
    Null,
    /// Section containing raw program data.
    ///
    /// This typically consists of program data.
    ProgBits {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Data for the section.
        data: Data,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Section containing a symbol table.
    Symtab {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Symbol table.
        syms: Syms,
        /// Section header of the associated string table.
        strtab: StrsRef,
        /// Index of the last local symbol in the symbol table.
        local_end: Offsets::Word,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Section containing a string table.
    Strtab {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// String table information.
        strs: Strs
    },
    /// Section containing relocations with explicit addends.
    Rela {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Relocation information.
        relas: Relas,
        /// Section header of the associated symbol table.
        symtab: SymsRef,
        /// Section header of the target section.
        target: HdrRef,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Section containing a symbol hash table.
    Hash {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Hash table information.
        hash: Hash,
        /// Section header of the target symbol table.
        symtab: SymsRef,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Section containing dynamic loading information.
    Dynamic {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Dynamic loading information.
        dynamic: Dynamic,
        /// Section header of the associated string table.
        strtab: StrsRef,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Section containing notes.
    Note {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Note information.
        note: Note,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Section to be allocated at runtime, but which has no file contents.
    ///
    /// This is typically used for the `.bss` section, which contains
    /// uninitialized program data.
    Nobits {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Logical offset in the ELF data.
        offset: Offsets::Offset,
        /// Size of data to be allocated.
        size: Offsets::Offset,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Section containing relocations with implicit addends.
    Rel {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Relocation information.
        rels: Rels,
        /// Section header of the associated symbol table.
        symtab: SymsRef,
        /// Section header of the target section.
        target: HdrRef,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Section containing a dynamic symbol table.
    ///
    /// This is typically a symbol table for a dynamic linking section.
    Dynsym {
        /// Name of the section.
        name: Str,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Dynamic symbol table.
        syms: Syms,
        /// Section header of the associated string table.
        strtab: StrsRef,
        /// Index of the last local symbol in the symbol table.
        local_end: Offsets::Word,
        /// Whether this section should occupy memory during execution.
        alloc: bool,
        /// Whether this section is writable.
        write: bool,
        /// Whether this section is executable.
        exec: bool
    },
    /// Unknown section type.
    Unknown {
        /// Name of the section.
        name: Str,
        /// Type tag for the section.
        tag: Offsets::Word,
        /// Starting address of the section.
        addr: Offsets::Addr,
        /// Alignment of the section.
        align: Offsets::Offset,
        /// Offset of the associated data in the file.
        offset: Offsets::Offset,
        /// Size of the section.
        size: Offsets::Offset,
        /// Entry size of the section.
        ent_size: Offsets::Word,
        /// Link field for the section header.
        link: Offsets::Word,
        /// Info field for the section header.
        info: Offsets::Word,
        /// Flags, including access.
        flags: Offsets::Offset,
    }
}

/// Errors that can occur when creating a [SectionHdrData].
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum SectionHdrError<Offsets: SectionHdrOffsets> {
    /// Section data is out of bounds.
    DataOutOfBounds {
        /// The offset of the data.
        offset: Offsets::Offset,
        /// The size of the data.
        size: Offsets::Offset
    },
    /// A section header index is out of bounds.
    EntryOutOfBounds {
        /// The bad index.
        idx: Offsets::Word
    },
    /// Entry size does not match expectation.
    BadEntSize {
        expected: usize,
        actual: Offsets::Word
    },
    /// Bad link reference.
    BadLink,
    /// Bad info value.
    BadInfo,
    /// An error occurred creating the [Symtab](crate::symtab::Symtab).
    SymtabErr(()),
    /// An error occurred creating the [Strtab](crate::strtab::Strtab).
    StrtabErr(()),
    /// An error occurred creating the [Relas](crate::reloc::Relas).
    RelasErr(()),
    /// An error occurred creating the [Rels](crate::reloc::Rels).
    RelsErr(()),
    /// An error occurred creating the [Dynamic](crate::dynamic::Dynamic).
    DynamicErr(()),
    /// An error occurred creating the [Hashtab](crate::hash::Hashtab).
    HashErr(HashtabError),
    /// An error occurred creating the [Notes](crate::note::Notes).
    NoteErr(()),
}

/// Offset and size of section data.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct SectionPos<Word> {
    /// Offset into the ELF data of the start of the section.
    pub offset: Word,
    /// Size of the section in bytes.
    pub size: Word
}

/// A composite structure designed to hold a symbol table and its
/// associated string table.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct SymsStrs<Syms, Strs> {
    /// The symbol table.
    syms: Syms,
    /// The string table.
    strs: Strs
}

fn project<'a, B, Offsets>(ent: &'a [u8], byteorder: PhantomData<B>,
                           offsets: PhantomData<Offsets>) ->
    Result<SectionHdrData<Offsets, Offsets::Word, Offsets::Word, Offsets::Word,
                          Offsets::Word, SectionPos<Offsets::Offset>,
                          SectionPos<Offsets::Offset>,
                          SectionPos<Offsets::Offset>,
                          SectionPos<Offsets::Offset>,
                          SectionPos<Offsets::Offset>,
                          SectionPos<Offsets::Offset>,
                          SectionPos<Offsets::Offset>,
                          SectionPos<Offsets::Offset>>,
           SectionHdrError<Offsets>>
    where Offsets: SectionHdrOffsets,
          B: ByteOrder {
    let kind = Offsets::read_word(&ent[Offsets::SH_KIND_START ..
                                       Offsets::SH_KIND_END],
                                  byteorder);

    match kind.into() {
        0 => Ok(SectionHdrData::Null),
        1 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                               Offsets::SH_NAME_END],
                                          byteorder);
            let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                               Offsets::SH_ADDR_END],
                                          byteorder);
            let align = Offsets::read_offset(&ent[Offsets::SH_ALIGN_START ..
                                                  Offsets::SH_ALIGN_END],
                                             byteorder);
            let flags = Offsets::read_offset(&ent[Offsets::SH_FLAGS_START ..
                                                  Offsets::SH_FLAGS_END],
                                             byteorder);
            let pos = SectionPos { offset: offset, size: size };
            let exec = flags & (0x4 as u8).into() != (0 as u8).into();
            let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
            let write = flags & (0x1 as u8).into() != (0 as u8).into();

            Ok(SectionHdrData::ProgBits { name: name, addr: addr, align: align,
                                          data: pos, alloc: alloc, write: write,
                                          exec: exec })
        },
        2 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let ent_size = Offsets::read_word(&ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                              byteorder);
            let strtab = Offsets::read_word(&ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                            byteorder);

            match ent_size.try_into() {
                Ok(ent_size) if ent_size == Offsets::ST_ENT_SIZE => {
                    let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                                       Offsets::SH_NAME_END],
                                                  byteorder);
                    let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                                       Offsets::SH_ADDR_END],
                                                  byteorder);
                    let align = Offsets::read_offset(
                        &ent[Offsets::SH_ALIGN_START .. Offsets::SH_ALIGN_END],
                        byteorder
                    );
                    let flags = Offsets::read_offset(
                        &ent[Offsets::SH_FLAGS_START .. Offsets::SH_FLAGS_END],
                        byteorder
                    );
                    let info = Offsets::read_word(&ent[Offsets::SH_INFO_START ..
                                                       Offsets::SH_INFO_END],
                                                  byteorder);
                    let pos = SectionPos { offset: offset, size: size };
                    let exec = flags & (0x4 as u8).into() != (0 as u8).into();
                    let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
                    let write = flags & (0x1 as u8).into() != (0 as u8).into();

                    Ok(SectionHdrData::Symtab { name: name, local_end: info,
                                                addr: addr, strtab: strtab,
                                                align: align, syms: pos,
                                                write: write, alloc: alloc,
                                                exec: exec })
                },
                _ => Err(SectionHdrError::BadEntSize {
                    expected: Offsets::ST_ENT_SIZE, actual: ent_size
                })
            }
        },
        3 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                               Offsets::SH_NAME_END],
                                          byteorder);
            let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                               Offsets::SH_ADDR_END],
                                          byteorder);
            let align = Offsets::read_offset(&ent[Offsets::SH_ALIGN_START ..
                                                  Offsets::SH_ALIGN_END],
                                             byteorder);
            let pos = SectionPos { offset: offset, size: size };

            Ok(SectionHdrData::Strtab { name: name, addr: addr,
                                        align: align, strs: pos })
        },
        4 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let ent_size = Offsets::read_word(&ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                              byteorder);
            let symtab = Offsets::read_word(&ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                            byteorder);
            let target = Offsets::read_word(&ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                            byteorder);

            match ent_size.try_into() {
                Ok(ent_size) if ent_size == Offsets::RELA_SIZE => {
                    let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                                       Offsets::SH_NAME_END],
                                                  byteorder);
                    let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                                       Offsets::SH_ADDR_END],
                                                  byteorder);
                    let align = Offsets::read_offset(
                        &ent[Offsets::SH_ALIGN_START .. Offsets::SH_ALIGN_END],
                        byteorder
                    );
                    let flags = Offsets::read_offset(
                        &ent[Offsets::SH_FLAGS_START .. Offsets::SH_FLAGS_END],
                        byteorder
                    );
                    let pos = SectionPos { offset: offset, size: size };
                    let exec = flags & (0x4 as u8).into() != (0 as u8).into();
                    let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
                    let write = flags & (0x1 as u8).into() != (0 as u8).into();

                    Ok(SectionHdrData::Rela { name: name, addr: addr,
                                              align: align, target: target,
                                              symtab: symtab, relas: pos,
                                              write: write, alloc: alloc,
                                              exec: exec })
                },
                _ => Err(SectionHdrError::BadEntSize {
                    expected: Offsets::RELA_SIZE, actual: ent_size
                })
            }
        },
        5 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let symtab = Offsets::read_word(&ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                            byteorder);
            let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                               Offsets::SH_NAME_END],
                                          byteorder);
            let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                               Offsets::SH_ADDR_END],
                                          byteorder);
            let align = Offsets::read_offset(&ent[Offsets::SH_ALIGN_START ..
                                                  Offsets::SH_ALIGN_END],
                                             byteorder);
            let flags = Offsets::read_offset(&ent[Offsets::SH_FLAGS_START ..
                                                  Offsets::SH_FLAGS_END],
                                             byteorder);
            let pos = SectionPos { offset: offset, size: size };
            let exec = flags & (0x4 as u8).into() != (0 as u8).into();
            let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
            let write = flags & (0x1 as u8).into() != (0 as u8).into();

            Ok(SectionHdrData::Hash { name: name, addr: addr, align: align,
                                      hash: pos, symtab: symtab, write: write,
                                      alloc: alloc, exec: exec })
        },
        6 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let ent_size = Offsets::read_word(&ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                              byteorder);
            let strtab = Offsets::read_word(&ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                            byteorder);

            match ent_size.try_into() {
                Ok(ent_size) if ent_size == Offsets::DYNAMIC_SIZE  => {
                    let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                                       Offsets::SH_NAME_END],
                                                  byteorder);
                    let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                                       Offsets::SH_ADDR_END],
                                                  byteorder);
                    let align = Offsets::read_offset(
                        &ent[Offsets::SH_ALIGN_START .. Offsets::SH_ALIGN_END],
                        byteorder
                    );
                    let flags = Offsets::read_offset(
                        &ent[Offsets::SH_FLAGS_START .. Offsets::SH_FLAGS_END],
                        byteorder
                    );
                    let pos = SectionPos { offset: offset, size: size };
                    let exec = flags & (0x4 as u8).into() != (0 as u8).into();
                    let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
                    let write = flags & (0x1 as u8).into() != (0 as u8).into();

                    Ok(SectionHdrData::Dynamic { name: name, align: align,
                                                 addr: addr, strtab: strtab,
                                                 dynamic: pos, write: write,
                                                 alloc: alloc, exec: exec })
                },
                _ => Err(SectionHdrError::BadEntSize {
                    expected: Offsets::DYNAMIC_SIZE, actual: ent_size
                })
            }
        },
        7 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                               Offsets::SH_NAME_END],
                                          byteorder);
            let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                               Offsets::SH_ADDR_END],
                                          byteorder);
            let align = Offsets::read_offset(&ent[Offsets::SH_ALIGN_START ..
                                                  Offsets::SH_ALIGN_END],
                                             byteorder);
            let flags = Offsets::read_offset(&ent[Offsets::SH_FLAGS_START ..
                                                  Offsets::SH_FLAGS_END],
                                             byteorder);
            let pos = SectionPos { offset: offset, size: size };
            let exec = flags & (0x4 as u8).into() != (0 as u8).into();
            let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
            let write = flags & (0x1 as u8).into() != (0 as u8).into();

            Ok(SectionHdrData::Note { name: name, addr: addr, align: align,
                                      note: pos, write: write, alloc: alloc,
                                      exec: exec })
        },
        8 => {
            let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                               Offsets::SH_NAME_END],
                                          byteorder);
            let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                               Offsets::SH_ADDR_END],
                                          byteorder);
            let align = Offsets::read_offset(&ent[Offsets::SH_ALIGN_START ..
                                                  Offsets::SH_ALIGN_END],
                                             byteorder);
            let flags = Offsets::read_offset(&ent[Offsets::SH_FLAGS_START ..
                                                  Offsets::SH_FLAGS_END],
                                             byteorder);
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let pos = SectionPos { offset: offset, size: size };
            let exec = flags & (0x4 as u8).into() != (0 as u8).into();
            let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
            let write = flags & (0x1 as u8).into() != (0 as u8).into();

            Ok(SectionHdrData::Nobits { name: name, addr: addr, align: align,
                                        size: size, offset: offset, exec: exec,
                                        write: write, alloc: alloc })
        },
        9 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let ent_size = Offsets::read_word(
                &ent[Offsets::SH_ENT_SIZE_START .. Offsets::SH_ENT_SIZE_END],
                byteorder
            );
            let symtab = Offsets::read_word(&ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                            byteorder);
            let target = Offsets::read_word(&ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                            byteorder);

            match ent_size.try_into() {
                Ok(ent_size) if ent_size == Offsets::REL_SIZE => {
                    let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                                       Offsets::SH_NAME_END],
                                                  byteorder);
                    let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                                       Offsets::SH_ADDR_END],
                                                  byteorder);
                    let align = Offsets::read_offset(
                        &ent[Offsets::SH_ALIGN_START .. Offsets::SH_ALIGN_END],
                        byteorder
                    );
                    let flags = Offsets::read_offset(
                        &ent[Offsets::SH_FLAGS_START .. Offsets::SH_FLAGS_END],
                        byteorder
                    );
                    let pos = SectionPos { offset: offset, size: size };
                    let exec = flags & (0x4 as u8).into() != (0 as u8).into();
                    let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
                    let write = flags & (0x1 as u8).into() != (0 as u8).into();

                    Ok(SectionHdrData::Rel { name: name, addr: addr,
                                             align: align, target: target,
                                             symtab: symtab, rels: pos,
                                             write: write, alloc: alloc,
                                             exec: exec })
                },
                _ => Err(SectionHdrError::BadEntSize {
                    expected: Offsets::REL_SIZE, actual: ent_size
                })
            }
        },
        11 => {
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let ent_size = Offsets::read_word(&ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                              byteorder);
            let strtab = Offsets::read_word(&ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                            byteorder);

            match ent_size.try_into() {
                Ok(ent_size) if ent_size == Offsets::ST_ENT_SIZE => {
                    let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                                       Offsets::SH_NAME_END],
                                                  byteorder);
                    let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                                       Offsets::SH_ADDR_END],
                                                  byteorder);
                    let align = Offsets::read_offset(
                        &ent[Offsets::SH_ALIGN_START .. Offsets::SH_ALIGN_END],
                        byteorder
                    );
                    let flags = Offsets::read_offset(
                        &ent[Offsets::SH_FLAGS_START .. Offsets::SH_FLAGS_END],
                        byteorder
                    );
                    let info = Offsets::read_word(&ent[Offsets::SH_INFO_START ..
                                                       Offsets::SH_INFO_END],
                                                  byteorder);
                    let pos = SectionPos { offset: offset, size: size };
                    let exec = flags & (0x4 as u8).into() != (0 as u8).into();
                    let alloc = flags & (0x2 as u8).into() != (0 as u8).into();
                    let write = flags & (0x1 as u8).into() != (0 as u8).into();

                    Ok(SectionHdrData::Dynsym { name: name, local_end: info,
                                                addr: addr, strtab: strtab,
                                                align: align, syms: pos,
                                                write: write, alloc: alloc,
                                                exec: exec })
                },
                _ => Err(SectionHdrError::BadEntSize {
                    expected: Offsets::ST_ENT_SIZE, actual: ent_size
                })
            }
        },
        _ => {
            let name = Offsets::read_word(&ent[Offsets::SH_NAME_START ..
                                               Offsets::SH_NAME_END],
                                          byteorder);
            let addr = Offsets::read_addr(&ent[Offsets::SH_ADDR_START ..
                                               Offsets::SH_ADDR_END],
                                          byteorder);
            let align = Offsets::read_offset(&ent[Offsets::SH_ALIGN_START ..
                                                  Offsets::SH_ALIGN_END],
                                             byteorder);
            let flags = Offsets::read_offset(&ent[Offsets::SH_FLAGS_START ..
                                                  Offsets::SH_FLAGS_END],
                                             byteorder);
            let link = Offsets::read_word(&ent[Offsets::SH_LINK_START ..
                                               Offsets::SH_LINK_END],
                                          byteorder);
            let info = Offsets::read_word(&ent[Offsets::SH_INFO_START ..
                                               Offsets::SH_INFO_END],
                                          byteorder);
            let offset = Offsets::read_offset(&ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                              byteorder);
            let size = Offsets::read_offset(&ent[Offsets::SH_SIZE_START ..
                                                 Offsets::SH_SIZE_END],
                                            byteorder);
            let ent_size = Offsets::read_word(&ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                              byteorder);

            Ok(SectionHdrData::Unknown { name: name, tag: kind, addr: addr,
                                         align: align, offset: offset,
                                         size: size, link: link, info: info,
                                         ent_size: ent_size, flags: flags })
        }
    }
}

fn create<'a, B, I, Offsets>(buf: &'a mut [u8], hdrs: I,
                             byteorder: PhantomData<B>,
                             offsets: PhantomData<Offsets>) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where I: Iterator<Item = SectionHdrData<Offsets, Offsets::Word,
                                            Offsets::Word, Offsets::Word,
                                            Offsets::Word,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>>>,
          Offsets: SectionHdrOffsets,
          B: ByteOrder {
    let len = buf.len();
    let mut idx = 0;

    for hdr in hdrs {
        if idx + Offsets::SECTION_HDR_SIZE <= len {
            let ent = &mut buf[idx .. idx + Offsets::SECTION_HDR_SIZE];

            match hdr {
                SectionHdrData::Null => {
                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          (0 as u8).into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                          (0 as u8).into(), byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                          (0 as u8).into(), byteorder);
                },
                SectionHdrData::ProgBits { name, addr, align, data, alloc,
                                           write, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (1 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          data.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         data.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                          (0 as u8).into(), byteorder);
                },
                SectionHdrData::Symtab { name, local_end, addr, strtab, align,
                                         syms, write, alloc, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (2 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          syms.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         syms.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        strtab, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        local_end, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                          Offsets::ST_ENT_SIZE_OFFSET,
                                          byteorder);
                },
                SectionHdrData::Strtab { name, addr, align, strs } => {
                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (3 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          (0 as u8).into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          strs.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         strs.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                 Offsets::SH_ENT_SIZE_END],
                                        (0 as u8).into(), byteorder);
                },
                SectionHdrData::Rela { name, addr, align, target, symtab,
                                       relas, write, alloc, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (4 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          relas.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         relas.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        symtab, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        target, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                          Offsets::RELA_SIZE_OFFSET, byteorder);
                },
                SectionHdrData::Hash { name, addr, align, hash, symtab,
                                       write, alloc, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (5 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          hash.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         hash.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        symtab, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                 Offsets::SH_ENT_SIZE_END],
                                        (0 as u8).into(), byteorder);
                },
                SectionHdrData::Dynamic { name, align, addr, strtab, dynamic,
                                          write, alloc, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (6 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          dynamic.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         dynamic.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        strtab, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                          Offsets::DYNAMIC_SIZE_OFFSET,
                                          byteorder);
                },
                SectionHdrData::Note { name, addr, align, note, write,
                                       alloc, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (7 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          note.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         note.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                          (0 as u8).into(), byteorder);
                },
                SectionHdrData::Nobits { name, addr, align, offset, size,
                                         write, alloc, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (8 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                 Offsets::SH_ENT_SIZE_END],
                                        (0 as u8).into(), byteorder);
                },
                SectionHdrData::Rel { name, addr, align, target, symtab,
                                      rels, write, alloc, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (9 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          rels.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         rels.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        symtab, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        target, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                          Offsets::REL_SIZE_OFFSET, byteorder);
                },
                SectionHdrData::Dynsym { name, local_end, addr, strtab, align,
                                         syms, write, alloc, exec } => {
                    let flags: u8 = if exec { 0x4 } else { 0 } |
                                    if alloc { 0x2 } else { 0 } |
                                    if write { 0x1 } else { 0 };

                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        (11 as u8).into(), byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags.into(), byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          syms.offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         syms.size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        strtab, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        local_end, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                   Offsets::SH_ENT_SIZE_END],
                                          Offsets::ST_ENT_SIZE_OFFSET,
                                          byteorder);
                },
                SectionHdrData::Unknown { name, tag, addr, align, offset, size,
                                          link, info, ent_size, flags } => {
                    Offsets::write_word(&mut ent[Offsets::SH_NAME_START ..
                                                 Offsets::SH_NAME_END],
                                        name, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_KIND_START ..
                                                 Offsets::SH_KIND_END],
                                        tag, byteorder);
                    Offsets::write_addr(&mut ent[Offsets::SH_ADDR_START ..
                                                 Offsets::SH_ADDR_END],
                                        addr, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_ALIGN_START ..
                                                   Offsets::SH_ALIGN_END],
                                          align, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_FLAGS_START ..
                                                   Offsets::SH_FLAGS_END],
                                          flags, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_LINK_START ..
                                                 Offsets::SH_LINK_END],
                                        link, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_INFO_START ..
                                                 Offsets::SH_INFO_END],
                                        info, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_OFFSET_START ..
                                                   Offsets::SH_OFFSET_END],
                                          offset, byteorder);
                    Offsets::write_offset(&mut ent[Offsets::SH_SIZE_START ..
                                                   Offsets::SH_SIZE_END],
                                         size, byteorder);
                    Offsets::write_word(&mut ent[Offsets::SH_ENT_SIZE_START ..
                                                 Offsets::SH_ENT_SIZE_END],
                                        ent_size, byteorder);
                }
            }

            idx += Offsets::SECTION_HDR_SIZE;
        } else {
            return Err(())
        }
    }

    Ok(buf.split_at_mut(idx))
}

impl SectionHdrOffsets for Elf32 {
    const SECTION_HDR_SIZE_HALF: Self::Half = Self::SECTION_HDR_SIZE as u16;
}

impl SectionHdrOffsets for Elf64 {
    const SECTION_HDR_SIZE_HALF: Self::Half = Self::SECTION_HDR_SIZE as u16;
}

impl<'a, B, Offsets, Syms, Strs, Rels, Relas, Hash, Dynamic, Note>
    WithSectionHdrs<'a, B, Offsets>
    for SectionHdrData<Offsets, Offsets::Word, Offsets::Word, Offsets::Word,
                       Offsets::Word, SectionPos<Offsets::Offset>,
                       Syms, Strs, Rels, Relas, Hash, Dynamic, Note>
    where Offsets: SectionHdrOffsets,
          B: ByteOrder {
    type Result = SectionHdrData<Offsets, Offsets::Word,
                                 SectionHdr<'a, B, Offsets>,
                                 SectionHdr<'a, B, Offsets>,
                                 SectionHdr<'a, B, Offsets>,
                                 SectionPos<Offsets::Offset>,
                                 Syms, Strs, Rels, Relas,
                                 Hash, Dynamic, Note>;
    type Error = Offsets::Word;

    #[inline]
    fn with_section_hdrs(self, section_hdrs: SectionHdrs<'a, B, Offsets>) ->
        Result<Self::Result, Self::Error> {
        match self {
            SectionHdrData::Null => Ok(SectionHdrData::Null),
            SectionHdrData::ProgBits { name, addr, align, alloc, write,
                                       exec, data } => {
                Ok(SectionHdrData::ProgBits {
                    name: name, addr: addr, align: align, data: data,
                    alloc: alloc, write: write, exec: exec
                })
            },
            SectionHdrData::Symtab { name, local_end, addr, align, syms, write,
                                     alloc, exec, strtab: strtab_idx } => {
                match strtab_idx.try_into() {
                    Ok(strtab) => {
                        let strtab_start = strtab * Offsets::SECTION_HDR_SIZE;
                        let strtab_end = strtab_start +
                                         Offsets::SECTION_HDR_SIZE;

                        if strtab_end >= section_hdrs.hdrs.len() {
                            Err(strtab_idx)
                        } else {
                            let data = &section_hdrs.hdrs[strtab_start ..
                                                          strtab_end];
                            let strtab = SectionHdr { byteorder: PhantomData,
                                                      offsets: PhantomData,
                                                      ent: data };

                            Ok(SectionHdrData::Symtab {
                                name: name, addr: addr, syms: syms,
                                strtab: strtab, align: align, write: write,
                                alloc: alloc, exec: exec, local_end: local_end
                            })
                        }
                    },
                    _ => Err(strtab_idx)
                }
            },
            SectionHdrData::Strtab { name, addr, align, strs } => {
                Ok(SectionHdrData::Strtab {
                    name: name, addr: addr, align: align, strs: strs
                })
            },
            SectionHdrData::Rela { name, addr, align, relas, write, alloc, exec,
                                   target: target_idx, symtab: symtab_idx} => {
                match (symtab_idx.try_into(), target_idx.try_into()) {
                    (Ok(symtab), Ok(target)) => {
                        let symtab_start = symtab * Offsets::SECTION_HDR_SIZE;
                        let symtab_end = symtab_start +
                                         Offsets::SECTION_HDR_SIZE;
                        let target_start = target * Offsets::SECTION_HDR_SIZE;
                        let target_end = target_start +
                                         Offsets::SECTION_HDR_SIZE;

                        if symtab_end >= section_hdrs.hdrs.len() {
                            Err(symtab_idx)
                        } else if target_end >= section_hdrs.hdrs.len() {
                            Err(target_idx)
                        } else {
                            let symtab_data = &section_hdrs.hdrs[symtab_start ..
                                                                 symtab_end];
                            let symtab = SectionHdr { byteorder: PhantomData,
                                                      offsets: PhantomData,
                                                      ent: symtab_data };
                            let target_data = &section_hdrs.hdrs[target_start ..
                                                                 target_end];
                            let target = SectionHdr { byteorder: PhantomData,
                                                      offsets: PhantomData,
                                                      ent: target_data };

                            Ok(SectionHdrData::Rela {
                                name: name, align: align, addr: addr,
                                target: target, symtab: symtab, relas: relas,
                                write: write, alloc: alloc, exec: exec,
                            })
                        }
                    },
                    (Ok(_), _) => Err(target_idx),
                    (_, _) => Err(symtab_idx)
                }
            },
            SectionHdrData::Hash { name, addr, align, hash, write, alloc, exec,
                                   symtab: symtab_idx } => {
                match symtab_idx.try_into() {
                    Ok(symtab) => {
                        let symtab_start = symtab * Offsets::SECTION_HDR_SIZE;
                        let symtab_end = symtab_start +
                                         Offsets::SECTION_HDR_SIZE;

                        if symtab_end >= section_hdrs.hdrs.len() {
                            Err(symtab_idx)
                        } else {
                            let data = &section_hdrs.hdrs[symtab_start ..
                                                          symtab_end];
                            let symtab = SectionHdr { byteorder: PhantomData,
                                                      offsets: PhantomData,
                                                      ent: data };

                            Ok(SectionHdrData::Hash {
                                name: name, addr: addr, align: align,
                                hash: hash, write: write, exec: exec,
                                alloc: alloc, symtab: symtab
                            })
                        }
                    },
                    _ => Err(symtab_idx)
                }
            },
            SectionHdrData::Dynamic { name, align, addr, dynamic, write, alloc,
                                      exec, strtab: strtab_idx } => {
                match strtab_idx.try_into() {
                    Ok(strtab) => {
                        let strtab_start = strtab * Offsets::SECTION_HDR_SIZE;
                        let strtab_end = strtab_start +
                                         Offsets::SECTION_HDR_SIZE;

                        if strtab_end >= section_hdrs.hdrs.len() {
                            Err(strtab_idx)
                        } else {
                            let data = &section_hdrs.hdrs[strtab_start ..
                                                          strtab_end];
                            let strtab = SectionHdr { byteorder: PhantomData,
                                                      offsets: PhantomData,
                                                      ent: data };

                            Ok(SectionHdrData::Dynamic {
                                name: name, align: align, addr: addr,
                                strtab: strtab, dynamic: dynamic, write: write,
                                alloc: alloc, exec: exec
                            })
                        }
                    },
                    _ => Err(strtab_idx)
                }
            },
            SectionHdrData::Note { name, addr, align, note,
                                   write, alloc, exec } => {
                Ok(SectionHdrData::Note { name: name, addr: addr, align: align,
                                          note: note, write: write,
                                          alloc: alloc, exec: exec })
            },
            SectionHdrData::Nobits { name, addr, align, offset, size,
                                     write, alloc, exec } => {
                Ok(SectionHdrData::Nobits { name: name, addr: addr, size: size,
                                            offset: offset, align: align,
                                            write: write, alloc: alloc,
                                            exec: exec })
            },
            SectionHdrData::Rel { name, addr, align, rels, write, alloc, exec,
                                  symtab: symtab_idx, target: target_idx } => {
                match (symtab_idx.try_into(), target_idx.try_into()) {
                    (Ok(symtab), Ok(target)) => {
                        let symtab_start = symtab * Offsets::SECTION_HDR_SIZE;
                        let symtab_end = symtab_start +
                                         Offsets::SECTION_HDR_SIZE;
                        let target_start = target * Offsets::SECTION_HDR_SIZE;
                        let target_end = target_start +
                                         Offsets::SECTION_HDR_SIZE;

                        if symtab_end >= section_hdrs.hdrs.len() {
                            Err(symtab_idx)
                        } else if target_end >= section_hdrs.hdrs.len() {
                            Err(target_idx)
                        } else {
                            let symtab_data = &section_hdrs.hdrs[symtab_start ..
                                                                 symtab_end];
                            let symtab = SectionHdr { byteorder: PhantomData,
                                                      offsets: PhantomData,
                                                      ent: symtab_data };
                            let target_data = &section_hdrs.hdrs[target_start ..
                                                                 target_end];
                            let target = SectionHdr { byteorder: PhantomData,
                                                      offsets: PhantomData,
                                                      ent: target_data };

                            Ok(SectionHdrData::Rel {
                                name: name, align: align, addr: addr,
                                target: target, symtab: symtab, rels: rels,
                                write: write, alloc: alloc, exec: exec,
                            })
                        }
                    },
                    (Ok(_), _) => Err(target_idx),
                    (_, _) => Err(symtab_idx)
                }
            },
            SectionHdrData::Dynsym { name, local_end, addr, align, syms, write,
                                     alloc, exec, strtab: strtab_idx } => {
                match strtab_idx.try_into() {
                    Ok(strtab) => {
                        let strtab_start = strtab * Offsets::SECTION_HDR_SIZE;
                        let strtab_end = strtab_start +
                                         Offsets::SECTION_HDR_SIZE;

                        if strtab_end >= section_hdrs.hdrs.len() {
                            Err(strtab_idx)
                        } else {
                            let data = &section_hdrs.hdrs[strtab_start ..
                                                          strtab_end];
                            let strtab = SectionHdr { byteorder: PhantomData,
                                                      offsets: PhantomData,
                                                      ent: data };

                            Ok(SectionHdrData::Symtab {
                                name: name, addr: addr, syms: syms,
                                strtab: strtab, align: align, write: write,
                                alloc: alloc, exec: exec, local_end: local_end
                            })
                        }
                    },
                    _ => Err(strtab_idx)
                }
            },
            SectionHdrData::Unknown { name, tag, addr, align, offset, size,
                                      link, info, ent_size, flags } => {
                Ok(SectionHdrData::Unknown { name: name, tag: tag, addr: addr,
                                             align: align, offset: offset,
                                             size: size, link: link, info: info,
                                             ent_size: ent_size, flags: flags })
            }
        }
    }
}

/// Calculate the number of bytes required to represent the program
/// header table containing `hdrs`.
///
/// # Examples
///
/// ```
/// extern crate elf_utils;
///
/// use byteorder::LittleEndian;
/// use elf_utils::Elf32;
/// use elf_utils::section_hdr::SectionHdrData;
/// use elf_utils::section_hdr::SectionPos;
/// use elf_utils::section_hdr;
///
/// const SECTION_HDR_CONTENTS: [SectionHdrData<Elf32, u32, u32, u32, u32,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>,
///                                             SectionPos<u32>>; 5] = [
///     SectionHdrData::Null,
///     SectionHdrData::Note { name: 12, addr: 0x174, align: 4,
///                            note: SectionPos { offset: 0x174, size: 0x18 },
///                            alloc: true, write: false, exec: false },
///     SectionHdrData::Dynsym { name: 22, addr: 0x18c, align: 4,
///                              syms: SectionPos { offset: 0x18c,
///                                                 size: 0x1b0 },
///                              strtab: 7, local_end: 1,
///                              alloc: true, write: false, exec: false },
///     SectionHdrData::Hash { name: 68, addr: 0x540, align: 4,
///                            hash: SectionPos { offset: 0x540, size: 0xe0 },
///                            symtab: 2, alloc: true, write: false,
///                            exec: false },
///     SectionHdrData::Strtab { name: 74, addr: 0x620, align: 1,
///                              strs: SectionPos { offset: 0x620,
///                                                 size: 0x1d2 } }
/// ];
///
/// assert_eq!(section_hdr::required_bytes(SECTION_HDR_CONTENTS
///                                        .iter().map(|x| *x)), 200);
/// ```
#[inline]
pub fn required_bytes<I, Offsets>(hdrs: I) -> usize
    where I: Iterator<Item = SectionHdrData<Offsets, Offsets::Word,
                                            Offsets::Word, Offsets::Word,
                                            Offsets::Word,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>,
                                            SectionPos<Offsets::Offset>>>,
          Offsets: SectionHdrOffsets {
    hdrs.count() * Offsets::SECTION_HDR_SIZE
}

impl<'a, B, Offsets> SectionHdrs<'a, B, Offsets>
    where Offsets: SectionHdrOffsets,
          B: ByteOrder {
    /// Attempt to create a `SectionHdrs` in `buf` containing the section
    /// header table entries in `hdrs`.
    ///
    /// This will write the section header table data into the buffer
    /// in the proper format for the ELF class and byte order.
    /// Returns both the `SectionHdrs` and the remaining space if
    /// successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the section header table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate elf_utils;
    ///
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use elf_utils::Elf32;
    /// use elf_utils::section_hdr::SectionHdrs;
    /// use elf_utils::section_hdr::SectionHdrData;
    /// use elf_utils::section_hdr::SectionPos;
    ///
    /// const SECTION_HDR_CONTENTS: [SectionHdrData<Elf32, u32, u32, u32, u32,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>>; 5] = [
    ///     SectionHdrData::Null,
    ///     SectionHdrData::Note { name: 12, addr: 0x174, align: 4,
    ///                            note: SectionPos { offset: 0x174,
    ///                                               size: 0x18 },
    ///                            alloc: true, write: false, exec: false },
    ///     SectionHdrData::Dynsym { name: 22, addr: 0x18c, align: 4,
    ///                              syms: SectionPos { offset: 0x18c,
    ///                                                 size: 0x1b0 },
    ///                              strtab: 7, local_end: 1,
    ///                              alloc: true, write: false, exec: false },
    ///     SectionHdrData::Hash { name: 68, addr: 0x540, align: 4,
    ///                            hash: SectionPos { offset: 0x540,
    ///                                               size: 0xe0 },
    ///                            symtab: 2, alloc: true, write: false,
    ///                            exec: false },
    ///     SectionHdrData::Strtab { name: 74, addr: 0x620, align: 1,
    ///                              strs: SectionPos { offset: 0x620,
    ///                                                 size: 0x1d2 } }
    /// ];
    ///
    /// let mut buf = [0; 208];
    /// let res: Result<(SectionHdrs<'_, LittleEndian, Elf32>,
    ///                     &'_ mut [u8]), ()> =
    ///     SectionHdrs::create_split(&mut buf[0..],
    ///                               SECTION_HDR_CONTENTS.iter().map(|x| *x));
    /// let (hdrs, rest) = res.unwrap();
    ///
    /// assert_eq!(rest.len(), 8);
    ///
    /// let mut iter = hdrs.iter();
    ///
    /// for i in 0 .. 5 {
    ///     let ent = iter.next().unwrap();
    ///     let data: SectionHdrData<Elf32, u32, u32, u32, u32, SectionPos<u32>,
    ///                              SectionPos<u32>, SectionPos<u32>,
    ///                              SectionPos<u32>, SectionPos<u32>,
    ///                              SectionPos<u32>, SectionPos<u32>,
    ///                              SectionPos<u32>> =
    ///         ent.try_into().unwrap();
    ///
    ///     assert_eq!(data, SECTION_HDR_CONTENTS[i]);
    /// }
    /// ```
    #[inline]
    pub fn create_split<I>(buf: &'a mut [u8], ents: I) ->
        Result<(Self, &'a mut [u8]), ()>
        where I: Iterator<Item = SectionHdrData<Offsets, Offsets::Word,
                                                Offsets::Word, Offsets::Word,
                                                Offsets::Word,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>>> {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (data, out) = create(buf, ents, byteorder, offsets)?;

        Ok((SectionHdrs { byteorder: byteorder, offsets: offsets, hdrs: data },
            out))
    }

    /// Attempt to create a `SectionHdrs` in `buf` containing the section
    /// header table entries in `hdrs`.
    ///
    /// This will write the section header table data into the buffer
    /// in the proper format for the ELF class and byte order.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the section header table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate elf_utils;
    ///
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use elf_utils::Elf32;
    /// use elf_utils::section_hdr::SectionHdrs;
    /// use elf_utils::section_hdr::SectionHdrData;
    /// use elf_utils::section_hdr::SectionPos;
    ///
    /// const SECTION_HDR_CONTENTS: [SectionHdrData<Elf32, u32, u32, u32, u32,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>,
    ///                                             SectionPos<u32>>; 5] = [
    ///     SectionHdrData::Null,
    ///     SectionHdrData::Note { name: 12, addr: 0x174, align: 4,
    ///                            note: SectionPos { offset: 0x174,
    ///                                               size: 0x18 },
    ///                            alloc: true, write: false, exec: false },
    ///     SectionHdrData::Dynsym { name: 22, addr: 0x18c, align: 4,
    ///                              syms: SectionPos { offset: 0x18c,
    ///                                                 size: 0x1b0 },
    ///                              strtab: 7, local_end: 1,
    ///                              alloc: true, write: false, exec: false },
    ///     SectionHdrData::Hash { name: 68, addr: 0x540, align: 4,
    ///                            hash: SectionPos { offset: 0x540,
    ///                                               size: 0xe0 },
    ///                            symtab: 2, alloc: true, write: false,
    ///                            exec: false },
    ///     SectionHdrData::Strtab { name: 74, addr: 0x620, align: 1,
    ///                              strs: SectionPos { offset: 0x620,
    ///                                                 size: 0x1d2 } }
    /// ];
    ///
    /// let mut buf = [0; 208];
    /// let res: Result<SectionHdrs<'_, LittleEndian, Elf32>, ()> =
    ///     SectionHdrs::create(&mut buf[0..],
    ///                         SECTION_HDR_CONTENTS.iter().map(|x| *x));
    /// let hdrs = res.unwrap();
    ///
    /// let mut iter = hdrs.iter();
    ///
    /// for i in 0 .. 5 {
    ///     let ent = iter.next().unwrap();
    ///     let data: SectionHdrData<Elf32, u32, u32, u32, u32, SectionPos<u32>,
    ///                              SectionPos<u32>, SectionPos<u32>,
    ///                              SectionPos<u32>, SectionPos<u32>,
    ///                              SectionPos<u32>, SectionPos<u32>,
    ///                              SectionPos<u32>> =
    ///         ent.try_into().unwrap();
    ///
    ///     assert_eq!(data, SECTION_HDR_CONTENTS[i]);
    /// }
    /// ```
    #[inline]
    pub fn create<I>(buf: &'a mut [u8],ents: I) -> Result<Self, ()>
        where I: Iterator<Item = SectionHdrData<Offsets, Offsets::Word,
                                                Offsets::Word, Offsets::Word,
                                                Offsets::Word,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>,
                                                SectionPos<Offsets::Offset>>>,
              Self: Sized {
        match Self::create_split(buf, ents) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }

    /// Get a [SectionHdr] for the section header table entry at `idx`.
    ///
    /// # Errors
    ///
    /// `None` will be returned if `idx` is out of bounds.
    #[inline]
    pub fn idx(&self, idx: usize) -> Option<SectionHdr<'a, B, Offsets>> {
        let len = self.hdrs.len();
        let start = idx * Offsets::SECTION_HDR_SIZE;

        if start < len {
            let end = start + Offsets::SECTION_HDR_SIZE;

            Some(SectionHdr { byteorder: PhantomData, offsets: PhantomData,
                              ent: &self.hdrs[start .. end ] })
        } else {
            None
        }
    }

    /// Get the number of program header table entries in this `SectionHdrs`.
    #[inline]
    pub fn num_hdrs(&self) -> usize {
        self.hdrs.len() / Offsets::SECTION_HDR_SIZE
    }

    /// Get an iterator over this `SectionHdrs`.
    #[inline]
    pub fn iter(&self) -> SectionHdrIter<'a, B, Offsets> {
        SectionHdrIter { byteorder: PhantomData, offsets: PhantomData,
                         hdrs: self.hdrs, idx: 0 }
    }
}

impl<'a, B, Offsets> TryFrom<&'a [u8]> for SectionHdrs<'a, B, Offsets>
    where Offsets: SectionHdrOffsets,
          B: ByteOrder {
    type Error = ();

    #[inline]
    fn try_from(hdrs: &'a [u8]) -> Result<SectionHdrs<'a, B, Offsets>,
                                          Self::Error> {
        let len = hdrs.len();

        if hdrs.len() % Offsets::SECTION_HDR_SIZE == 0 {
            Ok(SectionHdrs { byteorder: PhantomData, offsets: PhantomData,
                             hdrs: hdrs })
        } else {
            Err(())
        }
    }
}

impl<'a, B, Offsets> TryFrom<&'a mut [u8]> for SectionHdrs<'a, B, Offsets>
    where Offsets: SectionHdrOffsets,
          B: ByteOrder {
    type Error = ();

    #[inline]
    fn try_from(hdrs: &'a mut [u8]) -> Result<SectionHdrs<'a, B, Offsets>,
                                              Self::Error> {
        let len = hdrs.len();

        if hdrs.len() % Offsets::SECTION_HDR_SIZE == 0 {
            Ok(SectionHdrs { byteorder: PhantomData, offsets: PhantomData,
                             hdrs: hdrs })
        } else {
            Err(())
        }
    }
}

impl<'a, B, Str, Offsets> WithElfData<'a>
        for SectionHdrData<Offsets, Str, SectionHdr<'a, B, Offsets>,
                           SymsStrs<SectionHdr<'a, B, Offsets>,
                                    SectionHdr<'a, B, Offsets>>,
                           SectionHdr<'a, B, Offsets>,
                           SectionPos<Offsets::Offset>,
                           SectionPos<Offsets::Offset>,
                           SectionPos<Offsets::Offset>,
                           SectionPos<Offsets::Offset>,
                           SectionPos<Offsets::Offset>,
                           SectionPos<Offsets::Offset>,
                           SectionPos<Offsets::Offset>,
                           SectionPos<Offsets::Offset>>
    where Offsets: SectionHdrOffsets,
          B: ByteOrder {
    type Result = SectionHdrData<Offsets, Str, SectionHdr<'a, B, Offsets>,
                                 SymsStrs<&'a [u8], &'a [u8]>, &'a [u8],
                                 &'a [u8], &'a [u8], &'a [u8], &'a [u8],
                                 &'a [u8], &'a [u8], &'a [u8], &'a [u8]>;
    type Error = SectionHdrError<Offsets>;

    #[inline]
    fn with_elf_data(self, data: &'a [u8]) ->
        Result<Self::Result, Self::Error> {
        match self {
            SectionHdrData::Null => Ok(SectionHdrData::Null),
            SectionHdrData::ProgBits { data: SectionPos { offset, size },
                                       name, addr, align, alloc,
                                       write, exec } => {
                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::ProgBits {
                            name: name, addr: addr, align: align,
                            alloc: alloc, write: write, exec: exec,
                            data: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Symtab { syms: SectionPos { offset, size },
                                     name, local_end, addr, align, write,
                                     alloc, exec, strtab } => {
                // Convert the strtab into data first.
                let strtab = match strtab.try_into() {
                    Ok(SectionHdrData::Strtab {
                        strs: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::Symtab {
                            name: name, addr: addr, align: align, write: write,
                            strtab: strtab?, exec: exec, local_end: local_end,
                            alloc: alloc, syms: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Strtab { strs: SectionPos { offset, size },
                                     name, addr, align } => {
                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::Strtab {
                            name: name, addr: addr, align: align,
                            strs: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Rela { relas: SectionPos { offset, size },
                                   symtab: SymsStrs { syms, strs },
                                   name, addr, align, write, alloc,
                                   exec, target } => {
                let symtab = match syms.try_into() {
                    Ok(SectionHdrData::Symtab {
                        syms: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                let strtab = match strs.try_into() {
                    Ok(SectionHdrData::Strtab {
                        strs: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                let symtab = SymsStrs { syms: symtab?, strs: strtab? };

                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::Rela {
                            name: name, align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            target: target, symtab: symtab,
                            relas: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Hash { hash: SectionPos { offset, size },
                                   symtab: SymsStrs { syms, strs },
                                   name, addr, align, write, alloc, exec } => {
                let symtab = match syms.try_into() {
                    Ok(SectionHdrData::Symtab {
                        syms: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                let strtab = match strs.try_into() {
                    Ok(SectionHdrData::Strtab {
                        strs: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                let symtab = SymsStrs { syms: symtab?, strs: strtab? };

                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::Hash {
                            name: name, addr: addr, align: align, write: write,
                            exec: exec, alloc: alloc, symtab: symtab,
                            hash: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Dynamic { dynamic: SectionPos { offset, size },
                                      name, align, addr, write, alloc,
                                      exec, strtab } => {
                // Convert the strtab into data first.
                let strtab = match strtab.try_into() {
                    Ok(SectionHdrData::Strtab {
                        strs: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::Dynamic {
                            name: name, align: align, addr: addr, write: write,
                            alloc: alloc, exec: exec, strtab: strtab?,
                            dynamic: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Note { note: SectionPos { offset, size },
                                   name, addr, align, write, alloc, exec } => {
                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::Note {
                            name: name, addr: addr, align: align,
                            write: write, alloc: alloc, exec: exec,
                            note: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Nobits { name, addr, align, offset, size,
                                     write, alloc, exec } => {
                Ok(SectionHdrData::Nobits {
                    name: name, addr: addr, size: size, offset: offset,
                    align: align, write: write, alloc: alloc, exec: exec
                })
            },
            SectionHdrData::Rel { rels: SectionPos { offset, size },
                                  symtab: SymsStrs { syms, strs },
                                  name, addr, align, write, alloc,
                                  exec, target } => {
                let symtab = match syms.try_into() {
                    Ok(SectionHdrData::Symtab {
                        syms: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                let strtab = match strs.try_into() {
                    Ok(SectionHdrData::Strtab {
                        strs: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                let symtab = SymsStrs { syms: symtab?, strs: strtab? };

                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::Rel {
                            name: name, align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            target: target, symtab: symtab,
                            rels: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Dynsym { syms: SectionPos { offset, size },
                                     name, local_end, addr, align, write,
                                     alloc, exec, strtab } => {
                // Convert the strtab into data first.
                let strtab = match strtab.try_into() {
                    Ok(SectionHdrData::Strtab {
                        strs: SectionPos { offset, size }, ..
                    }) => match (offset.try_into(), size.try_into()) {
                        (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                            Ok(&data[offset .. offset + size]),
                        _ => Err(SectionHdrError::DataOutOfBounds {
                            offset: offset, size: size
                        })
                    },
                    Ok(_) => Err(SectionHdrError::BadLink),
                    Err(err) => Err(err)
                };

                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(SectionHdrData::Dynsym {
                            name: name, addr: addr, align: align, write: write,
                            strtab: strtab?, exec: exec, local_end: local_end,
                            alloc: alloc, syms: &data[offset .. offset + size]
                        }),
                    _ => Err(SectionHdrError::DataOutOfBounds { offset: offset,
                                                                size: size })
                }
            },
            SectionHdrData::Unknown { name, tag, addr, align, offset, size,
                                      link, info, ent_size, flags } => {
                Ok(SectionHdrData::Unknown { name: name, tag: tag, addr: addr,
                                             align: align, offset: offset,
                                             size: size, link: link, info: info,
                                             ent_size: ent_size, flags: flags })
            }
        }
    }
}

impl<'a, B, Str, Offsets>
    TryFrom<SectionHdrData<Offsets, Str, SectionHdr<'a, B, Offsets>,
                           SymsStrs<&'a [u8], &'a [u8]>, &'a [u8],
                           &'a [u8], &'a [u8], &'a [u8], &'a [u8],
                           &'a [u8], &'a [u8], &'a [u8], &'a [u8]>>
    for SectionHdrData<Offsets, Str, SectionHdr<'a, B, Offsets>,
                       SymsStrs<Symtab<'a, B, Offsets>, Strtab<'a>>,
                       Strtab<'a>, &'a [u8],
                       Symtab<'a, B, Offsets>, Strtab<'a>,
                       Rels<'a, B, Offsets>, Relas<'a, B, Offsets>,
                       Hashtab<'a, B, Offsets>, Dynamic<'a, B, Offsets>,
                       Notes<'a, B>>
    where Offsets: 'a + SectionHdrOffsets,
          B: 'a + ByteOrder {
    type Error = SectionHdrError<Offsets>;

    #[inline]
    fn try_from(data: SectionHdrData<Offsets, Str, SectionHdr<'a, B, Offsets>,
                                     SymsStrs<&'a [u8], &'a [u8]>, &'a [u8],
                                     &'a [u8], &'a [u8], &'a [u8], &'a [u8],
                                     &'a [u8], &'a [u8], &'a [u8], &'a [u8]>) ->
        Result<SectionHdrData<Offsets, Str, SectionHdr<'a, B, Offsets>,
                       SymsStrs<Symtab<'a, B, Offsets>, Strtab<'a>>,
                       Strtab<'a>, &'a [u8],
                       Symtab<'a, B, Offsets>, Strtab<'a>,
                       Rels<'a, B, Offsets>, Relas<'a, B, Offsets>,
                       Hashtab<'a, B, Offsets>, Dynamic<'a, B, Offsets>,
                       Notes<'a, B>>,
               SectionHdrError<Offsets>> {
        match data {
            SectionHdrData::Null => Ok(SectionHdrData::Null),
            SectionHdrData::ProgBits { name, addr, align, alloc,
                                       write, exec, data } => {
                Ok(SectionHdrData::ProgBits {
                    name: name, addr: addr, align: align,  alloc: alloc,
                    write: write, exec: exec, data: data
                })
            },
            SectionHdrData::Symtab { name, local_end, addr, align, write,
                                     alloc, exec, strtab, syms } => {
                match (Symtab::try_from(syms), Strtab::try_from(strtab)) {
                    (Ok(syms), Ok(strtab)) =>
                        Ok(SectionHdrData::Symtab {
                            name: name, addr: addr, align: align, write: write,
                            strtab: strtab, exec: exec, local_end: local_end,
                            alloc: alloc, syms: syms
                        }),
                    (_, Err(err)) => Err(SectionHdrError::StrtabErr(err)),
                    (Err(err), _) => Err(SectionHdrError::SymtabErr(err))
                }
            },
            SectionHdrData::Strtab { name, addr, align, strs } => {
                match Strtab::try_from(strs) {
                    Ok(strs) =>
                        Ok(SectionHdrData::Strtab { name: name, addr: addr,
                                                    align: align, strs: strs }),
                    Err(err) => Err(SectionHdrError::StrtabErr(err))
                }
            },
            SectionHdrData::Rela { symtab: SymsStrs { syms, strs },
                                   name, addr, align, write, alloc,
                                   exec, target, relas } => {
                match (Relas::try_from(relas), Symtab::try_from(syms),
                       Strtab::try_from(strs)) {
                    (Ok(relas), Ok(syms), Ok(strs)) =>
                        Ok(SectionHdrData::Rela {
                            name: name, align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            symtab: SymsStrs { syms: syms, strs: strs },
                            target: target, relas: relas
                        }),
                    (Err(err), _, _) => Err(SectionHdrError::RelasErr(err)),
                    (_, Err(err), _) => Err(SectionHdrError::SymtabErr(err)),
                    (_, _, Err(err)) => Err(SectionHdrError::StrtabErr(err))
                }
            },
            SectionHdrData::Hash { name, addr, align, write, alloc, exec, hash,
                                   symtab: SymsStrs { syms, strs } } => {
                match (Symtab::try_from(syms), Strtab::try_from(strs)) {
                    (Ok(syms), Ok(strs)) =>
                        match Hashtab::from_slice(hash, strs, syms) {
                            Ok(hash) =>
                                Ok(SectionHdrData::Hash {
                                    name: name, addr: addr, align: align,
                                    write: write, exec: exec, alloc: alloc,
                                    symtab: SymsStrs { syms: syms, strs: strs },
                                    hash: hash
                                }),
                            Err(err) => Err(SectionHdrError::HashErr(err))
                        },
                    (Err(err), _) => Err(SectionHdrError::SymtabErr(err)),
                    (_, Err(err)) => Err(SectionHdrError::StrtabErr(err))
                }
            },
            SectionHdrData::Dynamic { name, align, addr, write, alloc,
                                      exec, strtab, dynamic } => {
                match (Dynamic::try_from(dynamic), Strtab::try_from(strtab)) {
                    (Ok(dynamic), Ok(strtab)) =>
                        Ok(SectionHdrData::Dynamic {
                            name: name, align: align, addr: addr, write: write,
                            alloc: alloc, exec: exec, strtab: strtab,
                            dynamic: dynamic,
                        }),
                    (Err(err), _) => Err(SectionHdrError::DynamicErr(err)),
                    (_, Err(err)) => Err(SectionHdrError::StrtabErr(err))
                }
            },
            SectionHdrData::Note { name, addr, align, write,
                                   alloc, exec, note } => {
                match Notes::try_from(note) {
                    Ok(note) =>
                        Ok(SectionHdrData::Note {
                            name: name, addr: addr, align: align, write: write,
                            alloc: alloc, exec: exec, note: note
                        }),
                    Err(err) => Err(SectionHdrError::NoteErr(err))
                }
            },
            SectionHdrData::Nobits { name, addr, align, offset, size,
                                     write, alloc, exec } => {
                Ok(SectionHdrData::Nobits {
                    name: name, addr: addr, size: size, offset: offset,
                    align: align, write: write, alloc: alloc, exec: exec
                })
            },
            SectionHdrData::Rel { symtab: SymsStrs { syms, strs },
                                  name, addr, align, write, alloc,
                                  exec, target, rels } => {
                match (Rels::try_from(rels), Symtab::try_from(syms),
                       Strtab::try_from(strs)) {
                    (Ok(rels), Ok(syms), Ok(strs)) =>
                        Ok(SectionHdrData::Rel {
                            name: name, align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            symtab: SymsStrs { syms: syms, strs: strs },
                            target: target, rels: rels
                        }),
                    (Err(err), _, _) => Err(SectionHdrError::RelsErr(err)),
                    (_, Err(err), _) => Err(SectionHdrError::SymtabErr(err)),
                    (_, _, Err(err)) => Err(SectionHdrError::StrtabErr(err))
                }
            },
            SectionHdrData::Dynsym { name, local_end, addr, align, write,
                                     alloc, exec, strtab, syms } => {
                match (Symtab::try_from(syms), Strtab::try_from(strtab)) {
                    (Ok(syms), Ok(strtab)) =>
                        Ok(SectionHdrData::Dynsym {
                            name: name, addr: addr, align: align, write: write,
                            strtab: strtab, exec: exec, local_end: local_end,
                            alloc: alloc, syms: syms
                        }),
                    (_, Err(err)) => Err(SectionHdrError::StrtabErr(err)),
                    (Err(err), _) => Err(SectionHdrError::SymtabErr(err))
                }
            },
            SectionHdrData::Unknown { name, tag, addr, align, offset, size,
                                      link, info, ent_size, flags } => {
                Ok(SectionHdrData::Unknown { name: name, tag: tag, addr: addr,
                                             align: align, offset: offset,
                                             size: size, link: link, info: info,
                                             ent_size: ent_size, flags: flags })
            }
        }
    }
}

impl<'a, Offsets, HdrRef, SymsRef, StrsRef, Data,
     Syms, Strs, Rels, Relas, Hash, Dynamic, Note> WithStrtab<'a>
    for SectionHdrData<Offsets, Offsets::Word, HdrRef, SymsRef,
                       StrsRef, Data, Syms, Strs, Rels, Relas, Hash,
                       Dynamic, Note>
    where Offsets: 'a + SectionHdrOffsets {
    type Result = SectionHdrData<Offsets, Result<&'a str, &'a [u8]>, HdrRef,
                                 SymsRef, StrsRef, Data, Syms, Strs, Rels,
                                 Relas, Hash, Dynamic, Note>;
    type Error = ();

    #[inline]
    fn with_strtab(self, tab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match self {
            SectionHdrData::Null => Ok(SectionHdrData::Null),
            SectionHdrData::ProgBits { name, addr, align, alloc,
                                       write, exec, data } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::ProgBits {
                            name: Ok(name), addr: addr, align: align,
                            alloc: alloc, write: write, exec: exec, data: data
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::ProgBits {
                            name: Err(name), addr: addr, align: align,
                            alloc: alloc, write: write, exec: exec, data: data
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Symtab { name, local_end, addr, align, write,
                                     alloc, exec, strtab, syms } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Symtab {
                            name: Ok(name), addr: addr, align: align,
                            write: write, strtab: strtab, exec: exec,
                            local_end: local_end, alloc: alloc, syms: syms
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Symtab {
                            name: Err(name), addr: addr, align: align,
                            write: write, strtab: strtab, exec: exec,
                            local_end: local_end, alloc: alloc, syms: syms
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Strtab { name, addr, align, strs } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Strtab { name: Ok(name), addr: addr,
                                                    align: align, strs: strs }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Strtab { name: Err(name), addr: addr,
                                                    align: align, strs: strs }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Rela { name, addr, align, write, alloc,
                                   exec, target, symtab, relas } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Rela {
                            name: Ok(name), align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            symtab: symtab, target: target, relas: relas
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Rela {
                            name: Err(name), align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            symtab: symtab, target: target, relas: relas
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Hash { name, addr, align, write, alloc, exec,
                                   hash, symtab } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Hash {
                            name: Ok(name), addr: addr, align: align,
                            write: write, exec: exec, alloc: alloc,
                            symtab: symtab, hash: hash
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Hash {
                            name: Err(name), addr: addr, align: align,
                            write: write, exec: exec, alloc: alloc,
                            symtab: symtab, hash: hash
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Dynamic { name, align, addr, write, alloc,
                                      exec, strtab, dynamic } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Dynamic {
                            name: Ok(name), align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            strtab: strtab, dynamic: dynamic,
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Dynamic {
                            name: Err(name), align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            strtab: strtab, dynamic: dynamic,
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Note { name, addr, align, write,
                                   alloc, exec, note } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Note {
                            name: Ok(name), addr: addr, align: align,
                            write: write, alloc: alloc, exec: exec, note: note
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Note {
                            name: Err(name), addr: addr, align: align,
                            write: write, alloc: alloc, exec: exec, note: note
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Nobits { name, addr, align, offset, size,
                                     write, alloc, exec } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Nobits {
                            name: Ok(name), addr: addr, size: size,
                            offset: offset, align: align, write: write,
                            alloc: alloc, exec: exec
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Nobits {
                            name: Err(name), addr: addr, size: size,
                            offset: offset, align: align, write: write,
                            alloc: alloc, exec: exec
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Rel { name, addr, align, write, alloc,
                                  exec, target, symtab, rels } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Rel {
                            name: Ok(name), align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            symtab: symtab, target: target, rels: rels
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Rel {
                            name: Err(name), align: align, addr: addr,
                            write: write, alloc: alloc, exec: exec,
                            symtab: symtab, target: target, rels: rels
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Dynsym { name, local_end, addr, align, write,
                                     alloc, exec, strtab, syms } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Dynsym {
                            name: Ok(name), addr: addr, align: align,
                            write: write, strtab: strtab, exec: exec,
                            local_end: local_end, alloc: alloc, syms: syms
                        }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Dynsym {
                            name: Err(name), addr: addr, align: align,
                            write: write, strtab: strtab, exec: exec,
                            local_end: local_end, alloc: alloc, syms: syms
                        }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            },
            SectionHdrData::Unknown { name, tag, addr, align, offset, size,
                                      link, info, ent_size, flags } => {
                match tab.idx(name) {
                    Ok(name) =>
                        Ok(SectionHdrData::Unknown {
                            name: Ok(name), tag: tag, addr: addr, align: align,
                            offset: offset, size: size, link: link, info: info,
                            ent_size: ent_size, flags: flags }),
                    Err(StrtabError::UTF8Decode(name)) =>
                        Ok(SectionHdrData::Unknown {
                            name: Err(name), tag: tag, addr: addr, align: align,
                            offset: offset, size: size, link: link, info: info,
                            ent_size: ent_size, flags: flags }),
                    Err(StrtabError::OutOfBounds) => Err(())
                }
            }
        }
    }
}


impl<'a, B, Offsets> TryFrom<SectionHdr<'a, B, Offsets>>
    for SectionHdrData<Offsets, Offsets::Word, Offsets::Word, Offsets::Word,
                       Offsets::Word, SectionPos<Offsets::Offset>,
                       SectionPos<Offsets::Offset>, SectionPos<Offsets::Offset>,
                       SectionPos<Offsets::Offset>, SectionPos<Offsets::Offset>,
                       SectionPos<Offsets::Offset>, SectionPos<Offsets::Offset>,
                       SectionPos<Offsets::Offset>>
    where Offsets: SectionHdrOffsets,
          B: ByteOrder {
    type Error = SectionHdrError<Offsets>;

    #[inline]
    fn try_from(ent: SectionHdr<'a, B, Offsets>) ->
        Result<SectionHdrData<Offsets, Offsets::Word, Offsets::Word,
                              Offsets::Word, Offsets::Word,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>>,
               SectionHdrError<Offsets>> {
        project(ent.ent, ent.byteorder, ent.offsets)
    }
}

impl<'a, B, Offsets> TryFrom<SectionHdrMut<'a, B, Offsets>>
    for SectionHdrData<Offsets, Offsets::Word, Offsets::Word, Offsets::Word,
                       Offsets::Word, SectionPos<Offsets::Offset>,
                       SectionPos<Offsets::Offset>, SectionPos<Offsets::Offset>,
                       SectionPos<Offsets::Offset>, SectionPos<Offsets::Offset>,
                       SectionPos<Offsets::Offset>, SectionPos<Offsets::Offset>,
                       SectionPos<Offsets::Offset>>
    where Offsets: SectionHdrOffsets,
          B: ByteOrder {
    type Error = SectionHdrError<Offsets>;

    #[inline]
    fn try_from(ent: SectionHdrMut<'a, B, Offsets>) ->
        Result<SectionHdrData<Offsets, Offsets::Word, Offsets::Word,
                              Offsets::Word, Offsets::Word,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>,
                              SectionPos<Offsets::Offset>>,
               SectionHdrError<Offsets>> {
        project(ent.ent, ent.byteorder, ent.offsets)
    }
}

impl<'a, B, Offsets: SectionHdrOffsets> Iterator
    for SectionHdrIter<'a, B, Offsets>
    where B: ByteOrder {
    type Item = SectionHdr<'a, B, Offsets>;

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.len();

        (size, Some(size))
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.nth(0)
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let len = self.hdrs.len();
        let start = (self.idx + n) * Offsets::SECTION_HDR_SIZE;

        if start < len {
            let end = start + Offsets::SECTION_HDR_SIZE;

            self.idx += n + 1;

            Some(SectionHdr { byteorder: PhantomData, offsets: PhantomData,
                              ent: &self.hdrs[start .. end ] })
        } else {
            None
        }
    }
}

impl<'a, B, Offsets: SectionHdrOffsets> FusedIterator
    for SectionHdrIter<'a, B, Offsets> where B: ByteOrder {}

impl<'a, B, Offsets: SectionHdrOffsets> ExactSizeIterator
    for SectionHdrIter<'a, B, Offsets>
    where B: ByteOrder {
    #[inline]
    fn len(&self) -> usize {
        self.hdrs.len() / Offsets::SECTION_HDR_SIZE
    }
}
