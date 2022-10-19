//! ELF program header functionality.
//!
//! This module provides a [ProgHdrs] type which acts as a wrapper
//! around ELF program header data.
//!
//! # Examples
//!
//! A `ProgHdrs` can be created from any slice containing binary data
//! that contains a properly-formatted ELF program header table:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf32;
//! use elf_utils::prog_hdr::ProgHdrs;
//! use elf_utils::prog_hdr::ProgHdrsError;
//!
//! const PROG_HDR: [u8; 192] = [
//!     0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
//!     0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
//!     0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0xbc, 0x46, 0x00, 0x00, 0xbc, 0x46, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0xc0, 0x46, 0x00, 0x00,
//!     0xc0, 0x56, 0x00, 0x00, 0xc0, 0x56, 0x00, 0x00,
//!     0x05, 0x4d, 0x01, 0x00, 0x05, 0x4d, 0x01, 0x00,
//!     0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0xc8, 0x93, 0x01, 0x00,
//!     0xc8, 0xb3, 0x01, 0x00, 0xc8, 0xb3, 0x01, 0x00,
//!     0x48, 0x03, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x10, 0x97, 0x01, 0x00,
//!     0x10, 0xc7, 0x01, 0x00, 0x10, 0xc7, 0x01, 0x00,
//!     0x64, 0x00, 0x00, 0x00, 0x68, 0x0b, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x28, 0x96, 0x01, 0x00,
//!     0x28, 0xb6, 0x01, 0x00, 0x28, 0xb6, 0x01, 0x00,
//!     0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
//! ];
//!
//! let hdrs: Result<ProgHdrs<'_, LittleEndian, Elf32>, ProgHdrsError> =
//!     ProgHdrs::try_from(&PROG_HDR[0..]);
//!
//! assert!(hdrs.is_ok());
//! ```
//!
//! Indexing into a `ProgHdrs` with [idx](ProgHdrs::idx) will give a
//! [ProgHdr], which is itself a handle on a single ELF program header:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf32;
//! use elf_utils::prog_hdr::ProgHdrs;
//!
//! const PROG_HDR: [u8; 192] = [
//!     0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
//!     0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
//!     0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0xbc, 0x46, 0x00, 0x00, 0xbc, 0x46, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0xc0, 0x46, 0x00, 0x00,
//!     0xc0, 0x56, 0x00, 0x00, 0xc0, 0x56, 0x00, 0x00,
//!     0x05, 0x4d, 0x01, 0x00, 0x05, 0x4d, 0x01, 0x00,
//!     0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0xc8, 0x93, 0x01, 0x00,
//!     0xc8, 0xb3, 0x01, 0x00, 0xc8, 0xb3, 0x01, 0x00,
//!     0x48, 0x03, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x10, 0x97, 0x01, 0x00,
//!     0x10, 0xc7, 0x01, 0x00, 0x10, 0xc7, 0x01, 0x00,
//!     0x64, 0x00, 0x00, 0x00, 0x68, 0x0b, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x28, 0x96, 0x01, 0x00,
//!     0x28, 0xb6, 0x01, 0x00, 0x28, 0xb6, 0x01, 0x00,
//!     0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
//! ];
//!
//! let hdrs: ProgHdrs<'_, LittleEndian, Elf32> =
//!     ProgHdrs::try_from(&PROG_HDR[0..]).unwrap();
//!
//! assert!(hdrs.idx(0).is_some());
//! assert!(hdrs.idx(6).is_none());
//! ```
//!
//! A [ProgHdr] can be projected to a [ProgHdrData] with the
//! [TryFrom](core::convert::TryFrom) instance:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use core::convert::TryInto;
//! use elf_utils::Elf32;
//! use elf_utils::prog_hdr::ProgHdrs;
//! use elf_utils::prog_hdr::ProgHdrData;
//! use elf_utils::prog_hdr::ProgHdrDataRaw;
//! use elf_utils::prog_hdr::Segment;
//!
//! const PROG_HDR: [u8; 192] = [
//!     0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
//!     0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
//!     0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0xbc, 0x46, 0x00, 0x00, 0xbc, 0x46, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0xc0, 0x46, 0x00, 0x00,
//!     0xc0, 0x56, 0x00, 0x00, 0xc0, 0x56, 0x00, 0x00,
//!     0x05, 0x4d, 0x01, 0x00, 0x05, 0x4d, 0x01, 0x00,
//!     0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0xc8, 0x93, 0x01, 0x00,
//!     0xc8, 0xb3, 0x01, 0x00, 0xc8, 0xb3, 0x01, 0x00,
//!     0x48, 0x03, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x10, 0x97, 0x01, 0x00,
//!     0x10, 0xc7, 0x01, 0x00, 0x10, 0xc7, 0x01, 0x00,
//!     0x64, 0x00, 0x00, 0x00, 0x68, 0x0b, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x28, 0x96, 0x01, 0x00,
//!     0x28, 0xb6, 0x01, 0x00, 0x28, 0xb6, 0x01, 0x00,
//!     0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
//! ];
//!
//! let hdrs: ProgHdrs<'_, LittleEndian, Elf32> =
//!     ProgHdrs::try_from(&PROG_HDR[0..]).unwrap();
//! let ent = hdrs.idx(1).unwrap();
//! let data: ProgHdrDataRaw<Elf32> = ent.try_into().unwrap();
//!
//! assert_eq!(data, ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
//!                                      mem_size: 0x46bc, align: 0x1000,
//!                                      read: true, write: false, exec: false,
//!                                      content: Segment { offset: 0,
//!                                                         size: 0x46bc } });
//! ```
use byteorder::ByteOrder;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::LowerHex;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use core::str::from_utf8;
use crate::dynamic::Dynamic;
use crate::dynamic::DynamicError;
use crate::dynamic::DynamicOffsets;
use crate::elf::ElfClass;
use crate::elf::Elf32;
use crate::elf::Elf64;
use crate::elf::WithElfData;

/// Offsets for ELF program headers.
///
/// This contains the various offsets for fields in an ELF program
/// header table entry for a given ELF class.
pub trait ProgHdrOffsets: ElfClass {
    /// Start of the ELF program header type tag field.
    const P_KIND_START: usize = 0;
    /// Size of the ELF program header type tag field.
    const P_KIND_SIZE: usize = Self::WORD_SIZE;
    /// End of the ELF program header type tag field.
    const P_KIND_END: usize = Self::P_KIND_START + Self::P_KIND_SIZE;

    /// Start of the ELF program header offset field.
    const P_OFFSET_START: usize;
    /// Size of the ELF program header offset field.
    const P_OFFSET_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF program header offset field.
    const P_OFFSET_END: usize = Self::P_OFFSET_START + Self::P_OFFSET_SIZE;

    /// Start of the ELF program header virtual address field.
    const P_VADDR_START: usize;
    /// Size of the ELF program header virtual address field.
    const P_VADDR_SIZE: usize = Self::ADDR_SIZE;
    /// End of the ELF program header virtual address field.
    const P_VADDR_END: usize = Self::P_VADDR_START + Self::P_VADDR_SIZE;

    /// Start of the ELF program header physical address field.
    const P_PADDR_START: usize;
    /// Size of the ELF program header physical address field.
    const P_PADDR_SIZE: usize = Self::ADDR_SIZE;
    /// End of the ELF program header physical address field.
    const P_PADDR_END: usize = Self::P_PADDR_START + Self::P_PADDR_SIZE;

    /// Start of the ELF program header file size field.
    const P_FILE_SIZE_START: usize;
    /// Size of the ELF program header file size field.
    const P_FILE_SIZE_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF program header file size field.
    const P_FILE_SIZE_END: usize = Self::P_FILE_SIZE_START +
                                   Self::P_FILE_SIZE_SIZE;

    /// Start of the ELF program header memory size field.
    const P_MEM_SIZE_START: usize;
    /// Size of the ELF program header memory size field.
    const P_MEM_SIZE_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF program header memory size field.
    const P_MEM_SIZE_END: usize = Self::P_MEM_SIZE_START +
                                  Self::P_MEM_SIZE_SIZE;

    /// Start of the ELF program header flags field.
    const P_FLAGS_START: usize;
    /// Size of the ELF program header flags field.
    const P_FLAGS_SIZE: usize = Self::WORD_SIZE;
    /// End of the ELF program header flags field.
    const P_FLAGS_END: usize = Self::P_FLAGS_START + Self::P_FLAGS_SIZE;

    /// Start of the ELF program header align field.
    const P_ALIGN_START: usize;
    /// Size of the ELF program header align field.
    const P_ALIGN_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF program header align field.
    const P_ALIGN_END: usize = Self::P_ALIGN_START + Self::P_ALIGN_SIZE;

    /// Size of a program header.
    const PROG_HDR_SIZE: usize = Self::P_ALIGN_END;
    /// Size of a program header as an offset.
    const PROG_HDR_SIZE_HALF: Self::Half;
    /// Size of a program header as an offset.
    const PROG_HDR_SIZE_OFFSET: Self::Offset;
}

/// In-place read-only ELF program header table.
///
/// An ELF program header table is an array of data objects that
/// provide information for creating a running executable instance
/// from ELF data.  Program header tables are typically only found in
/// executable files.
///
/// A `ProgHdrs` is essentially a 'handle' for raw ELF data.  It can be
/// used to convert an index into a [ProgHdr] using the
/// [idx](ProgHdrs::idx) function, or iterated over with
/// [iter](ProgHdrs::iter).
///
/// A `ProgHdrs` can be created from raw data using the [TryFrom]
/// instance.
///
/// New `ProgHdrs` can be created from an iterator over
/// [ProgHdrData] with [create](ProgHdrs::create) or
/// [create_split](ProgHdrs::create_split).
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
/// use elf_utils::prog_hdr::ProgHdrs;
/// use elf_utils::prog_hdr::ProgHdrData;
/// use elf_utils::prog_hdr::ProgHdrDataRaw;
/// use elf_utils::prog_hdr::Segment;
///
/// const PROG_HDR: [u8; 192] = [
///     0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
///     0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
///     0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0xbc, 0x46, 0x00, 0x00, 0xbc, 0x46, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0xc0, 0x46, 0x00, 0x00,
///     0xc0, 0x56, 0x00, 0x00, 0xc0, 0x56, 0x00, 0x00,
///     0x05, 0x4d, 0x01, 0x00, 0x05, 0x4d, 0x01, 0x00,
///     0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0xc8, 0x93, 0x01, 0x00,
///     0xc8, 0xb3, 0x01, 0x00, 0xc8, 0xb3, 0x01, 0x00,
///     0x48, 0x03, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x10, 0x97, 0x01, 0x00,
///     0x10, 0xc7, 0x01, 0x00, 0x10, 0xc7, 0x01, 0x00,
///     0x64, 0x00, 0x00, 0x00, 0x68, 0x0b, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x28, 0x96, 0x01, 0x00,
///     0x28, 0xb6, 0x01, 0x00, 0x28, 0xb6, 0x01, 0x00,
///     0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
/// ];
///
/// const PROG_HDR_CONTENTS: [ProgHdrDataRaw<Elf32>; 6] = [
///     ProgHdrData::ProgHdr { virt_addr: 0x34, phys_addr: 0x34,
///                            content: Segment { offset: 0x34, size: 0x140 } },
///     ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
///                         mem_size: 0x46bc, align: 0x1000,
///                         read: true, write: false, exec: false,
///                         content: Segment { offset: 0, size: 0x46bc } },
///     ProgHdrData::Load { virt_addr: 0x56c0, phys_addr: 0x56c0,
///                         mem_size: 0x14d05, align: 0x1000,
///                         read: true, write: false, exec: true,
///                         content: Segment { offset: 0x46c0,
///                                            size: 0x14d05 } },
///     ProgHdrData::Load { virt_addr: 0x1b3c8, phys_addr: 0x1b3c8,
///                         mem_size: 0x348, align: 4096,
///                         read: true, write: true, exec: false,
///                         content: Segment { offset: 0x193c8, size: 0x348 } },
///     ProgHdrData::Load { virt_addr: 0x1c710, phys_addr: 0x1c710,
///                         mem_size: 0xb68, align: 4096,
///                         read: true, write: true, exec: false,
///                         content: Segment { offset: 0x19710, size: 0x64 } },
///     ProgHdrData::Dynamic { virt_addr: 0x1b628, phys_addr: 0x1b628,
///                            content: Segment { offset: 0x19628,
///                                               size: 0x88 } }
/// ];
///
/// let hdrs: ProgHdrs<'_, LittleEndian, Elf32> =
///     ProgHdrs::try_from(&PROG_HDR[0..]).unwrap();
///
/// for i in 0 .. 6 {
///     let ent = hdrs.idx(i).unwrap();
///     let data: ProgHdrDataRaw<Elf32> = ent.try_into().unwrap();
///
///     assert_eq!(data, PROG_HDR_CONTENTS[i]);
/// }
/// ```
#[derive(Copy, Clone)]
pub struct ProgHdrs<'a, B, Offsets: ProgHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    hdrs: &'a [u8]
}

/// In-place read-only ELF program header table entry.
///
/// An ELF program header table entry is a union of many different
/// kinds of information.  See [ProgHdrData] for more information.
///
/// A `ProgHdr` is essentially a 'handle' for raw ELF data.  Note that
/// this data may not be in host byte order, and may not even have the
/// same word size.  In order to directly manipulate the program
/// header data, it must be projected into a [ProgHdrData] using the
/// [TryFrom](core::convert::TryFrom) instance in order to access the
/// program header table entry's information directly.
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
/// use elf_utils::prog_hdr::ProgHdrs;
/// use elf_utils::prog_hdr::ProgHdrData;
/// use elf_utils::prog_hdr::ProgHdrDataRaw;
/// use elf_utils::prog_hdr::Segment;
///
/// const PROG_HDR: [u8; 192] = [
///     0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
///     0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
///     0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0xbc, 0x46, 0x00, 0x00, 0xbc, 0x46, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0xc0, 0x46, 0x00, 0x00,
///     0xc0, 0x56, 0x00, 0x00, 0xc0, 0x56, 0x00, 0x00,
///     0x05, 0x4d, 0x01, 0x00, 0x05, 0x4d, 0x01, 0x00,
///     0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0xc8, 0x93, 0x01, 0x00,
///     0xc8, 0xb3, 0x01, 0x00, 0xc8, 0xb3, 0x01, 0x00,
///     0x48, 0x03, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x10, 0x97, 0x01, 0x00,
///     0x10, 0xc7, 0x01, 0x00, 0x10, 0xc7, 0x01, 0x00,
///     0x64, 0x00, 0x00, 0x00, 0x68, 0x0b, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x28, 0x96, 0x01, 0x00,
///     0x28, 0xb6, 0x01, 0x00, 0x28, 0xb6, 0x01, 0x00,
///     0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
/// ];
///
/// let hdrs: ProgHdrs<'_, LittleEndian, Elf32> =
///     ProgHdrs::try_from(&PROG_HDR[0..]).unwrap();
/// let ent = hdrs.idx(1).unwrap();
/// let data: ProgHdrDataRaw<Elf32> = ent.try_into().unwrap();
///
/// assert_eq!(data, ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
///                                      mem_size: 0x46bc, align: 0x1000,
///                                      read: true, write: false, exec: false,
///                                      content: Segment { offset: 0,
///                                                         size: 0x46bc } });
/// ```
#[derive(Copy, Clone)]
pub struct ProgHdr<'a, B: ByteOrder, Offsets: ProgHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    ent: &'a [u8]
}

pub struct ProgHdrMut<'a, B: ByteOrder, Offsets: ProgHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    ent: &'a mut [u8]
}

/// Iterator for [ProgHdrs].
///
/// This iterator produces [ProgHdr]s referenceding the program header
/// table entries defined in an underlying `ProgHdrs`.
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
/// use elf_utils::prog_hdr::ProgHdrs;
/// use elf_utils::prog_hdr::ProgHdrData;
/// use elf_utils::prog_hdr::ProgHdrDataRaw;
/// use elf_utils::prog_hdr::Segment;
///
/// const PROG_HDR: [u8; 192] = [
///     0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
///     0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
///     0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0xbc, 0x46, 0x00, 0x00, 0xbc, 0x46, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0xc0, 0x46, 0x00, 0x00,
///     0xc0, 0x56, 0x00, 0x00, 0xc0, 0x56, 0x00, 0x00,
///     0x05, 0x4d, 0x01, 0x00, 0x05, 0x4d, 0x01, 0x00,
///     0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0xc8, 0x93, 0x01, 0x00,
///     0xc8, 0xb3, 0x01, 0x00, 0xc8, 0xb3, 0x01, 0x00,
///     0x48, 0x03, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x10, 0x97, 0x01, 0x00,
///     0x10, 0xc7, 0x01, 0x00, 0x10, 0xc7, 0x01, 0x00,
///     0x64, 0x00, 0x00, 0x00, 0x68, 0x0b, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x28, 0x96, 0x01, 0x00,
///     0x28, 0xb6, 0x01, 0x00, 0x28, 0xb6, 0x01, 0x00,
///     0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
/// ];
///
/// const PROG_HDR_CONTENTS: [ProgHdrDataRaw<Elf32>; 6] = [
///     ProgHdrData::ProgHdr { virt_addr: 0x34, phys_addr: 0x34,
///                            content: Segment { offset: 0x34, size: 0x140 } },
///     ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
///                         mem_size: 0x46bc, align: 0x1000,
///                         read: true, write: false, exec: false,
///                         content: Segment { offset: 0, size: 0x46bc } },
///     ProgHdrData::Load { virt_addr: 0x56c0, phys_addr: 0x56c0,
///                         mem_size: 0x14d05, align: 0x1000,
///                         read: true, write: false, exec: true,
///                         content: Segment { offset: 0x46c0,
///                                            size: 0x14d05 } },
///     ProgHdrData::Load { virt_addr: 0x1b3c8, phys_addr: 0x1b3c8,
///                         mem_size: 0x348, align: 4096,
///                         read: true, write: true, exec: false,
///                         content: Segment { offset: 0x193c8, size: 0x348 } },
///     ProgHdrData::Load { virt_addr: 0x1c710, phys_addr: 0x1c710,
///                         mem_size: 0xb68, align: 4096,
///                         read: true, write: true, exec: false,
///                         content: Segment { offset: 0x19710, size: 0x64 } },
///     ProgHdrData::Dynamic { virt_addr: 0x1b628, phys_addr: 0x1b628,
///                            content: Segment { offset: 0x19628,
///                                               size: 0x88 } }
/// ];
///
/// let hdrs: ProgHdrs<'_, LittleEndian, Elf32> =
///     ProgHdrs::try_from(&PROG_HDR[0..]).unwrap();
/// let mut iter = hdrs.iter();
///
/// for i in 0 .. 6 {
///     let ent = iter.next().unwrap();
///     let data: ProgHdrDataRaw<Elf32> = ent.try_into().unwrap();
///
///     assert_eq!(data, PROG_HDR_CONTENTS[i]);
/// }
/// ```
#[derive(Clone)]
pub struct ProgHdrIter<'a, B: ByteOrder, Offsets: ProgHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    hdrs: &'a [u8],
    idx: usize
}

/// Errors that can occur creating a [ProgHdrs].
///
/// The only error that can occur is if the data is not a multiple of
/// the size of a program header.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProgHdrsError {
    BadSize(usize)
}

/// Projected ELF program header data.
///
/// This is a representation of an ELF program header table entry
/// projected into a form that can be directly manipulated.  This data
/// can also be used to create a new [ProgHdrs] using
/// [create](ProgHdrs::create) or
/// [create_split](ProgHdrs::create_split).
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProgHdrData<Offsets: ElfClass, Data, Str, Dyn> {
    /// Null program header.
    Null,
    /// Loadable segment.
    ///
    /// This indicates data that should be loaded into memory at a
    /// particular address to create an executable image.  This
    /// frequently overlaps with other program header segments.
    Load {
        /// Runtime virtual address.
        virt_addr: Offsets::Addr,
        /// Runtime physical address.
        phys_addr: Offsets::Addr,
        /// Memory size (may be larger than the actual data).
        mem_size: Offsets::Offset,
        /// Memory alignment.
        align: Offsets::Offset,
        /// Whether the segment has read permissions.
        read: bool,
        /// Whether the segment has write permissions.
        write: bool,
        /// Whether the segment has execute permissions.
        exec: bool,
        /// Content from the file.
        content: Data
    },
    /// Dynamic linking information.
    ///
    /// This provides the virtual address and file location of the
    /// dynamic linking table.
    Dynamic {
        /// Runtime virtual address.
        virt_addr: Offsets::Addr,
        /// Runtime physical address.
        phys_addr: Offsets::Addr,
        /// Content from the file.
        content: Dyn
    },
    /// Location and size of a null-terminated string to invoke as an
    /// interpreter.
    ///
    /// This is typically a shared object whose purpose is to locate,
    /// load, and link dynamic libraries.
    Interp {
        /// Runtime virtual address.
        virt_addr: Offsets::Addr,
        /// Runtime physical address.
        phys_addr: Offsets::Addr,
        /// Content from the file.
        str: Str
    },
    /// Location of auxillary information.
    Note {
        /// Runtime virtual address.
        virt_addr: Offsets::Addr,
        /// Runtime physical address.
        phys_addr: Offsets::Addr,
        /// Content from the file.
        content: Data
    },
    /// Reserved for shared libraries.
    Shlib,
    /// Location and size of the program header table itself.
    ProgHdr {
        /// Runtime virtual address.
        virt_addr: Offsets::Addr,
        /// Runtime physical address.
        phys_addr: Offsets::Addr,
        /// Content from the file.
        content: Data
    },
    /// Unknown program header type.
    Unknown {
        /// Type tag.
        tag: Offsets::Word,
        /// Flags, including access.
        flags: Offsets::Word,
        /// Offset in the ELF data at which this occurs.
        offset: Offsets::Offset,
        /// Size of the representation in the ELF data.
        file_size: Offsets::Offset,
        /// Size of the representation in memory.
        mem_size: Offsets::Offset,
        /// Runtime physical address.
        phys_addr: Offsets::Addr,
        /// Runtime virtual address;
        virt_addr: Offsets::Addr,
        /// Alignment of data at runtime.
        align: Offsets::Offset
    }
}

/// Type alias for [ProgHdrData] as projected from a [ProgHdr].
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [ProgHdr].  This is also used in [ProgHdrs::create] and
/// [ProgHdrs::create_split].
pub type ProgHdrDataRaw<Class> =
    ProgHdrData<Class, Segment<<Class as ElfClass>::Offset>,
                Segment<<Class as ElfClass>::Offset>,
                Segment<<Class as ElfClass>::Offset>>;

/// Type alias for [ProgHdrData] with `&[u8]` buffers for all
/// segments.
///
/// This is produced from a [ProgHdrDataRaw] using the [WithElfData]
/// instance.
pub type ProgHdrDataBufs<'a, Class> =
    ProgHdrData<Class, &'a [u8], &'a [u8], &'a [u8]>;

/// Type alias for [ProgHdrData] with `&str` representing the
/// interpreter name.
///
/// This is obtained from the use of a [TryFrom] instance operating on
/// a [ProgHdrDataBufs].
pub type ProgHdrDataStr<'a, Class> =
    ProgHdrData<Class, &'a [u8], &'a [u8], &'a [u8]>;

/// Type alias for [ProgHdrData] with dynamic linking data represented
/// as a [Dynamic](crate::dynamic::Dynamic).
///
/// This is obtained from the use of a [TryFrom] instance operating on
/// a [ProgHdrDataBufs].
pub type ProgHdrDataDyn<'a, B, Offsets> =
    ProgHdrData<Offsets, &'a [u8], &'a str, Dynamic<'a, B, Offsets>>;

/// Type alias for [ProgHdrData] fully interpreted.
///
/// This is obtained from the use of [TryFrom] instances operating on
/// [ProgHdrDataBufs].
pub type ProgHdrDataFull<'a, B, Offsets> =
    ProgHdrData<Offsets, &'a [u8], &'a str, Dynamic<'a, B, Offsets>>;

/// Errors that can occur when projecting a [ProgHdr] to a [ProgHdrData].
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProgHdrError<Offsets: ProgHdrOffsets> {
    /// Segment data is out of bounds.
    DataOutOfBounds {
        /// The offset of the data.
        offset: Offsets::Offset,
        /// The size of the data.
        size: Offsets::Offset
    },
    /// A program header index is out of bounds.
    EntryOutOfBounds {
        /// The bad index.
        idx: Offsets::Word
    }
}

/// Offset and size of segment data.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct Segment<Word> {
    /// Offset into the ELF data of the start of the segment.
    pub offset: Word,
    /// Size of the segment in bytes.
    pub size: Word
}

#[inline]
fn project<'a, B, Offsets>(ent: &'a [u8]) -> Result<ProgHdrDataRaw<Offsets>,
                                                    ProgHdrError<Offsets>>
    where Offsets: ProgHdrOffsets,
          B: ByteOrder {
    let kind = Offsets::read_word::<B>(&ent[Offsets::P_KIND_START ..
                                            Offsets::P_KIND_END]);

    match kind.into() {
        0 => Ok(ProgHdrData::Null),
        1 => {
            let offset = Offsets::read_offset::<B>(
                &ent[Offsets::P_OFFSET_START .. Offsets::P_OFFSET_END]
            );
            let size = Offsets::read_offset::<B>(
                &ent[Offsets::P_FILE_SIZE_START .. Offsets::P_FILE_SIZE_END]
            );
            let virt_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_VADDR_START .. Offsets::P_VADDR_END]
            );
            let phys_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_PADDR_START .. Offsets::P_PADDR_END]
            );
            let mem_size = Offsets::read_offset::<B>(
                &ent[Offsets::P_MEM_SIZE_START .. Offsets::P_MEM_SIZE_END]
            );
            let align = Offsets::read_offset::<B>(&ent[Offsets::P_ALIGN_START ..
                                                       Offsets::P_ALIGN_END]);
            let flags = Offsets::read_word::<B>(&ent[Offsets::P_FLAGS_START ..
                                                     Offsets::P_FLAGS_END]);
            let pos = Segment { offset: offset, size: size };

            Ok(ProgHdrData::Load {
                align: align, mem_size: mem_size, content: pos,
                virt_addr: virt_addr, phys_addr: phys_addr,
                read: flags & (0x4 as u8).into() == (0x4 as u8).into(),
                write: flags & (0x2 as u8).into() == (0x2 as u8).into(),
                exec: flags & (0x1 as u8).into() == (0x1 as u8).into()
            })
        },
        2 => {
            let offset = Offsets::read_offset::<B>(
                &ent[Offsets::P_OFFSET_START .. Offsets::P_OFFSET_END]
            );
            let size = Offsets::read_offset::<B>(
                &ent[Offsets::P_FILE_SIZE_START .. Offsets::P_FILE_SIZE_END]
            );
            let virt_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_VADDR_START .. Offsets::P_VADDR_END]
            );
            let phys_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_PADDR_START .. Offsets::P_PADDR_END]
            );
            let pos = Segment { offset: offset, size: size };

            Ok(ProgHdrData::Dynamic { virt_addr: virt_addr,
                                      phys_addr: phys_addr,
                                      content: pos })
        },
        3 => {
            let offset = Offsets::read_offset::<B>(
                &ent[Offsets::P_OFFSET_START .. Offsets::P_OFFSET_END]
            );
            let size = Offsets::read_offset::<B>(
                &ent[Offsets::P_FILE_SIZE_START .. Offsets::P_FILE_SIZE_END]
            );
            let virt_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_VADDR_START .. Offsets::P_VADDR_END]
            );
            let phys_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_PADDR_START .. Offsets::P_PADDR_END]
            );
            let pos = Segment { offset: offset, size: size };

            Ok(ProgHdrData::Interp { virt_addr: virt_addr, phys_addr: phys_addr,
                                     str: pos })
        },
        4 => {
            let offset = Offsets::read_offset::<B>(
                &ent[Offsets::P_OFFSET_START .. Offsets::P_OFFSET_END]
            );
            let size = Offsets::read_offset::<B>(
                &ent[Offsets::P_FILE_SIZE_START .. Offsets::P_FILE_SIZE_END]
            );
            let virt_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_VADDR_START .. Offsets::P_VADDR_END]
            );
            let phys_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_PADDR_START .. Offsets::P_PADDR_END]
            );
            let pos = Segment { offset: offset, size: size };

            Ok(ProgHdrData::Note { virt_addr: virt_addr, phys_addr: phys_addr,
                                   content: pos })
        },
        6 => {
            let offset = Offsets::read_offset::<B>(
                &ent[Offsets::P_OFFSET_START .. Offsets::P_OFFSET_END]
            );
            let size = Offsets::read_offset::<B>(
                &ent[Offsets::P_FILE_SIZE_START .. Offsets::P_FILE_SIZE_END]
            );
            let virt_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_VADDR_START .. Offsets::P_VADDR_END]
            );
            let phys_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_PADDR_START .. Offsets::P_PADDR_END]
            );
            let pos = Segment { offset: offset, size: size };

            Ok(ProgHdrData::ProgHdr { virt_addr: virt_addr,
                                      phys_addr: phys_addr,
                                      content: pos })
        },
        _ => {
            let offset = Offsets::read_offset::<B>(
                &ent[Offsets::P_OFFSET_START .. Offsets::P_OFFSET_END]
            );
            let size = Offsets::read_offset::<B>(
                &ent[Offsets::P_FILE_SIZE_START .. Offsets::P_FILE_SIZE_END]
            );
            let virt_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_VADDR_START .. Offsets::P_VADDR_END]
            );
            let phys_addr = Offsets::read_addr::<B>(
                &ent[Offsets::P_PADDR_START .. Offsets::P_PADDR_END]
            );
            let mem_size = Offsets::read_offset::<B>(
               &ent[Offsets::P_MEM_SIZE_START .. Offsets::P_MEM_SIZE_END]
            );
            let align = Offsets::read_offset::<B>(&ent[Offsets::P_ALIGN_START ..
                                                       Offsets::P_ALIGN_END]);
            let flags = Offsets::read_word::<B>(&ent[Offsets::P_FLAGS_START ..
                                                     Offsets::P_FLAGS_END]);

            Ok(ProgHdrData::Unknown {
                tag: kind, flags: flags, offset: offset, align: align,
                virt_addr: virt_addr, phys_addr: phys_addr,
                file_size: size, mem_size: mem_size,
            })
        }
    }
}

fn create<'a, B, I, Offsets>(buf: &'a mut [u8], ents: I) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where I: Iterator<Item = ProgHdrDataRaw<Offsets>>,
          Offsets: ProgHdrOffsets,
          B: ByteOrder {
    let len = buf.len();
    let mut idx = 0;

    for ent in ents {
        if idx + Offsets::PROG_HDR_SIZE <= len {
            let data = &mut buf[idx .. idx + Offsets::PROG_HDR_SIZE];

            match ent {
                ProgHdrData::Null => {
                    Offsets::write_word::<B>(&mut data[Offsets::P_KIND_START ..
                                                       Offsets::P_KIND_END],
                                             (0 as u8).into());
                    Offsets::write_word::<B>(&mut data[Offsets::P_FLAGS_START ..
                                                       Offsets::P_FLAGS_END],
                                             (0 as u8).into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_OFFSET_START ..
                                  Offsets::P_OFFSET_END],
                        (0 as u8).into()
                    );
                    Offsets::write_addr::<B>(&mut data[Offsets::P_VADDR_START ..
                                                       Offsets::P_VADDR_END],
                                             (0 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::P_PADDR_START ..
                                                       Offsets::P_PADDR_END],
                                             (0 as u8).into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_FILE_SIZE_START ..
                                  Offsets::P_FILE_SIZE_END],
                        (0 as u8).into()
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_MEM_SIZE_START ..
                                  Offsets::P_MEM_SIZE_END],
                        (0 as u8).into()
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_ALIGN_START ..
                                  Offsets::P_ALIGN_END],
                        (0 as u8).into()
                    );
                },
                ProgHdrData::Load { virt_addr, phys_addr, mem_size,
                                    align, read, write, exec, content } => {
                    let flags: u8 = if read { 0x4 } else { 0 } |
                                    if write { 0x2 } else { 0 } |
                                    if exec { 0x1 } else { 0 };

                    Offsets::write_word::<B>(&mut data[Offsets::P_KIND_START ..
                                                       Offsets::P_KIND_END],
                                             (1 as u8).into());
                    Offsets::write_word::<B>(&mut data[Offsets::P_FLAGS_START ..
                                                       Offsets::P_FLAGS_END],
                                             flags.into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_OFFSET_START ..
                                  Offsets::P_OFFSET_END],
                        content.offset
                    );
                    Offsets::write_addr::<B>(&mut data[Offsets::P_VADDR_START ..
                                                       Offsets::P_VADDR_END],
                                             virt_addr);
                    Offsets::write_addr::<B>(&mut data[Offsets::P_PADDR_START ..
                                                       Offsets::P_PADDR_END],
                                             phys_addr);
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_FILE_SIZE_START ..
                                  Offsets::P_FILE_SIZE_END],
                        content.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_MEM_SIZE_START ..
                                  Offsets::P_MEM_SIZE_END],
                        mem_size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_ALIGN_START ..
                                  Offsets::P_ALIGN_END],
                        align
                    );
                },
                ProgHdrData::Dynamic { virt_addr, phys_addr, content } => {
                    let flags: u8 = 0x6;

                    Offsets::write_word::<B>(&mut data[Offsets::P_KIND_START ..
                                                       Offsets::P_KIND_END],
                                             (2 as u8).into());
                    Offsets::write_word::<B>(&mut data[Offsets::P_FLAGS_START ..
                                                       Offsets::P_FLAGS_END],
                                             flags.into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_OFFSET_START ..
                                  Offsets::P_OFFSET_END],
                        content.offset
                    );
                    Offsets::write_addr::<B>(&mut data[Offsets::P_VADDR_START ..
                                                       Offsets::P_VADDR_END],
                                             virt_addr);
                    Offsets::write_addr::<B>(&mut data[Offsets::P_PADDR_START ..
                                                       Offsets::P_PADDR_END],
                                             phys_addr);
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_FILE_SIZE_START ..
                                  Offsets::P_FILE_SIZE_END],
                        content.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_MEM_SIZE_START ..
                                  Offsets::P_MEM_SIZE_END],
                        content.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_ALIGN_START ..
                                  Offsets::P_ALIGN_END],
                        Offsets::OFFSET_ALIGN
                    );
                },
                ProgHdrData::Interp { virt_addr, phys_addr, str } => {
                    let flags: u8 = 0x4;

                    Offsets::write_word::<B>(&mut data[Offsets::P_KIND_START ..
                                                       Offsets::P_KIND_END],
                                             (3 as u8).into());
                    Offsets::write_word::<B>(&mut data[Offsets::P_FLAGS_START ..
                                                       Offsets::P_FLAGS_END],
                                             flags.into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_OFFSET_START ..
                                  Offsets::P_OFFSET_END],
                        str.offset
                    );
                    Offsets::write_addr::<B>(&mut data[Offsets::P_VADDR_START ..
                                                       Offsets::P_VADDR_END],
                                             virt_addr);
                    Offsets::write_addr::<B>(&mut data[Offsets::P_PADDR_START ..
                                                       Offsets::P_PADDR_END],
                                             phys_addr);
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_FILE_SIZE_START ..
                                  Offsets::P_FILE_SIZE_END],
                        str.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_MEM_SIZE_START ..
                                  Offsets::P_MEM_SIZE_END],
                        str.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_ALIGN_START ..
                                  Offsets::P_ALIGN_END],
                        (1 as u8).into()
                    );
                },
                ProgHdrData::Note { virt_addr, phys_addr, content } => {
                    let flags: u8 = 0x4;

                    Offsets::write_word::<B>(&mut data[Offsets::P_KIND_START ..
                                                       Offsets::P_KIND_END],
                                             (4 as u8).into());
                    Offsets::write_word::<B>(&mut data[Offsets::P_FLAGS_START ..
                                                       Offsets::P_FLAGS_END],
                                             flags.into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_OFFSET_START ..
                                  Offsets::P_OFFSET_END],
                        content.offset
                    );
                    Offsets::write_addr::<B>(&mut data[Offsets::P_VADDR_START ..
                                                       Offsets::P_VADDR_END],
                                             virt_addr);
                    Offsets::write_addr::<B>(&mut data[Offsets::P_PADDR_START ..
                                                       Offsets::P_PADDR_END],
                                             phys_addr);
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_FILE_SIZE_START ..
                                  Offsets::P_FILE_SIZE_END],
                        content.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_MEM_SIZE_START ..
                                  Offsets::P_MEM_SIZE_END],
                        content.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_ALIGN_START ..
                                  Offsets::P_ALIGN_END],
                        Offsets::WORD_ALIGN
                    );
                },
                ProgHdrData::Shlib => {
                    Offsets::write_word::<B>(&mut data[Offsets::P_KIND_START ..
                                                       Offsets::P_KIND_END],
                                             (5 as u8).into());
                    Offsets::write_word::<B>(&mut data[Offsets::P_FLAGS_START ..
                                                       Offsets::P_FLAGS_END],
                                             (0 as u8).into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_OFFSET_START ..
                                  Offsets::P_OFFSET_END],
                        (0 as u8).into()
                    );
                    Offsets::write_addr::<B>(&mut data[Offsets::P_VADDR_START ..
                                                       Offsets::P_VADDR_END],
                                             (0 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::P_PADDR_START ..
                                                       Offsets::P_PADDR_END],
                                             (0 as u8).into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_FILE_SIZE_START ..
                                  Offsets::P_FILE_SIZE_END],
                        (0 as u8).into()
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_MEM_SIZE_START ..
                                  Offsets::P_MEM_SIZE_END],
                        (0 as u8).into()
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_ALIGN_START ..
                                  Offsets::P_ALIGN_END],
                        (0 as u8).into()
                    );
                },
                ProgHdrData::ProgHdr { virt_addr, phys_addr, content } => {
                    let flags: u8 = 0x4;

                    Offsets::write_word::<B>(&mut data[Offsets::P_KIND_START ..
                                                       Offsets::P_KIND_END],
                                             (6 as u8).into());
                    Offsets::write_word::<B>(&mut data[Offsets::P_FLAGS_START ..
                                                       Offsets::P_FLAGS_END],
                                             flags.into());
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_OFFSET_START ..
                                  Offsets::P_OFFSET_END],
                        content.offset
                    );
                    Offsets::write_addr::<B>(&mut data[Offsets::P_VADDR_START ..
                                                       Offsets::P_VADDR_END],
                                             virt_addr);
                    Offsets::write_addr::<B>(&mut data[Offsets::P_PADDR_START ..
                                                       Offsets::P_PADDR_END],
                                             phys_addr);
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_FILE_SIZE_START ..
                                  Offsets::P_FILE_SIZE_END],
                        content.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_MEM_SIZE_START ..
                                  Offsets::P_MEM_SIZE_END],
                        content.size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_ALIGN_START ..
                                  Offsets::P_ALIGN_END],
                        Offsets::OFFSET_ALIGN
                    );
                },
                ProgHdrData::Unknown { tag, flags, offset, file_size, mem_size,
                                       phys_addr, virt_addr, align } => {
                    Offsets::write_word::<B>(&mut data[Offsets::P_KIND_START ..
                                                       Offsets::P_KIND_END],
                                             tag);
                    Offsets::write_word::<B>(&mut data[Offsets::P_FLAGS_START ..
                                                       Offsets::P_FLAGS_END],
                                             flags);
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_OFFSET_START ..
                                  Offsets::P_OFFSET_END],
                        offset
                    );
                    Offsets::write_addr::<B>(&mut data[Offsets::P_VADDR_START ..
                                                       Offsets::P_VADDR_END],
                                             virt_addr);
                    Offsets::write_addr::<B>(&mut data[Offsets::P_PADDR_START ..
                                                       Offsets::P_PADDR_END],
                                             phys_addr);
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_FILE_SIZE_START ..
                                  Offsets::P_FILE_SIZE_END],
                        file_size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_MEM_SIZE_START ..
                                  Offsets::P_MEM_SIZE_END],
                        mem_size
                    );
                    Offsets::write_offset::<B>(
                        &mut data[Offsets::P_ALIGN_START ..
                                  Offsets::P_ALIGN_END],
                        align
                    );
                }
            }

            idx += Offsets::PROG_HDR_SIZE;
        } else {
            return Err(())
        }
    }

    Ok(buf.split_at_mut(idx))
}

impl ProgHdrOffsets for Elf32 {
    const P_OFFSET_START: usize = Self::P_KIND_END;
    const P_VADDR_START: usize = Self::P_OFFSET_END;
    const P_PADDR_START: usize = Self::P_VADDR_END;
    const P_FILE_SIZE_START: usize = Self::P_PADDR_END;
    const P_MEM_SIZE_START: usize = Self::P_FILE_SIZE_END;
    const P_FLAGS_START: usize = Self::P_MEM_SIZE_END;
    const P_ALIGN_START: usize = Self::P_FLAGS_END;
    const PROG_HDR_SIZE_HALF: u16 = Self::PROG_HDR_SIZE as u16;
    const PROG_HDR_SIZE_OFFSET: u32 = Self::PROG_HDR_SIZE as u32;
}

impl ProgHdrOffsets for Elf64 {
    const P_FLAGS_START: usize = Self::P_KIND_END;
    const P_OFFSET_START: usize = Self::P_FLAGS_END;
    const P_VADDR_START: usize = Self::P_OFFSET_END;
    const P_PADDR_START: usize = Self::P_VADDR_END;
    const P_FILE_SIZE_START: usize = Self::P_PADDR_END;
    const P_MEM_SIZE_START: usize = Self::P_FILE_SIZE_END;
    const P_ALIGN_START: usize = Self::P_MEM_SIZE_END;
    const PROG_HDR_SIZE_HALF: u16 = Self::PROG_HDR_SIZE as u16;
    const PROG_HDR_SIZE_OFFSET: u64 = Self::PROG_HDR_SIZE as u64;
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
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf32;
/// use elf_utils::prog_hdr::ProgHdrs;
/// use elf_utils::prog_hdr::ProgHdrData;
/// use elf_utils::prog_hdr::ProgHdrDataRaw;
/// use elf_utils::prog_hdr::Segment;
/// use elf_utils::prog_hdr;
///
/// const PROG_HDR_CONTENTS: [ProgHdrDataRaw<Elf32>; 6] = [
///     ProgHdrData::ProgHdr { virt_addr: 0x34, phys_addr: 0x34,
///                            content: Segment { offset: 0x34, size: 0x140 } },
///     ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
///                         mem_size: 0x46bc, align: 0x1000,
///                         read: true, write: false, exec: false,
///                         content: Segment { offset: 0, size: 0x46bc } },
///     ProgHdrData::Load { virt_addr: 0x56c0, phys_addr: 0x56c0,
///                         mem_size: 0x14d05, align: 0x1000,
///                         read: true, write: false, exec: true,
///                         content: Segment { offset: 0x46c0,
///                                            size: 0x14d05 } },
///     ProgHdrData::Load { virt_addr: 0x1b3c8, phys_addr: 0x1b3c8,
///                         mem_size: 0x348, align: 4096,
///                         read: true, write: true, exec: false,
///                         content: Segment { offset: 0x193c8,
///                                            size: 0x348 } },
///     ProgHdrData::Load { virt_addr: 0x1c710, phys_addr: 0x1c710,
///                         mem_size: 0xb68, align: 4096,
///                         read: true, write: true, exec: false,
///                         content: Segment { offset: 0x19710, size: 0x64 } },
///     ProgHdrData::Dynamic { virt_addr: 0x1b628, phys_addr: 0x1b628,
///                            content: Segment { offset: 0x19628,
///                                               size: 0x88 } }
/// ];
///
/// assert_eq!(prog_hdr::required_bytes(PROG_HDR_CONTENTS.iter().map(|x| *x)),
///                                     192);
/// ```
#[inline]
pub fn required_bytes<I, Offsets>(hdrs: I) -> usize
    where I: Iterator<Item = ProgHdrDataRaw<Offsets>>,
          Offsets: ProgHdrOffsets {
    hdrs.count() * Offsets::PROG_HDR_SIZE
}

impl<'a, B, Offsets: ProgHdrOffsets> ProgHdrs<'a, B, Offsets>
    where B: ByteOrder {
    /// Attempt to create a `ProgHdrs` in `buf` containing the program
    /// header table entries in `hdrs`.
    ///
    /// This will write the program header table data into the buffer
    /// in the proper format for the ELF class and byte order.
    /// Returns both the `ProgHdrs` and the remaining space if
    /// successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the program header table doesn't
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
    /// use elf_utils::prog_hdr::ProgHdrs;
    /// use elf_utils::prog_hdr::ProgHdrData;
    /// use elf_utils::prog_hdr::ProgHdrDataRaw;
    /// use elf_utils::prog_hdr::Segment;
    ///
    /// const PROG_HDR_CONTENTS: [ProgHdrDataRaw<Elf32>; 6] = [
    ///     ProgHdrData::ProgHdr { virt_addr: 0x34, phys_addr: 0x34,
    ///                            content: Segment { offset: 0x34,
    ///                                               size: 0x140 } },
    ///     ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
    ///                         mem_size: 0x46bc, align: 0x1000,
    ///                         read: true, write: false, exec: false,
    ///                         content: Segment { offset: 0, size: 0x46bc } },
    ///     ProgHdrData::Load { virt_addr: 0x56c0, phys_addr: 0x56c0,
    ///                         mem_size: 0x14d05, align: 0x1000,
    ///                         read: true, write: false, exec: true,
    ///                         content: Segment { offset: 0x46c0,
    ///                                            size: 0x14d05 } },
    ///     ProgHdrData::Load { virt_addr: 0x1b3c8, phys_addr: 0x1b3c8,
    ///                         mem_size: 0x348, align: 4096,
    ///                         read: true, write: true, exec: false,
    ///                         content: Segment { offset: 0x193c8,
    ///                                            size: 0x348 } },
    ///     ProgHdrData::Load { virt_addr: 0x1c710, phys_addr: 0x1c710,
    ///                         mem_size: 0xb68, align: 4096,
    ///                         read: true, write: true, exec: false,
    ///                         content: Segment { offset: 0x19710,
    ///                                            size: 0x64 } },
    ///     ProgHdrData::Dynamic { virt_addr: 0x1b628, phys_addr: 0x1b628,
    ///                            content: Segment { offset: 0x19628,
    ///                                               size: 0x88 } }
    /// ];
    ///
    /// let mut buf = [0; 200];
    /// let res: Result<(ProgHdrs<'_, LittleEndian, Elf32>,
    ///                     &'_ mut [u8]), ()> =
    ///     ProgHdrs::create_split(&mut buf[0..],
    ///                            PROG_HDR_CONTENTS.iter().map(|x| *x));
    /// let (hdrs, rest) = res.unwrap();
    ///
    /// assert_eq!(rest.len(), 8);
    ///
    /// let mut iter = hdrs.iter();
    ///
    /// for i in 0 .. 6 {
    ///     let ent = iter.next().unwrap();
    ///     let data: ProgHdrDataRaw<Elf32> = ent.try_into().unwrap();
    ///
    ///     assert_eq!(data, PROG_HDR_CONTENTS[i]);
    /// }
    /// ```
    #[inline]
    pub fn create_split<I>(buf: &'a mut [u8], hdrs: I) ->
        Result<(Self, &'a mut [u8]), ()>
        where I: Iterator<Item = ProgHdrDataRaw<Offsets>> {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (hdrs, out) = create::<B, I, Offsets>(buf, hdrs)?;

        Ok((ProgHdrs { byteorder: byteorder, offsets: offsets, hdrs: hdrs },
            out))
    }

    /// Attempt to create a `ProgHdrs` in `buf` containing the dynamic
    /// linking entries in `hdrs`.
    ///
    /// This will write the program header table data into the buffer
    /// in the proper format for the ELF class and byte order.
    /// Returns both the `ProgHdrs` and the remaining space if
    /// successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the program header table doesn't
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
    /// use elf_utils::prog_hdr::ProgHdrs;
    /// use elf_utils::prog_hdr::ProgHdrData;
    /// use elf_utils::prog_hdr::ProgHdrDataRaw;
    /// use elf_utils::prog_hdr::Segment;
    ///
    /// const PROG_HDR_CONTENTS: [ProgHdrDataRaw<Elf32>; 6] = [
    ///     ProgHdrData::ProgHdr { virt_addr: 0x34, phys_addr: 0x34,
    ///                            content: Segment { offset: 0x34,
    ///                                               size: 0x140 } },
    ///     ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
    ///                         mem_size: 0x46bc, align: 0x1000,
    ///                         read: true, write: false, exec: false,
    ///                         content: Segment { offset: 0, size: 0x46bc } },
    ///     ProgHdrData::Load { virt_addr: 0x56c0, phys_addr: 0x56c0,
    ///                         mem_size: 0x14d05, align: 0x1000,
    ///                         read: true, write: false, exec: true,
    ///                         content: Segment { offset: 0x46c0,
    ///                                            size: 0x14d05 } },
    ///     ProgHdrData::Load { virt_addr: 0x1b3c8, phys_addr: 0x1b3c8,
    ///                         mem_size: 0x348, align: 4096,
    ///                         read: true, write: true, exec: false,
    ///                         content: Segment { offset: 0x193c8,
    ///                                            size: 0x348 } },
    ///     ProgHdrData::Load { virt_addr: 0x1c710, phys_addr: 0x1c710,
    ///                         mem_size: 0xb68, align: 4096,
    ///                         read: true, write: true, exec: false,
    ///                         content: Segment { offset: 0x19710,
    ///                                            size: 0x64 } },
    ///     ProgHdrData::Dynamic { virt_addr: 0x1b628, phys_addr: 0x1b628,
    ///                            content: Segment { offset: 0x19628,
    ///                                               size: 0x88 } }
    /// ];
    ///
    /// let mut buf = [0; 200];
    /// let hdrs: ProgHdrs<'_, LittleEndian, Elf32> =
    ///     ProgHdrs::create(&mut buf[0..],
    ///                      PROG_HDR_CONTENTS.iter().map(|x| *x))
    ///     .unwrap();
    /// let mut iter = hdrs.iter();
    ///
    /// for i in 0 .. 6 {
    ///     let ent = iter.next().unwrap();
    ///     let data: ProgHdrDataRaw<Elf32> = ent.try_into().unwrap();
    ///
    ///     assert_eq!(data, PROG_HDR_CONTENTS[i]);
    /// }
    /// ```
    #[inline]
    pub fn create<I>(buf: &'a mut [u8], hdrs: I) -> Result<Self, ()>
        where I: Iterator<Item = ProgHdrDataRaw<Offsets>>,
              Self: Sized {
        match Self::create_split(buf, hdrs) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }

    /// Get a [ProgHdr] for the program header table entry at `idx`.
    ///
    /// # Errors
    ///
    /// `None` will be returned if `idx` is out of bounds.
    #[inline]
    pub fn idx(&self, idx: usize) -> Option<ProgHdr<'a, B, Offsets>> {
        let len = self.hdrs.len();
        let start = idx * Offsets::PROG_HDR_SIZE;

        if start < len {
            let end = start + Offsets::PROG_HDR_SIZE;

            Some(ProgHdr { byteorder: PhantomData, offsets: PhantomData,
                           ent: &self.hdrs[start .. end ] })
        } else {
            None
        }
    }

    /// Get the number of program header table entries in this `ProgHdrs`.
    #[inline]
    pub fn num_hdrs(&self) -> usize {
        self.hdrs.len() / Offsets::PROG_HDR_SIZE
    }

    /// Get an iterator over this `ProgHdrs`.
    #[inline]
    pub fn iter(&self) -> ProgHdrIter<'a, B, Offsets> {
        ProgHdrIter { byteorder: PhantomData, offsets: PhantomData,
                      hdrs: self.hdrs, idx: 0 }
    }
}

impl<'a, Offsets> WithElfData<'a>
    for ProgHdrDataRaw<Offsets>
    where Offsets: ProgHdrOffsets {
    type Result = ProgHdrDataBufs<'a, Offsets>;
    type Error = ProgHdrError<Offsets>;

    #[inline]
    fn with_elf_data(self, data: &'a [u8]) ->
        Result<Self::Result, Self::Error> {
        match self {
            ProgHdrData::Null => Ok(ProgHdrData::Null),
            ProgHdrData::Load { content: Segment { offset, size },
                                virt_addr, phys_addr, mem_size,
                                align, read, write, exec } => {
                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(ProgHdrData::Load {
                            virt_addr: virt_addr, phys_addr: phys_addr,
                            mem_size: mem_size, align: align, read: read,
                            write: write, exec: exec,
                            content: &data[offset .. offset + size]
                        }),
                    _ => Err(ProgHdrError::DataOutOfBounds { offset: offset,
                                                             size: size })
                }
            },
            ProgHdrData::Dynamic { content: Segment { offset, size },
                                   virt_addr, phys_addr } => {
                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(ProgHdrData::Dynamic {
                            virt_addr: virt_addr, phys_addr: phys_addr,
                            content: &data[offset .. offset + size]
                        }),
                    _ => Err(ProgHdrError::DataOutOfBounds { offset: offset,
                                                             size: size })
                }
            },
            ProgHdrData::Interp { str: Segment { offset, size },
                                  virt_addr, phys_addr } => {
                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(ProgHdrData::Interp {
                            virt_addr: virt_addr, phys_addr: phys_addr,
                            str: &data[offset .. offset + size]
                        }),
                    _ => Err(ProgHdrError::DataOutOfBounds { offset: offset,
                                                             size: size })
                }
            },
            ProgHdrData::Note { content: Segment { offset, size },
                                virt_addr, phys_addr } => {
                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(ProgHdrData::Note {
                            virt_addr: virt_addr, phys_addr: phys_addr,
                            content: &data[offset .. offset + size]
                        }),
                    _ => Err(ProgHdrError::DataOutOfBounds { offset: offset,
                                                             size: size })
                }
            },
            ProgHdrData::Shlib => Ok(ProgHdrData::Shlib),
            ProgHdrData::ProgHdr { content: Segment { offset, size },
                                   virt_addr, phys_addr } => {
                match (offset.try_into(), size.try_into()) {
                    (Ok(offset), Ok(size)) if offset + size <= data.len() =>
                        Ok(ProgHdrData::ProgHdr {
                            virt_addr: virt_addr, phys_addr: phys_addr,
                            content: &data[offset .. offset + size]
                        }),
                    _ => Err(ProgHdrError::DataOutOfBounds { offset: offset,
                                                             size: size })
                }
            },
            ProgHdrData::Unknown { tag, flags, offset, file_size, mem_size,
                                   phys_addr, virt_addr, align } => {
                Ok(ProgHdrData::Unknown {
                    tag: tag, flags: flags, offset: offset,
                    file_size: file_size, mem_size: mem_size,
                    phys_addr: phys_addr, virt_addr: virt_addr,
                    align: align
                })
            }
        }
    }
}

impl<'a, B, Offsets> TryFrom<&'a [u8]> for ProgHdrs<'a, B, Offsets>
    where Offsets: ProgHdrOffsets,
          B: ByteOrder {
    type Error = ProgHdrsError;

    #[inline]
    fn try_from(hdrs: &'a [u8]) -> Result<ProgHdrs<'a, B, Offsets>,
                                          Self::Error> {
        let len = hdrs.len();

        if hdrs.len() % Offsets::PROG_HDR_SIZE == 0 {
            Ok(ProgHdrs { byteorder: PhantomData, offsets: PhantomData,
                          hdrs: hdrs })
        } else {
            Err(ProgHdrsError::BadSize(len))
        }
    }
}

impl<'a, B, Offsets> TryFrom<&'a mut [u8]> for ProgHdrs<'a, B, Offsets>
    where Offsets: ProgHdrOffsets,
          B: ByteOrder {
    type Error = ProgHdrsError;

    #[inline]
    fn try_from(hdrs: &'a mut [u8]) -> Result<ProgHdrs<'a, B, Offsets>,
                                              ProgHdrsError> {
        let len = hdrs.len();

        if hdrs.len() % Offsets::PROG_HDR_SIZE == 0 {
            Ok(ProgHdrs { byteorder: PhantomData, offsets: PhantomData,
                          hdrs: hdrs })
        } else {
            Err(ProgHdrsError::BadSize(len))
        }
    }
}

impl<'a, B, Offsets> TryFrom<ProgHdr<'a, B, Offsets>>
    for ProgHdrDataRaw<Offsets>
    where Offsets: ProgHdrOffsets,
          B: ByteOrder {
    type Error = ProgHdrError<Offsets>;

    #[inline]
    fn try_from(ent: ProgHdr<'a, B, Offsets>) ->
        Result<ProgHdrDataRaw<Offsets>,
               Self::Error> {
        project::<B, Offsets>(ent.ent)
    }
}

impl<'a, B, Offsets> TryFrom<ProgHdrMut<'a, B, Offsets>>
    for ProgHdrDataRaw<Offsets>
    where Offsets: ProgHdrOffsets,
          B: ByteOrder {
    type Error = ProgHdrError<Offsets>;

    #[inline]
    fn try_from(ent: ProgHdrMut<'a, B, Offsets>) ->
        Result<ProgHdrDataRaw<Offsets>,
               Self::Error> {
        project::<B, Offsets>(ent.ent)
    }
}

impl<'a, B, Offsets, Data, Str> TryFrom<ProgHdrData<Offsets, Data,
                                                    Str, &'a [u8]>>
    for ProgHdrData<Offsets, Data, Str, Dynamic<'a, B, Offsets>>
    where Offsets: ProgHdrOffsets + DynamicOffsets,
          B: ByteOrder {
    type Error = DynamicError;

    #[inline]
    fn try_from(ent: ProgHdrData<Offsets, Data, Str, &'a [u8]>) ->
        Result<ProgHdrData<Offsets, Data, Str, Dynamic<'a, B, Offsets>>,
               Self::Error> {
        match ent {
            ProgHdrData::Null => Ok(ProgHdrData::Null),
            ProgHdrData::Load { content, virt_addr, phys_addr, mem_size,
                                align, read, write, exec } =>
                Ok(ProgHdrData::Load { content, virt_addr, phys_addr, mem_size,
                                       align, read, write, exec }),
            ProgHdrData::Dynamic { content, virt_addr, phys_addr } =>
                match Dynamic::try_from(content) {
                    Ok(content) =>
                        Ok(ProgHdrData::Dynamic { content, virt_addr,
                                                  phys_addr }),
                    Err(err) => Err(err)
                },
            ProgHdrData::Interp { str, virt_addr, phys_addr } =>
                Ok(ProgHdrData::Interp { str, virt_addr, phys_addr }),
            ProgHdrData::Note { content, virt_addr, phys_addr } =>
                Ok(ProgHdrData::Note { content, virt_addr, phys_addr }),
            ProgHdrData::Shlib => Ok(ProgHdrData::Shlib),
            ProgHdrData::ProgHdr { content, virt_addr, phys_addr } =>
                Ok(ProgHdrData::ProgHdr { content, virt_addr, phys_addr }),
            ProgHdrData::Unknown { tag, flags, offset, file_size, mem_size,
                                   phys_addr, virt_addr, align } =>
                Ok(ProgHdrData::Unknown { tag, flags, offset, file_size,
                                          mem_size, phys_addr, virt_addr,
                                          align })
        }
    }
}

impl<'a, Offsets, Data, Dyn> TryFrom<ProgHdrData<Offsets, Data, &'a [u8], Dyn>>
    for ProgHdrData<Offsets, Data, &'a str, Dyn>
    where Offsets: ProgHdrOffsets {
    type Error = &'a [u8];

    #[inline]
    fn try_from(ent: ProgHdrData<Offsets, Data, &'a [u8], Dyn>) ->
        Result<ProgHdrData<Offsets, Data, &'a str, Dyn>,
               Self::Error> {
        match ent {
            ProgHdrData::Null => Ok(ProgHdrData::Null),
            ProgHdrData::Load { content, virt_addr, phys_addr, mem_size,
                                align, read, write, exec } =>
                Ok(ProgHdrData::Load { content, virt_addr, phys_addr, mem_size,
                                       align, read, write, exec }),
            ProgHdrData::Dynamic { content, virt_addr, phys_addr } =>
                Ok(ProgHdrData::Dynamic { content, virt_addr, phys_addr }),
            ProgHdrData::Interp { str, virt_addr, phys_addr } =>
                match from_utf8(str) {
                    Ok(str) => Ok(ProgHdrData::Interp { str, virt_addr,
                                                        phys_addr }),
                    Err(_) => Err(str)
                }
            ProgHdrData::Note { content, virt_addr, phys_addr } =>
                Ok(ProgHdrData::Note { content, virt_addr, phys_addr }),
            ProgHdrData::Shlib => Ok(ProgHdrData::Shlib),
            ProgHdrData::ProgHdr { content, virt_addr, phys_addr } =>
                Ok(ProgHdrData::ProgHdr { content, virt_addr, phys_addr }),
            ProgHdrData::Unknown { tag, flags, offset, file_size, mem_size,
                                   phys_addr, virt_addr, align } =>
                Ok(ProgHdrData::Unknown { tag, flags, offset, file_size,
                                          mem_size, phys_addr, virt_addr,
                                          align })
        }
    }
}

impl<'a, B, Offsets: ProgHdrOffsets> Iterator for ProgHdrIter<'a, B, Offsets>
    where B: ByteOrder {
    type Item = ProgHdr<'a, B, Offsets>;

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

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let len = self.hdrs.len();
        let start = (self.idx + n) * Offsets::PROG_HDR_SIZE;

        if start < len {
            let end = start + Offsets::PROG_HDR_SIZE;

            self.idx += n + 1;

            Some(ProgHdr { byteorder: PhantomData, offsets: PhantomData,
                           ent: &self.hdrs[start .. end ] })
        } else {
            None
        }
    }
}

impl<'a, B, Offsets: ProgHdrOffsets> FusedIterator
    for ProgHdrIter<'a, B, Offsets>
    where B: ByteOrder {}

impl<'a, B, Offsets: ProgHdrOffsets> ExactSizeIterator
    for ProgHdrIter<'a, B, Offsets>
    where B: ByteOrder {
    #[inline]
    fn len(&self) -> usize {
        (self.hdrs.len() / Offsets::PROG_HDR_SIZE) - self.idx
    }
}

impl<Offset> Display for Segment<Offset>
    where Offset: LowerHex {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        let Segment { offset, size } = self;

        write!(f, "offset = 0x{:x}, size = 0x{:x}", offset, size)
    }
}

impl<Offsets, Data, Str, Dyn> Display for ProgHdrData<Offsets, Data, Str, Dyn>
    where Offsets: ProgHdrOffsets,
          Data: Display,
          Str: Display,
          Dyn: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ProgHdrData::Null => write!(f, "  Null"),
            ProgHdrData::Load { content, virt_addr, phys_addr, mem_size,
                                align, read, write, exec } =>
                write!(f, concat!("  Loadable data\n",
                                  "    Virtual address: 0x{:x}\n",
                                  "    Physical address: 0x{:x}\n",
                                  "    Memory size: 0x{:x}\n",
                                  "    Alignment: 0x{:x}\n",
                                  "    Readable: {}\n",
                                  "    Writable: {}\n",
                                  "    Executable: {}\n",
                                  "    Content: {}"),
                       virt_addr, phys_addr, mem_size, align,
                       read, write, exec, content),
            ProgHdrData::Dynamic { content, virt_addr, phys_addr } =>
                write!(f, concat!("  Dynamic linking table\n",
                                  "    Virtual address: 0x{:x}\n",
                                  "    Physical address: 0x{:x}\n",
                                  "    Content: {}"),
                       virt_addr, phys_addr, content),
            ProgHdrData::Interp { str, virt_addr, phys_addr } =>
                write!(f, concat!("  Interpreter\n",
                                  "    Virtual address: 0x{:x}\n",
                                  "    Physical address: 0x{:x}\n",
                                  "    Content: {}"),
                       virt_addr, phys_addr, str),
            ProgHdrData::Note { content, virt_addr, phys_addr } =>
                write!(f, concat!("  Notes\n",
                                  "    Virtual address: 0x{:x}\n",
                                  "    Physical address: 0x{:x}\n",
                                  "    Content: {}"),
                       virt_addr, phys_addr, content),
            ProgHdrData::Shlib => write!(f, "  Shlib"),
            ProgHdrData::ProgHdr { content, virt_addr, phys_addr } =>
                write!(f, concat!("  Program headers\n",
                                  "    Virtual address: 0x{:x}\n",
                                  "    Physical address: 0x{:x}\n",
                                  "    Content: {}"),
                       virt_addr, phys_addr, content),
            ProgHdrData::Unknown { tag, flags, offset, file_size, mem_size,
                                   phys_addr, virt_addr, align } =>
                write!(f, concat!("  Unknown type 0x{:x}\n",
                                  "    Virtual address: 0x{:x}\n",
                                  "    Physical address: 0x{:x}\n",
                                  "    Memory size: 0x{:x}\n",
                                  "    Alignment: 0x{:x}\n",
                                  "    Flags: 0x{:x}\n",
                                  "    Offset: 0x{:x}\n",
                                  "    File size: 0x{:x}"),
                       tag, virt_addr, phys_addr, mem_size, align,
                       flags, offset, file_size)
        }
    }
}

    impl Display for ProgHdrsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ProgHdrsError::BadSize(size) =>
                write!(f, "bad program header table size {}",
                       size)
        }
    }
}
