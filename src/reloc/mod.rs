//! ELF relocation table functionality.
//!
//! This module provides the [Rels] and [Relas] types which act as a
//! wrapper around ELF relocation table data.
//!
//! # Examples
//!
//! These examples use `Rela`s; analogous functionality exists for `Rels`.
//!
//! A `Relas` can be created from any slice containing binary data
//! whose length is a multiple of the relocation entry size using the
//! [TryFrom](core::convert::TryFrom) instances:
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf64;
//! use elf_utils::reloc::Relas;
//!
//! const RELAS: [u8; 96] = [
//!     0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
//!     0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//!     0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
//!     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//!     0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
//!     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//! ];
//!
//! let relas: Result<Relas<'_, LittleEndian, Elf64>, ()> =
//!     Relas::try_from(&RELAS[0..]);
//!
//! assert!(relas.is_ok());
//! ```
//!
//! Indexing into a `Relas` with [idx](Relas::idx) will give a
//! [Rela], which is itself a handle on a single ELF relocation entry:
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf64;
//! use elf_utils::reloc::Relas;
//!
//! const RELAS: [u8; 96] = [
//!     0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
//!     0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//!     0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
//!     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//!     0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
//!     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//! ];
//!
//! let relas: Relas<'_, LittleEndian, Elf64> =
//!     Relas::try_from(&RELAS[0..]).unwrap();
//!
//! assert!(relas.idx(0).is_some());
//! assert!(relas.idx(5).is_none());
//! ```
//!
//! A [Rela] can be projected to a [RelaData] with the
//! [TryFrom](core::convert::TryFrom) instance:
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use core::convert::TryInto;
//! use elf_utils::Elf64;
//! use elf_utils::reloc::Relas;
//! use elf_utils::reloc::RelaData;
//!
//! const RELAS: [u8; 96] = [
//!     0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
//!     0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//!     0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
//!     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//!     0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
//!     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//! ];
//!
//! let relas: Relas<'_, LittleEndian, Elf64> =
//!     Relas::try_from(&RELAS[0..]).unwrap();
//!
//! let rela = relas.idx(1).unwrap();
//! let data: RelaData<u32, Elf64> = rela.try_into().unwrap();
//!
//! assert_eq!(data, RelaData { offset: 0x2c, sym: 36, kind: 2, addend: -4 });
//! ```
pub mod x86;

use byteorder::ByteOrder;
use core::convert::TryFrom;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::LowerHex;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use crate::elf::Elf32;
use crate::elf::Elf64;
use crate::elf::ElfClass;

/// Extension to [ElfClass](crate::ElfClass) providing formatting
/// information specific to relocations.
pub trait RelClass: ElfClass {
    /// Type used to hold relocation kind tags.
    type RelKind: Copy + Display;

    /// Read the info value and split it into a kind tag and a symbol index.
    fn read_info<B: ByteOrder>(data: &[u8], byteorder: PhantomData<B>) ->
        (Self::RelKind, Self::Word);

    /// Combine a symbol index and kind tag into an info value and write it.
    fn write_info<B: ByteOrder>(data: &mut [u8], tag: Self::RelKind,
                                sym: Self::Word, byteorder: PhantomData<B>);
}

/// Offsets for ELF relocation table entries.
///
/// This contains the various offsets for fields in an ELF relocation
/// table entry for a given ELF class.
pub trait RelOffsets: RelClass {
    /// Start of the ELF relocation offset field.
    const R_OFFSET_START: usize = 0;
    /// Size of the ELF relocation offset field.
    const R_OFFSET_SIZE: usize = Self::ADDR_SIZE;
    /// End of the ELF relocation offset field.
    const R_OFFSET_END: usize = Self::R_OFFSET_START + Self::R_OFFSET_SIZE;

    /// Start of the ELF relocation info field.
    const R_INFO_START: usize = Self::R_OFFSET_END;
    /// Size of the ELF relocation info field.
    const R_INFO_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF relocation info field.
    const R_INFO_END: usize = Self::R_INFO_START + Self::R_INFO_SIZE;

    /// Size of a relocation table entry.
    const REL_SIZE: usize = Self::R_INFO_END;
    /// Size of a relocation table entry as an offset.
    const REL_SIZE_OFFSET: Self::Offset;
}

/// Offsets for ELF relocation table entries with explicit addends.
///
/// This contains the various offsets for fields in an ELF relocation
/// table entry with an explicit addend for a given ELF class.
pub trait RelaOffsets: RelOffsets {
    /// Start of the ELF relocation addend field.
    const R_ADDEND_START: usize = Self::R_INFO_END;
    /// Size of the ELF relocation addend field.
    const R_ADDEND_SIZE: usize = Self::ADDEND_SIZE;
    /// End of the ELF relocation addend field.
    const R_ADDEND_END: usize = Self::R_ADDEND_START + Self::R_ADDEND_SIZE;

    /// Size of a relocation table entry with explicit addends.
    const RELA_SIZE: usize = Self::R_ADDEND_END;
    /// Size of a relocation table entry as an offset.
    const RELA_SIZE_OFFSET: Self::Offset;
}

/// In-place read-only ELF relocation table.
///
/// An ELF relocation table is an array of entries describing
/// adjustments to be made to a particular section's data based on the
/// addresses that are not known at the time of the creation of the
/// file.  Linkers apply these relocations once the absolute addresses
/// are known.  This type refers to a variant that does not possess
/// explicit addends; relocations that do are accessed using [Relas].
///
/// A `Rels` is essentially a 'handle' for raw ELF data.  It can be
/// used to convert an index into a [Rel] using the [idx](Rels::idx)
/// function, or iterated over with [iter](Rels::iter).
///
/// A `Rels` can be created from raw data using the
/// [TryFrom](core::convert::TryFrom) instance.
///
/// New `Rels` can be created from an iterator over [RelData] with
/// [create](Rels::create) or [create_split](Rels::create_split).
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf32;
/// use elf_utils::reloc::Rels;
/// use elf_utils::reloc::RelData;
///
/// const RELS: [u8; 32] = [
///     0x15, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x00,
///     0x1e, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x00,
///     0x2d, 0x00, 0x00, 0x00, 0x01, 0x53, 0x00, 0x00,
///     0x39, 0x00, 0x00, 0x00, 0x02, 0x60, 0x00, 0x00,
/// ];
/// const RELS_CONTENTS: [RelData<u32, Elf32>; 4] = [
///     RelData { offset: 0x15, sym: 97, kind: 1 },
///     RelData { offset: 0x1e, sym: 97, kind: 1 },
///     RelData { offset: 0x2d, sym: 83, kind: 1 },
///     RelData { offset: 0x39, sym: 96, kind: 2 },
/// ];
///
/// let rels: Rels<'_, LittleEndian, Elf32> =
///     Rels::try_from(&RELS[0..]).unwrap();
///
/// for i in 0 .. 4 {
///     let rel = rels.idx(i).unwrap();
///     let data: RelData<u32, Elf32> = rel.try_into().unwrap();
///
///     assert_eq!(data, RELS_CONTENTS[i]);
/// }
/// ```
#[derive(Copy, Clone)]
pub struct Rels<'a, B: ByteOrder, Offsets: RelOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8]
}

/// In-place read-only ELF relocation table with explicit addends.
///
/// An ELF relocation table is an array of entries describing
/// adjustments to be made to a particular section's data based on the
/// addresses that are not known at the time of the creation of the
/// file.  Linkers apply these relocations once the absolute addresses
/// are known.  This type refers to a variant that possesses explicit
/// addends; relocations that do not are accessed using [Rels].
///
/// A `Relas` is essentially a 'handle' for raw ELF data.  It can be
/// used to convert an index into a [Rela] using the [idx](Relas::idx)
/// function, or iterated over with [iter](Relas::iter).
///
/// A `Relas` can be created from raw data using the
/// [TryFrom](core::convert::TryFrom) instance.
///
/// New `Relas` can be created from an iterator over [RelaData] with
/// [create](Relas::create) or [create_split](Relas::create_split).
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::reloc::Relas;
/// use elf_utils::reloc::RelaData;
///
/// const RELAS: [u8; 96] = [
///     0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
///     0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
///     0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
///     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
///     0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
///     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/// ];
/// const RELAS_CONTENTS: [RelaData<u32, Elf64>; 4] = [
///    RelaData { offset: 0x22, sym: 36, kind: 2, addend: -5 },
///    RelaData { offset: 0x2c, sym: 36, kind: 2, addend: -4 },
///    RelaData { offset: 0x42, sym: 21, kind: 10, addend: 0 },
///    RelaData { offset: 0x4f, sym: 35, kind: 4, addend: -4 }
/// ];
///
/// let relas: Relas<'_, LittleEndian, Elf64> =
///     Relas::try_from(&RELAS[0..]).unwrap();
///
/// for i in 0 .. 4 {
///     let rela = relas.idx(i).unwrap();
///     let data: RelaData<u32, Elf64> = rela.try_into().unwrap();
///
///     assert_eq!(data, RELAS_CONTENTS[i]);
/// }
/// ```
#[derive(Copy, Clone)]
pub struct Relas<'a, B: ByteOrder, Offsets: RelaOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8]
}

/// In-place read-only ELF relocation entry.
///
/// An ELF relocation entry describes adjustments to be made to a
/// particular section's data based on the addresses that are not
/// known at the time of the creation of the file.  Linkers apply
/// these relocations once the absolute addresses are known.  This
/// type refers to a variant that does not possess explicit addends;
/// relocations that do are accessed using [Relas].
///
/// A `Rel` is essentially a 'handle' for raw ELF data.  Note that
/// this data may not be in host byte order, and may not even have the
/// same word size.  In order to directly manipulate the relocation data,
/// it must be projected into a [RelData] using the
/// [TryFrom](core::convert::TryFrom) instance in order to access the
/// relocation's information directly.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf32;
/// use elf_utils::reloc::Rels;
/// use elf_utils::reloc::RelData;
///
/// const RELS: [u8; 32] = [
///     0x15, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x00,
///     0x1e, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x00,
///     0x2d, 0x00, 0x00, 0x00, 0x01, 0x53, 0x00, 0x00,
///     0x39, 0x00, 0x00, 0x00, 0x02, 0x60, 0x00, 0x00,
/// ];
/// const RELS_CONTENTS: [RelData<u32, Elf32>; 4] = [
///     RelData { offset: 0x15, sym: 97, kind: 1 },
///     RelData { offset: 0x1e, sym: 97, kind: 1 },
///     RelData { offset: 0x2d, sym: 83, kind: 1 },
///     RelData { offset: 0x39, sym: 96, kind: 2 },
/// ];
///
/// let rels: Rels<'_, LittleEndian, Elf32> =
///     Rels::try_from(&RELS[0..]).unwrap();
/// let rel = rels.idx(1).unwrap();
/// let data: RelData<u32, Elf32> = rel.try_into().unwrap();
///
/// assert_eq!(data, RelData { offset: 0x1e, sym: 97, kind: 1 });
/// ```
#[derive(Copy, Clone)]
pub struct Rel<'a, B: ByteOrder, Offsets: RelOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8]
}

/// In-place read-only ELF relocation entry.
///
/// An ELF relocation entry describes adjustments to be made to a
/// particular section's data based on the addresses that are not
/// known at the time of the creation of the file.  Linkers apply
/// these relocations once the absolute addresses are known.  This
/// type refers to a variant that possesses explicit addends;
/// relocations that do not are accessed using [Rels].
///
/// A `Rela` is essentially a 'handle' for raw ELF data.  Note that
/// this data may not be in host byte order, and may not even have the
/// same word size.  In order to directly manipulate the relocation data,
/// it must be projected into a [RelaData] using the
/// [TryFrom](core::convert::TryFrom) instance in order to access the
/// relocation's information directly.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::reloc::Relas;
/// use elf_utils::reloc::RelaData;
///
/// const RELAS: [u8; 96] = [
///     0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
///     0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
///     0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
///     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
///     0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
///     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/// ];
///
/// let relas: Relas<'_, LittleEndian, Elf64> =
///     Relas::try_from(&RELAS[0..]).unwrap();
/// let rela = relas.idx(1).unwrap();
/// let data: RelaData<u32, Elf64> = rela.try_into().unwrap();
///
/// assert_eq!(data, RelaData { offset: 0x2c, sym: 36, kind: 2, addend: -4 });
/// ```
#[derive(Copy, Clone)]
pub struct Rela<'a, B: ByteOrder, Offsets: RelaOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8]
}

/// Iterator for [Rels].
///
/// This iterator produces [Rel]s referenceding the relocations
/// defined in an underlying `Rels`.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf32;
/// use elf_utils::reloc::Rels;
/// use elf_utils::reloc::RelData;
///
/// const RELS: [u8; 32] = [
///     0x15, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x00,
///     0x1e, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x00,
///     0x2d, 0x00, 0x00, 0x00, 0x01, 0x53, 0x00, 0x00,
///     0x39, 0x00, 0x00, 0x00, 0x02, 0x60, 0x00, 0x00,
/// ];
/// const RELS_CONTENTS: [RelData<u32, Elf32>; 4] = [
///     RelData { offset: 0x15, sym: 97, kind: 1 },
///     RelData { offset: 0x1e, sym: 97, kind: 1 },
///     RelData { offset: 0x2d, sym: 83, kind: 1 },
///     RelData { offset: 0x39, sym: 96, kind: 2 },
/// ];
///
/// let rels: Rels<'_, LittleEndian, Elf32> =
///     Rels::try_from(&RELS[0..]).unwrap();
/// let mut iter = rels.iter();
///
/// for i in 0 .. 4 {
///     let rel = iter.next().unwrap();
///     let data: RelData<u32, Elf32> = rel.try_into().unwrap();
///
///     assert_eq!(data, RELS_CONTENTS[i]);
/// }
///
/// assert!(iter.next().is_none());
/// ```
#[derive(Clone)]
pub struct RelIter<'a, B: ByteOrder, Offsets: RelOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8],
    idx: usize
}

/// Iterator for [Relas].
///
/// This iterator produces [Rela]s referenceding the relocations
/// defined in an underlying `Relas`.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::reloc::Relas;
/// use elf_utils::reloc::RelaData;
///
/// const RELAS: [u8; 96] = [
///     0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
///     0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
///     0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
///     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
///     0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
///     0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/// ];
/// const RELAS_CONTENTS: [RelaData<u32, Elf64>; 4] = [
///    RelaData { offset: 0x22, sym: 36, kind: 2, addend: -5 },
///    RelaData { offset: 0x2c, sym: 36, kind: 2, addend: -4 },
///    RelaData { offset: 0x42, sym: 21, kind: 10, addend: 0 },
///    RelaData { offset: 0x4f, sym: 35, kind: 4, addend: -4 }
/// ];
///
/// let relas: Relas<'_, LittleEndian, Elf64> =
///     Relas::try_from(&RELAS[0..]).unwrap();
/// let mut iter = relas.iter();
///
/// for i in 0 .. 4 {
///     let rela = iter.next().unwrap();
///     let data: RelaData<u32, Elf64> = rela.try_into().unwrap();
///
///     assert_eq!(data, RELAS_CONTENTS[i]);
/// }
///
/// assert!(iter.next().is_none());
/// ```
#[derive(Clone)]
pub struct RelaIter<'a, B: ByteOrder, Offsets: RelaOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8],
    idx: usize
}

/// Projected ELF relocation data.
///
/// This is a representation of an ELF relocation projected into a form
/// that can be directly manipulated.  This data can also be used to
/// create a new [Rels] using [create](Rels::create) or
/// [create_split](Rels::create_split).
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct RelData<Name, Class: RelClass> {
    pub offset: Class::Offset,
    pub sym: Name,
    pub kind: Class::RelKind
}

/// Projected ELF relocation data with explicit addends.
///
/// This is a representation of an ELF relocation projected into a form
/// that can be directly manipulated.  This data can also be used to
/// create a new [Relas] using [create](Rels::create) or
/// [create_split](Relas::create_split).
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct RelaData<Name, Class: RelClass> {
    pub offset: Class::Offset,
    pub addend: Class::Addend,
    pub sym: Name,
    pub kind: Class::RelKind,
}

fn create_relas<'a, 'b, B, I, Offsets>(buf: &'a mut [u8], relas: I,
                                       byteorder: PhantomData<B>,
                                       offsets: PhantomData<Offsets>) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where I: Iterator<Item = &'b RelaData<Offsets::Word, Offsets>>,
          Offsets: 'b + RelaOffsets,
          B: ByteOrder {
    let len = buf.len();
    let mut idx = 0;

    for RelaData { offset, addend, sym, kind } in relas {
        if idx + Offsets::RELA_SIZE <= len {
            let relabuf = &mut buf[idx .. idx + Offsets::RELA_SIZE];

            Offsets::write_offset(&mut relabuf[Offsets::R_OFFSET_START ..
                                               Offsets::R_OFFSET_END],
                              *offset, byteorder);
            Offsets::write_info(&mut relabuf[Offsets::R_INFO_START ..
                                             Offsets::R_INFO_END],
                                *kind, *sym, byteorder);
            Offsets::write_addend(&mut relabuf[Offsets::R_ADDEND_START ..
                                               Offsets::R_ADDEND_END],
                                *addend, byteorder);
            idx += Offsets::RELA_SIZE;
        } else {
            return Err(())
        }
    }

    Ok(buf.split_at_mut(idx))
}

fn create_rels<'a, 'b, B, I, Offsets>(buf: &'a mut [u8], rels: I,
                                      byteorder: PhantomData<B>,
                                      offsets: PhantomData<Offsets>) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where I: Iterator<Item = &'b RelData<Offsets::Word, Offsets>>,
          Offsets: 'b + RelOffsets,
          B: ByteOrder {
    let len = buf.len();
    let mut idx = 0;

    for RelData { offset, sym, kind } in rels {
        if idx + Offsets::REL_SIZE <= len {
            let relbuf = &mut buf[idx .. idx + Offsets::REL_SIZE];

            Offsets::write_offset(&mut relbuf[Offsets::R_OFFSET_START ..
                                              Offsets::R_OFFSET_END],
                              *offset, byteorder);
            Offsets::write_info(&mut relbuf[Offsets::R_INFO_START ..
                                            Offsets::R_INFO_END],
                              *kind, *sym, byteorder);
            idx += Offsets::REL_SIZE;
        } else {
            return Err(())
        }
    }

    Ok(buf.split_at_mut(idx))
}

impl RelClass for Elf32 {
    type RelKind = u8;

    fn read_info<B: ByteOrder>(data: &[u8], byteorder: PhantomData<B>) ->
        (Self::RelKind, Self::Word) {
        let info = B::read_u32(data);
        let kind = (info & 0xff) as u8;
        let sym = (info >> 8) as u32;

        (kind, sym)
    }

    fn write_info<B: ByteOrder>(data: &mut [u8], kind: Self::RelKind,
                                sym: Self::Word, byteorder: PhantomData<B>) {
        let info = ((sym as u32) << 8) | (kind as u32);

        B::write_u32(data, info);

    }
}

impl RelClass for Elf64 {
    type RelKind = u32;

    fn read_info<B: ByteOrder>(data: &[u8], byteorder: PhantomData<B>) ->
        (Self::RelKind, Self::Word) {
        let info = B::read_u64(data);
        let kind = (info & 0xffffffff) as u32;
        let sym = (info >> 32) as u32;

        (kind, sym)
    }

    fn write_info<B: ByteOrder>(data: &mut [u8], kind: Self::RelKind,
                                sym: Self::Word, byteorder: PhantomData<B>) {
        let info = ((sym as u64) << 32) | (kind as u64);

        B::write_u64(data, info);

    }
}

impl RelOffsets for Elf32 {
    const REL_SIZE_OFFSET: Self::Offset = Self::REL_SIZE as u32;
}

impl RelaOffsets for Elf32 {
    const RELA_SIZE_OFFSET: Self::Offset = Self::RELA_SIZE as u32;
}

impl RelOffsets for Elf64 {
    const REL_SIZE_OFFSET: Self::Offset = Self::REL_SIZE as u64;
}

impl RelaOffsets for Elf64 {
    const RELA_SIZE_OFFSET: Self::Offset = Self::RELA_SIZE as u64;
}

/// Calculate the number of bytes required to represent the relocation
/// table containing `rels`.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf32;
/// use elf_utils::reloc::Rels;
/// use elf_utils::reloc::RelData;
/// use elf_utils::reloc;
///
/// const RELS_CONTENTS: [RelData<u32, Elf32>; 4] = [
///     RelData { offset: 0x15, sym: 97, kind: 1 },
///     RelData { offset: 0x1e, sym: 97, kind: 1 },
///     RelData { offset: 0x2d, sym: 83, kind: 1 },
///     RelData { offset: 0x39, sym: 96, kind: 2 },
/// ];
///
/// assert_eq!(reloc::rels_required_bytes(RELS_CONTENTS.iter()), 32);
/// ```
#[inline]
pub fn rels_required_bytes<'b, I, Offsets>(rels: I) -> usize
    where I: Iterator<Item = &'b RelData<Offsets::Word, Offsets>>,
          Offsets: 'b + RelOffsets {
    rels.count() * Offsets::REL_SIZE
}

/// Calculate the number of bytes required to represent the relocation
/// table containing `relas`.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::reloc::Relas;
/// use elf_utils::reloc::RelaData;
/// use elf_utils::reloc;
///
/// const RELAS_CONTENTS: [RelaData<u32, Elf64>; 4] = [
///    RelaData { offset: 0x22, sym: 36, kind: 2, addend: -5 },
///    RelaData { offset: 0x2c, sym: 36, kind: 2, addend: -4 },
///    RelaData { offset: 0x42, sym: 21, kind: 10, addend: 0 },
///    RelaData { offset: 0x4f, sym: 35, kind: 4, addend: -4 }
/// ];
///
/// assert_eq!(reloc::relas_required_bytes(RELAS_CONTENTS.iter()), 96);
/// ```
#[inline]
pub fn relas_required_bytes<'b, I, Offsets>(relas: I) -> usize
    where I: Iterator<Item = &'b RelaData<Offsets::Word, Offsets>>,
          Offsets: 'b + RelaOffsets {
    relas.count() * Offsets::RELA_SIZE
}

impl<'a, B, Offsets> Relas<'a, B, Offsets>
    where Offsets: RelaOffsets,
          B: ByteOrder {
    /// Attempt to create a `Relas` in `buf` containing the relocations
    /// in `relas`.
    ///
    /// This will write the relocation table data into the buffer in the
    /// proper format for the ELF class and byte order.  Returns both
    /// the `Relas` and the remaining space if successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the relocation table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use elf_utils::Elf64;
    /// use elf_utils::reloc::Relas;
    /// use elf_utils::reloc::RelaData;
    /// use elf_utils::reloc;
    ///
    /// const RELAS_CONTENTS: [RelaData<u32, Elf64>; 4] = [
    ///    RelaData { offset: 0x22, sym: 36, kind: 2, addend: -5 },
    ///    RelaData { offset: 0x2c, sym: 36, kind: 2, addend: -4 },
    ///    RelaData { offset: 0x42, sym: 21, kind: 10, addend: 0 },
    ///    RelaData { offset: 0x4f, sym: 35, kind: 4, addend: -4 }
    /// ];
    ///
    /// let mut buf = [0; 100];
    /// let res: Result<(Relas<'_, LittleEndian, Elf64>,
    ///                  &'_ mut [u8]), ()> =
    ///     Relas::create_split(&mut buf[0..], RELAS_CONTENTS.iter());
    /// let (relas, rest) = res.unwrap();
    ///
    /// assert_eq!(rest.len(), 4);
    ///
    /// let mut iter = relas.iter();
    ///
    /// for i in 0 .. 4 {
    ///     let rela = iter.next().unwrap();
    ///     let data: RelaData<u32, Elf64> = rela.try_into().unwrap();
    ///
    ///     assert_eq!(data, RELAS_CONTENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    #[inline]
    pub fn create_split<'b, I>(buf: &'a mut [u8], relas: I) ->
        Result<(Self, &'a mut [u8]), ()>
        where I: Iterator<Item = &'b RelaData<Offsets::Word, Offsets>>,
              Offsets: 'b {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (data, out) = create_relas(buf, relas, byteorder, offsets)?;

        Ok((Relas { byteorder: byteorder, offsets: offsets, data: data }, out))
    }

    /// Attempt to create a `Relas` in `buf` containing the relocations
    /// in `relas`.
    ///
    /// This will write the relocation table data into the buffer in the
    /// proper format for the ELF class and byte order.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the relocation table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use elf_utils::Elf64;
    /// use elf_utils::reloc::Relas;
    /// use elf_utils::reloc::RelaData;
    /// use elf_utils::reloc;
    ///
    /// const RELAS_CONTENTS: [RelaData<u32, Elf64>; 4] = [
    ///    RelaData { offset: 0x22, sym: 36, kind: 2, addend: -5 },
    ///    RelaData { offset: 0x2c, sym: 36, kind: 2, addend: -4 },
    ///    RelaData { offset: 0x42, sym: 21, kind: 10, addend: 0 },
    ///    RelaData { offset: 0x4f, sym: 35, kind: 4, addend: -4 }
    /// ];
    ///
    /// let mut buf = [0; 100];
    /// let relas: Relas<'_, LittleEndian, Elf64> =
    ///     Relas::create(&mut buf[0..], RELAS_CONTENTS.iter()).unwrap();
    /// let mut iter = relas.iter();
    ///
    /// for i in 0 .. 4 {
    ///     let rela = iter.next().unwrap();
    ///     let data: RelaData<u32, Elf64> = rela.try_into().unwrap();
    ///
    ///     assert_eq!(data, RELAS_CONTENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    #[inline]
    pub fn create<'b, I>(buf: &'a mut [u8], relas: I) -> Result<Self, ()>
        where I: Iterator<Item = &'b RelaData<Offsets::Word, Offsets>>,
              Self: Sized,
              Offsets: 'b {
        match Self::create_split(buf, relas) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }

    /// Get a [Rela] for the relocation at `idx`.
    ///
    /// # Errors
    ///
    /// `None` will be returned if `idx` is out of bounds.
    #[inline]
    pub fn idx(&self, idx: usize) -> Option<Rela<'a, B, Offsets>> {
        let len = self.data.len();
        let start = idx * Offsets::RELA_SIZE;

        if start < len {
            let end = start + Offsets::RELA_SIZE;

            Some(Rela { byteorder: PhantomData, offsets: PhantomData,
                        data: &self.data[start .. end ] })
        } else {
            None
        }
    }

    /// Get the number of relocations in this `Relas`.
    #[inline]
    pub fn num_relocs(&self) -> usize {
        self.data.len() / Offsets::RELA_SIZE
    }

    /// Get an iterator over this `Relas`.
    #[inline]
    pub fn iter(&self) -> RelaIter<'a, B, Offsets> {
        RelaIter { byteorder: PhantomData, offsets: PhantomData,
                   data: self.data, idx: (0 as u8).into() }
    }
}

impl<'a, B, Offsets> Rels<'a, B, Offsets>
    where Offsets: RelOffsets,
          B: ByteOrder {
    #[inline]
    /// Attempt to create a `Relas` in `buf` containing the relocations
    /// in `relas`.
    ///
    /// This will write the relocation table data into the buffer in the
    /// proper format for the ELF class and byte order.  Returns both
    /// the `Relas` and the remaining space if successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the relocation table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use elf_utils::Elf32;
    /// use elf_utils::reloc::Rels;
    /// use elf_utils::reloc::RelData;
    /// use elf_utils::reloc;
    ///
    /// const RELS_CONTENTS: [RelData<u32, Elf32>; 4] = [
    ///     RelData { offset: 0x15, sym: 97, kind: 1 },
    ///     RelData { offset: 0x1e, sym: 97, kind: 1 },
    ///     RelData { offset: 0x2d, sym: 83, kind: 1 },
    ///     RelData { offset: 0x39, sym: 96, kind: 2 },
    /// ];
    ///
    /// let mut buf = [0; 40];
    /// let res: Result<(Rels<'_, LittleEndian, Elf32>,
    ///                  &'_ mut [u8]), ()> =
    ///     Rels::create_split(&mut buf[0..], RELS_CONTENTS.iter());
    /// let (rels, rest) = res.unwrap();
    ///
    /// assert_eq!(rest.len(), 8);
    ///
    /// let mut iter = rels.iter();
    ///
    /// for i in 0 .. 4 {
    ///     let rel = iter.next().unwrap();
    ///     let data: RelData<u32, Elf32> = rel.try_into().unwrap();
    ///
    ///     assert_eq!(data, RELS_CONTENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    pub fn create_split<'b, I>(buf: &'a mut [u8], rels: I) ->
        Result<(Self, &'a mut [u8]), ()>
        where I: Iterator<Item = &'b RelData<Offsets::Word, Offsets>>,
              Offsets: 'b {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (data, out) = create_rels(buf, rels, byteorder, offsets)?;

        Ok((Rels { byteorder: byteorder, offsets: offsets, data: data }, out))
    }

    /// Attempt to create a `Relas` in `buf` containing the relocations
    /// in `relas`.
    ///
    /// This will write the relocation table data into the buffer in the
    /// proper format for the ELF class and byte order.  Returns both
    /// the `Relas` and the remaining space if successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the relocation table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use elf_utils::Elf32;
    /// use elf_utils::reloc::Rels;
    /// use elf_utils::reloc::RelData;
    /// use elf_utils::reloc;
    ///
    /// const RELS_CONTENTS: [RelData<u32, Elf32>; 4] = [
    ///     RelData { offset: 0x15, sym: 97, kind: 1 },
    ///     RelData { offset: 0x1e, sym: 97, kind: 1 },
    ///     RelData { offset: 0x2d, sym: 83, kind: 1 },
    ///     RelData { offset: 0x39, sym: 96, kind: 2 },
    /// ];
    ///
    /// let mut buf = [0; 40];
    /// let rels: Rels<'_, LittleEndian, Elf32> =
    ///     Rels::create(&mut buf[0..], RELS_CONTENTS.iter()).unwrap();
    /// let mut iter = rels.iter();
    ///
    /// for i in 0 .. 4 {
    ///     let rel = iter.next().unwrap();
    ///     let data: RelData<u32, Elf32> = rel.try_into().unwrap();
    ///
    ///     assert_eq!(data, RELS_CONTENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    #[inline]
    pub fn create<'b, I>(buf: &'a mut [u8], rels: I) -> Result<Self, ()>
        where I: Iterator<Item = &'b RelData<Offsets::Word, Offsets>>,
              Self: Sized,
              Offsets: 'b {
        match Self::create_split(buf, rels) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }

    /// Get a [Rel] for the relocation at `idx`.
    ///
    /// # Errors
    ///
    /// `None` will be returned if `idx` is out of bounds.
    #[inline]
    pub fn idx(&self, idx: usize) -> Option<Rel<'a, B, Offsets>> {
        let len = self.data.len();
        let start = idx * Offsets::REL_SIZE;

        if start < len {
            let end = start + Offsets::REL_SIZE;

            Some(Rel { byteorder: PhantomData, offsets: PhantomData,
                       data: &self.data[start .. end ] })
        } else {
            None
        }
    }

    /// Get the number of relocations in this `Rels`.
    #[inline]
    pub fn num_relocs(&self) -> usize {
        self.data.len() / Offsets::REL_SIZE
    }

    /// Get an iterator over this `Rels`.
    #[inline]
    pub fn iter(&self) -> RelIter<'a, B, Offsets> {
        RelIter { byteorder: PhantomData, offsets: PhantomData,
                  data: self.data, idx: (0 as u8).into() }
    }
}

impl<'a, B, Offsets: RelOffsets> TryFrom<&'a [u8]> for Rels<'a, B, Offsets>
    where B: ByteOrder {
    type Error = ();

    /// Create a `Rels` from the data buffer.  This will check that
    /// the data buffer is a multiple of the relocation size.
    #[inline]
    fn try_from(data: &'a [u8]) -> Result<Rels<'a, B, Offsets>, Self::Error> {
        let len = data.len();

        if data.len() % Offsets::REL_SIZE == 0 {
            Ok(Rels { byteorder: PhantomData, offsets: PhantomData,
                      data: data })
        } else {
            Err(())
        }
    }
}

impl<'a, B, Offsets: RelOffsets> TryFrom<&'a mut [u8]> for Rels<'a, B, Offsets>
    where B: ByteOrder {
    type Error = ();

    /// Create a `Rels` from the data buffer.  This will check that
    /// the data buffer is a multiple of the relocation size.
    #[inline]
    fn try_from(data: &'a mut [u8]) -> Result<Rels<'a, B, Offsets>,
                                              Self::Error> {
        let len = data.len();

        if data.len() % Offsets::REL_SIZE == 0 {
            Ok(Rels { byteorder: PhantomData, offsets: PhantomData,
                      data: data })
        } else {
            Err(())
        }
    }
}

impl<'a, B, Offsets: RelaOffsets> TryFrom<&'a [u8]>
    for Relas<'a, B, Offsets>
    where B: ByteOrder {
    type Error = ();

    /// Create a `Rels` from the data buffer.  This will check that
    /// the data buffer is a multiple of the relocation size.
    #[inline]
    fn try_from(data: &'a [u8]) -> Result<Relas<'a, B, Offsets>, Self::Error> {
        let len = data.len();

        if data.len() % Offsets::RELA_SIZE == 0 {
            Ok(Relas { byteorder: PhantomData, offsets: PhantomData,
                       data: data })
        } else {
            Err(())
        }
    }
}

impl<'a, B, Offsets: RelaOffsets> TryFrom<&'a mut [u8]>
    for Relas<'a, B, Offsets>
    where B: ByteOrder {
    type Error = ();

    /// Create a `Rels` from the data buffer.  This will check that
    /// the data buffer is a multiple of the relocation size.
    #[inline]
    fn try_from(data: &'a mut [u8]) -> Result<Relas<'a, B, Offsets>,
                                              Self::Error> {
        let len = data.len();

        if data.len() % Offsets::RELA_SIZE == 0 {
            Ok(Relas { byteorder: PhantomData, offsets: PhantomData,
                       data: data })
        } else {
            Err(())
        }
    }
}

impl<'a, B, Offsets> From<Rel<'a, B, Offsets>>
    for RelData<Offsets::Word, Offsets>
    where Offsets: RelOffsets,
          B: ByteOrder {
    #[inline]
    fn from(rel: Rel<'a, B, Offsets>) -> RelData<Offsets::Word, Offsets> {
        let offset = Offsets::read_offset(&rel.data[Offsets::R_OFFSET_START ..
                                                    Offsets::R_OFFSET_END],
                                      rel.byteorder);
        let (kind, sym) = Offsets::read_info(&rel.data[Offsets::R_INFO_START ..
                                                       Offsets::R_INFO_END],
                                       rel.byteorder);

        RelData { offset: offset, sym: sym, kind: kind }
    }
}

impl<Name: Display, Class> Display for RelData<Name, Class>
    where Class: RelClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        let RelData { offset, sym, kind } = self;

        write!(f, concat!("  sym: {}\n  kind: {}\n  offset: {}\n"),
               sym, kind, offset)
    }
}

impl<'a, B, Offsets> From<Rela<'a, B, Offsets>>
    for RelaData<Offsets::Word, Offsets>
    where Offsets: RelaOffsets,
          B: ByteOrder {
    #[inline]
    fn from(rel: Rela<'a, B, Offsets>) -> RelaData<Offsets::Word, Offsets> {
        let offset = Offsets::read_offset(&rel.data[Offsets::R_OFFSET_START ..
                                                    Offsets::R_OFFSET_END],
                                        rel.byteorder);
        let (kind, sym) = Offsets::read_info(&rel.data[Offsets::R_INFO_START ..
                                                       Offsets::R_INFO_END],
                                             rel.byteorder);
        let addend = Offsets::read_addend(&rel.data[Offsets::R_ADDEND_START ..
                                                    Offsets::R_ADDEND_END],
                                          rel.byteorder);

        RelaData { offset: offset, sym: sym, kind: kind, addend: addend }
    }
}

impl<Name: Display, Class> Display for RelaData<Name, Class>
    where Class: RelClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        let RelaData { offset, sym, kind, addend } = self;

        write!(f, "  sym: {}\n  kind: {}\n  offset: {}, addend: {}\n",
               sym, kind, offset, addend)
    }
}

impl<'a, B, Offsets: RelOffsets> Iterator for RelIter<'a, B, Offsets>
    where B: ByteOrder {
    type Item = Rel<'a, B, Offsets>;

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
        let len = self.data.len();
        let start = (self.idx + n) * Offsets::REL_SIZE;

        if start < len {
            let end = start + Offsets::REL_SIZE;

            self.idx += n + 1;

            Some(Rel { byteorder: PhantomData, offsets: PhantomData,
                       data: &self.data[start .. end ] })
        } else {
            None
        }
    }
}

impl<'a, B, Offsets: RelOffsets> FusedIterator for RelIter<'a, B, Offsets>
    where B: ByteOrder {}

impl<'a, B, Offsets: RelOffsets> ExactSizeIterator for RelIter<'a, B, Offsets>
    where B: ByteOrder {
    #[inline]
    fn len(&self) -> usize {
        self.data.len() / Offsets::REL_SIZE
    }
}

impl<'a, B, Offsets: RelaOffsets> Iterator for RelaIter<'a, B, Offsets>
    where B: ByteOrder {
    type Item = Rela<'a, B, Offsets>;

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
        let len = self.data.len();
        let start = (self.idx + n) * Offsets::RELA_SIZE;

        if start < len {
            let end = start + Offsets::RELA_SIZE;

            self.idx += n + 1;

            Some(Rela { byteorder: PhantomData, offsets: PhantomData,
                        data: &self.data[start .. end ] })
        } else {
            None
        }
    }
}

impl<'a, B, Offsets: RelaOffsets> FusedIterator for RelaIter<'a, B, Offsets>
    where B: ByteOrder {}

impl<'a, B, Offsets: RelaOffsets> ExactSizeIterator for RelaIter<'a, B, Offsets>
    where B: ByteOrder {
    #[inline]
    fn len(&self) -> usize {
        self.data.len() / Offsets::RELA_SIZE
    }
}
