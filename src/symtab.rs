//! ELF symbol table functionality.
//!
//! This module provides the [Symtab] type which acts as a wrapper
//! around ELF symbol table data.
//!
//! # Examples
//!
//! A `Symtab` can be created from any slice containing binary data
//! whose length is a multiple of the symbol size using the
//! [TryFrom](core::convert::TryFrom) instances:
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf64;
//! use elf_utils::symtab::Symtab;
//! use elf_utils::symtab::SymtabError;
//!
//! const SYMTAB: [u8; 120] = [
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
//!     0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
//!     0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let symtab: Result<Symtab<'_, LittleEndian, Elf64>, SymtabError> =
//!     Symtab::try_from(&SYMTAB[0..]);
//!
//! assert!(symtab.is_ok());
//! ```
//!
//! Indexing into a `Symtab` with [idx](Symtab::idx) will give a
//! [Sym], which is itself a handle on a single ELF symbol:
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf64;
//! use elf_utils::symtab::Symtab;
//!
//! const SYMTAB: [u8; 120] = [
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
//!     0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
//!     0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let symtab: Symtab<'_, LittleEndian, Elf64> =
//!     Symtab::try_from(&SYMTAB[0..]).unwrap();
//!
//! assert!(symtab.idx(0).is_some());
//! assert!(symtab.idx(5).is_none());
//! ```
//!
//! A [Sym] can be projected to a [SymData] with the
//! [TryFrom](core::convert::TryFrom) instance:
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use core::convert::TryInto;
//! use elf_utils::Elf64;
//! use elf_utils::symtab::Symtab;
//! use elf_utils::symtab::SymBase;
//! use elf_utils::symtab::SymBind;
//! use elf_utils::symtab::SymData;
//! use elf_utils::symtab::SymDataRaw;
//! use elf_utils::symtab::SymKind;
//!
//! const SYMTAB: [u8; 120] = [
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
//!     0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
//!     0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let symtab: Symtab<'_, LittleEndian, Elf64> =
//!     Symtab::try_from(&SYMTAB[0..]).unwrap();
//! let sym = symtab.idx(1).unwrap();
//! let data: SymDataRaw<Elf64> = sym.try_into().unwrap();
//!
//! assert_eq!(data, SymData { name: Some(1), value: 0, size: 0,
//!                            kind: SymKind::File, bind: SymBind::Local,
//!                            section: SymBase::Absolute });
//! ```
//!
//! The `name` field in a `SymData` can be resolved using a
//! [Strtab](crate::strtab::Strtab):
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use core::convert::TryInto;
//! use elf_utils::Elf64;
//! use elf_utils::strtab::Strtab;
//! use elf_utils::strtab::WithStrtab;
//! use elf_utils::symtab::Symtab;
//! use elf_utils::symtab::SymBase;
//! use elf_utils::symtab::SymBind;
//! use elf_utils::symtab::SymData;
//! use elf_utils::symtab::SymDataRaw;
//! use elf_utils::symtab::SymKind;
//!
//! const SYMTAB: [u8; 120] = [
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
//!     0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
//!     0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! const STRTAB: [u8; 39] = [
//!     0x00, 0x63, 0x72, 0x74, 0x31, 0x5f, 0x63, 0x2e,
//!     0x63, 0x00, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69,
//!     0x7a, 0x65, 0x72, 0x00, 0x68, 0x61, 0x6e, 0x64,
//!     0x6c, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x69,
//!     0x63, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x00
//! ];
//!
//! let strtab: Strtab<'_> =
//!     Strtab::try_from(&STRTAB[0..]).expect("Expected success");
//! let symtab: Symtab<'_, LittleEndian, Elf64> =
//!     Symtab::try_from(&SYMTAB[0..]).unwrap();
//! let sym = symtab.idx(2).unwrap();
//! let data: SymDataRaw<Elf64> = sym.try_into().unwrap();
//! let with_str = data.with_strtab(strtab).unwrap();
//!
//! assert_eq!(with_str, SymData { name: Some(Ok("finalizer")), value: 560,
//!                                size: 90, kind: SymKind::Function,
//!                                bind: SymBind::Local,
//!                                section: SymBase::Index(1) });
//! ```

use byteorder::ByteOrder;
use core::borrow::Borrow;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::LowerHex;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use crate::elf::Elf32;
use crate::elf::Elf64;
use crate::elf::ElfClass;
use crate::strtab::Strtab;
use crate::strtab::StrtabIdxError;
use crate::strtab::WithStrtab;

/// Trait for things that can be converted from one type to another
/// with the use of a [Symtab].
///
/// This is typically used with objects such as relocations and
/// dynamic entries that contain a symbol index.  It can also be used
/// to convert iterators and other objects to produce data that
/// contains symbol references.
pub trait WithSymtab<'a, B: ByteOrder, Offsets: SymOffsets> {
    /// Result of conversion.
    type Result;
    /// Errors that can occur.
    type Error;

    /// Consume the caller to convert it using `symtab`.
    fn with_symtab(self, symtab: Symtab<'a, B, Offsets>) ->
        Result<Self::Result, Self::Error>;
}

/// Offsets for ELF symbol table entries.
///
/// This contains the various offsets for fields in an ELF symbol
/// table entry for a given ELF class.
pub trait SymOffsets: ElfClass {
    /// Start of the ELF symbol name field.
    const ST_NAME_START: usize = 0;
    /// Size of the ELF symbol name field.
    const ST_NAME_SIZE: usize = Self::WORD_SIZE;
    /// End of the ELF symbol name field.
    const ST_NAME_END: usize = Self::ST_NAME_START + Self::ST_NAME_SIZE;

    /// Start of the ELF symbol value field.
    const ST_VALUE_START: usize;
    /// Size of the ELF symbol value field.
    const ST_VALUE_SIZE: usize = Self::ADDR_SIZE;
    /// End of the ELF symbol value field.
    const ST_VALUE_END: usize = Self::ST_VALUE_START + Self::ST_VALUE_SIZE;

    /// Start of the ELF symbol size field.
    const ST_SIZE_START: usize;
    /// Size of the ELF symbol size field.
    const ST_SIZE_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF symbol size field.
    const ST_SIZE_END: usize = Self::ST_SIZE_START + Self::ST_SIZE_SIZE;

    /// Start of the ELF symbol info field.
    const ST_INFO_START: usize;
    /// Size of the ELF symbol info field.
    const ST_INFO_SIZE: usize = 1;
    /// End of the ELF symbol info field.
    const ST_INFO_END: usize = Self::ST_INFO_START + Self::ST_INFO_SIZE;

    /// Start of the ELF symbol other field.
    const ST_OTHER_START: usize;
    /// Size of the ELF symbol other field.
    const ST_OTHER_SIZE: usize = 1;
    /// End of the ELF symbol other field.
    const ST_OTHER_END: usize = Self::ST_OTHER_START + Self::ST_OTHER_SIZE;

    /// Start of the ELF symbol other field.
    const ST_SHIDX_START: usize;
    /// Size of the ELF symbol other field.
    const ST_SHIDX_SIZE: usize = Self::HALF_SIZE;
    /// End of the ELF symbol other field.
    const ST_SHIDX_END: usize = Self::ST_SHIDX_START + Self::ST_SHIDX_SIZE;

    /// Size of a symbol table entry.
    const ST_ENT_SIZE: usize;
    /// Size of a symbol table entry as an offset.
    const ST_ENT_SIZE_OFFSET: Self::Offset;
}

/// Trait for creating symbol tables from their contents.
pub trait SymtabCreate<'a, B: ByteOrder, Offsets: SymOffsets> {
    /// Calculate the number of bytes required to represent the symbol
    /// table built by `syms`.
    fn required_bytes<'b, S, I>(syms: I) -> usize
        where I: Iterator<Item = &'b SymDataRaw<Offsets>>,
              Offsets: 'b;

    /// Attempt to create a `Symtab` in `buf` containing the symbols
    /// in `syms`.  Return both the `Symtab` and the remaining space
    /// if successful.
    fn create_split<'b, I>(buf: &'a mut [u8], syms: I) ->
        Result<(Self, &'a mut [u8]), ()>
        where I: Iterator<Item = &'b SymDataRaw<Offsets>>,
              Self: Sized,
              Offsets: 'b;

    /// Attempt to create a `Symtab` in `buf` containing the symbols
    /// in `syms`.
    #[inline]
    fn create<'b, S, I>(buf: &'a mut [u8], syms: I) -> Result<Self, ()>
        where I: Iterator<Item = &'b SymDataRaw<Offsets>>,
              Self: Sized,
              Offsets: 'b {
        match Self::create_split(buf, syms) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }
}

pub trait SymtabMutOps<'a, B: ByteOrder, Offsets: SymOffsets> {
    type Iter: Iterator<Item = Sym<'a, B, Offsets>>;

    /// Get the symbol at index `idx`.
    fn idx(&'a self, idx: usize) -> Option<Sym<'a, B, Offsets>>;

    /// Get the number of symbols in the table.
    fn num_syms(&self) -> usize;

    /// Get an `Iterator` over the symbols in the table.
    fn iter(&'a self) -> Self::Iter;
}

/// In-place read-only ELF symbol table.
///
/// An ELF symbol table is an array of references to various objects
/// defined in other sections of the ELF data.  Some of these
/// references have names defined in the associated string table.
///
/// A `Symtab` is essentially a 'handle' for raw ELF data.  It can be
/// used to convert a symbol index into a [Sym] using the
/// [idx](Symtab::idx) function, or iterated over with
/// [iter](Symtab::iter).
///
/// A `Symtab` can be created from raw data using the
/// [TryFrom](core::convert::TryFrom) instance.
///
/// New `Symtab`s can be created from an iterator over [SymData] with
/// [create](Symtab::create) or [create_split](Symtab::create_split).
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::symtab::Symtab;
/// use elf_utils::symtab::SymBase;
/// use elf_utils::symtab::SymBind;
/// use elf_utils::symtab::SymData;
/// use elf_utils::symtab::SymDataRaw;
/// use elf_utils::symtab::SymKind;
///
/// const SYMTAB: [u8; 120] = [
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
///     0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
///     0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// ];
/// const SYMTAB_CONTENTS: [SymDataRaw<Elf64>; 5] = [
///    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
///              bind: SymBind::Local, section: SymBase::Undef },
///    SymData { name: Some(1), value: 0, size: 0, kind: SymKind::File,
///              bind: SymBind::Local, section: SymBase::Absolute },
///    SymData { name: Some(10), value: 560, size: 90, kind: SymKind::Function,
///              bind: SymBind::Local, section: SymBase::Index(1) },
///    SymData { name: Some(20), value: 272, size: 282, kind: SymKind::Function,
///              bind: SymBind::Local, section: SymBase::Index(1) },
///    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
///              bind: SymBind::Local, section: SymBase::Index(1) },
/// ];
///
/// let symtab: Symtab<'_, LittleEndian, Elf64> =
///     Symtab::try_from(&SYMTAB[0..]).unwrap();
///
/// for i in 0 .. 5 {
///     let sym = symtab.idx(i).unwrap();
///     let data: SymDataRaw<Elf64> = sym.try_into().unwrap();
///
///     assert_eq!(data, SYMTAB_CONTENTS[i]);
/// }
/// ```
#[derive(Copy, Clone)]
pub struct Symtab<'a, B: ByteOrder, Offsets: SymOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    symtab: &'a [u8]
}

pub struct SymtabMut<'a, B: ByteOrder, Offsets: SymOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    symtab: &'a mut [u8]
}

/// In-place read-only ELF symbol.
///
/// An ELF symbol is a reference to an object defined in another
/// section of the ELF data.  Some symbols have names defined in the
/// string table associated with the symbol table holding this symbol.
///
/// A `Sym` is essentially a 'handle' for raw ELF data.  Note that
/// this data may not be in host byte order, and may not even have the
/// same word size.  In order to directly manipulate the symbol data,
/// it must be projected into a [SymData] using the
/// [TryFrom](core::convert::TryFrom) instance in order to access the
/// symbol's information directly.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::symtab::Symtab;
/// use elf_utils::symtab::SymBase;
/// use elf_utils::symtab::SymBind;
/// use elf_utils::symtab::SymData;
/// use elf_utils::symtab::SymDataRaw;
/// use elf_utils::symtab::SymKind;
///
/// const SYMTAB: [u8; 120] = [
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
///     0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
///     0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// ];
///
/// let symtab: Symtab<'_, LittleEndian, Elf64> =
///     Symtab::try_from(&SYMTAB[0..]).unwrap();
/// let sym = symtab.idx(1).unwrap();
/// let data: SymDataRaw<Elf64> = sym.try_into().unwrap();
///
/// assert_eq!(data, SymData { name: Some(1), value: 0, size: 0,
///                            kind: SymKind::File, bind: SymBind::Local,
///                            section: SymBase::Absolute });
/// ```
#[derive(Copy, Clone)]
pub struct Sym<'a, B: ByteOrder, Offsets: SymOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    sym: &'a [u8]
}

pub struct SymMut<'a, B: ByteOrder, Offsets: SymOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    sym: &'a mut [u8]
}

/// Iterator for [Symtab]s.
///
/// This iterator produces [Sym]s referenceding the symbols defined in
/// an underlying `Symtab`.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::symtab::Symtab;
/// use elf_utils::symtab::SymBase;
/// use elf_utils::symtab::SymBind;
/// use elf_utils::symtab::SymData;
/// use elf_utils::symtab::SymDataRaw;
/// use elf_utils::symtab::SymKind;
///
/// const SYMTAB: [u8; 120] = [
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
///     0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
///     0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// ];
/// const SYMTAB_CONTENTS: [SymDataRaw<Elf64>; 5] = [
///    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
///              bind: SymBind::Local, section: SymBase::Undef },
///    SymData { name: Some(1), value: 0, size: 0, kind: SymKind::File,
///              bind: SymBind::Local, section: SymBase::Absolute },
///    SymData { name: Some(10), value: 560, size: 90, kind: SymKind::Function,
///              bind: SymBind::Local, section: SymBase::Index(1) },
///    SymData { name: Some(20), value: 272, size: 282, kind: SymKind::Function,
///              bind: SymBind::Local, section: SymBase::Index(1) },
///    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
///              bind: SymBind::Local, section: SymBase::Index(1) },
/// ];
///
/// let symtab: Symtab<'_, LittleEndian, Elf64> =
///     Symtab::try_from(&SYMTAB[0..]).unwrap();
/// let mut iter = symtab.iter();
///
/// for i in 0 .. 5 {
///     let sym = iter.next().unwrap();
///     let data: SymDataRaw<Elf64> = sym.try_into().unwrap();
///
///     assert_eq!(data, SYMTAB_CONTENTS[i]);
/// }
///
/// assert!(iter.next().is_none());
/// ```
#[derive(Clone)]
pub struct SymtabIter<'a, B: ByteOrder, Offsets: SymOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    symtab: &'a [u8],
    idx: usize
}

/// ELF symbol type identifiers.
///
/// These define the type of data referenced by an ELF symbol.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum SymKind {
    /// No symbol type.
    None,
    /// A data object.
    Object,
    /// An executable function or other code.
    Function,
    /// An entire section.  This is used primarily for relocation.
    /// Typically given `Local` binding.
    Section,
    /// The name of the source file.  This typically has `Local`
    /// binding and preceeds all other `Local` symbols.
    File,
    /// A thread-local storage object.
    ThreadLocal,
    /// Unknown type.
    ArchSpecific(u8)
}

/// ELF symbol binding kind.
///
/// These define how the binding represented by the ELF symbol
/// interacts with symbols defined in other files.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum SymBind {
    /// Local symbols, not visible outside the object file containing
    /// the defintion.
    Local,
    /// Global symbols, visible to all object files.  One file's
    /// definition of a global symbol will satisfy another's.
    Global,
    /// Weak symbols, visible to all object files; however, these will
    /// be overridden by another `Global` symbol of the same name.
    Weak,
    /// Architecture-specific kind.
    ArchSpecific(u8)
}

/// Base of an ELF symbol.
///
/// This is information held in the `st_section` field of an ELF
/// symbol.  In most cases, this is an `Index(i)`, where `i` is a
/// section index; however, other values are possible.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum SymBase<Section, Half> {
    /// Undefined section.
    Undef,
    /// Absolute value.
    Absolute,
    /// Common data.
    Common,
    /// Index stored elsewhere.
    Escape,
    /// Normal section index.
    Index(Section),
    /// Architecture-specific.
    ArchSpecific(Half),
    /// OS-specific.
    OSSpecific(Half)
}

/// Projected ELF symbol data.
///
/// This is a representation of an ELF symbol projected into a form
/// that can be directly manipulated.  This data can also be used to
/// create a new [Symtab] using [create](Symtab::create) or
/// [create_split](Symtab::create_split).
///
/// `SymData` directly projected from a [Sym] will have an index for
/// its `name` field.  In order to obtain a string, it is necessary to
/// use the [WithStrtab](crate::strtab::WithStrtab) instance:
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::strtab::Strtab;
/// use elf_utils::strtab::WithStrtab;
/// use elf_utils::symtab::Symtab;
/// use elf_utils::symtab::SymBase;
/// use elf_utils::symtab::SymBind;
/// use elf_utils::symtab::SymData;
/// use elf_utils::symtab::SymDataRaw;
/// use elf_utils::symtab::SymKind;
///
/// const SYMTAB: [u8; 120] = [
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xf1, 0xff,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
///     0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
///     0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x1a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// ];
///
/// const STRTAB: [u8; 39] = [
///     0x00, 0x63, 0x72, 0x74, 0x31, 0x5f, 0x63, 0x2e,
///     0x63, 0x00, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69,
///     0x7a, 0x65, 0x72, 0x00, 0x68, 0x61, 0x6e, 0x64,
///     0x6c, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x69,
///     0x63, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x00
/// ];
///
/// let strtab: Strtab<'_> =
///     Strtab::try_from(&STRTAB[0..]).expect("Expected success");
/// let symtab: Symtab<'_, LittleEndian, Elf64> =
///     Symtab::try_from(&SYMTAB[0..]).unwrap();
/// let sym = symtab.idx(2).unwrap();
/// let data: SymDataRaw<Elf64> = sym.try_into().unwrap();
///
/// assert_eq!(data, SymData { name: Some(10), value: 560, size: 90,
///                            kind: SymKind::Function, bind: SymBind::Local,
///                            section: SymBase::Index(1) });
///
/// let with_str = data.with_strtab(strtab).unwrap();
///
/// assert_eq!(with_str, SymData { name: Some(Ok("finalizer")), value: 560,
///                                size: 90, kind: SymKind::Function,
///                                bind: SymBind::Local,
///                                section: SymBase::Index(1) });
/// ```
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct SymData<Name, Section, Class: ElfClass> {
    /// Symbol name, or `None` if it has no name.
    pub name: Option<Name>,
    /// Symbol value.
    pub value: Class::Addr,
    /// Symbol size.
    pub size: Class::Offset,
    /// Type of symbol.
    pub kind: SymKind,
    /// Symbol binding.
    pub bind: SymBind,
    /// Section for this symbol.
    pub section: SymBase<Section, Class::Half>
}

/// Type synonym for [SymData] as projected from a [Sym].
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [Sym].  This is also used in [Symtab::create] and
/// [Symtab::create_split].
pub type SymDataRaw<Class> =
    SymData<<Class as ElfClass>::Word, <Class as ElfClass>::Half, Class>;

/// Type synonym for [SymData] as projected from a [Sym], with symbol
/// names represented as the results of UTF-8 decoding.
///
/// This is obtained from the [WithStrtab] instance on a [SymDataRaw].
pub type SymDataStrData<'a, Class> =
    SymData<Result<&'a str, &'a [u8]>, <Class as ElfClass>::Half, Class>;

/// Type synonym for [SymData] as projected from a [Sym], with symbol
/// names represented as fully-resolved `&'a str`s.
///
/// This is obtained from the [WithStrtab] instance on a [SymDataRaw].
pub type SymDataStr<'a, Class> =
    SymData<&'a str, <Class as ElfClass>::Half, Class>;

/// Errors that can occur when projecting a [Sym] to a [SymData].
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum SymError {
    /// Bad binding value.
    BadBind(u8),
    /// Bad type value.
    BadType(u8)
}

/// Errors that can occur when projecting a [Sym] to a [SymData] using
/// [WithStrtab](WithStrtab::with_strtab).
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum StrSymError {
    /// Error looking up the symbol name.
    BadName,
    /// Bad binding value.
    BadBind(u8),
    /// Bad type value.
    BadType(u8)
}

/// Errors that can occur creating a [Symtab].
///
/// The only error that can occur is if the data is not a multiple of
/// the size of a symbol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SymtabError {
    BadSize(usize)
}

#[inline]
fn name_lookup<'a, Name, Section, Class>(sym: SymData<Name, Section, Class>,
                                        strtab: Strtab<'a>) ->
    Result<SymData<Result<&'a str, &'a [u8]>, Section, Class>, ()>
    where Class: ElfClass,
          Name: Clone + TryInto<usize> {
    let SymData { name, value, size, bind, kind, section } = sym;

    match name {
        Some(name) => {
            match strtab.idx(name) {
                Ok(name) => Ok(SymData { name: Some(Ok(name)), value: value,
                                         size: size, bind: bind, kind: kind,
                                         section: section }),
                Err(StrtabIdxError::UTF8Decode(data)) => {
                    Ok(SymData { name: Some(Err(data)), value: value,
                                 size: size, bind: bind, kind: kind,
                                 section: section })
                },
                _ => Err(())
            }
        },
        None => {
            Ok(SymData { name: None, value: value, size: size,
                         bind: bind, kind: kind, section: section })
        }
    }
}

#[inline]
fn project<'a, B, Offsets>(data: &'a [u8]) -> Result<SymDataRaw<Offsets>,
                                                     SymError>
    where Offsets: SymOffsets,
          B: ByteOrder {
    let name = Offsets::read_word::<B>(&data[Offsets::ST_NAME_START ..
                                             Offsets::ST_NAME_END]).into();
    let value = Offsets::read_addr::<B>(&data[Offsets::ST_VALUE_START ..
                                              Offsets::ST_VALUE_END]);
    let size = Offsets::read_offset::<B>(&data[Offsets::ST_SIZE_START ..
                                               Offsets::ST_SIZE_END]);
    let info = data[Offsets::ST_INFO_START];
    let section = Offsets::read_half::<B>(&data[Offsets::ST_SHIDX_START ..
                                                Offsets::ST_SHIDX_END]);
    let bind = info >> 4;
    let kind = info & 0xf;

    match (bind.try_into(), kind.try_into()) {
        (Ok(bind), Ok(kind)) => {
            let name = if name == (0 as u8).into() {
                None
            } else {
                Some(name.into())
            };

            Ok(SymData { name: name, value: value, size: size, bind: bind,
                         kind: kind, section: SymBase::from(section) })
        },
        (Err(bad), _) => Err(SymError::BadBind(bad)),
        (_, Err(bad)) => Err(SymError::BadType(bad))
    }
}

fn create<'a, 'b, B, I, Offsets>(buf: &'a mut [u8], syms: I) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where I: Iterator,
          I::Item: Borrow<SymDataRaw<Offsets>>,
          Offsets: 'b + SymOffsets,
          B: ByteOrder {
    let len = buf.len();
    let mut idx = 0;

    for sym in syms {
        let sym = sym.borrow();
        if idx + Offsets::ST_ENT_SIZE <= len {
            let symbuf = &mut buf[idx .. idx + Offsets::ST_ENT_SIZE];
            let bind: u8 = sym.bind.into();
            let kind: u8 = sym.kind.into();
            let info = (bind << 4) | kind;

            match sym.name {
                Some(name) => {
                    Offsets::write_word::<B>(
                        &mut symbuf[Offsets::ST_NAME_START ..
                                    Offsets::ST_NAME_END], name
                    )
                }
                None => {
                    Offsets::write_word::<B>(
                        &mut symbuf[Offsets::ST_NAME_START ..
                                    Offsets::ST_NAME_END],
                        (0 as u8).into()
                    )
                }
            }

            Offsets::write_addr::<B>(&mut symbuf[Offsets::ST_VALUE_START ..
                                                 Offsets::ST_VALUE_END],
                                     sym.value);
            Offsets::write_offset::<B>(&mut symbuf[Offsets::ST_SIZE_START ..
                                                   Offsets::ST_SIZE_END],
                                       sym.size);
            symbuf[Offsets::ST_INFO_START] = info;
            Offsets::write_half::<B>(&mut symbuf[Offsets::ST_SHIDX_START ..
                                                 Offsets::ST_SHIDX_END],
                                     sym.section.encode());
            idx += Offsets::ST_ENT_SIZE;
        } else {
            return Err(())
        }
    }

    Ok(buf.split_at_mut(idx))
}

impl SymOffsets for Elf32 {
    const ST_VALUE_START: usize = Self::ST_NAME_END;
    const ST_SIZE_START: usize = Self::ST_VALUE_END;
    const ST_INFO_START: usize = Self::ST_SIZE_END;
    const ST_OTHER_START: usize = Self::ST_INFO_END;
    const ST_SHIDX_START: usize = Self::ST_OTHER_END;
    const ST_ENT_SIZE: usize = Self::ST_SHIDX_END;
    const ST_ENT_SIZE_OFFSET: Self::Offset = Self::ST_ENT_SIZE as u32;
}

impl SymOffsets for Elf64 {
    const ST_INFO_START: usize = Self::ST_NAME_END;
    const ST_OTHER_START: usize = Self::ST_INFO_END;
    const ST_SHIDX_START: usize = Self::ST_OTHER_END;
    const ST_VALUE_START: usize = Self::ST_SHIDX_END;
    const ST_SIZE_START: usize = Self::ST_VALUE_END;
    const ST_ENT_SIZE: usize = Self::ST_SIZE_END;
    const ST_ENT_SIZE_OFFSET: Self::Offset = Self::ST_ENT_SIZE as u64;
}

/// Calculate the number of bytes required to represent the symbol
/// table containing `syms`.
///
/// # Examples
///
/// ```
/// extern crate elf_utils;
///
/// use elf_utils::Elf64;
/// use elf_utils::symtab::SymBase;
/// use elf_utils::symtab::SymBind;
/// use elf_utils::symtab::SymData;
/// use elf_utils::symtab::SymDataRaw;
/// use elf_utils::symtab::SymKind;
/// use elf_utils::symtab;
///
/// const SYMTAB_CONTENTS: [SymDataRaw<Elf64>; 5] = [
///    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
///              bind: SymBind::Local, section: SymBase::Undef },
///    SymData { name: Some(1), value: 0, size: 0, kind: SymKind::File,
///              bind: SymBind::Local, section: SymBase::Absolute },
///    SymData { name: Some(10), value: 560, size: 90,
///              kind: SymKind::Function, bind: SymBind::Local,
///              section: SymBase::Index(1) },
///    SymData { name: Some(20), value: 272, size: 282,
///              kind: SymKind::Function, bind: SymBind::Local,
///              section: SymBase::Index(1) },
///    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
///              bind: SymBind::Local, section: SymBase::Index(1) },
/// ];
///
/// assert_eq!(symtab::required_bytes(SYMTAB_CONTENTS.iter()), 120);
/// ```
#[inline]
pub fn required_bytes<'b, I, Offsets>(syms: I) -> usize
    where I: Iterator<Item = &'b SymDataRaw<Offsets>>,
          Offsets: 'b + SymOffsets {
    syms.count() * Offsets::ST_ENT_SIZE
}

impl<'a, B, Offsets> Symtab<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    /// Attempt to create a `Symtab` in `buf` containing the symbols
    /// in `syms`.
    ///
    /// This will write the symbol table data into the buffer in the
    /// proper format for the ELF class and byte order.  Returns both
    /// the `Symtab` and the remaining space if successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the symbol table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use elf_utils::Elf64;
    /// use elf_utils::symtab::Symtab;
    /// use elf_utils::symtab::SymBase;
    /// use elf_utils::symtab::SymBind;
    /// use elf_utils::symtab::SymData;
    /// use elf_utils::symtab::SymDataRaw;
    /// use elf_utils::symtab::SymKind;
    ///
    /// const SYMTAB_CONTENTS: [SymDataRaw<Elf64>; 5] = [
    ///    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
    ///              bind: SymBind::Local, section: SymBase::Undef },
    ///    SymData { name: Some(1), value: 0, size: 0, kind: SymKind::File,
    ///              bind: SymBind::Local, section: SymBase::Absolute },
    ///    SymData { name: Some(10), value: 560, size: 90,
    ///              kind: SymKind::Function, bind: SymBind::Local,
    ///              section: SymBase::Index(1) },
    ///    SymData { name: Some(20), value: 272, size: 282,
    ///              kind: SymKind::Function, bind: SymBind::Local,
    ///              section: SymBase::Index(1) },
    ///    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
    ///              bind: SymBind::Local, section: SymBase::Index(1) },
    /// ];
    ///
    /// let mut buf = [0; 128];
    /// let res: Result<(Symtab<'_, LittleEndian, Elf64>,
    ///                     &'_ mut [u8]), ()> =
    ///     Symtab::create_split(&mut buf[0..], SYMTAB_CONTENTS.iter());
    /// let (symtab, rest) = res.unwrap();
    ///
    /// assert_eq!(rest.len(), 8);
    ///
    /// let mut iter = symtab.iter();
    ///
    /// for i in 0 .. 5 {
    ///     let sym = iter.next().unwrap();
    ///     let data: SymDataRaw<Elf64> = sym.try_into().unwrap();
    ///
    ///     assert_eq!(data, SYMTAB_CONTENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    #[inline]
    pub fn create_split<'b, I>(buf: &'a mut [u8], syms: I) ->
        Result<(Self, &'a mut [u8]), ()>
        where I: Iterator,
              I::Item: Borrow<SymDataRaw<Offsets>>,
              Offsets: 'b {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (data, out) = create::<B, I, Offsets>(buf, syms)?;

        Ok((Symtab { byteorder: byteorder, offsets: offsets, symtab: data },
            out))
    }

    /// Attempt to create a `Symtab` in `buf` containing the symbols
    /// in `syms`.
    ///
    /// This will write the symbol table data into the buffer in the
    /// proper format for the ELF class and byte order.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the symbol table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use elf_utils::Elf64;
    /// use elf_utils::symtab::Symtab;
    /// use elf_utils::symtab::SymBase;
    /// use elf_utils::symtab::SymBind;
    /// use elf_utils::symtab::SymData;
    /// use elf_utils::symtab::SymDataRaw;
    /// use elf_utils::symtab::SymKind;
    ///
    /// const SYMTAB_CONTENTS: [SymDataRaw<Elf64>; 5] = [
    ///    SymData { name: None, value: 0, size: 0, kind: SymKind::None,
    ///              bind: SymBind::Local, section: SymBase::Undef },
    ///    SymData { name: Some(1), value: 0, size: 0, kind: SymKind::File,
    ///              bind: SymBind::Local, section: SymBase::Absolute },
    ///    SymData { name: Some(10), value: 560, size: 90,
    ///              kind: SymKind::Function, bind: SymBind::Local,
    ///              section: SymBase::Index(1) },
    ///    SymData { name: Some(20), value: 272, size: 282,
    ///              kind: SymKind::Function, bind: SymBind::Local,
    ///              section: SymBase::Index(1) },
    ///    SymData { name: None, value: 0, size: 0, kind: SymKind::Section,
    ///              bind: SymBind::Local, section: SymBase::Index(1) },
    /// ];
    ///
    /// let mut buf = [0; 128];
    /// let symtab: Symtab<'_, LittleEndian, Elf64> =
    ///     Symtab::create(&mut buf[0..], SYMTAB_CONTENTS.iter()).unwrap();
    /// let mut iter = symtab.iter();
    ///
    /// for i in 0 .. 5 {
    ///     let sym = iter.next().unwrap();
    ///     let data: SymDataRaw<Elf64> = sym.try_into().unwrap();
    ///
    ///     assert_eq!(data, SYMTAB_CONTENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    #[inline]
    pub fn create<'b, I>(buf: &'a mut [u8], syms: I) -> Result<Self, ()>
        where I: Iterator,
              I::Item: Borrow<SymDataRaw<Offsets>>,
              Self: Sized,
              Offsets: 'b {
        match Self::create_split(buf, syms) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }

    /// Get a [Sym] for the symbol at `idx`.
    ///
    /// # Errors
    ///
    /// `None` will be returned if `idx` is out of bounds.
    #[inline]
    pub fn idx(&self, idx: usize) -> Option<Sym<'a, B, Offsets>> {
        let len = self.symtab.len();
        let start = idx * Offsets::ST_ENT_SIZE;

        if start < len {
            let end = start + Offsets::ST_ENT_SIZE;

            Some(Sym { byteorder: PhantomData, offsets: PhantomData,
                       sym: &self.symtab[start .. end ] })
        } else {
            None
        }
    }

    /// Get the number of symbols in this `Symtab`.
    #[inline]
    pub fn num_syms(&self) -> usize {
        self.symtab.len() / Offsets::ST_ENT_SIZE
    }

    /// Get an iterator over this `Symtab`.
    #[inline]
    pub fn iter(&self) -> SymtabIter<'a, B, Offsets> {
        SymtabIter { byteorder: PhantomData, offsets: PhantomData,
                     symtab: self.symtab, idx: (0 as u8).into() }
    }
}

impl<'a, B, Offsets> TryFrom<&'a [u8]> for Symtab<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    type Error = SymtabError;

    /// Create a `Symtab` from the data buffer.  This will check that
    /// the data buffer is a multiple of the symbol size.
    #[inline]
    fn try_from(data: &'a [u8]) -> Result<Symtab<'a, B, Offsets>, Self::Error> {
        let len = data.len();

        if data.len() % Offsets::ST_ENT_SIZE == 0 {
            Ok(Symtab { byteorder: PhantomData, offsets: PhantomData,
                        symtab: data })
        } else {
            Err(SymtabError::BadSize(len))
        }
    }
}

impl<'a, B, Offsets> TryFrom<&'a mut [u8]> for Symtab<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    type Error = SymtabError;

    /// Create a `Symtab` from the data buffer.  This will check that
    /// the data buffer is a multiple of the symbol size.
    #[inline]
    fn try_from(data: &'a mut [u8]) ->
        Result<Symtab<'a, B, Offsets>, Self::Error> {
        let len = data.len();

        if data.len() % Offsets::ST_ENT_SIZE == 0 {
            Ok(Symtab { byteorder: PhantomData, offsets: PhantomData,
                        symtab: data })
        } else {
            Err(SymtabError::BadSize(len))
        }
    }
}

impl<'a, B, Offsets> TryFrom<&'a mut [u8]> for SymtabMut<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    type Error = SymtabError;

    /// Create a `Symtab` from the data buffer.  This will check that
    /// the data buffer is a multiple of the symbol size.
    #[inline]
    fn try_from(data: &'a mut [u8]) ->
        Result<SymtabMut<'a, B, Offsets>, Self::Error> {
        let len = data.len();

        if data.len() % Offsets::ST_ENT_SIZE == 0 {
            Ok(SymtabMut { byteorder: PhantomData, offsets: PhantomData,
                           symtab: data })
        } else {
            Err(SymtabError::BadSize(len))
        }
    }
}

impl<'a, B, Offsets> SymtabMutOps<'a, B, Offsets> for SymtabMut<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    type Iter = SymtabIter<'a, B, Offsets>;

    #[inline]
    fn idx(&'a self, idx: usize) -> Option<Sym<'a, B, Offsets>> {
        let len = self.symtab.len();
        let start = idx * Offsets::ST_ENT_SIZE;

        if start < len {
            let end = start + Offsets::ST_ENT_SIZE;

            Some(Sym { byteorder: PhantomData, offsets: PhantomData,
                       sym: &self.symtab[start .. end ] })
        } else {
            None
        }
    }

    #[inline]
    fn num_syms(&self) -> usize {
        self.symtab.len() / Offsets::ST_ENT_SIZE
    }

    #[inline]
    fn iter(&'a self) -> Self::Iter {
        SymtabIter { byteorder: PhantomData, offsets: PhantomData,
                     symtab: self.symtab, idx: (0 as u8).into() }
    }
}

impl<'a, B, Offsets> SymtabCreate<'a, B, Offsets> for SymtabMut<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    #[inline]
    fn required_bytes<'b, S, I>(syms: I) -> usize
        where I: Iterator<Item = &'b SymDataRaw<Offsets>>,
              Offsets: 'b {
        syms.count() * Offsets::ST_ENT_SIZE
    }

    #[inline]
    fn create_split<'b, I>(buf: &'a mut [u8], syms: I) ->
        Result<(Self, &'a mut [u8]), ()>
        where I: Iterator<Item = &'b SymDataRaw<Offsets>>,
              Offsets: 'b {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (data, out) = create::<B, I, Offsets>(buf, syms)?;

        Ok((SymtabMut { byteorder: byteorder, offsets: offsets, symtab: data },
            out))
    }
}

impl<Name, Section, Class> Display for SymData<Name, Section, Class>
    where Class: ElfClass,
          Section: Display,
          Name: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        let SymData { name, value, size, bind, kind, section } = self;

        match name {
            Some(name) => write!(f, concat!("  name: {}\n  kind: {}\n  ",
                                            "bind: {}\n  value: {:x}\n  ",
                                            "size: {:x}\n  section: {}"),
                       name, kind, bind, value, size, section),
            None => write!(f, concat!("  kind: {}\n  bind: {}\n  ",
                                      "value: {:x}\n  size: {:x}\n  ",
                                      "section: {}"),
                           kind, bind, value, size, section)
        }
    }
}

impl Display for SymKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            SymKind::None => write!(f, "none"),
            SymKind::Object => write!(f, "object"),
            SymKind::Function => write!(f, "function"),
            SymKind::Section => write!(f, "section"),
            SymKind::File => write!(f, "file"),
            SymKind::ThreadLocal => write!(f, "thread-local"),
            SymKind::ArchSpecific(code) =>
                write!(f, "architecture-specific ({:x})", code)
        }
    }
}

impl From<SymKind> for u8 {
    #[inline]
    fn from(kind: SymKind) -> u8 {
        match kind {
            SymKind::None => 0,
            SymKind::Object => 1,
            SymKind::Function => 2,
            SymKind::Section => 3,
            SymKind::File => 4,
            SymKind::ThreadLocal => 6,
            SymKind::ArchSpecific(code) => code
        }
    }
}

impl<'a> From<&'a SymKind> for u8 {
    #[inline]
    fn from(kind: &'a SymKind) -> u8 {
        (*kind).into()
    }
}

impl<'a> From<&'a mut SymKind> for u8 {
    #[inline]
    fn from(kind: &'a mut SymKind) -> u8 {
        (*kind).into()
    }
}

impl TryFrom<u8> for SymKind {
    type Error = u8;

    #[inline]
    fn try_from(kind: u8) -> Result<SymKind, u8> {
        match kind {
            0 => Ok(SymKind::None),
            1 => Ok(SymKind::Object),
            2 => Ok(SymKind::Function),
            3 => Ok(SymKind::Section),
            4 => Ok(SymKind::File),
            6 => Ok(SymKind::ThreadLocal),
            _ if kind >= 13 => Ok(SymKind::ArchSpecific(kind)),
            bad => Err(bad)
        }
    }
}

impl<'a> TryFrom<&'a u8> for SymKind {
    type Error = u8;

    #[inline]
    fn try_from(kind: &'a u8) -> Result<SymKind, u8> {
        SymKind::try_from(*kind)
    }
}

impl<'a> TryFrom<&'a mut u8> for SymKind {
    type Error = u8;

    #[inline]
    fn try_from(kind: &'a mut u8) -> Result<SymKind, u8> {
        SymKind::try_from(*kind)
    }
}

impl Display for SymBind {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            SymBind::Local => write!(f, "local"),
            SymBind::Global => write!(f, "global"),
            SymBind::Weak => write!(f, "weak"),
            SymBind::ArchSpecific(code) =>
                write!(f, "architecture-specific ({:x})", code)
        }
    }
}

impl From<SymBind> for u8 {
    #[inline]
    fn from(bind: SymBind) -> u8 {
        match bind {
            SymBind::Local => 0,
            SymBind::Global => 1,
            SymBind::Weak => 2,
            SymBind::ArchSpecific(code) => code
        }
    }
}

impl<'a> From<&'a SymBind> for u8 {
    #[inline]
    fn from(bind: &'a SymBind) -> u8 {
        (*bind).into()
    }
}

impl TryFrom<u8> for SymBind {
    type Error = u8;

    #[inline]
    fn try_from(bind: u8) -> Result<SymBind, u8> {
        match bind {
            0 => Ok(SymBind::Local),
            1 => Ok(SymBind::Global),
            2 => Ok(SymBind::Weak),
            _ if bind >= 13 => Ok(SymBind::ArchSpecific(bind)),
            bad => Err(bad)
        }
    }
}

impl<'a> TryFrom<&'a u8> for SymBind {
    type Error = u8;

    #[inline]
    fn try_from(bind: &'a u8) -> Result<SymBind, u8> {
        SymBind::try_from(*bind)
    }
}

impl<'a> TryFrom<&'a mut u8> for SymBind {
    type Error = u8;

    #[inline]
    fn try_from(bind: &'a mut u8) -> Result<SymBind, u8> {
        SymBind::try_from(*bind)
    }
}

impl<Section: Display, Half: LowerHex> Display for SymBase<Section, Half> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            SymBase::Undef => write!(f, "undefined"),
            SymBase::Common => write!(f, "common data"),
            SymBase::Absolute => write!(f, "absolute"),
            SymBase::Escape => write!(f, "escaped"),
            SymBase::Index(idx) => write!(f, "section {}", idx),
            SymBase::ArchSpecific(idx) =>
                write!(f, "architecture-specific ({:x})", idx),
            SymBase::OSSpecific(idx) =>
                write!(f, "OS-specific ({:x})", idx)
        }
    }
}

impl<Half: Copy> SymBase<Half, Half>
    where Half: From<u16> {
    #[inline]
    fn encode(self) -> Half {
        match self {
            SymBase::Undef => Half::from(0 as u16),
            SymBase::Absolute => Half::from(0xfff1 as u16),
            SymBase::Common => Half::from(0xfff2 as u16),
            SymBase::Escape => Half::from(0xffff as u16),
            SymBase::Index(idx) => idx,
            SymBase::ArchSpecific(code) => code,
            SymBase::OSSpecific(code) => code,
        }
    }
}

impl<Half: Copy> From<Half> for SymBase<Half, Half>
    where Half: Into<u16> {
    #[inline]
    fn from(bind: Half) -> SymBase<Half, Half> {
        match bind.into() {
            0 => SymBase::Undef,
            0xfff1 => SymBase::Absolute,
            0xfff2 => SymBase::Common,
            0xffff => SymBase::Escape,
            code if code >= 0xff00 && code < 0xff20 =>
                SymBase::ArchSpecific(bind),
            code if code >= 0xff20 && code < 0xff40 =>
                SymBase::OSSpecific(bind),
            _ => SymBase::Index(bind)
        }
    }
}

impl<'a, Half: Copy> From<&'a Half> for SymBase<Half, Half>
    where Half: Into<u16> {
    #[inline]
    fn from(bind: &'a Half) -> SymBase<Half, Half> {
        SymBase::from(*bind)
    }
}

impl<'a, Half: Copy> From<&'a mut Half> for SymBase<Half, Half>
    where Half: Into<u16> {
    #[inline]
    fn from(bind: &'a mut Half) -> SymBase<Half, Half> {
        SymBase::from(*bind)
    }
}

impl<'a, B, Offsets> WithStrtab<'a> for Sym<'a, B, Offsets>
    where Offsets: 'a + SymOffsets,
          B: ByteOrder {
    type Result = SymDataStrData<'a, Offsets>;
    type Error = StrSymError;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match project::<B, Offsets>(self.sym) {
            Ok(data) => match name_lookup(data, strtab) {
                Ok(out) => Ok(out),
                Err(_) => Err(StrSymError::BadName),
            }
            Err(SymError::BadType(bad)) => Err(StrSymError::BadType(bad)),
            Err(SymError::BadBind(bad)) => Err(StrSymError::BadBind(bad))
        }
    }
}

impl<'a, B, Offsets> WithStrtab<'a> for &'_ Sym<'a, B, Offsets>
    where Offsets: 'a + SymOffsets,
          B: ByteOrder {
    type Result = SymDataStrData<'a, Offsets>;
    type Error = StrSymError;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        self.clone().with_strtab(strtab)
    }
}

impl<'a, B, Offsets> WithStrtab<'a> for &'_ mut Sym<'a, B, Offsets>
    where Offsets: 'a + SymOffsets,
          B: ByteOrder {
    type Result = SymDataStrData<'a, Offsets>;
    type Error = StrSymError;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        self.clone().with_strtab(strtab)
    }
}

impl<'a, Offsets> TryFrom<SymDataStrData<'a, Offsets>>
    for SymDataStr<'a, Offsets>
    where Offsets: SymOffsets {
    type Error = &'a [u8];

    #[inline]
    fn try_from(sym: SymDataStrData<'a, Offsets>) ->
        Result<SymDataStr<'a, Offsets>, &'a [u8]> {
        match sym {
            SymData { name: Some(Ok(name)), value, size,
                      bind, kind, section } =>
                Ok(SymData { name: Some(name), value: value, size: size,
                             bind: bind, kind: kind, section: section }),
            SymData { name: None, value, size, bind, kind, section } =>
                Ok(SymData { name: None, value: value, size: size,
                             bind: bind, kind: kind, section: section }),
            SymData { name: Some(Err(data)), .. } => Err(data)
        }
    }
}

impl<'a, Offsets> TryFrom<&'_ mut SymDataStrData<'a, Offsets>>
    for SymDataStr<'a, Offsets>
    where Offsets: SymOffsets {
    type Error = &'a [u8];

    #[inline]
    fn try_from(sym: &'_ mut SymDataStrData<'a, Offsets>) ->
        Result<SymDataStr<'a, Offsets>, &'a [u8]> {
        SymDataStr::try_from(sym.clone())
    }
}

impl<'a, Offsets> TryFrom<&'_ SymDataStrData<'a, Offsets>>
    for SymDataStr<'a, Offsets>
    where Offsets: SymOffsets {
    type Error = &'a [u8];

    #[inline]
    fn try_from(sym: &'_ SymDataStrData<'a, Offsets>) ->
        Result<SymDataStr<'a, Offsets>, &'a [u8]> {
        SymDataStr::try_from(sym.clone())
    }
}

impl<'a, B, Offsets> TryFrom<&'_ Sym<'a, B, Offsets>> for SymDataRaw<Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    type Error = SymError;

    #[inline]
    fn try_from(sym: &'_ Sym<'a, B, Offsets>) ->
        Result<SymDataRaw<Offsets>, Self::Error> {
        project::<B, Offsets>(sym.sym)
    }
}

impl<'a, B, Offsets> TryFrom<&'_ mut Sym<'a, B, Offsets>>
    for SymDataRaw<Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    type Error = SymError;

    #[inline]
    fn try_from(sym: &'_ mut Sym<'a, B, Offsets>) ->
        Result<SymDataRaw<Offsets>, Self::Error> {
        project::<B, Offsets>(sym.sym)
    }
}

impl<'a, B, Offsets> TryFrom<Sym<'a, B, Offsets>> for SymDataRaw<Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    type Error = SymError;

    #[inline]
    fn try_from(sym: Sym<'a, B, Offsets>) ->
        Result<SymDataRaw<Offsets>, Self::Error> {
        project::<B, Offsets>(sym.sym)
    }
}

impl<'a, Name, Section, Class> WithStrtab<'a> for SymData<Name, Section, Class>
    where Class: ElfClass,
          Name: Copy + TryInto<usize> {
    type Error = Name;
    type Result = SymData<Result<&'a str, &'a [u8]>, Section, Class>;

    /// Resolve the name of the symbol, returns the name index if it
    /// is out of bounds.
    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        let SymData { name, value, size, bind, kind, section } = self;

        match name {
            Some(name) => {
                match strtab.idx(name) {
                    Ok(name) => Ok(SymData { name: Some(Ok(name)), size: size,
                                             kind: kind, value: value,
                                             section: section, bind: bind }),
                    Err(StrtabIdxError::UTF8Decode(data)) => {
                        Ok(SymData { name: Some(Err(data)), value: value,
                                     size: size, bind: bind, kind: kind,
                                     section: section })
                    },
                    _ => Err(name)
                }
            },
            None => {
                Ok(SymData { name: None, value: value, size: size,
                             bind: bind, kind: kind, section: section })
            }
        }
    }
}

impl<'a, Name, Section, Class> WithStrtab<'a>
    for &'_ mut SymData<Name, Section, Class>
    where Class: ElfClass,
          Name: Copy + TryInto<usize>,
          Section: Clone {
    type Error = Name;
    type Result = SymData<Result<&'a str, &'a [u8]>, Section, Class>;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        self.clone().with_strtab(strtab)
    }
}

impl<'a, Name, Section, Class> WithStrtab<'a>
    for &'_ SymData<Name, Section, Class>
    where Class: ElfClass,
          Name: Copy + TryInto<usize>,
          Section: Clone {
    type Error = Name;
    type Result = SymData<Result<&'a str, &'a [u8]>, Section, Class>;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        self.clone().with_strtab(strtab)
    }
}

impl<'a, B, Offsets> Iterator for SymtabIter<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    type Item = Sym<'a, B, Offsets>;

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
        let len = self.symtab.len();
        let start = (self.idx + n) * Offsets::ST_ENT_SIZE;

        if start < len {
            let end = start + Offsets::ST_ENT_SIZE;

            self.idx += n + 1;

            Some(Sym { byteorder: PhantomData, offsets: PhantomData,
                       sym: &self.symtab[start .. end ] })
        } else {
            None
        }
    }
}

impl<'a, B, Offsets> FusedIterator for SymtabIter<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {}

impl<'a, B, Offsets> ExactSizeIterator for SymtabIter<'a, B, Offsets>
    where Offsets: SymOffsets,
          B: ByteOrder {
    #[inline]
    fn len(&self) -> usize {
        (self.symtab.len() / Offsets::ST_ENT_SIZE) - self.idx
    }
}

impl Display for SymtabError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            SymtabError::BadSize(size) =>
                write!(f, "bad symbol table size {}", size)
        }
    }
}
