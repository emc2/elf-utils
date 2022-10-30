//! ELF hash table section functionality.
//!
//! This module provides a [Hashtab] type which acts as a wrapper
//! around ELF hash table section data.
//!
//! # Examples
//!
//! A `Hashtab` can be created from any slice containing binary data
//! containing a properly-formatted ELF hash table along with a
//! matching [Symtab](crate::symtab::Symtab) and
//! [Strtab](crate::strtab::Strtab) using the
//! [from_slice](Hashtab::from_slice) function.
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf64;
//! use elf_utils::hash::Hashtab;
//! use elf_utils::hash::HashtabError;
//! use elf_utils::strtab::Strtab;
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
//! const STRTAB: [u8; 39] = [
//!     0x00, 0x63, 0x72, 0x74, 0x31, 0x5f, 0x63, 0x2e,
//!     0x63, 0x00, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69,
//!     0x7a, 0x65, 0x72, 0x00, 0x68, 0x61, 0x6e, 0x64,
//!     0x6c, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x69,
//!     0x63, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x00
//! ];
//!
//! const HASHTAB: [u8; 48] = [
//!     0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let strtab: Strtab<'_> =
//!     Strtab::try_from(&STRTAB[0..]).expect("Expected success");
//! let symtab: Symtab<'_, LittleEndian, Elf64> =
//!     Symtab::try_from(&SYMTAB[0..]).unwrap();
//! let hash = Hashtab::from_slice(&HASHTAB[0..], strtab, symtab);
//!
//! assert!(hash.is_ok());
//! ```
//!
//! Once created, a `Hashtab` can lookup any named symbol by its name
//! using the [lookup](Hashtab::lookup) function:
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use core::convert::TryInto;
//! use elf_utils::Elf64;
//! use elf_utils::hash::Hashtab;
//! use elf_utils::hash::HashtabError;
//! use elf_utils::strtab::Strtab;
//! use elf_utils::strtab::WithStrtab;
//! use elf_utils::symtab::Symtab;
//! use elf_utils::symtab::SymBase;
//! use elf_utils::symtab::SymBind;
//! use elf_utils::symtab::SymData;
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
//! const HASHTAB: [u8; 48] = [
//!     0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let strtab: Strtab<'_> =
//!     Strtab::try_from(&STRTAB[0..]).expect("Expected success");
//! let symtab: Symtab<'_, LittleEndian, Elf64> =
//!     Symtab::try_from(&SYMTAB[0..]).unwrap();
//! let hash = Hashtab::from_slice(&HASHTAB[0..], strtab, symtab).unwrap();
//! let sym = hash.lookup("finalizer");
//!
//! assert!(sym.is_ok());
//!
//! let data: SymData<Result<&'_ str, &'_ [u8]>, u16, Elf64> =
//!     sym.unwrap().unwrap().with_strtab(strtab).unwrap();
//!
//! assert_eq!(data, SymData { name: Some(Ok("finalizer")), value: 560,
//!                            size: 90, kind: SymKind::Function,
//!                            bind: SymBind::Local,
//!                            section: SymBase::Index(1) });
//! ```
//!
//! A new `Hashtab` can be created from a `Symtab` and associated
//! `Strtab` and an appropriately-sized buffer with the
//! [create](Hashtab::create) and
//! [create_split](Hashtab::create_split) functions:
//!
//! ```
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf64;
//! use elf_utils::hash::Hashtab;
//! use elf_utils::strtab::Strtab;
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
//! let mut buf = [0; 48];
//! let hash = Hashtab::create(&mut buf[0..], strtab, symtab,
//!                            symtab.num_syms());
//!
//! assert!(hash.is_ok());
//! ```
use byteorder::ByteOrder;
use core::convert::TryInto;
use core::fmt::Display;
use core::fmt::Formatter;
use crate::strtab::Strtab;
use crate::strtab::WithStrtab;
use crate::symtab::Sym;
use crate::symtab::SymData;
use crate::symtab::Symtab;
use crate::symtab::SymOffsets;

const ELF_HASH_WORD_SIZE: usize = 4;
const ELF_HASH_NHASHES_START: usize = 0;
const ELF_HASH_NHASHES_SIZE: usize = ELF_HASH_WORD_SIZE;
const ELF_HASH_NHASHES_END: usize = ELF_HASH_NHASHES_START +
                                    ELF_HASH_NHASHES_SIZE;
const ELF_HASH_NCHAINS_START: usize = ELF_HASH_NHASHES_END;
const ELF_HASH_NCHAINS_SIZE: usize = ELF_HASH_WORD_SIZE;
const ELF_HASH_NCHAINS_END: usize = ELF_HASH_NCHAINS_START +
                                    ELF_HASH_NCHAINS_SIZE;
const ELF_HASH_HASHES_START: usize = ELF_HASH_NCHAINS_END;

/// Trait for datatypes that can be hashed according to the ELF standard.
///
/// The ELF standard defines its own hash function, which is likely
/// distinct from the one used by any given Rust implementation.
/// Additionally, the ELF standard is based on the ASCII format, and
/// we want to be able to work with ELF symbol names that might fail
/// UTF-8 verification.  The `ElfName` trait is designed to facilitate
/// both goals.
pub trait ElfName {
    /// Compute the hash according to the ELF standard.
    fn hash_name(&self) -> u32;

    /// Compare this name against a `str` or a `[u8]` that failed
    /// UTF-8 verification.
    fn cmp_name(&self, other: &Result<&str, &[u8]>) -> bool;
}

/// In-place read-only ELF symbol hash table.
///
/// An ELF symbol hash table is an auxillary data structure used to do
/// fast lookups on named ELF symbols in an associated ELF symbol
/// table.
///
/// A `Hashtab` is essentially a 'handle' for raw ELF data, along with
/// references to the associated [Symtab](crate::symtab::Symtab)
/// and [Strtab](crate::strtab::Strtab).  It can be used in a
/// manner similar to an ordinary hash table to look up named
/// [Sym](crate::symtab::Sym)s by their names.
///
/// A `Hashtab` can be created from a slice containing the raw ELF
/// data and the associated `Symtab` and `Strtab` using the
/// [from_slice](Hashtab::from_slice) function.
///
/// New `Hashtab`s can be created from a `Symtab` and associated
/// `Strtab` using the [create](Hashtab::create) and
/// [create_split](Hashtab::create_split) functions.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use elf_utils::Elf64;
/// use elf_utils::hash::Hashtab;
/// use elf_utils::hash::HashtabError;
/// use elf_utils::strtab::Strtab;
/// use elf_utils::strtab::WithStrtab;
/// use elf_utils::symtab::Symtab;
/// use elf_utils::symtab::SymBase;
/// use elf_utils::symtab::SymBind;
/// use elf_utils::symtab::SymData;
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
/// const HASHTAB: [u8; 48] = [
///     0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
///
/// let strtab: Strtab<'_> =
///     Strtab::try_from(&STRTAB[0..]).expect("Expected success");
/// let symtab: Symtab<'_, LittleEndian, Elf64> =
///     Symtab::try_from(&SYMTAB[0..]).unwrap();
/// let hash = Hashtab::from_slice(&HASHTAB[0..], strtab, symtab).unwrap();
///
/// assert_eq!(hash.lookup("crt1_c.c").unwrap().unwrap()
///                .with_strtab(strtab).unwrap(),
///            SymData { name: Some(Ok("crt1_c.c")), value: 0, size: 0,
///                      kind: SymKind::File, bind: SymBind::Local,
///                      section: SymBase::Absolute });
/// assert_eq!(hash.lookup("finalizer").unwrap().unwrap()
///                .with_strtab(strtab).unwrap(),
///            SymData { name: Some(Ok("finalizer")), value: 560,
///                            size: 90, kind: SymKind::Function,
///                            bind: SymBind::Local,
///                            section: SymBase::Index(1) });
/// assert_eq!(hash.lookup("handle_static_init").unwrap().unwrap()
///                .with_strtab(strtab).unwrap(),
///            SymData { name: Some(Ok("handle_static_init")), value: 272,
///                      size: 282, kind: SymKind::Function,
///                      bind: SymBind::Local, section: SymBase::Index(1) });
/// ```
#[derive(Copy, Clone)]
pub struct Hashtab<'a, B: ByteOrder, Offsets: SymOffsets> {
    symtab: Symtab<'a, B, Offsets>,
    strtab: Strtab<'a>,
    hashes: &'a [u8],
    chains: &'a [u8]
}

pub struct HashtabMut<'a, B: ByteOrder, Offsets: SymOffsets> {
    symtab: Symtab<'a, B, Offsets>,
    strtab: Strtab<'a>,
    hashes: &'a mut [u8],
    chains: &'a mut [u8]
}

/// Errors that can occur when creating `Hashtab`s from raw data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HashtabError {
    /// The buffer was too short.
    TooShort,
    /// The chain table size doesn't match the number of symbols.
    BadChains {
        /// Expected number of chains (number of symbols).
        expected: u32,
        /// Actual number of chains in the hash data.
        actual: u32
    },
    /// Bad number of hash buckets (currently, anything other than 0
    /// is supported)
    BadHashes
}

/// Create an empty hash table from the sizes of the two tables.
#[inline]
fn create_split_empty<'a, B>(buf: &'a mut [u8], nhashes: usize,
                             nchains: usize) ->
    Result<(&'a mut [u8], &'a mut [u8], &'a mut [u8]), HashtabError>
    where B: ByteOrder {
    let size = ELF_HASH_WORD_SIZE * (nhashes + nchains + 2);

    if buf.len() >= size {
        let (data, rest) = buf.split_at_mut(size);

        B::write_u32(&mut data[ELF_HASH_NHASHES_START ..
                               ELF_HASH_NHASHES_END], nhashes as u32);
        B::write_u32(&mut data[ELF_HASH_NCHAINS_START ..
                               ELF_HASH_NCHAINS_END], nchains as u32);

        let chains_start = ELF_HASH_WORD_SIZE * nhashes;
        let tabs = &mut data[ELF_HASH_HASHES_START..];
        let (hashes, chains) = tabs.split_at_mut(chains_start);

        Ok((hashes, chains, rest))
    } else {
        Err(HashtabError::TooShort)
    }
}

fn create_split_filled<'a, B, Offsets>(buf: &'a mut [u8], strtab: Strtab<'a>,
                                       symtab: Symtab<'a, B, Offsets>,
                                       nhashes: usize) ->
    Result<(&'a mut [u8], &'a mut [u8], &'a mut [u8]), ()>
    where Sym<'a, B, Offsets>: TryInto<SymData<Offsets::Word, Offsets::Half,
                                               Offsets>>,
          B: 'a + ByteOrder,
          Offsets: 'a + SymOffsets {
    let nsyms = symtab.num_syms();
    let (hashes, chains, rest) =
        match create_split_empty::<B>(buf, nhashes, nsyms) {
            Ok(trio) => trio,
            Err(_) => return Err(())
        };

    for i in 0 .. nsyms {
        match symtab.idx(i) {
            Some(sym) => match sym.try_into() {
                Ok(_) => match sym.with_strtab(strtab) {
                    Ok(SymData { name: Some(name), .. }) => {
                        let hashidx = (name.hash_name() as usize) % nhashes;
                        let oldsym = B::read_u32(&hashes[hashidx * 4 ..
                                                         (hashidx + 1) * 4]);

                        if oldsym != 0 {
                            // We're kicking someone out.  Write to the
                            // chain table
                            B::write_u32(&mut chains[i * 4 .. (i + 1) * 4],
                                         oldsym);
                        }

                        B::write_u32(&mut hashes[hashidx * 4 ..
                                                 (hashidx + 1) * 4],
                                     i as u32);
                    },
                    // This symbol has no name; skip it.
                    Ok(_) => {},
                    Err(_) => return Err(())
                },
                Err(_) => return Err(())
            },
            None => return Err(())
        }
    }

    Ok((hashes, chains, rest))
}

/// Lookup the index of the symbol with `name`, giving `Ok(None)`
/// if no such symbol is found.
fn lookup_sym<'a, B, Offsets, Name>(hashes: &'a [u8], chains: &'a [u8],
                                  symtab: Symtab<'a, B, Offsets>,
                                  strtab: Strtab<'a>, name: Name) ->
    Result<Option<Sym<'a, B, Offsets>>, ()>
    where Sym<'a, B, Offsets>: TryInto<SymData<Offsets::Word, Offsets::Half,
                                               Offsets>>,
          B: 'a + ByteOrder,
          Offsets: 'a + SymOffsets,
          Name: ElfName {
    let nhashes = hashes.len() / ELF_HASH_WORD_SIZE;
    let nchains = chains.len() / ELF_HASH_WORD_SIZE;
    let hash = name.hash_name() as usize;
    let idx = hash % nhashes;
    let offset = idx * ELF_HASH_WORD_SIZE;
    let end = offset + ELF_HASH_WORD_SIZE;
    let mut symidx = B::read_u32(&hashes[offset .. end ]);

    // It is possible to construct pathological hash tables that
    // contain looping chains.  We defeat this by bounding the
    // number of iterations to the number of chain table entries.
    for _ in 0 .. nchains {
        if (symidx as usize) < nchains {
            // Check if we're at the end of the chain.
            if symidx != 0 {
                // Non-zero index means we're still good.
                let sym = match symtab.idx(symidx as usize) {
                    Some(sym) => sym,
                    None => return Err(())
                };
                let raw: SymData<Offsets::Word, Offsets::Half, Offsets> =
                    match sym.try_into() {
                        Ok(raw) => raw,
                        Err(_) => return Err(())
                    };
                let symdata = match raw.with_strtab(strtab) {
                    Ok(symdata) => symdata,
                    Err(_) => return Err(())
                };

                // Check if the names match.
                match symdata.name {
                    Some(symname) if name.cmp_name(&symname) => {
                        // The name matched, we found the symbol.
                        return Ok(Some(sym))
                    },
                    _ => {
                        // Otherwise, look up the next index in the
                        // chain table and repeat.
                        let offset = (symidx as usize) * ELF_HASH_WORD_SIZE;
                        let end = offset + ELF_HASH_WORD_SIZE;

                        symidx = B::read_u32(&chains[offset .. end ]);
                    }
                }
            } else {
                // We've got a 0 symbol index, so we're at the end of
                // the chain.
                break
            }
        } else {
            return Err(())
        }
    }

    Ok(None)
}

impl<'a, B, Offsets> Hashtab<'a, B, Offsets>
    where Sym<'a, B, Offsets>: TryInto<SymData<Offsets::Word, Offsets::Half,
                                               Offsets>> + WithStrtab<'a>,
          B: 'a + ByteOrder,
          Offsets: 'a + SymOffsets {
    /// Create a `Hashtab` from a slice containing data, along with
    /// the associated `Strtab` and `Symtab`.
    ///
    /// # Errors
    ///
    /// Any error in [HashtabError] can occur if bad hash table data
    /// is provided.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use elf_utils::Elf64;
    /// use elf_utils::hash::Hashtab;
    /// use elf_utils::hash::HashtabError;
    /// use elf_utils::strtab::Strtab;
    /// use elf_utils::symtab::Symtab;
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
    /// const HASHTAB: [u8; 48] = [
    ///     0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    /// ];
    ///
    /// let strtab: Strtab<'_> =
    ///     Strtab::try_from(&STRTAB[0..]).expect("Expected success");
    /// let symtab: Symtab<'_, LittleEndian, Elf64> =
    ///     Symtab::try_from(&SYMTAB[0..]).unwrap();
    /// let hash = Hashtab::from_slice(&HASHTAB[0..], strtab, symtab);
    ///
    /// assert!(hash.is_ok());
    /// ```
    pub fn from_slice(data: &'a [u8], strtab: Strtab<'a>,
                      symtab: Symtab<'a, B, Offsets>) ->
        Result<Hashtab<'a, B, Offsets>, HashtabError> {
        if data.len() > ELF_HASH_WORD_SIZE * 2 {
            let nhashes = B::read_u32(&data[ELF_HASH_NHASHES_START ..
                                            ELF_HASH_NHASHES_END]) as usize;
            let nchains = B::read_u32(&data[ELF_HASH_NCHAINS_START ..
                                            ELF_HASH_NCHAINS_END]) as usize;
            let size = ELF_HASH_WORD_SIZE * (nhashes + nchains + 2);

            if nchains != symtab.num_syms() {
                Err(HashtabError::BadChains {
                    expected: symtab.num_syms() as u32,
                    actual: nchains as u32
                })
            } else if nhashes == 0 {
                Err(HashtabError::BadHashes)
            } else if data.len() < size {
                Err(HashtabError::TooShort)
            } else {
                let chains_start = ELF_HASH_WORD_SIZE * nhashes;
                let tabs = &data[ELF_HASH_HASHES_START..];
                let (hashes, chains) = tabs.split_at(chains_start);

                Ok(Hashtab { symtab: symtab, strtab: strtab,
                             hashes: hashes, chains: chains })
            }
        } else {
            Err(HashtabError::TooShort)
        }
    }

    /// Attempt to create a `Hashtab` by filling in `buf` with data
    /// from `strtab` and `symtab`.
    ///
    /// This will write the symbol hash table data into the buffer in
    /// the proper ELF format.  Returns both the `Symtab` and the
    /// remaining space if successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the symbol table doesn't
    /// fit into the provided buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use elf_utils::Elf64;
    /// use elf_utils::hash::Hashtab;
    /// use elf_utils::strtab::Strtab;
    /// use elf_utils::strtab::WithStrtab;
    /// use elf_utils::symtab::Symtab;
    /// use elf_utils::symtab::SymBase;
    /// use elf_utils::symtab::SymBind;
    /// use elf_utils::symtab::SymData;
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
    /// let mut buf = [0; 60];
    /// let (hash, rest) = Hashtab::create_split(&mut buf[0..], strtab, symtab,
    ///                                          symtab.num_syms()).unwrap();
    ///
    /// assert_eq!(rest.len(), 12);
    ///
    /// assert_eq!(hash.lookup("crt1_c.c").unwrap().unwrap()
    ///                .with_strtab(strtab).unwrap(),
    ///            SymData { name: Some(Ok("crt1_c.c")), value: 0, size: 0,
    ///                      kind: SymKind::File, bind: SymBind::Local,
    ///                      section: SymBase::Absolute });
    /// assert_eq!(hash.lookup("finalizer").unwrap().unwrap()
    ///                .with_strtab(strtab).unwrap(),
    ///            SymData { name: Some(Ok("finalizer")), value: 560,
    ///                            size: 90, kind: SymKind::Function,
    ///                            bind: SymBind::Local,
    ///                            section: SymBase::Index(1) });
    /// assert_eq!(hash.lookup("handle_static_init").unwrap().unwrap()
    ///                .with_strtab(strtab).unwrap(),
    ///            SymData { name: Some(Ok("handle_static_init")), value: 272,
    ///                      size: 282, kind: SymKind::Function,
    ///                      bind: SymBind::Local,
    ///                      section: SymBase::Index(1) });
    /// assert!(hash.lookup("not present").unwrap().is_none());
    /// ```
    #[inline]
    pub fn create_split(buf: &'a mut [u8], strtab: Strtab<'a>,
                        symtab: Symtab<'a, B, Offsets>, nhashes: usize) ->
        Result<(Hashtab<'a, B, Offsets>, &'a mut [u8]), ()> {
        match create_split_filled(buf, strtab, symtab, nhashes) {
            Ok((hashes, chains, rest)) => {
                Ok((Hashtab { symtab: symtab, strtab: strtab,
                              hashes: hashes, chains: chains }, rest))
            },
            Err(err) => Err(err)
        }
    }

    /// Attempt to create a `Hashtab` by filling in `buf` with data
    /// from `strtab` and `symtab`.
    ///
    /// This will write the symbol hash table data into the buffer in
    /// the proper ELF format.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the symbol table doesn't
    /// fit into the provided buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use elf_utils::Elf64;
    /// use elf_utils::hash::Hashtab;
    /// use elf_utils::strtab::Strtab;
    /// use elf_utils::strtab::WithStrtab;
    /// use elf_utils::symtab::Symtab;
    /// use elf_utils::symtab::SymBase;
    /// use elf_utils::symtab::SymBind;
    /// use elf_utils::symtab::SymData;
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
    /// let mut buf = [0; 48];
    /// let hash = Hashtab::create(&mut buf[0..], strtab, symtab,
    ///                            symtab.num_syms()).unwrap();
    ///
    /// assert_eq!(hash.lookup("crt1_c.c").unwrap().unwrap()
    ///                .with_strtab(strtab).unwrap(),
    ///            SymData { name: Some(Ok("crt1_c.c")), value: 0, size: 0,
    ///                      kind: SymKind::File, bind: SymBind::Local,
    ///                      section: SymBase::Absolute });
    /// assert_eq!(hash.lookup("finalizer").unwrap().unwrap()
    ///                .with_strtab(strtab).unwrap(),
    ///            SymData { name: Some(Ok("finalizer")), value: 560,
    ///                            size: 90, kind: SymKind::Function,
    ///                            bind: SymBind::Local,
    ///                            section: SymBase::Index(1) });
    /// assert_eq!(hash.lookup("handle_static_init").unwrap().unwrap()
    ///                .with_strtab(strtab).unwrap(),
    ///            SymData { name: Some(Ok("handle_static_init")), value: 272,
    ///                      size: 282, kind: SymKind::Function,
    ///                      bind: SymBind::Local,
    ///                      section: SymBase::Index(1) });
    /// ```
    #[inline]
    pub fn create(buf: &'a mut [u8], strtab: Strtab<'a>,
                  symtab: Symtab<'a, B, Offsets>, nhashes: usize) ->
        Result<Hashtab<'a, B, Offsets>, ()> {
        match Self::create_split(buf, strtab, symtab, nhashes) {
            Ok((hashtab, _)) => Ok(hashtab),
            Err(err) => Err(err)
        }
    }

    /// Look up the [Sym](crate::symtab::Sym) by `name`.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the internal hash table
    /// formatting is bad.  If `name` does not reference any symbol,
    /// `Ok(None)` will be returned.
    #[inline]
    pub fn lookup<Name>(&self, name: Name) ->
        Result<Option<Sym<'a, B, Offsets>>, ()>
        where Name: ElfName {
        lookup_sym(self.hashes, self.chains, self.symtab, self.strtab, name)
    }
}

impl<'a, B, Offsets> HashtabMut<'a, B, Offsets>
    where Sym<'a, B, Offsets>: TryInto<SymData<Offsets::Word, Offsets::Half,
                                               Offsets>> +
                               WithStrtab<'a>,
          B: 'a + ByteOrder,
          Offsets: 'a + SymOffsets {
    /// Create a `HashtabMut` from a slice containing data, along with
    /// the associated `Strtab` and `Symtab`.
    pub fn from_slice(data: &'a mut [u8], strtab: Strtab<'a>,
                      symtab: Symtab<'a, B, Offsets>) ->
        Result<HashtabMut<'a, B, Offsets>, HashtabError> {
        if data.len() > ELF_HASH_WORD_SIZE * 2 {
            let nhashes = B::read_u32(&data[ELF_HASH_NHASHES_START ..
                                            ELF_HASH_NHASHES_END]) as usize;
            let nchains = B::read_u32(&data[ELF_HASH_NCHAINS_START ..
                                            ELF_HASH_NCHAINS_END]) as usize;
            let size = ELF_HASH_WORD_SIZE * (nhashes + nchains + 2);

            if nchains != symtab.num_syms() {
                Err(HashtabError::BadChains {
                    expected: symtab.num_syms() as u32,
                    actual: nchains as u32
                })
            } else if nhashes == 0 {
                Err(HashtabError::BadHashes)
            } else if data.len() < size {
                Err(HashtabError::TooShort)
            } else {
                let chains_start = ELF_HASH_WORD_SIZE * nhashes;
                let tabs = &mut data[ELF_HASH_HASHES_START..];
                let (hashes, chains) = tabs.split_at_mut(chains_start);

                Ok(HashtabMut { symtab: symtab, strtab: strtab,
                                hashes: hashes, chains: chains })
            }
        } else {
            Err(HashtabError::TooShort)
        }
    }

    /// Create a `HashtabMut` by filling in `buf` with data from `strtab`
    /// and `symtab`.  Return the rest of the buffer.
    #[inline]
    pub fn create_split(buf: &'a mut [u8], strtab: Strtab<'a>,
                        symtab: Symtab<'a, B, Offsets>, nhashes: usize) ->
        Result<(HashtabMut<'a, B, Offsets>, &'a mut [u8]), ()> {
        match create_split_filled(buf, strtab, symtab, nhashes) {
            Ok((hashes, chains, rest)) => {
                Ok((HashtabMut { symtab: symtab, strtab: strtab,
                                 hashes: hashes, chains: chains }, rest))
            },
            Err(err) => Err(err)
        }
    }

    /// Create a `HashtabMut` by filling in `buf` with data from `strtab`
    /// and `symtab`.  Return the rest of the buffer.
    #[inline]
    pub fn create(buf: &'a mut [u8], strtab: Strtab<'a>,
                  symtab: Symtab<'a, B, Offsets>, nhashes: usize) ->
        Result<HashtabMut<'a, B, Offsets>, ()> {
        match Self::create_split(buf, strtab, symtab, nhashes) {
            Ok((hashtab, _)) => Ok(hashtab),
            Err(err) => Err(err)
        }
    }

    #[inline]
    pub fn lookup<Name>(&'a self, name: Name) ->
        Result<Option<Sym<'a, B, Offsets>>, ()>
        where Name: ElfName {
        lookup_sym(self.hashes, self.chains, self.symtab, self.strtab, name)
    }
}

impl ElfName for [u8] {
    fn hash_name(&self) -> u32 {
        let mut h = 0;

        for byte in self {
            h = (h << 4) + (*byte as u32);

            let g = h & 0xf0000000;

            if g != 0 {
                h ^= g >> 24;
                h &= !g;
            }
        }

        h
    }

    #[inline]
    fn cmp_name(&self, other: &Result<&str, &[u8]>) -> bool {
        match other {
            Ok(str) => str.as_bytes() == self,
            Err(bytes) => *bytes == self
        }
    }
}

impl ElfName for str {
    #[inline]
    fn hash_name(&self) -> u32 {
        self.as_bytes().hash_name()
    }

    #[inline]
    fn cmp_name(&self, other: &Result<&str, &[u8]>) -> bool {
        match other {
            Ok(str) => *str == self,
            Err(_) => false
        }
    }
}

impl<'a> ElfName for &'a str {
    #[inline]
    fn hash_name(&self) -> u32 {
        self.as_bytes().hash_name()
    }

    #[inline]
    fn cmp_name(&self, other: &Result<&str, &[u8]>) -> bool {
        match other {
            Ok(str) => *str == *self,
            Err(_) => false
        }
    }
}
/*
impl ElfName for String {
    #[inline]
    fn hash_name(&self) -> u32 {
        self.as_str().hash_name()
    }

    #[inline]
    fn cmp_name(&self, other: Result<&str, &[u8]>) -> bool {
        self.as_str().cmp_name(other)
    }
}
*/
impl<'a> ElfName for Result<&'a str, &'a [u8]> {
    #[inline]
    fn hash_name(&self) -> u32 {
        match self {
            Ok(str) => str.hash_name(),
            Err(str) => str.hash_name()
        }
    }

    #[inline]
    fn cmp_name(&self, other: &Result<&str, &[u8]>) -> bool {
        self == other
    }
}

impl Display for HashtabError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            HashtabError::TooShort => write!(f, "buffer too short"),
            HashtabError::BadChains { expected, actual } => {
                write!(f, "chain table is wrong size, expected: {}, actual: {}",
                       expected, actual)
            }
            HashtabError::BadHashes => write!(f, "wrong number of hash buckets")
        }
    }
}
