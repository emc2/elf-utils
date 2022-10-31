//! ELF dynamic section functionality.
//!
//! This module provides a [Dynamic] type which acts as a wrapper
//! around ELF dynamic section data.
//!
//! # Examples
//!
//! A `Dynamic` can be created from any slice containing binary data
//! that contains a properly-formatted ELF dynamic linking table:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf32;
//! use elf_utils::dynamic::Dynamic;
//! use elf_utils::dynamic::DynamicError;
//!
//! const DYNAMIC: [u8; 96] = [
//!     0x1e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
//!     0x11, 0x00, 0x00, 0x00, 0xf4, 0x07, 0x00, 0x00,
//!     0x12, 0x00, 0x00, 0x00, 0xe8, 0x05, 0x00, 0x00,
//!     0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
//!     0x0b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
//!     0x05, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
//!     0x1a, 0x00, 0x00, 0x00, 0xa8, 0xb3, 0x01, 0x00,
//!     0x1c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let dynamic: Result<Dynamic<'_, LittleEndian, Elf32>, DynamicError> =
//!     Dynamic::try_from(&DYNAMIC[0..]);
//!
//! assert!(dynamic.is_ok());
//! ```
//!
//! Indexing into a `Dynamic` with [idx](Dynamic::idx) will give a
//! [DynamicEnt], which is itself a handle on a single ELF dynamic
//! linking entry:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::Elf32;
//! use elf_utils::dynamic::Dynamic;
//!
//! const DYNAMIC: [u8; 96] = [
//!     0x1e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
//!     0x11, 0x00, 0x00, 0x00, 0xf4, 0x07, 0x00, 0x00,
//!     0x12, 0x00, 0x00, 0x00, 0xe8, 0x05, 0x00, 0x00,
//!     0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
//!     0x0b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
//!     0x05, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
//!     0x1a, 0x00, 0x00, 0x00, 0xa8, 0xb3, 0x01, 0x00,
//!     0x1c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let dynamic: Dynamic<'_, LittleEndian, Elf32> =
//!     Dynamic::try_from(&DYNAMIC[0..]).unwrap();
//!
//! assert!(dynamic.idx(0).is_some());
//! assert!(dynamic.idx(12).is_none());
//! ```
//!
//! A [DynamicEnt] can be projected to a [DynamicEntData] with the
//! [TryFrom](core::convert::TryFrom) instance:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use core::convert::TryInto;
//! use elf_utils::Elf32;
//! use elf_utils::dynamic::Dynamic;
//! use elf_utils::dynamic::DynamicEntData;
//! use elf_utils::dynamic::DynamicEntDataRaw;
//!
//! const DYNAMIC: [u8; 96] = [
//!     0x1e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
//!     0x11, 0x00, 0x00, 0x00, 0xf4, 0x07, 0x00, 0x00,
//!     0x12, 0x00, 0x00, 0x00, 0xe8, 0x05, 0x00, 0x00,
//!     0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
//!     0x06, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
//!     0x0b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
//!     0x05, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
//!     0x0a, 0x00, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
//!     0x1a, 0x00, 0x00, 0x00, 0xa8, 0xb3, 0x01, 0x00,
//!     0x1c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let dynamic: Dynamic<'_, LittleEndian, Elf32> =
//!     Dynamic::try_from(&DYNAMIC[0..]).unwrap();
//! let ent = dynamic.idx(1).unwrap();
//! let data: DynamicEntDataRaw<Elf32> = ent.try_into().unwrap();
//!
//! assert_eq!(data, DynamicEntData::Rel { tab: 0x7f4 });
//! ```

use byteorder::ByteOrder;
use core::borrow::Borrow;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::Display;
use core::fmt::Formatter;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use crate::elf::Elf32;
use crate::elf::Elf64;
use crate::elf::ElfClass;
use crate::elf::WithElfData;
use crate::hash::Hashtab;
use crate::hash::HashtabError;
use crate::reloc::Rels;
use crate::reloc::RelsError;
use crate::reloc::Relas;
use crate::reloc::RelasError;
use crate::reloc::RelOffsets;
use crate::reloc::RelaOffsets;
use crate::strtab::Strtab;
use crate::strtab::StrtabError;
use crate::strtab::StrtabIdxError;
use crate::strtab::WithStrtab;
use crate::symtab::Symtab;
use crate::symtab::SymtabError;
use crate::symtab::SymOffsets;

/// Offsets for ELF dynamic linking table entries.
///
/// This contains the various offsets for fields in an ELF dynamic
/// linking table entry for a given ELF class.
pub trait DynamicOffsets: ElfClass {
    /// Start of the ELF dynamic table entry tag field.
    const D_TAG_START: usize = 0;
    /// Size of the ELF dynamic table entry tag field.
    const D_TAG_SIZE: usize;
    /// End of the ELF dynamic table entry tag field.
    const D_TAG_END: usize = Self::D_TAG_START + Self::D_TAG_SIZE;

    /// Start of the ELF dynamic table entry val field.
    const D_VAL_START: usize = Self::D_TAG_END;
    /// Size of the ELF dynamic table entry val field.
    const D_VAL_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF dynamic table entry val field.
    const D_VAL_END: usize = Self::D_VAL_START + Self::D_VAL_SIZE;

    /// Start of the ELF dynamic table entry ptr field.
    const D_PTR_START: usize = Self::D_TAG_END;
    /// Size of the ELF dynamic table entry ptr field.
    const D_PTR_SIZE: usize = Self::ADDR_SIZE;
    /// End of the ELF dynamic table entry ptr field.
    const D_PTR_END: usize = Self::D_PTR_START + Self::D_PTR_SIZE;

    /// Size of a dynamic linking table entry.
    const DYNAMIC_SIZE: usize = Self::D_PTR_END;
    /// Size of a dynamic linking table entry as an offset.
    const DYNAMIC_SIZE_OFFSET: Self::Offset;
}

/// In-place read-only ELF dynamic linking table.
///
/// An ELF dynamic linking table is an array of data objects that
/// provide information for runtime linking to function.  Some of
/// these references have names defined in the associated string
/// table.
///
/// A `Dynamic` is essentially a 'handle' for raw ELF data.  It can be
/// used to convert an index into a [DynamicEnt] using the
/// [idx](Dynamic::idx) function, or iterated over with
/// [iter](Dynamic::iter).
///
/// A `Dynamic` can be created from raw data using the
/// [TryFrom](core::convert::TryFrom) instance.
///
/// New `Dynamic`s can be created from an iterator over
/// [DynamicEntData] with [create](Dynamic::create) or
/// [create_split](Dynamic::create_split).
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
/// use elf_utils::dynamic::Dynamic;
/// use elf_utils::dynamic::DynamicEntData;
/// use elf_utils::dynamic::DynamicEntDataRaw;
///
/// const DYNAMIC: [u8; 96] = [
///     0x1e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
///     0x11, 0x00, 0x00, 0x00, 0xf4, 0x07, 0x00, 0x00,
///     0x12, 0x00, 0x00, 0x00, 0xe8, 0x05, 0x00, 0x00,
///     0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
///     0x0b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
///     0x05, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
///     0x1a, 0x00, 0x00, 0x00, 0xa8, 0xb3, 0x01, 0x00,
///     0x1c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
/// const DYNAMIC_ENTS: [DynamicEntDataRaw<Elf32>; 12] = [
///     DynamicEntData::Flags { flags: 0x2 },
///     DynamicEntData::Rel { tab: 0x7f4 },
///     DynamicEntData::RelSize { size: 1512 },
///     DynamicEntData::RelEntSize { size: 8 },
///     DynamicEntData::Symtab { tab: 0x18c },
///     DynamicEntData::SymtabEntSize { size: 16 },
///     DynamicEntData::Strtab { tab: 0x620 },
///     DynamicEntData::StrtabSize { size: 466 },
///     DynamicEntData::Hash { tab: 0x540 },
///     DynamicEntData::FiniArray { arr: 0x1b3a8 },
///     DynamicEntData::FiniArraySize { size: 4 },
///     DynamicEntData::None
/// ];
///
/// let dynamic: Dynamic<'_, LittleEndian, Elf32> =
///     Dynamic::try_from(&DYNAMIC[0..]).unwrap();
///
/// for i in 0 .. 12 {
///     let ent = dynamic.idx(i).unwrap();
///     let data: DynamicEntDataRaw<Elf32> = ent.try_into().unwrap();
///
///     assert_eq!(data, DYNAMIC_ENTS[i]);
/// }
/// ```
#[derive(Copy, Clone)]
pub struct Dynamic<'a, B: ByteOrder, Offsets: DynamicOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8]
}

/// In-place read-only ELF dynamic linking table entry.
///
/// An ELF dynamic linking entry is a union of many different kinds of
/// information.  See [DynamicEntData] for more information.
///
/// A `DynamicEnt` is essentially a 'handle' for raw ELF data.  Note
/// that this data may not be in host byte order, and may not even
/// have the same word size.  In order to directly manipulate the
/// dynamic linking data, it must be projected into a [DynamicEntData]
/// using the [TryFrom](core::convert::TryFrom) instance in order to
/// access the dynamic linking entry's information directly.
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
/// use elf_utils::dynamic::Dynamic;
/// use elf_utils::dynamic::DynamicEntData;
/// use elf_utils::dynamic::DynamicEntDataRaw;
///
/// const DYNAMIC: [u8; 96] = [
///     0x1e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
///     0x11, 0x00, 0x00, 0x00, 0xf4, 0x07, 0x00, 0x00,
///     0x12, 0x00, 0x00, 0x00, 0xe8, 0x05, 0x00, 0x00,
///     0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
///     0x0b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
///     0x05, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
///     0x1a, 0x00, 0x00, 0x00, 0xa8, 0xb3, 0x01, 0x00,
///     0x1c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
///
/// let dynamic: Dynamic<'_, LittleEndian, Elf32> =
///     Dynamic::try_from(&DYNAMIC[0..]).unwrap();
/// let ent = dynamic.idx(1).unwrap();
/// let data: DynamicEntDataRaw<Elf32> = ent.try_into().unwrap();
///
/// assert_eq!(data, DynamicEntData::Rel { tab: 0x7f4 });
/// ```
#[derive(Copy, Clone)]
pub struct DynamicEnt<'a, B: ByteOrder, Offsets: DynamicOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8]
}

/// Iterator for [Dynamic]s.
///
/// This iterator produces [DynamicEnt]s referenceding the dynamic
/// linking entries defined in an underlying `Dynamic`.
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
/// use elf_utils::dynamic::Dynamic;
/// use elf_utils::dynamic::DynamicEntData;
/// use elf_utils::dynamic::DynamicEntDataRaw;
///
/// const DYNAMIC: [u8; 96] = [
///     0x1e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
///     0x11, 0x00, 0x00, 0x00, 0xf4, 0x07, 0x00, 0x00,
///     0x12, 0x00, 0x00, 0x00, 0xe8, 0x05, 0x00, 0x00,
///     0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
///     0x06, 0x00, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00,
///     0x0b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
///     0x05, 0x00, 0x00, 0x00, 0x20, 0x06, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x00, 0xd2, 0x01, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00,
///     0x1a, 0x00, 0x00, 0x00, 0xa8, 0xb3, 0x01, 0x00,
///     0x1c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
/// const DYNAMIC_ENTS: [DynamicEntDataRaw<Elf32>; 12] = [
///     DynamicEntData::Flags { flags: 0x2 },
///     DynamicEntData::Rel { tab: 0x7f4 },
///     DynamicEntData::RelSize { size: 1512 },
///     DynamicEntData::RelEntSize { size: 8 },
///     DynamicEntData::Symtab { tab: 0x18c },
///     DynamicEntData::SymtabEntSize { size: 16 },
///     DynamicEntData::Strtab { tab: 0x620 },
///     DynamicEntData::StrtabSize { size: 466 },
///     DynamicEntData::Hash { tab: 0x540 },
///     DynamicEntData::FiniArray { arr: 0x1b3a8 },
///     DynamicEntData::FiniArraySize { size: 4 },
///     DynamicEntData::None
/// ];
///
/// let dynamic: Dynamic<'_, LittleEndian, Elf32> =
///     Dynamic::try_from(&DYNAMIC[0..]).unwrap();
/// let mut iter = dynamic.iter();
///
/// for i in 0 .. 12 {
///     let ent = iter.next().unwrap();
///     let data: DynamicEntDataRaw<Elf32> = ent.try_into().unwrap();
///
///     assert_eq!(data, DYNAMIC_ENTS[i]);
/// }
/// ```
#[derive(Clone)]
pub struct DynamicIter<'a, B: ByteOrder, Offsets: DynamicOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a [u8],
    idx: usize
}

/// Iterator for dependencies expressed in a dynamic setting.
#[derive(Clone)]
pub struct DynamicNeededIter<'a, B: ByteOrder, Offsets: DynamicOffsets> {
    inner: DynamicIter<'a, B, Offsets>
}

/// Errors that can occur creating a [Dynamic].
///
/// The only error that can occur is if the data is not a multiple of
/// the size of a dynamic entry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DynamicError {
    /// Buffer size was not a multiple of a dynamic entry.
    BadSize(usize)
}

/// Errors that can occur when projecting a [DynamicEnt] into
/// [DynamicEntData].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DynamicEntDataError<Class: ElfClass> {
    /// Bad relocation type code.
    BadRelocs(Class::Offset),
    /// Type code could not be decoded.
    ///
    /// This can only happen if the type code value is too large for
    /// the host `usize`.
    BadKind(Class::Offset),
}

/// Errors that can occur when projecting a [DynamicEnt] into
/// [DynamicEntData].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DynamicEntStrsError<Class: ElfClass> {
    /// Bad relocation type code.
    BadRelocs(Class::Offset),
    /// Type code could not be decoded.
    ///
    /// This can only happen if the type code value is too large for
    /// the host `usize`.
    BadKind(Class::Offset),
    /// Name index was out-of-bounds.
    BadName(Class::Offset),
}

/// Projected ELF dynamic linking data.
///
/// This is a representation of an ELF dynamic linking entry projected
/// into a form that can be directly manipulated.  This data can also
/// be used to create a new [Dynamic] using [create](Dynamic::create)
/// or [create_split](Dynamic::create_split).
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum DynamicEntData<Name, Idx, Class: ElfClass> {
    /// Null data.
    None,
    /// Indicates the name of a required library.
    Needed {
        /// Name of the required library.
        name: Name
    },
    /// Indicates the size of the PLT/GOT relocation table.
    PLTRelSize {
        /// Size of the relocation table for the PLT/GOT.
        size: Class::Offset
    },
    /// Provides the PLT or GOT.
    PLTGOT {
        /// Address of the PLT or GOT.
        tab: Class::Addr
    },
    /// Provides the hash table for the associated symbol table.
    Hash {
        /// Address of the symbol hash table.
        tab: Class::Addr
    },
    /// Provides the associated symbol table.
    Symtab {
        /// Address of the symbol table.
        tab: Class::Addr
    },
    /// Provides the associated string table.
    Strtab {
        /// Address of the string table.
        tab: Class::Addr
    },
    /// Provides the associated relocation table with explicit addends.
    Rela {
        /// Address of the relacation table with explicit addends.
        tab: Class::Addr
    },
    /// Indicates the size of the associated relocation table with
    /// explicit addends.
    RelaSize {
        /// Size of the relocation table with explicit addends.
        size: Class::Offset
    },
    /// Indicates the size of the entries in the associated relocation
    /// table with explicit addends.
    RelaEntSize {
        /// Size of the entries in the relocation table with explicit
        /// addends.
        size: Class::Offset
    },
    /// Indicates the size of the associated string table.
    StrtabSize {
        /// Size of the string table.
        size: Class::Offset
    },
    /// Indicates the size of the entries in the associated symbol table.
    SymtabEntSize {
        /// Size of the entries in the symbol table.
        size: Class::Offset
    },
    /// Provides the initialization function.
    Init {
        /// Address of the initialization function.
        func: Class::Addr
    },
    /// Provides the finalization function.
    Fini {
        /// Address of the finalization function.
        func: Class::Addr
    },
    /// Indicates the name of this shared object.
    Name {
        /// Name of this shared object.
        name: Name
    },
    /// Indicates the search path for shared objects.
    RPath {
        /// Search path for shared objects.
        path: Name
    },
    /// Indicates that the search for symbols should start in the
    /// shared object itself, not the executable.
    Symbolic,
    /// Provides the associated relocation table with implicit addends.
    Rel {
        /// Address of the relacation table with implicit addends.
        tab: Class::Addr
    },
    /// Indicates the size of the associated relocation table with
    /// implicit addends.
    RelSize {
        /// Size of the relocation table with implicit addends.
        size: Class::Offset
    },
    /// Indicates the size of the entries in the associated relocation
    /// table with implicit addends.
    RelEntSize {
        /// Size of the entries in the relocation table with implicit
        /// addends.
        size: Class::Offset
    },
    /// Indicates whether the PLT relocation entries have explicit addends.
    PLTRela {
        /// True if the PLT relocation entries have explicit addends.
        rela: bool
    },
    /// Provides the a pointer to debugging information.
    Debug {
        /// Address of the debugging information.
        tab: Class::Addr
    },
    /// If present, indicates that relocation entries may modify a
    /// non-writable segment.
    TextRel,
    /// Provides the relocation table associated with the PLT.
    JumpRel {
        /// Address of the relocation table associated with the PLT.
        tab: Class::Addr
    },
    /// Indicates that relocations should be processed eagerly.
    BindNow,
    /// Provides the initialization function array.
    InitArray {
        /// Address of the initialization function array.
        arr: Class::Addr
    },
    /// Provides the finalization function array.
    FiniArray {
        /// Address of the finalization function array.
        arr: Class::Addr
    },
    /// Provides the initialization function array size.
    InitArraySize {
        /// Address of the initialization function array size.
        size: Class::Offset
    },
    /// Provides the finalization function array size.
    FiniArraySize {
        /// Address of the finalization function array.
        size: Class::Offset
    },
    /// Provides the flags.
    Flags {
        /// The flags field.
        flags: Class::Offset
    },
    /// Provides the pre-initialization function array.
    PreInitArray {
        /// Address of the pre-initialization function array.
        arr: Class::Addr
    },
    /// Provides the pre-initialization function array size.
    PreInitArraySize {
        /// Address of the pre-initialization function array size.
        size: Class::Offset
    },
    /// Provides the section header index of the associated symbol table.
    SymtabIdx {
        /// Section header index of the symbol table.
        idx: Idx
    },
    /// Unknown dynamic information type.
    Unknown {
        /// The tag for this information.
        tag: Class::Offset,
        /// Information field as word.
        info: Class::Offset
    }
}

/// Summary of the dynamic section.
///
/// This summarizes most of the dynamic section entries.  It does not,
/// however, include `Needed` entries.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct DynamicInfo<Name, Flags, Strs, Syms, Hash,
                       Rel, Rela, B, Offsets: ElfClass> {
    byteorder: PhantomData<B>,
    /// Pointer to the string table for the dynamic symbol table.
    pub strtab: Strs,
    /// Pointer to the dynamic symbol table.
    pub symtab: Syms,
    /// Pointer to the hash section associated with the dynamic symbol table.
    pub hash: Hash,
    /// Name of the shared object.
    pub name: Option<Name>,
    /// Run path of the shared object.
    pub rpath: Option<Name>,
    /// Whether or not to bind immediately.
    pub bind_now: bool,
    /// Whether relocations can modify the `.text` section.
    pub text_rel: bool,
    /// Whether symbols should be resolved from the shared object first.
    pub symbolic: bool,
    /// Dynamic relocation information.
    pub reloc: Option<Relocs<Rel, Rela>>,
    /// Pointer to debugging information.
    pub debug: Option<Offsets::Addr>,
    /// Relocation information for the PLT/GOT.
    pub jump_reloc: Option<Relocs<Rel, Rela>>,
    /// Relocation flags.
    pub flags: Option<Flags>,
    /// Pointer to the initialization function.
    pub init: Option<Offsets::Addr>,
    /// Pointer to the finalizer function.
    pub fini: Option<Offsets::Addr>,
    /// The pre-initialization function array.
    pub pre_init_arr: Option<AddrRange<Offsets>>,
    /// The initialization function array.
    pub init_arr: Option<AddrRange<Offsets>>,
    /// The finalizer function array.
    pub fini_arr: Option<AddrRange<Offsets>>,
    /// Section header index of the symbol table.
    pub symtab_idx: Option<Offsets::Offset>
}

/// Errors that can occur when converting a [`DynamicInfoRaw`] with
/// using the [WithElfData] instance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DynamicInfoWithDataError<Offsets: ElfClass> {
    /// Offset is out of bounds.
    OutOfBounds(usize),
    /// Offset can't be converted to `usize`.
    BadOffset(Offsets::Offset),
    /// Address can't be converted to `usize`.
    BadAddr(Offsets::Addr)
}

/// Errors that can occur when converting a [`DynamicInfoData`] with
/// using the [TryFrom] instance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DynamicInfoFullStrDataError<Offsets: ElfClass> {
    /// Errors parsing a [Strtab].
    Strtab(StrtabError),
    /// Errors parsing a [Symtab].
    Symtab(SymtabError),
    /// Errors parsing a [Hashtab].
    Hash(HashtabError),
    /// Errors parsing a [Relas].
    Rela(RelasError),
    /// Errors parsing a [Rela].
    Rel(RelsError),
    /// Index out of bounds when looking up a name or rpath.
    StrtabOutOfBounds(Offsets::Offset)
}

/// [DynamicInfo] as projected from a [Dynamic] using the [TryFrom]
/// instance.
pub type DynamicInfoRaw<B, Offsets> =
    DynamicInfo<<Offsets as ElfClass>::Offset, <Offsets as ElfClass>::Offset,
                AddrRange<Offsets>, <Offsets as ElfClass>::Addr,
                <Offsets as ElfClass>::Addr, AddrRange<Offsets>,
                AddrRange<Offsets>, B, Offsets>;

/// [DynamicInfo] as projected from a [DynamicInfoRaw] using the [WithElfData]
/// instance.
pub type DynamicInfoData<'a, B, Offsets> =
    DynamicInfo<<Offsets as ElfClass>::Offset, <Offsets as ElfClass>::Offset,
                &'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8], B, Offsets>;

pub type DynamicInfoFullStrData<'a, B, Offsets> =
    DynamicInfo<Result<&'a str, &'a [u8]>, <Offsets as ElfClass>::Offset,
                Strtab<'a>, Symtab<'a, B, Offsets>, Hashtab<'a, B, Offsets>,
                Rels<'a, B, Offsets>, Relas<'a, B, Offsets>, B, Offsets>;

pub type DynamicInfoFullStrs<'a, B, Offsets> =
    DynamicInfo<&'a str, <Offsets as ElfClass>::Offset, Strtab<'a>,
                Symtab<'a, B, Offsets>, Hashtab<'a, B, Offsets>,
                Rels<'a, B, Offsets>, Relas<'a, B, Offsets>, B, Offsets>;

/// Enum for relocations.
///
/// This can support relocations with or without explicit addends.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Relocs<Rel, Rela> {
    /// Relocations without explicit addends.
    Rel(Rel),
    /// Relocations with explicit addends.
    Rela(Rela)
}

/// Address range, with a size.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct AddrRange<Offsets: ElfClass> {
    /// Starting address.
    pub addr: Offsets::Addr,
    /// Address range size.
    pub size: Offsets::Offset
}

/// Errors that can occur collecting dynamic entries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum DynamicInfoError<Offsets: ElfClass> {
    /// Errors projecting a [DynamicEntDataRaw].
    EntDataError(DynamicEntDataError<Offsets>),
    /// PLT/GOT relocation information is incomplete.
    IncompleteJumpRelocs,
    /// Pre-initialization array information is incomplete.
    IncompletePreInitArr,
    /// Initialization array information is incomplete.
    IncompleteInitArr,
    /// Finalization array information is incomplete.
    IncompleteFiniArr,
    /// String table information is incomplete
    IncompleteStrtab,
    /// Dynamic relocation information is incomplete.
    IncompleteRelas,
    /// Dynamic relocation information is incomplete.
    IncompleteRels,
    /// Multiple entries of type [DynamicEntData::PLTRelSize](PLTRelSize).
    MultiplePLTRelSize,
    /// Multiple entries of type [DynamicEntData::JumpRel](JumpRel).
    MultipleJumpRel,
    /// Multiple entries of type [DynamicEntData::PLTRela](PLTRela).
    MultiplePLTRela,
    /// Multiple entries of type [DynamicEntData::PLTGOT](PLTGOT).
    MultiplePLTGOT,
    /// Multiple entries of type [DynamicEntData::Symtab](Symtab).
    MultipleSymtab,
    /// Multiple entries of type [DynamicEntData::Strtab](Strtab).
    MultipleStrtab,
    /// Multiple entries of type [DynamicEntData::Flags](Flags).
    MultipleFlags,
    /// Multiple entries of type [DynamicEntData::Relas](Relas).
    MultipleRelas,
    /// Multiple entries of type [DynamicEntData::RPath](RPath).
    MultipleRPath,
    /// Multiple entries of type [DynamicEntData::Debug](Debug).
    MultipleDebug,
    /// Multiple entries of type [DynamicEntData::Name](Name).
    MultipleName,
    /// Multiple entries of type [DynamicEntData::Hash](Hash).
    MultipleHash,
    /// Multiple entries of type [DynamicEntData::Rels](Rels).
    MultipleRels,
    /// Multiple entries of type [DynamicEntData::Fini](Fini).
    MultipleFini,
    /// Multiple entries of type [DynamicEntData::Init](Init).
    MultipleInit,
    /// Multiple entries of type [DynamicEntData::PreInitArr](PreInitArr).
    MultiplePreInitArr,
    /// Multiple entries of type [DynamicEntData::InitArr](InitArr).
    MultipleInitArr,
    /// Multiple entries of type [DynamicEntData::FiniArr](FiniArr).
    MultipleFiniArr,
    /// Multiple entries of type [DynamicEntData::SymtabIdx](SymtabIdx).
    MultipleSymtabIdx,
    /// Missing string table information.
    NoStrtab,
    /// Missing symbol table information.
    NoSymtab,
    /// Missing hash table information.
    NoHash,
    /// Relocation entry size has the wrong value.
    BadRelEntSize,
    /// Relocation entry size has the wrong value.
    BadRelaEntSize,
    /// Symbol table entry size has the wrong value.
    BadSymtabEntSize,
}

/// Type synonym for [DynamicEntData] as projected from a [DynamicEnt].
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [DynamicEnt].  This is also used in [Dynamic::create] and
/// [Dynamic::create_split].
pub type DynamicEntDataRaw<Class> =
    DynamicEntData<<Class as ElfClass>::Offset, <Class as ElfClass>::Offset,
                   Class>;

/// Type synonym for [DynamicEntData] as projected from a
/// [DynamicEnt], with symbol names represented as the results of
/// UTF-8 decoding.
///
/// This is obtained from the [WithStrtab] instance on a
/// [DynamicEntDataRaw].
pub type DynamicEntDataStrData<'a, Class> =
    DynamicEntData<Result<&'a str, &'a [u8]>, <Class as ElfClass>::Offset,
                   Class>;

/// Type synonym for [DynamicEntData] as projected from a
/// [DynamicEnt], with symbol names represented as fully-resolved `&'a
/// str`s.
///
/// This is obtained from the [WithStrtab] instance on a
/// [DynamicEntDataRaw].
pub type DynamicEntDataStr<'a, Class> =
    DynamicEntData<&'a str, <Class as ElfClass>::Offset, Class>;

#[inline]
fn project<'a, B, Offsets>(data: &'a [u8]) ->
    Result<DynamicEntData<Offsets::Offset, Offsets::Offset, Offsets>,
           DynamicEntDataError<Offsets>>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    let tag = Offsets::read_offset::<B>(&data[Offsets::D_TAG_START ..
                                              Offsets::D_TAG_END]);

    match tag.try_into() {
        Ok(0) => Ok(DynamicEntData::None),
        Ok(1) => {
            let name = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                       Offsets::D_VAL_END]);

            Ok(DynamicEntData::Needed { name: name })
        },
        Ok(2) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::PLTRelSize { size: val })
        },
        Ok(3) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::PLTGOT { tab: ptr })
        },
        Ok(4) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::Hash { tab: ptr })
        },
        Ok(5) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::Strtab { tab: ptr })
        },
        Ok(6) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::Symtab { tab: ptr })
        },
        Ok(7) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::Rela { tab: ptr })
        },
        Ok(8) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::RelaSize { size: val })
        },
        Ok(9) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::RelaEntSize { size: val })
        },
        Ok(10) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::StrtabSize { size: val })
        },
        Ok(11) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::SymtabEntSize { size: val })
        },
        Ok(12) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::Init { func: ptr })
        },
        Ok(13) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::Fini { func: ptr })
        },
        Ok(14) => {
            let name = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                       Offsets::D_VAL_END]);

            Ok(DynamicEntData::Name { name: name })
        },
        Ok(15) => {
            let path = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                       Offsets::D_VAL_END]);

            Ok(DynamicEntData::RPath { path: path })
        },
        Ok(16) => Ok(DynamicEntData::Symbolic),
        Ok(17) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::Rel { tab: ptr })
        },
        Ok(18) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::RelSize { size: val })
        },
        Ok(19) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::RelEntSize { size: val })
        },
        Ok(20) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            match val.try_into() {
                Ok(7) => Ok(DynamicEntData::PLTRela { rela: true }),
                Ok(17) => Ok(DynamicEntData::PLTRela { rela: false }),
                Ok(_) => Err(DynamicEntDataError::BadRelocs(val)),
                Err(_) => Err(DynamicEntDataError::BadRelocs(val))
            }
        },
        Ok(21) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::Debug { tab: ptr })
        },
        Ok(22) => Ok(DynamicEntData::TextRel),
        Ok(23) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::JumpRel { tab: ptr })
        },
        Ok(24) => Ok(DynamicEntData::TextRel),
        Ok(25) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::InitArray { arr: ptr })
        },
        Ok(26) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::FiniArray { arr: ptr })
        },
        Ok(27) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::InitArraySize { size: val })
        },
        Ok(28) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::FiniArraySize { size: val })
        },
        Ok(29) => {
            let path = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                       Offsets::D_VAL_END]);

            Ok(DynamicEntData::RPath { path: path })
        },
        Ok(30) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_PTR_START ..
                                                      Offsets::D_PTR_END]);

            Ok(DynamicEntData::Flags { flags: val })
        },
        Ok(32) => {
            let ptr = Offsets::read_addr::<B>(&data[Offsets::D_PTR_START ..
                                                    Offsets::D_PTR_END]);

            Ok(DynamicEntData::PreInitArray { arr: ptr })
        },
        Ok(33) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::PreInitArraySize { size: val })
        },
        Ok(34) => {
            let idx = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::SymtabIdx { idx: idx })
        },
        Ok(_) => {
            let val = Offsets::read_offset::<B>(&data[Offsets::D_VAL_START ..
                                                      Offsets::D_VAL_END]);

            Ok(DynamicEntData::Unknown { tag: tag, info: val })
        },
        Err(_) => Err(DynamicEntDataError::BadKind(tag))
    }
}

fn create<'a, B, I, Offsets>(buf: &'a mut [u8], ents: I) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where I: Iterator,
          I::Item: Borrow<DynamicEntData<Offsets::Offset, Offsets::Offset,
                                         Offsets>>,
          Offsets: DynamicOffsets,
          B: ByteOrder {
    let len = buf.len();
    let mut idx = 0;

    for ent in ents {
        let ent = ent.borrow();

        if idx + Offsets::DYNAMIC_SIZE <= len {
            let data = &mut buf[idx .. idx + Offsets::DYNAMIC_SIZE];

            match ent {
                DynamicEntData::None => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (0 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               (0 as u8).into());
                },
                DynamicEntData::Needed { name } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (1 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *name);
                },
                DynamicEntData::PLTRelSize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (2 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::PLTGOT { tab } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (3 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *tab);
                },
                DynamicEntData::Hash { tab } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (4 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *tab);
                },
                DynamicEntData::Strtab { tab } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (5 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *tab);
                },
                DynamicEntData::Symtab { tab } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (6 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *tab);
                },
                DynamicEntData::Rela { tab } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (7 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *tab);
                },
                DynamicEntData::RelaSize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (8 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::RelaEntSize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (9 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::StrtabSize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (10 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::SymtabEntSize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (11 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::Init { func } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (12 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *func);
                },
                DynamicEntData::Fini { func } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (13 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *func);
                },
                DynamicEntData::Name { name } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (14 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_PTR_START ..
                                                         Offsets::D_PTR_END],
                                               *name);
                },
                DynamicEntData::RPath { path } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (29 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_PTR_START ..
                                                         Offsets::D_PTR_END],
                                               *path);
                },
                DynamicEntData::Symbolic => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (16 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               (0 as u8).into());
                },
                DynamicEntData::Rel { tab } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (17 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *tab);
                },
                DynamicEntData::RelSize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (18 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::RelEntSize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (19 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::PLTRela { rela: true } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (20 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               (7 as u8).into());
                },
                DynamicEntData::PLTRela { rela: false } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (20 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               (17 as u8).into());
                },
                DynamicEntData::Debug { tab } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (21 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *tab);
                },
                DynamicEntData::TextRel => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (22 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               (0 as u8).into());
                },
                DynamicEntData::JumpRel { tab } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (23 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *tab);
                },
                DynamicEntData::BindNow => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (24 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               (0 as u8).into());
                },
                DynamicEntData::InitArray { arr } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (25 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *arr);
                },
                DynamicEntData::FiniArray { arr } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (26 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *arr);
                },
                DynamicEntData::InitArraySize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (27 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::FiniArraySize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (28 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::Flags { flags } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (30 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *flags);
                },
                DynamicEntData::PreInitArray { arr } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (32 as u8).into());
                    Offsets::write_addr::<B>(&mut data[Offsets::D_PTR_START ..
                                                       Offsets::D_PTR_END],
                                             *arr);
                },
                DynamicEntData::PreInitArraySize { size } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (33 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *size);
                },
                DynamicEntData::SymtabIdx { idx } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               (34 as u8).into());
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *idx);
                },
                DynamicEntData::Unknown { tag, info } => {
                    Offsets::write_offset::<B>(&mut data[Offsets::D_TAG_START ..
                                                         Offsets::D_TAG_END],
                                               *tag);
                    Offsets::write_offset::<B>(&mut data[Offsets::D_VAL_START ..
                                                         Offsets::D_VAL_END],
                                               *info);
                }
            }

            idx += Offsets::DYNAMIC_SIZE;
        } else {
            return Err(())
        }
    }

    Ok(buf.split_at_mut(idx))
}

impl DynamicOffsets for Elf32 {
    const D_TAG_SIZE: usize = Self::WORD_SIZE;
    const DYNAMIC_SIZE_OFFSET: Self::Offset = Self::DYNAMIC_SIZE as u32;
}

impl DynamicOffsets for Elf64 {
    const D_TAG_SIZE: usize = Self::OFFSET_SIZE;
    const DYNAMIC_SIZE_OFFSET: Self::Offset = Self::DYNAMIC_SIZE as u64;
}

impl<'a, B, Offsets: DynamicOffsets> TryFrom<&'a [u8]>
    for Dynamic<'a, B, Offsets>
    where B: ByteOrder {
    type Error = DynamicError;

    /// Create a `Dynamic` from the data buffer.  This will check that
    /// the data buffer is a multiple of the dynamic linking entry
    /// size.
    #[inline]
    fn try_from(data: &'a [u8]) ->
        Result<Dynamic<'a, B, Offsets>, Self::Error> {
        let len = data.len();

        if data.len() % Offsets::DYNAMIC_SIZE == 0 {
            Ok(Dynamic { byteorder: PhantomData, offsets: PhantomData,
                         data: data })
        } else {
            Err(DynamicError::BadSize(len))
        }
    }
}

impl<'a, B, Offsets: DynamicOffsets> TryFrom<&'a mut [u8]>
    for Dynamic<'a, B, Offsets>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    type Error = DynamicError;

    /// Create a `Dynamic` from the data buffer.  This will check that
    /// the data buffer is a multiple of the dynamic linking entry
    /// size.
    #[inline]
    fn try_from(data: &'a mut [u8]) ->
        Result<Dynamic<'a, B, Offsets>, Self::Error> {
        let len = data.len();

        if data.len() % Offsets::DYNAMIC_SIZE == 0 {
            Ok(Dynamic { byteorder: PhantomData, offsets: PhantomData,
                         data: data })
        } else {
            Err(DynamicError::BadSize(len))
        }
    }
}

/// Calculate the number of bytes required to represent the dynamic
/// linking table containing `ents`.
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
/// use elf_utils::dynamic::Dynamic;
/// use elf_utils::dynamic::DynamicEntData;
/// use elf_utils::dynamic::DynamicEntDataRaw;
/// use elf_utils::dynamic;
///
/// const DYNAMIC_ENTS: [DynamicEntDataRaw<Elf32>; 12] = [
///     DynamicEntData::Flags { flags: 0x2 },
///     DynamicEntData::Rel { tab: 0x7f4 },
///     DynamicEntData::RelSize { size: 1512 },
///     DynamicEntData::RelEntSize { size: 8 },
///     DynamicEntData::Symtab { tab: 0x18c },
///     DynamicEntData::SymtabEntSize { size: 16 },
///     DynamicEntData::Strtab { tab: 0x620 },
///     DynamicEntData::StrtabSize { size: 466 },
///     DynamicEntData::Hash { tab: 0x540 },
///     DynamicEntData::FiniArray { arr: 0x1b3a8 },
///     DynamicEntData::FiniArraySize { size: 4 },
///     DynamicEntData::None
/// ];
///
/// assert_eq!(dynamic::required_bytes(DYNAMIC_ENTS.iter().map(|x| *x)), 96);
/// ```
#[inline]
pub fn required_bytes<I, Offsets>(ents: I) -> usize
    where I: Iterator<Item = DynamicEntDataRaw<Offsets>>,
          Offsets: DynamicOffsets {
    ents.count() * Offsets::DYNAMIC_SIZE
}

impl<'a, B, Offsets> Dynamic<'a, B, Offsets>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    /// Attempt to create a `Dynamic` in `buf` containing the dynamic
    /// linking entries in `ents`.
    ///
    /// This will write the dynamic linking table data into the buffer
    /// in the proper format for the ELF class and byte order.
    /// Returns both the `Dynamic` and the remaining space if
    /// successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the dynamic linking table doesn't
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
    /// use elf_utils::dynamic::Dynamic;
    /// use elf_utils::dynamic::DynamicEntData;
    /// use elf_utils::dynamic::DynamicEntDataRaw;
    /// use elf_utils::dynamic;
    ///
    /// const DYNAMIC_ENTS: [DynamicEntDataRaw<Elf32>; 12] = [
    ///     DynamicEntData::Flags { flags: 0x2 },
    ///     DynamicEntData::Rel { tab: 0x7f4 },
    ///     DynamicEntData::RelSize { size: 1512 },
    ///     DynamicEntData::RelEntSize { size: 8 },
    ///     DynamicEntData::Symtab { tab: 0x18c },
    ///     DynamicEntData::SymtabEntSize { size: 16 },
    ///     DynamicEntData::Strtab { tab: 0x620 },
    ///     DynamicEntData::StrtabSize { size: 466 },
    ///     DynamicEntData::Hash { tab: 0x540 },
    ///     DynamicEntData::FiniArray { arr: 0x1b3a8 },
    ///     DynamicEntData::FiniArraySize { size: 4 },
    ///     DynamicEntData::None
    /// ];
    ///
    /// let mut buf = [0; 100];
    /// let res: Result<(Dynamic<'_, LittleEndian, Elf32>,
    ///                     &'_ mut [u8]), ()> =
    ///     Dynamic::create_split(&mut buf[0..],
    ///                           DYNAMIC_ENTS.iter().map(|x| *x));
    /// let (dynamic, rest) = res.unwrap();
    ///
    /// assert_eq!(rest.len(), 4);
    ///
    /// let mut iter = dynamic.iter();
    ///
    /// for i in 0 .. 12 {
    ///     let sym = iter.next().unwrap();
    ///     let data: DynamicEntDataRaw<Elf32> =
    ///         sym.try_into().unwrap();
    ///
    ///     assert_eq!(data, DYNAMIC_ENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    #[inline]
    pub fn create_split<I>(buf: &'a mut [u8], ents: I) ->
        Result<(Self, &'a mut [u8]), ()>
        where I: Iterator,
              I::Item: Borrow<DynamicEntDataRaw<Offsets>> {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (data, out) = create::<B, I, Offsets>(buf, ents)?;

        Ok((Dynamic { byteorder: byteorder, offsets: offsets, data: data },
            out))
    }

    /// Attempt to create a `Dynamic` in `buf` containing the dynamic
    /// linking entries in `ents`.
    ///
    /// This will write the dynamic linking table data into the buffer
    /// in the proper format for the ELF class and byte order.
    /// Returns both the `Dynamic` and the remaining space if
    /// successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the dynamic linking table
    /// doesn't fit into the provided memory.
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
    /// use elf_utils::dynamic::Dynamic;
    /// use elf_utils::dynamic::DynamicEntData;
    /// use elf_utils::dynamic::DynamicEntDataRaw;
    /// use elf_utils::dynamic;
    ///
    /// const DYNAMIC_ENTS: [DynamicEntDataRaw<Elf32>; 12] = [
    ///     DynamicEntData::Flags { flags: 0x2 },
    ///     DynamicEntData::Rel { tab: 0x7f4 },
    ///     DynamicEntData::RelSize { size: 1512 },
    ///     DynamicEntData::RelEntSize { size: 8 },
    ///     DynamicEntData::Symtab { tab: 0x18c },
    ///     DynamicEntData::SymtabEntSize { size: 16 },
    ///     DynamicEntData::Strtab { tab: 0x620 },
    ///     DynamicEntData::StrtabSize { size: 466 },
    ///     DynamicEntData::Hash { tab: 0x540 },
    ///     DynamicEntData::FiniArray { arr: 0x1b3a8 },
    ///     DynamicEntData::FiniArraySize { size: 4 },
    ///     DynamicEntData::None
    /// ];
    ///
    /// let mut buf = [0; 100];
    /// let res: Result<Dynamic<'_, LittleEndian, Elf32>, ()> =
    ///     Dynamic::create(&mut buf[0..], DYNAMIC_ENTS.iter().map(|x| *x));
    /// let dynamic = res.unwrap();
    /// let mut iter = dynamic.iter();
    ///
    /// for i in 0 .. 12 {
    ///     let sym = iter.next().unwrap();
    ///     let data: DynamicEntDataRaw<Elf32> =
    ///         sym.try_into().unwrap();
    ///
    ///     assert_eq!(data, DYNAMIC_ENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    #[inline]
    pub fn create<I>(buf: &'a mut [u8], ents: I) -> Result<Self, ()>
        where I: Iterator,
              I::Item: Borrow<DynamicEntDataRaw<Offsets>> {
        match Self::create_split(buf, ents) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }

    /// Get a [DynamicEnt] for the dynamic linking entry at `idx`.
    ///
    /// # Errors
    ///
    /// `None` will be returned if `idx` is out of bounds.
    #[inline]
    pub fn idx(&self, idx: usize) -> Option<DynamicEnt<'a, B, Offsets>> {
        let len = self.data.len();
        let start = idx * Offsets::DYNAMIC_SIZE;

        if start < len {
            let end = start + Offsets::DYNAMIC_SIZE;

            Some(DynamicEnt { byteorder: PhantomData, offsets: PhantomData,
                              data: &self.data[start .. end ] })
        } else {
            None
        }
    }

    /// Get the number of dynamic linking entries in this `Dynamic`.
    #[inline]
    pub fn num_ents(&self) -> usize {
        self.data.len() / Offsets::DYNAMIC_SIZE
    }

    /// Get an iterator over this `Dynamic`.
    #[inline]
    pub fn iter(&self) -> DynamicIter<'a, B, Offsets> {
        DynamicIter { byteorder: PhantomData, offsets: PhantomData,
                      data: self.data, idx: 0 }
    }
}

impl<'a, B, Offsets> TryFrom<Dynamic<'a, B, Offsets>>
    for DynamicInfoRaw<B, Offsets>
    where Offsets: DynamicOffsets + RelOffsets + RelaOffsets + SymOffsets,
          B: ByteOrder {
    type Error = DynamicInfoError<Offsets>;

    fn try_from(dynamic: Dynamic<'a, B, Offsets>) -> Result<Self, Self::Error> {
        let mut pltgot = None;
        let mut hash = None;
        let mut symtab = None;
        let mut strtab = None;
        let mut strtab_size = None;
        let mut name = None;
        let mut rpath = None;
        let mut relas = None;
        let mut relas_size = None;
        let mut rels = None;
        let mut rels_size = None;
        let mut init = None;
        let mut fini = None;
        let mut pre_init_arr = None;
        let mut pre_init_arr_size = None;
        let mut init_arr = None;
        let mut init_arr_size = None;
        let mut fini_arr = None;
        let mut fini_arr_size = None;
        let mut debug = None;
        let mut jump_rel = None;
        let mut jump_rel_size = None;
        let mut bind_now = false;
        let mut text_rel = false;
        let mut symbolic = false;
        let mut jump_rela = None;
        let mut flags = None;
        let mut symtab_idx = None;

        for ent in dynamic.iter() {
            let ent: DynamicEntDataRaw<Offsets> = match ent.try_into() {
                Ok(ent) => Ok(ent),
                Err(err) => Err(DynamicInfoError::EntDataError(err))
            }?;

            match ent {
                DynamicEntData::PLTRelSize { size } => match jump_rel_size {
                    Some(_) => {
                        return Err(DynamicInfoError::MultiplePLTRelSize)
                    },
                    None => {
                        jump_rel_size = Some(size)
                    }
                },
                DynamicEntData::PLTGOT { tab } => match pltgot {
                    Some(_) => {
                        return Err(DynamicInfoError::MultiplePLTGOT)
                    },
                    None => {
                        pltgot = Some(tab)
                    }
                },
                DynamicEntData::Hash { tab } => match hash {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleHash)
                    },
                    None => {
                        hash = Some(tab)
                    }
                },
                DynamicEntData::Symtab { tab } => match symtab {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleSymtab)
                    },
                    None => {
                        symtab = Some(tab)
                    }
                },
                DynamicEntData::Strtab { tab } => match strtab {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleStrtab)
                    },
                    None => {
                        strtab = Some(tab)
                    }
                },
                DynamicEntData::Rela { tab } => match relas {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleRelas)
                    },
                    None => {
                        relas = Some(tab)
                    }
                },
                DynamicEntData::RelaSize { size } => match relas_size {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleRelas)
                    },
                    None => {
                        relas_size = Some(size)
                    }
                },
                DynamicEntData::RelaEntSize { size }
                if size != Offsets::RELA_SIZE_OFFSET => {
                    return Err(DynamicInfoError::BadRelaEntSize)
                },
                DynamicEntData::StrtabSize { size } => match strtab_size {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleStrtab)
                    },
                    None => {
                        strtab_size = Some(size)
                    }
                },
                DynamicEntData::SymtabEntSize { size }
                if size != Offsets::ST_ENT_SIZE_OFFSET => {
                    return Err(DynamicInfoError::BadSymtabEntSize)
                },
                DynamicEntData::Init { func } => match init {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleInit)
                    },
                    None => {
                        init = Some(func)
                    }
                },
                DynamicEntData::Fini { func } => match fini {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleFini)
                    },
                    None => {
                        fini = Some(func)
                    }
                },
                DynamicEntData::Name { name: addr } => match name {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleName)
                    },
                    None => {
                        name = Some(addr)
                    }
                },
                DynamicEntData::RPath { path: addr } => match rpath {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleRPath)
                    },
                    None => {
                        rpath = Some(addr)
                    }
                },
                DynamicEntData::Symbolic => {
                    symbolic = true
                },
                DynamicEntData::Rel { tab } => match rels {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleRels)
                    },
                    None => {
                        rels = Some(tab)
                    }
                },
                DynamicEntData::RelSize { size } => match rels_size {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleRels)
                    },
                    None => {
                        rels_size = Some(size)
                    }
                },
                DynamicEntData::RelEntSize { size }
                if size != Offsets::REL_SIZE_OFFSET => {
                    return Err(DynamicInfoError::BadRelEntSize)
                },
                DynamicEntData::PLTRela { rela } => match jump_rela {
                    Some(_) => {
                        return Err(DynamicInfoError::MultiplePLTRela)
                    },
                    None => {
                        jump_rela = Some(rela)
                    }
                },
                DynamicEntData::Debug { tab } => match debug {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleDebug)
                    },
                    None => {
                        debug = Some(tab)
                    }
                },
                DynamicEntData::TextRel => {
                    text_rel = true
                },
                DynamicEntData::JumpRel { tab } => match jump_rel {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleJumpRel)
                    },
                    None => {
                        jump_rel = Some(tab)
                    }
                },
                DynamicEntData::BindNow => {
                    bind_now = true
                },
                DynamicEntData::InitArray { arr } => match init_arr {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleInitArr)
                    },
                    None => {
                        init_arr = Some(arr)
                    }
                },
                DynamicEntData::InitArraySize { size } => match init_arr_size {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleInitArr)
                    },
                    None => {
                        init_arr_size = Some(size)
                    }
                },
                DynamicEntData::FiniArray { arr } => match fini_arr {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleFiniArr)
                    },
                    None => {
                        fini_arr = Some(arr)
                    }
                },
                DynamicEntData::FiniArraySize { size } => match fini_arr_size {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleFiniArr)
                    },
                    None => {
                        fini_arr_size = Some(size)
                    }
                },
                DynamicEntData::PreInitArray { arr } => match pre_init_arr {
                    Some(_) => {
                        return Err(DynamicInfoError::MultiplePreInitArr)
                    },
                    None => {
                        pre_init_arr = Some(arr)
                    }
                },
                DynamicEntData::PreInitArraySize { size } =>
                    match pre_init_arr_size {
                        Some(_) => {
                            return Err(DynamicInfoError::MultiplePreInitArr)
                        },
                        None => {
                            pre_init_arr_size = Some(size)
                        }
                    },
                DynamicEntData::Flags { flags: val } => match flags {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleFlags)
                    },
                    None => {
                        flags = Some(val)
                    }
                },
                DynamicEntData::SymtabIdx { idx } => match symtab_idx {
                    Some(_) => {
                        return Err(DynamicInfoError::MultipleSymtabIdx)
                    },
                    None => {
                        symtab_idx = Some(idx)
                    }
                },
                _ => {}
            }
        }

        let pre_init_arr = match (pre_init_arr, pre_init_arr_size) {
            (Some(arr), Some(size)) => Ok(Some(AddrRange { addr: arr,
                                                           size: size })),
            (None, None) => Ok(None),
            _ => Err(DynamicInfoError::IncompletePreInitArr)
        }?;
        let init_arr = match (init_arr, init_arr_size) {
            (Some(arr), Some(size)) => Ok(Some(AddrRange { addr: arr,
                                                           size: size })),
            (None, None) => Ok(None),
            _ => Err(DynamicInfoError::IncompleteInitArr)
        }?;
        let fini_arr = match (fini_arr, fini_arr_size) {
            (Some(arr), Some(size)) => Ok(Some(AddrRange { addr: arr,
                                                           size: size })),
            (None, None) => Ok(None),
            _ => Err(DynamicInfoError::IncompleteFiniArr)
        }?;
        let strtab = match (strtab, strtab_size) {
            (Some(tab), Some(size)) => Ok(AddrRange { addr: tab, size: size }),
            (None, None) => Err(DynamicInfoError::NoStrtab),
            _ => Err(DynamicInfoError::IncompleteStrtab)
        }?;
        let symtab = match symtab {
            Some(tab) => Ok(tab),
            None => Err(DynamicInfoError::NoSymtab)
        }?;
        let hash = match hash {
            Some(tab) => Ok(tab),
            None => Err(DynamicInfoError::NoSymtab)
        }?;
        let reloc = match (relas, relas_size, rels, rels_size) {
            (Some(tab), Some(size), None, None) =>
                Ok(Some(Relocs::Rela(AddrRange { addr: tab, size: size }))),
            (None, None, Some(tab), Some(size)) =>
                Ok(Some(Relocs::Rel(AddrRange { addr: tab, size: size }))),
            (None, None, None, None) => Ok(None),
            (Some(_), None, None, None) =>
                Err(DynamicInfoError::IncompleteRelas),
            (None, Some(_), None, None) =>
                Err(DynamicInfoError::IncompleteRelas),
            (None, None, Some(_), None) =>
                Err(DynamicInfoError::IncompleteRels),
            (None, None, None, Some(_)) =>
                Err(DynamicInfoError::IncompleteRels),
            _ => Err(DynamicInfoError::IncompleteFiniArr)
        }?;
        let jump_reloc = match (jump_rel, jump_rel_size, jump_rela) {
            (Some(tab), Some(size), Some(true)) =>
                Ok(Some(Relocs::Rela(AddrRange { addr: tab, size: size }))),
            (Some(tab), Some(size), Some(false)) =>
                Ok(Some(Relocs::Rel(AddrRange { addr: tab, size: size }))),
            (None, None, None) => Ok(None),
            _ => Err(DynamicInfoError::IncompleteJumpRelocs),
        }?;

        Ok(DynamicInfo { name: name, rpath: rpath, bind_now: bind_now,
                         hash: hash, symtab: symtab, debug: debug,
                         jump_reloc: jump_reloc, strtab: strtab,
                         symtab_idx: symtab_idx, reloc: reloc,
                         text_rel: text_rel, symbolic: symbolic,
                         flags: flags, init: init, fini: fini,
                         fini_arr: fini_arr, init_arr: init_arr,
                         pre_init_arr: pre_init_arr,
                         byteorder: PhantomData })

    }
}

impl<'a, B, Offsets> TryFrom<&'_ Dynamic<'a, B, Offsets>>
    for DynamicInfoRaw<B, Offsets>
    where Offsets: DynamicOffsets + RelOffsets + RelaOffsets + SymOffsets,
          B: ByteOrder {
    type Error = DynamicInfoError<Offsets>;

    fn try_from(dynamic: &'_ Dynamic<'a, B, Offsets>) ->
        Result<Self, Self::Error> {
        DynamicInfo::try_from(dynamic.clone())
    }
}

impl<'a, B, Offsets> TryFrom<&'_ mut Dynamic<'a, B, Offsets>>
    for DynamicInfoRaw<B, Offsets>
    where Offsets: DynamicOffsets + RelOffsets + RelaOffsets + SymOffsets,
          B: ByteOrder {
    type Error = DynamicInfoError<Offsets>;

    fn try_from(dynamic: &'_ mut Dynamic<'a, B, Offsets>) ->
        Result<Self, Self::Error> {
        DynamicInfo::try_from(dynamic.clone())
    }
}

impl<'a, B, Offsets> TryFrom<DynamicEnt<'a, B, Offsets>>
    for DynamicEntDataRaw<Offsets>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    type Error = DynamicEntDataError<Offsets>;

    #[inline]
    fn try_from(ent: DynamicEnt<'a, B, Offsets>) ->
        Result<DynamicEntData<Offsets::Offset, Offsets::Offset, Offsets>,
               Self::Error> {
        project::<B, Offsets>(ent.data)
    }
}

impl<'a, B, Offsets> TryFrom<&'_ DynamicEnt<'a, B, Offsets>>
    for DynamicEntDataRaw<Offsets>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    type Error = DynamicEntDataError<Offsets>;

    #[inline]
    fn try_from(ent: &'_ DynamicEnt<'a, B, Offsets>) ->
        Result<DynamicEntData<Offsets::Offset, Offsets::Offset, Offsets>,
               Self::Error> {
        project::<B, Offsets>(ent.data)
    }
}

impl<'a, B, Offsets> TryFrom<&'_ mut DynamicEnt<'a, B, Offsets>>
    for DynamicEntDataRaw<Offsets>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    type Error = DynamicEntDataError<Offsets>;

    #[inline]
    fn try_from(ent: &'_ mut DynamicEnt<'a, B, Offsets>) ->
        Result<DynamicEntData<Offsets::Offset, Offsets::Offset, Offsets>,
               Self::Error> {
        project::<B, Offsets>(ent.data)
    }
}

impl<'a, B, Offsets> WithElfData<'a> for DynamicInfoRaw<B, Offsets>
    where Offsets: ElfClass + SymOffsets,
          B: ByteOrder {
    type Result = DynamicInfoData<'a, B, Offsets>;
    type Error = DynamicInfoWithDataError<Offsets>;

    fn with_elf_data(self, data: &'a [u8]) ->
        Result<Self::Result, Self::Error> {
        let DynamicInfo { name, rpath, bind_now, text_rel, symbolic,
                          hash, symtab, strtab, reloc, debug,
                          jump_reloc, flags, init, fini, pre_init_arr,
                          init_arr, fini_arr, symtab_idx, .. } = self;
        // Convert strtab.
        let AddrRange { addr: strtab_addr, size: strtab_size } = strtab;
        let strtab_start: usize = match strtab_addr.try_into() {
            Ok(addr) => Ok(addr),
            Err(_) => Err(DynamicInfoWithDataError::BadAddr(strtab_addr))
        }?;
        let strtab_size: usize = match strtab_addr.try_into() {
            Ok(size) => Ok(size),
            Err(_) => Err(DynamicInfoWithDataError::BadOffset(strtab_size))
        }?;
        let strtab_end = strtab_start + strtab_size;

        let strtab = if strtab_start > data.len() {
            Err(DynamicInfoWithDataError::OutOfBounds(strtab_start))
        } else if strtab_end > data.len() {
            Err(DynamicInfoWithDataError::OutOfBounds(strtab_end))
        } else {
            Ok(&data[strtab_start .. strtab_end])
        }?;
        // We have to peek at the hash table to get its size.
        let hash_start: usize = match hash.try_into() {
            Ok(addr) => Ok(addr),
            Err(_) => Err(DynamicInfoWithDataError::BadAddr(hash))
        }?;
        let hash_peek_end = hash_start + 8;
        let hash_peek = &data[hash_start .. hash_peek_end];
        let nhashes = B::read_u32(&hash_peek[0 .. 4]) as usize;
        let nchains = B::read_u32(&hash_peek[4 .. 8]) as usize;
        let hash_size = 4 * (nhashes + nchains + 2);
        let hash_end = hash_start + hash_size;
        let hash = &data[hash_start .. hash_end];
        // The nchains value also gives us the size of the symbol table.
        let symtab_start: usize = match symtab.try_into() {
            Ok(addr) => Ok(addr),
            Err(_) => Err(DynamicInfoWithDataError::BadAddr(symtab))
        }?;
        let symtab_size = nchains * Offsets::ST_ENT_SIZE;
        let symtab_end = symtab_start + symtab_size;
        let symtab = &data[symtab_start .. symtab_end];
        let reloc = match reloc {
            Some(Relocs::Rel(AddrRange { addr, size })) => {
                let start: usize = match addr.try_into() {
                    Ok(addr) => Ok(addr),
                    Err(_) => Err(DynamicInfoWithDataError::BadAddr(addr))
                }?;
                let size: usize = match size.try_into() {
                    Ok(size) => Ok(size),
                    Err(_) => Err(DynamicInfoWithDataError::BadOffset(size))
                }?;
                let end = start + size;

                if start > data.len() {
                    Err(DynamicInfoWithDataError::OutOfBounds(start))
                } else if end > data.len() {
                    Err(DynamicInfoWithDataError::OutOfBounds(end))
                } else {
                    Ok(Some(Relocs::Rel(&data[start .. end])))
                }
            },
            Some(Relocs::Rela(AddrRange { addr, size })) => {
                let start: usize = match addr.try_into() {
                    Ok(addr) => Ok(addr),
                    Err(_) => Err(DynamicInfoWithDataError::BadAddr(addr))
                }?;
                let size: usize = match size.try_into() {
                    Ok(size) => Ok(size),
                    Err(_) => Err(DynamicInfoWithDataError::BadOffset(size))
                }?;
                let end = start + size;

                if start > data.len() {
                    Err(DynamicInfoWithDataError::OutOfBounds(start))
                } else if end > data.len() {
                    Err(DynamicInfoWithDataError::OutOfBounds(end))
                } else {
                    Ok(Some(Relocs::Rela(&data[start .. end])))
                }
            },
            None => Ok(None)
        }?;
        let jump_reloc = match jump_reloc {
            Some(Relocs::Rel(AddrRange { addr, size })) => {
                let start: usize = match addr.try_into() {
                    Ok(addr) => Ok(addr),
                    Err(_) => Err(DynamicInfoWithDataError::BadAddr(addr))
                }?;
                let size: usize = match size.try_into() {
                    Ok(size) => Ok(size),
                    Err(_) => Err(DynamicInfoWithDataError::BadOffset(size))
                }?;
                let end = start + size;

                if start > data.len() {
                    Err(DynamicInfoWithDataError::OutOfBounds(start))
                } else if end > data.len() {
                    Err(DynamicInfoWithDataError::OutOfBounds(end))
                } else {
                    Ok(Some(Relocs::Rel(&data[start .. end])))
                }
            },
            Some(Relocs::Rela(AddrRange { addr, size })) => {
                let start: usize = match addr.try_into() {
                    Ok(addr) => Ok(addr),
                    Err(_) => Err(DynamicInfoWithDataError::BadAddr(addr))
                }?;
                let size: usize = match size.try_into() {
                    Ok(size) => Ok(size),
                    Err(_) => Err(DynamicInfoWithDataError::BadOffset(size))
                }?;
                let end = start + size;

                if start > data.len() {
                    Err(DynamicInfoWithDataError::OutOfBounds(start))
                } else if end > data.len() {
                    Err(DynamicInfoWithDataError::OutOfBounds(end))
                } else {
                    Ok(Some(Relocs::Rela(&data[start .. end])))
                }
            },
            None => Ok(None)
        }?;

        Ok(DynamicInfo { name, rpath, bind_now, text_rel, symbolic,
                         hash, symtab, strtab, reloc, debug,
                         jump_reloc, flags, init, fini, pre_init_arr,
                         init_arr, fini_arr, symtab_idx,
                         byteorder: PhantomData })
    }
}

impl<'a, B, Offsets> TryFrom<DynamicInfoData<'a, B, Offsets>>
    for DynamicInfoFullStrData<'a, B, Offsets>
    where Offsets: 'a + DynamicOffsets + RelaOffsets + RelOffsets + SymOffsets,
          B: 'a + ByteOrder {
    type Error = DynamicInfoFullStrDataError<Offsets>;

    #[inline]
    fn try_from(data: DynamicInfoData<'a, B, Offsets>) ->
        Result<DynamicInfoFullStrData<'a, B, Offsets>, Self::Error> {
        let DynamicInfo { name, rpath, bind_now, text_rel, symbolic,
                          hash, symtab, strtab, reloc, debug,
                          jump_reloc, flags, init, fini, pre_init_arr,
                          init_arr, fini_arr, symtab_idx, .. } = data;
        let strtab: Strtab<'a> = match strtab.try_into() {
            Ok(strtab) => Ok(strtab),
            Err(err) => Err(DynamicInfoFullStrDataError::Strtab(err))
        }?;
        let symtab: Symtab<'a, B, Offsets> = match symtab.try_into() {
            Ok(symtab) => Ok(symtab),
            Err(err) => Err(DynamicInfoFullStrDataError::Symtab(err))
        }?;
        let hash: Hashtab<'a, B, Offsets> =
            match Hashtab::from_slice(hash, strtab, symtab) {
                Ok(hash) => Ok(hash),
                Err(err) => Err(DynamicInfoFullStrDataError::Hash(err))
            }?;
        let reloc = match reloc {
            Some(Relocs::Rela(reloc)) => match reloc.try_into() {
                Ok(reloc) => Ok(Some(Relocs::Rela(reloc))),
                Err(err) => Err(DynamicInfoFullStrDataError::Rela(err))
            },
            Some(Relocs::Rel(reloc)) => match reloc.try_into() {
                Ok(reloc) => Ok(Some(Relocs::Rel(reloc))),
                Err(err) => Err(DynamicInfoFullStrDataError::Rel(err))
            },
            None => Ok(None)
        }?;
        let jump_reloc = match jump_reloc {
            Some(Relocs::Rela(reloc)) => match reloc.try_into() {
                Ok(reloc) => Ok(Some(Relocs::Rela(reloc))),
                Err(err) => Err(DynamicInfoFullStrDataError::Rela(err))
            },
            Some(Relocs::Rel(reloc)) => match reloc.try_into() {
                Ok(reloc) => Ok(Some(Relocs::Rel(reloc))),
                Err(err) => Err(DynamicInfoFullStrDataError::Rel(err))
            },
            None => Ok(None)
        }?;
        let name = match name {
            Some(name) => match strtab.idx(name) {
                Ok(str) => Ok(Some(Ok(str))),
                Err(StrtabIdxError::OutOfBounds(idx)) =>
                    Err(DynamicInfoFullStrDataError
                        ::StrtabOutOfBounds(idx)),
                Err(StrtabIdxError::UTF8Decode(data)) =>
                    Ok(Some(Err(data)))
            },
            None => Ok(None)
        }?;
        let rpath = match rpath {
            Some(path) => match strtab.idx(path) {
                Ok(str) => Ok(Some(Ok(str))),
                Err(StrtabIdxError::OutOfBounds(idx)) =>
                    Err(DynamicInfoFullStrDataError
                        ::StrtabOutOfBounds(idx)),
                Err(StrtabIdxError::UTF8Decode(data)) =>
                    Ok(Some(Err(data)))
            },
            None => Ok(None)
        }?;

        Ok(DynamicInfo { name, rpath, bind_now, text_rel, symbolic,
                         hash, symtab, strtab, reloc, debug,
                         jump_reloc, flags, init, fini, pre_init_arr,
                         init_arr, fini_arr, symtab_idx,
                         byteorder: PhantomData })
    }
}

impl<'a, B, Offsets> TryFrom<DynamicInfoFullStrData<'a, B, Offsets>>
    for DynamicInfoFullStrs<'a, B, Offsets>
    where Offsets: 'a + DynamicOffsets + RelaOffsets + RelOffsets + SymOffsets,
          B: 'a + ByteOrder {
    type Error = &'a [u8];

    #[inline]
    fn try_from(data: DynamicInfoFullStrData<'a, B, Offsets>) ->
        Result<DynamicInfoFullStrs<'a, B, Offsets>, Self::Error> {
        let DynamicInfo { name, rpath, bind_now, text_rel, symbolic,
                          hash, symtab, strtab, reloc, debug,
                          jump_reloc, flags, init, fini, pre_init_arr,
                          init_arr, fini_arr, symtab_idx, .. } = data;
        let name = match name {
            Some(Ok(str)) => Ok(Some(str)),
            Some(Err(buf)) => Err(buf),
            None => Ok(None)
        }?;
        let rpath = match rpath {
            Some(Ok(str)) => Ok(Some(str)),
            Some(Err(buf)) => Err(buf),
            None => Ok(None)
        }?;

        Ok(DynamicInfo { name, rpath, bind_now, text_rel, symbolic,
                         hash, symtab, strtab, reloc, debug,
                         jump_reloc, flags, init, fini, pre_init_arr,
                         init_arr, fini_arr, symtab_idx,
                         byteorder: PhantomData })
    }
}

impl<'a, B, Offsets> TryFrom<&'_ DynamicInfoFullStrData<'a, B, Offsets>>
    for DynamicInfoFullStrs<'a, B, Offsets>
    where Offsets: 'a + DynamicOffsets + RelaOffsets + RelOffsets + SymOffsets,
          B: 'a + ByteOrder {
    type Error = &'a [u8];

    #[inline]
    fn try_from(data: &'_ DynamicInfoFullStrData<'a, B, Offsets>) ->
        Result<DynamicInfoFullStrs<'a, B, Offsets>, Self::Error> {
        DynamicInfo::try_from(data.clone())
    }
}

impl<'a, B, Offsets> TryFrom<&'_ mut DynamicInfoFullStrData<'a, B, Offsets>>
    for DynamicInfoFullStrs<'a, B, Offsets>
    where Offsets: 'a + DynamicOffsets + RelaOffsets + RelOffsets + SymOffsets,
          B: 'a + ByteOrder {
    type Error = &'a [u8];

    #[inline]
    fn try_from(data: &'_ mut DynamicInfoFullStrData<'a, B, Offsets>) ->
        Result<DynamicInfoFullStrs<'a, B, Offsets>, Self::Error> {
        DynamicInfo::try_from(data.clone())
    }
}

impl<'a, B, Offsets> TryFrom<&'_ DynamicInfoData<'a, B, Offsets>>
    for DynamicInfoFullStrData<'a, B, Offsets>
    where Offsets: 'a + DynamicOffsets + RelaOffsets + RelOffsets + SymOffsets,
          B: 'a + ByteOrder {
    type Error = DynamicInfoFullStrDataError<Offsets>;

    #[inline]
    fn try_from(data: &'_ DynamicInfoData<'a, B, Offsets>) ->
        Result<DynamicInfoFullStrData<'a, B, Offsets>, Self::Error> {
        DynamicInfo::try_from(data.clone())
    }
}

impl<'a, B, Offsets> TryFrom<&'_ mut DynamicInfoData<'a, B, Offsets>>
    for DynamicInfoFullStrData<'a, B, Offsets>
    where Offsets: 'a + DynamicOffsets + RelaOffsets + RelOffsets + SymOffsets,
          B: 'a + ByteOrder {
    type Error = DynamicInfoFullStrDataError<Offsets>;

    #[inline]
    fn try_from(data: &'_ mut DynamicInfoData<'a, B, Offsets>) ->
        Result<DynamicInfoFullStrData<'a, B, Offsets>, Self::Error> {
        DynamicInfo::try_from(data.clone())
    }
}

impl<'a, B, Offsets> WithStrtab<'a> for DynamicEnt<'a, B, Offsets>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    type Error = DynamicEntStrsError<Offsets>;
    type Result = DynamicEntData<Result<&'a str, &'a [u8]>,
                                 Offsets::Offset, Offsets>;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match project::<B, Offsets>(self.data) {
            Ok(DynamicEntData::None) =>
                Ok(DynamicEntData::None),
            Ok(DynamicEntData::Needed { name }) => match strtab.idx(name) {
                Ok(name) => Ok(DynamicEntData::Needed { name: Ok(name) }),
                Err(StrtabIdxError::UTF8Decode(data)) =>
                    Ok(DynamicEntData::Needed { name: Err(data) }),
                _ => Err(DynamicEntStrsError::BadName(name))
            },
            Ok(DynamicEntData::PLTRelSize { size }) =>
                Ok(DynamicEntData::PLTRelSize { size: size }),
            Ok(DynamicEntData::PLTGOT { tab }) =>
                Ok(DynamicEntData::PLTGOT { tab: tab }),
            Ok(DynamicEntData::Hash { tab }) =>
                Ok(DynamicEntData::Hash { tab: tab }),
            Ok(DynamicEntData::Symtab { tab }) =>
                Ok(DynamicEntData::Symtab { tab: tab }),
            Ok(DynamicEntData::Strtab { tab }) =>
                Ok(DynamicEntData::Strtab { tab: tab }),
            Ok(DynamicEntData::Rela { tab }) =>
                Ok(DynamicEntData::Rela { tab: tab }),
            Ok(DynamicEntData::RelaSize { size }) =>
                Ok(DynamicEntData::RelaSize { size: size }),
            Ok(DynamicEntData::RelaEntSize { size }) =>
                Ok(DynamicEntData::RelaEntSize { size: size }),
            Ok(DynamicEntData::StrtabSize { size }) =>
                Ok(DynamicEntData::StrtabSize { size: size }),
            Ok(DynamicEntData::SymtabEntSize { size }) =>
                Ok(DynamicEntData::SymtabEntSize { size: size }),
            Ok(DynamicEntData::Init { func }) =>
                Ok(DynamicEntData::Init { func: func }),
            Ok(DynamicEntData::Fini { func }) =>
                Ok(DynamicEntData::Fini { func: func }),
            Ok(DynamicEntData::Name { name }) => match strtab.idx(name) {
                Ok(name) => Ok(DynamicEntData::Name { name: Ok(name) }),
                Err(StrtabIdxError::UTF8Decode(data)) =>
                    Ok(DynamicEntData::Name { name: Err(data) }),
                _ => Err(DynamicEntStrsError::BadName(name))
            },
            Ok(DynamicEntData::RPath { path }) => match strtab.idx(path) {
                Ok(path) => Ok(DynamicEntData::RPath { path: Ok(path) }),
                Err(StrtabIdxError::UTF8Decode(data)) =>
                    Ok(DynamicEntData::RPath { path: Err(data) }),
                _ => Err(DynamicEntStrsError::BadName(path))
            },
            Ok(DynamicEntData::Symbolic) =>
                Ok(DynamicEntData::Symbolic),
            Ok(DynamicEntData::Rel { tab }) =>
                Ok(DynamicEntData::Rel { tab: tab }),
            Ok(DynamicEntData::RelSize { size }) =>
                Ok(DynamicEntData::RelSize { size: size }),
            Ok(DynamicEntData::RelEntSize { size }) =>
                Ok(DynamicEntData::RelEntSize { size: size }),
            Ok(DynamicEntData::PLTRela { rela }) =>
                Ok(DynamicEntData::PLTRela { rela: rela }),
            Ok(DynamicEntData::Debug { tab }) =>
                Ok(DynamicEntData::Debug { tab: tab }),
            Ok(DynamicEntData::TextRel) => Ok(DynamicEntData::TextRel),
            Ok(DynamicEntData::JumpRel { tab }) =>
                Ok(DynamicEntData::JumpRel { tab: tab }),
            Ok(DynamicEntData::BindNow) => Ok(DynamicEntData::BindNow),
            Ok(DynamicEntData::InitArray { arr }) =>
                Ok(DynamicEntData::InitArray { arr: arr }),
            Ok(DynamicEntData::FiniArray { arr }) =>
                Ok(DynamicEntData::FiniArray { arr: arr }),
            Ok(DynamicEntData::InitArraySize { size }) =>
                Ok(DynamicEntData::InitArraySize { size: size }),
            Ok(DynamicEntData::FiniArraySize { size }) =>
                Ok(DynamicEntData::FiniArraySize { size: size }),
            Ok(DynamicEntData::Flags { flags }) =>
                Ok(DynamicEntData::Flags { flags: flags }),
            Ok(DynamicEntData::PreInitArray { arr }) =>
                Ok(DynamicEntData::PreInitArray { arr: arr }),
            Ok(DynamicEntData::PreInitArraySize { size }) =>
                Ok(DynamicEntData::PreInitArraySize { size: size }),
            Ok(DynamicEntData::SymtabIdx { idx }) =>
                Ok(DynamicEntData::SymtabIdx { idx: idx }),
            Ok(DynamicEntData::Unknown { tag, info }) =>
                Ok(DynamicEntData::Unknown { tag: tag, info: info }),
            Err(DynamicEntDataError::BadRelocs(reloc)) =>
                Err(DynamicEntStrsError::BadRelocs(reloc)),
            Err(DynamicEntDataError::BadKind(kind)) =>
                Err(DynamicEntStrsError::BadKind(kind))
        }
    }
}

impl<'a, B, Offsets> WithStrtab<'a> for &'_ DynamicEnt<'a, B, Offsets>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    type Error = DynamicEntStrsError<Offsets>;
    type Result = DynamicEntData<Result<&'a str, &'a [u8]>,
                                 Offsets::Offset, Offsets>;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        self.clone().with_strtab(strtab.clone())
    }
}

impl<'a, B, Offsets> WithStrtab<'a> for &'_ mut DynamicEnt<'a, B, Offsets>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    type Error = DynamicEntStrsError<Offsets>;
    type Result = DynamicEntData<Result<&'a str, &'a [u8]>,
                                 Offsets::Offset, Offsets>;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        self.clone().with_strtab(strtab)
    }
}

impl<'a, Name, Idx, Class> WithStrtab<'a> for DynamicEntData<Name, Idx, Class>
    where Class: ElfClass,
          Name: TryInto<usize> + Copy {
    type Error = Name;
    type Result = DynamicEntData<Result<&'a str, &'a [u8]>, Idx, Class>;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match self {
            DynamicEntData::None =>
                Ok(DynamicEntData::None),
            DynamicEntData::Needed { name } => match strtab.idx(name) {
                Ok(name) => Ok(DynamicEntData::Needed { name: Ok(name) }),
                Err(StrtabIdxError::UTF8Decode(data)) =>
                    Ok(DynamicEntData::Needed { name: Err(data) }),
                _ => Err(name)
            },
            DynamicEntData::PLTRelSize { size } =>
                Ok(DynamicEntData::PLTRelSize { size: size }),
            DynamicEntData::PLTGOT { tab } =>
                Ok(DynamicEntData::PLTGOT { tab: tab }),
            DynamicEntData::Hash { tab } =>
                Ok(DynamicEntData::Hash { tab: tab }),
            DynamicEntData::Symtab { tab } =>
                Ok(DynamicEntData::Symtab { tab: tab }),
            DynamicEntData::Strtab { tab } =>
                Ok(DynamicEntData::Strtab { tab: tab }),
            DynamicEntData::Rela { tab } =>
                Ok(DynamicEntData::Rela { tab: tab }),
            DynamicEntData::RelaSize { size } =>
                Ok(DynamicEntData::RelaSize { size: size }),
            DynamicEntData::RelaEntSize { size } =>
                Ok(DynamicEntData::RelaEntSize { size: size }),
            DynamicEntData::StrtabSize { size } =>
                Ok(DynamicEntData::StrtabSize { size: size }),
            DynamicEntData::SymtabEntSize { size } =>
                Ok(DynamicEntData::SymtabEntSize { size: size }),
            DynamicEntData::Init { func } =>
                Ok(DynamicEntData::Init { func: func }),
            DynamicEntData::Fini { func } =>
                Ok(DynamicEntData::Fini { func: func }),
            DynamicEntData::Name { name } => match strtab.idx(name) {
                Ok(name) => Ok(DynamicEntData::Name { name: Ok(name) }),
                Err(StrtabIdxError::UTF8Decode(data)) =>
                    Ok(DynamicEntData::Name { name: Err(data) }),
                _ => Err(name)
            },
            DynamicEntData::RPath { path } => match strtab.idx(path) {
                Ok(path) => Ok(DynamicEntData::RPath { path: Ok(path) }),
                Err(StrtabIdxError::UTF8Decode(data)) =>
                    Ok(DynamicEntData::RPath { path: Err(data) }),
                _ => Err(path)
            },
            DynamicEntData::Symbolic =>
                Ok(DynamicEntData::Symbolic),
            DynamicEntData::Rel { tab } =>
                Ok(DynamicEntData::Rel { tab: tab }),
            DynamicEntData::RelSize { size } =>
                Ok(DynamicEntData::RelSize { size: size }),
            DynamicEntData::RelEntSize { size } =>
                Ok(DynamicEntData::RelEntSize { size: size }),
            DynamicEntData::PLTRela { rela } =>
                Ok(DynamicEntData::PLTRela { rela: rela }),
            DynamicEntData::Debug { tab } =>
                Ok(DynamicEntData::Debug { tab: tab }),
            DynamicEntData::TextRel => Ok(DynamicEntData::TextRel),
            DynamicEntData::JumpRel { tab } =>
                Ok(DynamicEntData::JumpRel { tab: tab }),
            DynamicEntData::BindNow => Ok(DynamicEntData::BindNow),
            DynamicEntData::InitArray { arr } =>
                Ok(DynamicEntData::InitArray { arr: arr }),
            DynamicEntData::FiniArray { arr } =>
                Ok(DynamicEntData::FiniArray { arr: arr }),
            DynamicEntData::InitArraySize { size } =>
                Ok(DynamicEntData::InitArraySize { size: size }),
            DynamicEntData::FiniArraySize { size } =>
                Ok(DynamicEntData::FiniArraySize { size: size }),
            DynamicEntData::Flags { flags } =>
                Ok(DynamicEntData::Flags { flags: flags }),
            DynamicEntData::PreInitArray { arr } =>
                Ok(DynamicEntData::PreInitArray { arr: arr }),
            DynamicEntData::PreInitArraySize { size } =>
                Ok(DynamicEntData::PreInitArraySize { size: size }),
            DynamicEntData::SymtabIdx { idx } =>
                Ok(DynamicEntData::SymtabIdx { idx: idx }),
            DynamicEntData::Unknown { tag, info } =>
                Ok(DynamicEntData::Unknown { tag: tag, info: info }),
        }
    }
}

impl<'a, Name, Idx, Class> WithStrtab<'a>
    for &'_ DynamicEntData<Name, Idx, Class>
    where Class: ElfClass,
          Name: Copy + TryInto<usize>,
          Idx: Copy {
    type Error = Name;
    type Result = DynamicEntData<Result<&'a str, &'a [u8]>, Idx, Class>;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        self.clone().with_strtab(strtab)
    }
}

impl<'a, Name, Idx, Class> WithStrtab<'a>
    for &'_ mut DynamicEntData<Name, Idx, Class>
    where Class: ElfClass,
          Name: Copy + TryInto<usize>,
          Idx: Copy {
    type Error = Name;
    type Result = DynamicEntData<Result<&'a str, &'a [u8]>, Idx, Class>;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        self.clone().with_strtab(strtab)
    }
}

impl<'a, Idx, Class> TryFrom<DynamicEntData<Result<&'a str, &'a [u8]>,
                                            Idx, Class>>
    for DynamicEntData<&'a str, Idx, Class>
    where Class: ElfClass,
          Idx: Copy {
    type Error = &'a [u8];

    #[inline]
    fn try_from(data: DynamicEntData<Result<&'a str, &'a [u8]>,
                                     Idx, Class>) ->
        Result<DynamicEntData<&'a str, Idx, Class>, Self::Error> {
        match data {
            DynamicEntData::None =>
                Ok(DynamicEntData::None),
            DynamicEntData::Needed { name: Ok(name) } =>
                Ok(DynamicEntData::Needed { name: name }),
            DynamicEntData::Needed { name: Err(err) } => Err(err),
            DynamicEntData::PLTRelSize { size } =>
                Ok(DynamicEntData::PLTRelSize { size: size }),
            DynamicEntData::PLTGOT { tab } =>
                Ok(DynamicEntData::PLTGOT { tab: tab }),
            DynamicEntData::Hash { tab } =>
                Ok(DynamicEntData::Hash { tab: tab }),
            DynamicEntData::Symtab { tab } =>
                Ok(DynamicEntData::Symtab { tab: tab }),
            DynamicEntData::Strtab { tab } =>
                Ok(DynamicEntData::Strtab { tab: tab }),
            DynamicEntData::Rela { tab } =>
                Ok(DynamicEntData::Rela { tab: tab }),
            DynamicEntData::RelaSize { size } =>
                Ok(DynamicEntData::RelaSize { size: size }),
            DynamicEntData::RelaEntSize { size } =>
                Ok(DynamicEntData::RelaEntSize { size: size }),
            DynamicEntData::StrtabSize { size } =>
                Ok(DynamicEntData::StrtabSize { size: size }),
            DynamicEntData::SymtabEntSize { size } =>
                Ok(DynamicEntData::SymtabEntSize { size: size }),
            DynamicEntData::Init { func } =>
                Ok(DynamicEntData::Init { func: func }),
            DynamicEntData::Fini { func } =>
                Ok(DynamicEntData::Fini { func: func }),
            DynamicEntData::Name { name: Ok(name) } =>
                Ok(DynamicEntData::Name { name: name }),
            DynamicEntData::Name { name: Err(err) } => Err(err),
            DynamicEntData::RPath { path: Ok(path) } =>
                Ok(DynamicEntData::RPath { path: path }),
            DynamicEntData::RPath { path: Err(err) } => Err(err),
            DynamicEntData::Symbolic =>
                Ok(DynamicEntData::Symbolic),
            DynamicEntData::Rel { tab } =>
                Ok(DynamicEntData::Rel { tab: tab }),
            DynamicEntData::RelSize { size } =>
                Ok(DynamicEntData::RelSize { size: size }),
            DynamicEntData::RelEntSize { size } =>
                Ok(DynamicEntData::RelEntSize { size: size }),
            DynamicEntData::PLTRela { rela } =>
                Ok(DynamicEntData::PLTRela { rela: rela }),
            DynamicEntData::Debug { tab } =>
                Ok(DynamicEntData::Debug { tab: tab }),
            DynamicEntData::TextRel => Ok(DynamicEntData::TextRel),
            DynamicEntData::JumpRel { tab } =>
                Ok(DynamicEntData::JumpRel { tab: tab }),
            DynamicEntData::BindNow => Ok(DynamicEntData::BindNow),
            DynamicEntData::InitArray { arr } =>
                Ok(DynamicEntData::InitArray { arr: arr }),
            DynamicEntData::FiniArray { arr } =>
                Ok(DynamicEntData::FiniArray { arr: arr }),
            DynamicEntData::InitArraySize { size } =>
                Ok(DynamicEntData::InitArraySize { size: size }),
            DynamicEntData::FiniArraySize { size } =>
                Ok(DynamicEntData::FiniArraySize { size: size }),
            DynamicEntData::Flags { flags } =>
                Ok(DynamicEntData::Flags { flags: flags }),
            DynamicEntData::PreInitArray { arr } =>
                Ok(DynamicEntData::PreInitArray { arr: arr }),
            DynamicEntData::PreInitArraySize { size } =>
                Ok(DynamicEntData::PreInitArraySize { size: size }),
            DynamicEntData::SymtabIdx { idx } =>
                Ok(DynamicEntData::SymtabIdx { idx: idx }),
            DynamicEntData::Unknown { tag, info } =>
                Ok(DynamicEntData::Unknown { tag: tag, info: info }),
        }
    }
}

impl<'a, Idx, Class> TryFrom<&'_ DynamicEntData<Result<&'a str, &'a [u8]>,
                                                Idx, Class>>
    for DynamicEntData<&'a str, Idx, Class>
    where Class: ElfClass,
          Idx: Copy {
    type Error = &'a [u8];

    #[inline]
    fn try_from(data: &'_ DynamicEntData<Result<&'a str, &'a [u8]>,
                                         Idx, Class>) ->
        Result<DynamicEntData<&'a str, Idx, Class>, Self::Error> {
        DynamicEntData::try_from(data.clone())
    }
}

impl<'a, Idx, Class> TryFrom<&'_ mut DynamicEntData<Result<&'a str, &'a [u8]>,
                                                    Idx, Class>>
    for DynamicEntData<&'a str, Idx, Class>
    where Class: ElfClass,
          Idx: Copy {
    type Error = &'a [u8];

    #[inline]
    fn try_from(data: &'_ mut DynamicEntData<Result<&'a str, &'a [u8]>,
                                             Idx, Class>) ->
        Result<DynamicEntData<&'a str, Idx, Class>, Self::Error> {
        DynamicEntData::try_from(data.clone())
    }
}

impl<'a, B, Offsets: DynamicOffsets> Iterator for DynamicIter<'a, B, Offsets>
    where B: ByteOrder {
    type Item = DynamicEnt<'a, B, Offsets>;

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
        let start = (self.idx + n) * Offsets::DYNAMIC_SIZE;

        if start < len {
            let end = start + Offsets::DYNAMIC_SIZE;

            self.idx += n + 1;

            Some(DynamicEnt { byteorder: PhantomData, offsets: PhantomData,
                              data: &self.data[start .. end ] })
        } else {
            None
        }
    }
}

impl<'a, B, Offsets: DynamicOffsets> ExactSizeIterator
    for DynamicIter<'a, B, Offsets>
    where B: ByteOrder {
    #[inline]
    fn len(&self) -> usize {
        (self.data.len() / Offsets::DYNAMIC_SIZE) - self.idx
    }
}

impl<'a, B, Offsets: DynamicOffsets> FusedIterator
    for DynamicIter<'a, B, Offsets> where B: ByteOrder {}

impl<'a, B, Offsets: DynamicOffsets> Iterator
    for DynamicNeededIter<'a, B, Offsets>
    where B: ByteOrder {
    type Item = Offsets::Offset;

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.inner.len();

        (size, None)
    }

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next() {
            Some(ent) => {
                let ent: DynamicEntDataRaw<Offsets> = match ent.try_into() {
                    Ok(ent) => ent,
                    Err(_) => return self.next()
                };

                match ent {
                    DynamicEntData::Needed { name } => Some(name),
                    _ => self.next()
                }
            },
            None => None
        }
    }
}

impl<'a, B, Offsets: DynamicOffsets> FusedIterator
    for DynamicNeededIter<'a, B, Offsets> where B: ByteOrder {}

impl Display for DynamicError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DynamicError::BadSize(size) =>
                write!(f, "bad dynamic table size {}", size)
        }
    }
}

impl<Offsets: ElfClass> Display for DynamicInfoWithDataError<Offsets> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DynamicInfoWithDataError::OutOfBounds(offset) =>
                write!(f, "offset out of bounds {}", offset),
            DynamicInfoWithDataError::BadOffset(offset) =>
                write!(f, "offset out of bounds {}", offset),
            DynamicInfoWithDataError::BadAddr(addr) =>
                write!(f, "offset out of bounds {}", addr)
        }
    }
}

impl<Offsets: ElfClass> Display for DynamicInfoFullStrDataError<Offsets> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DynamicInfoFullStrDataError::Strtab(err) => err.fmt(f),
            DynamicInfoFullStrDataError::Symtab(err) => err.fmt(f),
            DynamicInfoFullStrDataError::Hash(err) => err.fmt(f),
            DynamicInfoFullStrDataError::Rela(err) => err.fmt(f),
            DynamicInfoFullStrDataError::Rel(err) => err.fmt(f),
            DynamicInfoFullStrDataError::StrtabOutOfBounds(offset) => {
                write!(f, "offset {} out of strtab bounds", offset)
            }
        }
    }
}

impl<Offsets> Display for DynamicEntDataError<Offsets>
    where Offsets: ElfClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DynamicEntDataError::BadRelocs(code) =>
                write!(f, "bad relocation type code {:x}", code),
            DynamicEntDataError::BadKind(code) =>
                write!(f, "bad type code {:x}", code)
        }
    }
}

impl<Offsets> Display for DynamicEntStrsError<Offsets>
    where Offsets: ElfClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DynamicEntStrsError::BadRelocs(code) =>
                write!(f, "bad relocation type code {:x}", code),
            DynamicEntStrsError::BadKind(code) =>
                write!(f, "bad type code {:x}", code),
            DynamicEntStrsError::BadName(idx) =>
                write!(f, "bad name index {:x}", idx),
        }
    }
}

impl<Rel, Rela> Display for Relocs<Rel, Rela>
    where Rela: Display,
          Rel: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            Relocs::Rel(rel) => rel.fmt(f),
            Relocs::Rela(rela) => rela.fmt(f)
        }
    }
}

impl<Offsets> Display for AddrRange<Offsets>
    where Offsets: ElfClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "addr: {}, size: {}", self.addr, self.size)
    }
}

impl<Name, Idx, Offsets> Display for DynamicEntData<Name, Idx, Offsets>
    where Offsets: DynamicOffsets,
          Name: Display,
          Idx: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DynamicEntData::None => write!(f, "none"),
            DynamicEntData::Needed { name } => {
                write!(f, "Needed library: {}", name)
            },
            DynamicEntData::PLTRelSize { size } => {
                write!(f, "PLT relocation table size: 0x{:x}", size)
            },
            DynamicEntData::PLTGOT { tab } => {
                write!(f, "PLT/GOT: 0x{:x}", tab)
            },
            DynamicEntData::Hash { tab } => {
                write!(f, "Symbol hash table: 0x{:x}", tab)
            },
            DynamicEntData::Symtab { tab } => {
                write!(f, "Symbol table: 0x{:x}", tab)
            },
            DynamicEntData::Strtab { tab } => {
                write!(f, "String table: 0x{:x}", tab)
            },
            DynamicEntData::Rela { tab } => {
                write!(f, "Relocation table (explicit addends): 0x{:x}", tab)
            },
            DynamicEntData::RelaSize { size } => {
                write!(f, "Relocation table size: 0x{:x}", size)
            },
            DynamicEntData::RelaEntSize { size } => {
                write!(f, "Relocation table entry size: 0x{:x}", size)
            },
            DynamicEntData::StrtabSize { size } => {
                write!(f, "String table size: 0x{:x}", size)
            },
            DynamicEntData::SymtabEntSize { size } => {
                write!(f, "Symbol table entry size: 0x{:x}", size)
            },
            DynamicEntData::Init { func } => {
                write!(f, "Initializer: 0x{:x}", func)
            },
            DynamicEntData::Fini { func } => {
                write!(f, "Initializer: 0x{:x}", func)
            },
            DynamicEntData::Name { name } => {
                write!(f, "Dynamic object name: {}", name)
            }
            DynamicEntData::RPath { path } => {
                write!(f, "Dynamic linking path: {}", path)
            }
            DynamicEntData::Symbolic => write!(f, "Symbolic linking"),
            DynamicEntData::Rel { tab } => {
                write!(f, "Relocation table: 0x{:x}", tab)
            },
            DynamicEntData::RelSize { size } => {
                write!(f, "Relocation table size: 0x{:x}", size)
            },
            DynamicEntData::RelEntSize { size } => {
                write!(f, "Relocation table entry size: 0x{:x}", size)
            },
            DynamicEntData::PLTRela { rela: true } => {
                write!(f, "PLT relocation table has explicit addends")
            },
            DynamicEntData::PLTRela { rela: false } => {
                write!(f, "PLT relocation table has no addends")
            },
            DynamicEntData::Debug { tab } => {
                write!(f, "Debug table: 0x{:x}", tab)
            },
            DynamicEntData::TextRel =>
                write!(f, "Relocations modify non-writable segments"),
            DynamicEntData::JumpRel { tab } => {
                write!(f, "PLT relocation table: 0x{:x}", tab)
            },
            DynamicEntData::BindNow => write!(f, "Eager relocation processing"),
            DynamicEntData::InitArray { arr } => {
                write!(f, "Initializer array: 0x{:x}", arr)
            },
            DynamicEntData::FiniArray { arr } => {
                write!(f, "Finalizer array: 0x{:x}", arr)
            },
            DynamicEntData::InitArraySize { size } => {
                write!(f, "Initializer array size: 0x{:x}", size)
            },
            DynamicEntData::FiniArraySize { size } => {
                write!(f, "Initializer array size: 0x{:x}", size)
            },
            DynamicEntData::Flags { flags } => {
                write!(f, "Flags: 0x{:x}", flags)
            },
            DynamicEntData::PreInitArray { arr } => {
                write!(f, "Pre-initializer array: 0x{:x}", arr)
            },
            DynamicEntData::PreInitArraySize { size } => {
                write!(f, "Pre-initializer array size: 0x{:x}", size)
            },
            DynamicEntData::SymtabIdx { idx } => {
                write!(f, "Symbol table: {}", idx)
            },
            DynamicEntData::Unknown { tag, info } => {
                write!(f, "Unknown type 0x{:x}: 0x{:x}", tag, info)
            }
        }
    }
}

impl<Name, Flags, Strs, Syms, Hash, Rel, Rela, B, Offsets> Display
    for DynamicInfo<Name, Flags, Strs, Syms, Hash, Rel, Rela, B, Offsets>
    where Offsets: DynamicOffsets,
          Flags: Display,
          Name: Display,
          Strs: Display,
          Syms: Display,
          Hash: Display,
          Rela: Display,
          Rel: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match &self.name {
            Some(name) => write!(f, "Dynamic object name: {}\n", name)?,
            None => {}
        };
        match &self.rpath {
            Some(path) => write!(f, "Dynamic linking path: {}\n", path)?,
            None => {}
        };

        write!(f, "Eager relocation processing: {}\n", self.bind_now)?;
        write!(f, "Relocations modify non-writable segments: {}\n",
               self.text_rel)?;
        write!(f, "Symbolic linking: {}\n", self.symbolic)?;

        match &self.symtab_idx {
            Some(arr) => write!(f, "Symbol table index: {}\n", arr)?,
            None => {}
        };
        write!(f, "Symbol hash table: {}\n", self.hash)?;
        write!(f, "Symbol table: {}\n", self.symtab)?;
        write!(f, "String table: {}\n", self.strtab)?;
        match &self.reloc {
            Some(tab) => write!(f, "Dynamic relocation table: {}\n", tab)?,
            None => {}
        };
        match &self.debug {
            Some(addr) => write!(f, "Debugging information: {}\n", addr)?,
            None => {}
        };
        match &self.jump_reloc {
            Some(tab) => write!(f, "PLT/GOT relocation table: {}\n", tab)?,
            None => {}
        };
        match &self.flags {
            Some(flags) => write!(f, "Flags: {}\n", flags)?,
            None => {}
        };
        match &self.init {
            Some(func) => write!(f, "Initializer: {}\n", func)?,
            None => {}
        };
        match &self.fini {
            Some(func) => write!(f, "Finalizer: {}\n", func)?,
            None => {}
        };
        match &self.pre_init_arr {
            Some(arr) => write!(f, "Pre-initializer array: {}\n", arr)?,
            None => {}
        };
        match &self.init_arr {
            Some(arr) => write!(f, "Initializer array: {}\n", arr)?,
            None => {}
        };
        match &self.fini_arr {
            Some(arr) => write!(f, "Finalizer array: {}\n", arr)?,
            None => {}
        };

        Ok(())
    }
}

impl<Offsets> Display for DynamicInfoError<Offsets>
    where Offsets: DynamicOffsets {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DynamicInfoError::EntDataError(ent) => {
                ent.fmt(f)
            },
            DynamicInfoError::IncompleteJumpRelocs => {
                write!(f, "PLT/GOT relocation information is incomplete")
            },
            DynamicInfoError::IncompletePreInitArr => {
                write!(f, "pre-initialization array information is incomplete")
            },
            DynamicInfoError::IncompleteInitArr => {
                write!(f, "initialization array information is incomplete")
            },
            DynamicInfoError::IncompleteFiniArr => {
                write!(f, "finalization array information is incomplete")
            },
            DynamicInfoError::IncompleteStrtab => {
                write!(f, "string table information is incomplete")
            },
            DynamicInfoError::IncompleteRelas => {
                write!(f, "dynamic relocation information is incomplete")
            },
            DynamicInfoError::IncompleteRels => {
                write!(f, "dynamic relocation information is incomplete")
            },
            DynamicInfoError::MultiplePLTRelSize => {
                write!(f, "multiple dynamic entries for PLT/GOT relocations")
            },
            DynamicInfoError::MultipleJumpRel => {
                write!(f, "multiple dynamic entries for PLT/GOT relocations")
            },
            DynamicInfoError::MultiplePLTRela => {
                write!(f, "multiple dynamic entries for PLT/GOT relocations")
            },
            DynamicInfoError::MultiplePLTGOT => {
                write!(f, "multiple dynamic entries for PLT/GOT")
            },
            DynamicInfoError::MultipleSymtab => {
                write!(f, "multiple dynamic entries for dynamic symtab")
            },
            DynamicInfoError::MultipleStrtab => {
                write!(f, "multiple dynamic entries for dynamic strtab")
            },
            DynamicInfoError::MultipleFlags => {
                write!(f, "multiple dynamic entries for flags")
            },
            DynamicInfoError::MultipleRelas => {
                write!(f, "multiple dynamic entries for dynamic relocations")
            },
            DynamicInfoError::MultipleRPath => {
                write!(f, "multiple dynamic entries for run path")
            },
            DynamicInfoError::MultipleDebug => {
                write!(f, "multiple dynamic entries for debug info")
            },
            DynamicInfoError::MultipleName => {
                write!(f, "multiple dynamic entries for name")
            },
            DynamicInfoError::MultipleHash => {
                write!(f, "multiple dynamic entries for dynamic hash")
            },
            DynamicInfoError::MultipleRels => {
                write!(f, "multiple dynamic entries for dynamic relocations")
            },
            DynamicInfoError::MultipleFini => {
                write!(f, "multiple dynamic entries for finializer function")
            },
            DynamicInfoError::MultipleInit => {
                write!(f, "multiple dynamic entries for initializer function")
            },
            DynamicInfoError::MultiplePreInitArr => {
                write!(f, "multiple dynamic entries for pre-initializer array")
            },
            DynamicInfoError::MultipleInitArr => {
                write!(f, "multiple dynamic entries for initializer array")
            },
            DynamicInfoError::MultipleFiniArr => {
                write!(f, "multiple dynamic entries for finalizer array")
            },
            DynamicInfoError::MultipleSymtabIdx => {
                write!(f, "multiple dynamic entries for dynamic symtab index")
            },
            DynamicInfoError::NoStrtab => {
                write!(f, "missing string table")
            },
            DynamicInfoError::NoSymtab => {
                write!(f, "missing symbol table")
            },
            DynamicInfoError::NoHash => {
                write!(f, "missing symbol hash table")
            },
            DynamicInfoError::BadRelEntSize => {
                write!(f, "bad relocation entry size")
            },
            DynamicInfoError::BadRelaEntSize => {
                write!(f, "bad relocation entry size")
            },
            DynamicInfoError::BadSymtabEntSize => {
                write!(f, "bad symtab entry size")
            }
        }
    }
}
