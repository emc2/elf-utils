//! ELF note section functionality.
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
//! let dynamic: Result<Dynamic<'_, LittleEndian, Elf32>, ()> =
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
//! let data: DynamicEntData<usize, usize, Elf32> = ent.try_into().unwrap();
//!
//! assert_eq!(data, DynamicEntData::Rel { tab: 0x7f4 });
//! ```

use byteorder::ByteOrder;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use crate::elf::Elf32;
use crate::elf::Elf64;
use crate::elf::ElfClass;

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
/// const DYNAMIC_ENTS: [DynamicEntData<usize, usize, Elf32>; 12] = [
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
///     let data: DynamicEntData<usize, usize, Elf32> = ent.try_into().unwrap();
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
/// let data: DynamicEntData<usize, usize, Elf32> = ent.try_into().unwrap();
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
/// const DYNAMIC_ENTS: [DynamicEntData<usize, usize, Elf32>; 12] = [
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
///     let data: DynamicEntData<usize, usize, Elf32> = ent.try_into().unwrap();
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
    /// Indicates the relocation entry size for the PLT relocation table.
    PLTRelSize {
        /// Size of relocation entries for the PLT.
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
    /// If present, indicates that relocation entries my modify a
    /// non-writable segment.
    TextRel,
    /// Provides the relocation table associated with the PLT.
    JumpRel {
        /// Address of the relacation table associated with the PLT.
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

#[inline]
fn project<'a, B, Offsets>(data: &'a [u8], byteorder: PhantomData<B>,
                           offsets: PhantomData<Offsets>) ->
    Result<DynamicEntData<usize, usize, Offsets>, ()>
    where Offsets: DynamicOffsets,
          B: ByteOrder {
    let tag = Offsets::read_offset(&data[Offsets::D_TAG_START ..
                                         Offsets::D_TAG_END],
                                   byteorder);

    match tag.try_into() {
        Ok(0) => Ok(DynamicEntData::None),
        Ok(1) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            match val.try_into() {
                Ok(name) => Ok(DynamicEntData::Needed { name: name }),
                Err(_) => Err(())
            }
        },
        Ok(2) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::PLTRelSize { size: val })
        },
        Ok(3) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::PLTGOT { tab: ptr })
        },
        Ok(4) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::Hash { tab: ptr })
        },
        Ok(5) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::Strtab { tab: ptr })
        },
        Ok(6) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::Symtab { tab: ptr })
        },
        Ok(7) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                              Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::Rela { tab: ptr })
        },
        Ok(8) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::RelaSize { size: val })
        },
        Ok(9) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::RelaEntSize { size: val })
        },
        Ok(10) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::StrtabSize { size: val })
        },
        Ok(11) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::SymtabEntSize { size: val })
        },
        Ok(12) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::Init { func: ptr })
        },
        Ok(13) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::Fini { func: ptr })
        },
        Ok(14) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            match val.try_into() {
                Ok(name) => Ok(DynamicEntData::Name { name: name }),
                Err(_) => Err(())
            }
        },
        Ok(15) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            match val.try_into() {
                Ok(path) => Ok(DynamicEntData::RPath { path: path }),
                Err(_) => Err(())
            }
        },
        Ok(16) => Ok(DynamicEntData::Symbolic),
        Ok(17) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::Rel { tab: ptr })
        },
        Ok(18) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::RelSize { size: val })
        },
        Ok(19) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::RelEntSize { size: val })
        },
        Ok(20) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            match val.try_into() {
                Ok(7) => Ok(DynamicEntData::PLTRela { rela: true }),
                Ok(17) => Ok(DynamicEntData::PLTRela { rela: false }),
                _ => Err(())
            }
        },
        Ok(21) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::Debug { tab: ptr })
        },
        Ok(22) => Ok(DynamicEntData::TextRel),
        Ok(23) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::JumpRel { tab: ptr })
        },
        Ok(24) => Ok(DynamicEntData::TextRel),
        Ok(25) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::InitArray { arr: ptr })
        },
        Ok(26) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::FiniArray { arr: ptr })
        },
        Ok(27) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                            byteorder);

            Ok(DynamicEntData::InitArraySize { size: val })
        },
        Ok(28) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                            byteorder);

            Ok(DynamicEntData::FiniArraySize { size: val })
        },
        Ok(29) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            match val.try_into() {
                Ok(path) => Ok(DynamicEntData::RPath { path: path }),
                Err(_) => Err(())
            }
        },
        Ok(30) => {
            let val = Offsets::read_offset(&data[Offsets::D_PTR_START ..
                                                 Offsets::D_PTR_END],
                                           byteorder);

            Ok(DynamicEntData::Flags { flags: val })
        },
        Ok(32) => {
            let ptr = Offsets::read_addr(&data[Offsets::D_PTR_START ..
                                               Offsets::D_PTR_END],
                                         byteorder);

            Ok(DynamicEntData::PreInitArray { arr: ptr })
        },
        Ok(33) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::PreInitArraySize { size: val })
        },
        Ok(34) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            match val.try_into() {
                Ok(idx) => Ok(DynamicEntData::SymtabIdx { idx: idx }),
                Err(_) => Err(())
            }
        },
        Ok(_) => {
            let val = Offsets::read_offset(&data[Offsets::D_VAL_START ..
                                                 Offsets::D_VAL_END],
                                           byteorder);

            Ok(DynamicEntData::Unknown { tag: tag, info: val })
        },
        Err(_) => Err(())
    }
}

fn create<'a, B, I, Offsets>(buf: &'a mut [u8], ents: I,
                             byteorder: PhantomData<B>,
                             offsets: PhantomData<Offsets>) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where I: Iterator<Item = DynamicEntData<usize, usize, Offsets>>,
          Offsets: DynamicOffsets,
          B: ByteOrder {
    let len = buf.len();
    let mut idx = 0;

    for ent in ents {
        if idx + Offsets::DYNAMIC_SIZE <= len {
            let data = &mut buf[idx .. idx + Offsets::DYNAMIC_SIZE];

            match ent {
                DynamicEntData::None => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (0 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          (0 as u8).into(), byteorder);
                },
                DynamicEntData::Needed { name } => match name.try_into() {
                    Ok(name) => {
                        Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                        Offsets::D_TAG_END],
                                              (1 as u8).into(), byteorder);
                        Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                        Offsets::D_VAL_END],
                                              name, byteorder);
                    },
                    Err(_) => return Err(())
                },
                DynamicEntData::PLTRelSize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (2 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::PLTGOT { tab } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (3 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        tab, byteorder);
                },
                DynamicEntData::Hash { tab } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (4 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        tab, byteorder);
                },
                DynamicEntData::Strtab { tab } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (5 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        tab, byteorder);
                },
                DynamicEntData::Symtab { tab } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (6 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        tab, byteorder);
                },
                DynamicEntData::Rela { tab } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (7 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        tab, byteorder);
                },
                DynamicEntData::RelaSize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (8 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::RelaEntSize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (9 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::StrtabSize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (10 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::SymtabEntSize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (11 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::Init { func } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (12 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        func, byteorder);
                },
                DynamicEntData::Fini { func } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (13 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        func, byteorder);
                },
                DynamicEntData::Name { name } => match name.try_into() {
                    Ok(name) => {
                        Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                        Offsets::D_TAG_END],
                                              (14 as u8).into(), byteorder);
                        Offsets::write_offset(&mut data[Offsets::D_PTR_START ..
                                                        Offsets::D_PTR_END],
                                              name, byteorder);
                    },
                    Err(_) => return Err(())
                },
                DynamicEntData::RPath { path } => match path.try_into() {
                    Ok(path) => {
                        Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                        Offsets::D_TAG_END],
                                              (29 as u8).into(), byteorder);
                        Offsets::write_offset(&mut data[Offsets::D_PTR_START ..
                                                        Offsets::D_PTR_END],
                                              path, byteorder);
                    },
                    Err(_) => return Err(())
                },
                DynamicEntData::Symbolic => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (16 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          (0 as u8).into(), byteorder);
                },
                DynamicEntData::Rel { tab } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (17 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        tab, byteorder);
                },
                DynamicEntData::RelSize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (18 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::RelEntSize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (19 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::PLTRela { rela: true } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (20 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          (7 as u8).into(), byteorder);
                },
                DynamicEntData::PLTRela { rela: false } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (20 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          (17 as u8).into(), byteorder);
                },
                DynamicEntData::Debug { tab } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (21 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        tab, byteorder);
                },
                DynamicEntData::TextRel => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (22 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          (0 as u8).into(), byteorder);
                },
                DynamicEntData::JumpRel { tab } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (23 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        tab, byteorder);
                },
                DynamicEntData::BindNow => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (24 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          (0 as u8).into(), byteorder);
                },
                DynamicEntData::InitArray { arr } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (25 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        arr, byteorder);
                },
                DynamicEntData::FiniArray { arr } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (26 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        arr, byteorder);
                },
                DynamicEntData::InitArraySize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (27 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::FiniArraySize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (28 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::Flags { flags } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (30 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          flags, byteorder);
                },
                DynamicEntData::PreInitArray { arr } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (32 as u8).into(), byteorder);
                    Offsets::write_addr(&mut data[Offsets::D_PTR_START ..
                                                  Offsets::D_PTR_END],
                                        arr, byteorder);
                },
                DynamicEntData::PreInitArraySize { size } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          (33 as u8).into(), byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          size, byteorder);
                },
                DynamicEntData::SymtabIdx { idx: idx } => match idx.try_into() {
                    Ok(shidx) => {
                        Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                        Offsets::D_TAG_END],
                                              (34 as u8).into(), byteorder);
                        Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                        Offsets::D_VAL_END],
                                              shidx, byteorder);
                    },
                    Err(_) => return Err(())
                },
                DynamicEntData::Unknown { tag, info } => {
                    Offsets::write_offset(&mut data[Offsets::D_TAG_START ..
                                                    Offsets::D_TAG_END],
                                          tag, byteorder);
                    Offsets::write_offset(&mut data[Offsets::D_VAL_START ..
                                                    Offsets::D_VAL_END],
                                          info, byteorder);
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
    type Error = ();

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
            Err(())
        }
    }
}

impl<'a, B, Offsets: DynamicOffsets> TryFrom<&'a mut [u8]>
    for Dynamic<'a, B, Offsets>
    where B: ByteOrder {
    type Error = ();

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
            Err(())
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
/// use elf_utils::dynamic;
///
/// const DYNAMIC_ENTS: [DynamicEntData<usize, usize, Elf32>; 12] = [
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
    where I: Iterator<Item = DynamicEntData<usize, usize, Offsets>>,
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
    /// use elf_utils::dynamic;
    ///
    /// const DYNAMIC_ENTS: [DynamicEntData<usize, usize, Elf32>; 12] = [
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
    ///     let data: DynamicEntData<usize, usize, Elf32> =
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
        where I: Iterator<Item = DynamicEntData<usize, usize, Offsets>> {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (data, out) = create(buf, ents, byteorder, offsets)?;

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
    /// use elf_utils::dynamic;
    ///
    /// const DYNAMIC_ENTS: [DynamicEntData<usize, usize, Elf32>; 12] = [
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
    ///     let data: DynamicEntData<usize, usize, Elf32> =
    ///         sym.try_into().unwrap();
    ///
    ///     assert_eq!(data, DYNAMIC_ENTS[i]);
    /// }
    ///
    /// assert!(iter.next().is_none());
    /// ```
    #[inline]
    pub fn create<I>(buf: &'a mut [u8], ents: I) -> Result<Self, ()>
        where I: Iterator<Item = DynamicEntData<usize, usize, Offsets>>,
              Self: Sized {
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

impl<'a, B, Offsets: DynamicOffsets> TryFrom<DynamicEnt<'a, B, Offsets>>
    for DynamicEntData<usize, usize, Offsets>
    where B: ByteOrder {
    type Error = ();

    #[inline]
    fn try_from(ent: DynamicEnt<'a, B, Offsets>) ->
        Result<DynamicEntData<usize, usize, Offsets>, Self::Error> {
        project(ent.data, ent.byteorder, ent.offsets)
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
        self.data.len() / Offsets::DYNAMIC_SIZE
    }
}

impl<'a, B, Offsets: DynamicOffsets> FusedIterator
    for DynamicIter<'a, B, Offsets> where B: ByteOrder {}