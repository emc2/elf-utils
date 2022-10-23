//! Relocation types for 32-bit x86 architecture.
//!
//! This module provides the `X86Reloc` type, which describes the
//! relocation entries for the IA-32 (aka. x86, i386) architecture.
//! These can be converted to and from
//! [RelData](crate::reloc::RelData) or
//! [RelaData](crate::reloc::RelaData) with [Elf32](crate::Elf32) as
//! the [ElfClass](crate::ElfClass) type argument using the
//! [TryFrom](core::convert::TryFrom) instances for easier handling.
use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::Display;
use core::fmt::Formatter;
use crate::elf::Elf32;
use crate::reloc::RelData;
use crate::reloc::RelaData;
use crate::reloc::RelocSymtabError;
use crate::strtab::Strtab;
use crate::strtab::WithStrtab;
use crate::symtab::Symtab;
use crate::symtab::SymBase;
use crate::symtab::SymData;
use crate::symtab::SymDataRaw;
use crate::symtab::SymDataStr;
use crate::symtab::SymDataStrData;
use crate::symtab::WithSymtab;

/// Relocation entries for 32-bit x86 architectures (aka. IA-32, i386).
///
/// This datatype provides a semantic-level presentation of the x86
/// relocation entries.  These can be converted to and from
/// [RelData](crate::reloc::RelData) or
/// [RelaData](crate::reloc::RelaData) with [Elf32](crate::Elf32) as
/// the [ElfClass](crate::ElfClass) type argument using the
/// [TryFrom](core::convert::TryFrom) instances for easier handling.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86Reloc<Name> {
    /// Null relocation.
    None,
    /// 32-bit absolute offset.
    ///
    /// Sets the 4-byte word at `offset` to `sym + addend`.
    Abs32 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// 32-bit PC-relative offset.
    ///
    /// Set the 4-byte word at `offset` to the relative address of
    /// `sym + addend` (computed by subtracting the offset or
    /// address of the target word from `sym + addend`).
    PC32 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// 16-bit absolute offset.
    ///
    /// Set the 2-byte word at `offset` to `sym + addend`.
    Abs16 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// 16-bit PC-relative offset.
    ///
    /// Set the 2-byte word at `offset` to the relative address of
    /// `sym + addend` (computed by subtracting the offset or
    /// address of the target word from `sym + addend`).
    PC16 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// 8-bit absolute offset.
    ///
    /// Set the 1-byte word at `offset` to `sym + addend`.
    Abs8 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// 8-bit PC-relative offset.
    ///
    /// Set the 1-byte word at `offset` to the relative address of
    /// `sym + addend` (computed by subtracting the offset or
    /// address of the target word from `sym + addend`).
    PC8 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// 32-bit Global Offset Table index.
    ///
    /// Set the 4-byte word at `offset` to the sum of the address of
    /// the Global Offset Table and `addend`.
    GOT32 {
        /// Offset in the section.
        offset: u32,
        /// The addend argument.
        addend: i32
    },
    /// Procedure Linkage Table index.
    ///
    /// Set the 4-byte word at `offset` to the relative address of the
    /// sum of the address of the Procedure Linkage Table and `addend`
    /// (computed by subtracting the offset or address of the target
    /// word from the sum of the address of the Procedure Linkage
    /// Table and `addend`).
    PLTRel {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// Writable copy.
    ///
    /// Create a copy of the symbol `sym` in a writable segment.
    Copy {
        /// Symbol reference.
        sym: Name
    },
    /// Global Offset Table entry fill.
    ///
    /// Set a Global Offset Table entry to the address of `sym`.
    GlobalData {
        /// Offset in the GOT.
        offset: u32,
        /// Symbol reference.
        sym: Name
    },
    /// Procedure Linkage Table jump-slot fill.
    ///
    /// Set a Procedure Linkage Table entry to the address of `sym`.
    JumpSlot {
        /// Offset in the PLT.
        offset: u32,
        /// Symbol reference.
        sym: Name
    },
    /// 32-bit offset relative to the image base.
    ///
    /// Set the 4-byte word at `offset` to the sum of the base address
    /// and `addend`.
    Relative {
        /// Offset in the section.
        offset: u32,
        /// The addend argument.
        addend: i32
    },
    /// 32-bit absolute offset to a Global Offset Table entry.
    ///
    /// Set the 4-byte word at `offset` to the relative
    /// address of `sym + addend` from the Global Offset Table.
    GOTRel {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// 32-bit PC-relative offset to a Global Offset Table entry.
    ///
    /// Set the 4-byte word at `offset` relative address of Global
    /// Offset Table address added to `addend` from the address of the
    /// word at `offset`.
    GOTPC {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    },
    /// 32-bit absolute offset to a Procedure Linkage Table entry.
    ///
    /// Set the 4-byte word at `offset` to the sum of the address of
    /// the Procedure Linkage Table and `addend`.
    PLTAbs {
        /// Offset in the section.
        offset: u32,
        /// The addend argument.
        addend: i32
    },
    /// Symbol size.
    ///
    /// Set the 4-byte word at `offset` to the sum of the size of the
    /// symbol and `addend`.
    Size {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i32
    }
}

/// Type synonym for [X86Reloc] as projected from a [Rel](crate::reloc::Rel).
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [Rel](crate::reloc::Rel).
pub type X86RelocRaw = X86Reloc<u32>;

/// Type synonym for [X86Reloc] with [SymDataRaw] as the symbol type.
///
/// This is obtained directly from the [WithSymtab] instance acting on a
/// [X86RelocRaw].
pub type X86RelocRawSym = X86Reloc<SymDataRaw<Elf32>>;

/// Type synonym for [X86Reloc] with [SymDataStrData] as the symbol type.
///
/// This is obtained directly from the [WithStrtab] instance acting on
/// a [X86RelocRawSym].
pub type X86RelocStrDataSym<'a> = X86Reloc<SymDataStrData<'a, Elf32>>;

/// Type synonym for [X86Reloc] with [SymDataStr] as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelocStrDataSym].
pub type X86RelocStrData<'a> = X86Reloc<Option<Result<&'a str, &'a [u8]>>>;

/// Type synonym for [X86Reloc] with UTF-8 decoded string data as the
/// symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelocStrDataSym].
pub type X86RelocStrSym<'a> = X86Reloc<SymDataStr<'a, Elf32>>;

/// Type synonym for [X86Reloc] with a `&'a str`s as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelocStrSym].
pub type X86RelocStr<'a> = X86Reloc<Option<&'a str>>;

/// Errors that can occur converting an [X86Reloc] to a
/// [RelData](crate::reloc::RelData).
///
/// At present, this can only happen with a non-zero addend.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum X86ToRelError {
    /// Non-zero addend.
    BadAddend(i32)
}

/// Errors that can occur converting a
/// [RelData](crate::reloc::RelData) or
/// [RelData](crate::reloc::RelaData) to a [X86Reloc].
///
/// At present, this can only happen with a bad tag value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum X86RelocError {
    /// Unknown tag value.
    BadTag(u8)
}

impl<Name> Display for X86Reloc<Name>
    where Name: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86Reloc::None => write!(f, "none"),
            X86Reloc::Abs32 { offset, sym, addend } =>
                write!(f, ".section[{:x}..{:x}] <- &{} + {:x}",
                       offset, offset + 4, sym, addend),
            X86Reloc::PC32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 4, sym, addend, offset),
            X86Reloc::Abs16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 2, sym, addend),
            X86Reloc::PC16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 2, sym, addend, offset),
            X86Reloc::Abs8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- &{} + {}",
                       offset, sym, addend),
            X86Reloc::PC8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- (&{} + {}) - (&.section + {})",
                       offset, sym, addend, offset),
            X86Reloc::GOT32 { offset, addend } =>
                write!(f, ".section[{}..{}] <- &.got + {}",
                       offset, offset + 4, addend),
            X86Reloc::PLTRel { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.plt + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86Reloc::Copy { sym } => write!(f, "copy {}", sym),
            X86Reloc::GlobalData { offset, sym } =>
                write!(f, ".got[{}..{}] <- &{}", offset, offset + 4, sym),
            X86Reloc::JumpSlot { offset, sym } =>
                write!(f, ".plt[{}..{}] <- &{}", offset, offset + 4, sym),
            X86Reloc::Relative { offset, addend } =>
                write!(f, ".section[{}..{}] <- &base + {}",
                       offset, offset + 4, addend),
            X86Reloc::GOTRel { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - &.got",
                       offset, offset + 4, sym, addend),
            X86Reloc::GOTPC { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.got + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86Reloc::PLTAbs { offset, addend } =>
                write!(f, ".section[{}..{}] <- &.plt + {}",
                       offset, offset + 4, addend),
            X86Reloc::Size { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- sizeof({}) + {}",
                       offset, offset + 4, sym, addend),
        }
    }
}

impl Display for X86RelocError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86RelocError::BadTag(tag) => write!(f, "bad tag value {}", tag)
        }
    }
}

impl Display for X86ToRelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86ToRelError::BadAddend(addend) =>
                write!(f, "non-zero addend value {}", addend)
        }
    }
}

pub enum X86RelocErr<Section> {
    BadSymBase(SymBase<Section, u16>)
}
/*
impl<Name, Section> Reloc<Elf32> for X86Reloc<SymData<Name, Section, Elf32>> {
    type Error = X86RelocErr<Section>;

    fn reloc(&self, mem: &mut [u8], base: u32) ->
        Result<(), Self::Error> {
        match self {
            X86Reloc::None => Ok(()),
            X86Reloc::Abs32 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                              offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let value = ((*value as i32) + addend) as u32;

                Elf32::write_word::<LittleEndian>(&mut mem[range], value,
                                                  PhantomData);

                Ok(())
            },
            X86Reloc::Abs32 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocErr::BadSymBase(*section)),
            X86Reloc::PC32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 4, sym, addend, offset),
            X86Reloc::Abs16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 2, sym, addend),
            X86Reloc::PC16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 2, sym, addend, offset),
            X86Reloc::Abs8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- &{} + {}",
                       offset, sym, addend),
            X86Reloc::PC8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- (&{} + {}) - (&.section + {})",
                       offset, sym, addend, offset),
            X86Reloc::GOT32 { offset, addend } =>
                write!(f, ".section[{}..{}] <- &.got + {}",
                       offset, offset + 4, addend),
            X86Reloc::PLTRel { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.plt + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86Reloc::Copy { sym } => write!(f, "copy {}", sym),
            X86Reloc::GlobalData { offset, sym } =>
                write!(f, ".got[{}..{}] <- &{}", offset, offset + 4, sym),
            X86Reloc::JumpSlot { offset, sym } =>
                write!(f, ".plt[{}..{}] <- &{}", offset, offset + 4, sym),
            X86Reloc::Relative { offset, addend } =>
                write!(f, ".section[{}..{}] <- &base + {}",
                       offset, offset + 4, addend),
            X86Reloc::GOTRel { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - &.got",
                       offset, offset + 4, sym, addend),
            X86Reloc::GOTPC { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.got + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86Reloc::PLTAbs { offset, addend } =>
                write!(f, ".section[{}..{}] <- &.plt + {}",
                       offset, offset + 4, addend),
            X86Reloc::Size { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- sizeof({}) + {}",
                       offset, offset + 4, sym, addend),
        }
    }
}
*/

fn convert_to<Name>(offset: u32, sym: Name, kind: u8, addend: i32) ->
    Result<X86Reloc<Name>, X86RelocError> {
    match kind {
        0 => Ok(X86Reloc::None),
        1 => Ok(X86Reloc::Abs32 { offset: offset, sym: sym, addend: addend }),
        2 => Ok(X86Reloc::PC32 { offset: offset, sym: sym, addend: addend }),
        3 => Ok(X86Reloc::GOT32 { offset: offset, addend: addend }),
        4 => Ok(X86Reloc::PLTRel { offset: offset, sym: sym, addend: addend }),
        5 => Ok(X86Reloc::Copy { sym: sym }),
        6 => Ok(X86Reloc::GlobalData { offset: offset, sym: sym }),
        7 => Ok(X86Reloc::JumpSlot { offset: offset, sym: sym }),
        8 => Ok(X86Reloc::Relative { offset: offset, addend: addend }),
        9 => Ok(X86Reloc::GOTRel { offset: offset, sym: sym, addend: addend }),
        10 => Ok(X86Reloc::GOTPC { offset: offset, sym: sym, addend: addend }),
        11 => Ok(X86Reloc::PLTAbs { offset: offset, addend: addend }),
        20 => Ok(X86Reloc::Abs16 { offset: offset, sym: sym, addend: addend }),
        21 => Ok(X86Reloc::PC16 { offset: offset, sym: sym, addend: addend }),
        22 => Ok(X86Reloc::Abs8 { offset: offset, sym: sym, addend: addend }),
        23 => Ok(X86Reloc::PC8 { offset: offset, sym: sym, addend: addend }),
        38 => Ok(X86Reloc::Size { offset: offset, sym: sym, addend: addend }),
        tag => Err(X86RelocError::BadTag(tag))
    }
}

impl<Name> TryFrom<RelData<Name, Elf32>> for X86Reloc<Name> {
    type Error = X86RelocError;

    #[inline]
    fn try_from(rel: RelData<Name, Elf32>) -> Result<X86Reloc<Name>,
                                                     X86RelocError> {
        let RelData { offset, sym, kind } = rel;

        convert_to(offset, sym, kind, 0)
    }
}

impl TryFrom<X86Reloc<u32>> for RelData<u32, Elf32> {
    type Error = X86ToRelError;

    #[inline]
    fn try_from(rel: X86Reloc<u32>) -> Result<RelData<u32, Elf32>,
                                              X86ToRelError> {
        match rel {
            X86Reloc::None => Ok(RelData { offset: 0, sym: 0, kind: 0 }),
            X86Reloc::Abs32 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 1 }),
            X86Reloc::Abs32 { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::PC32 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 2 }),
            X86Reloc::PC32 { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::GOT32 { offset, addend: 0 } =>
                Ok(RelData { offset: offset, sym: 0, kind: 3 }),
            X86Reloc::GOT32 { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::PLTRel { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 4 }),
            X86Reloc::PLTRel { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::Copy { sym } =>
                Ok(RelData { offset: 0, sym: sym, kind: 5 }),
            X86Reloc::GlobalData { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 6 }),
            X86Reloc::JumpSlot { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 7 }),
            X86Reloc::Relative { offset, addend: 0 } =>
                Ok(RelData { offset: offset, sym: 0, kind: 8 }),
            X86Reloc::Relative { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::GOTRel { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 9 }),
            X86Reloc::GOTRel { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::GOTPC { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 10 }),
            X86Reloc::GOTPC { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::PLTAbs { offset, addend: 0 } =>
                Ok(RelData { offset: offset, sym: 0, kind: 11 }),
            X86Reloc::PLTAbs { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::Abs16 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 20 }),
            X86Reloc::Abs16 { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::PC16 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 21 }),
            X86Reloc::PC16 { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::Abs8 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 22 }),
            X86Reloc::Abs8 { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::PC8 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 23 }),
            X86Reloc::PC8 { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
            X86Reloc::Size { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 38 }),
            X86Reloc::Size { addend, .. } =>
                Err(X86ToRelError::BadAddend(addend)),
        }
    }
}

impl<Name> TryFrom<RelaData<Name, Elf32>> for X86Reloc<Name> {
    type Error = X86RelocError;

    #[inline]
    fn try_from(rela: RelaData<Name, Elf32>) -> Result<X86Reloc<Name>,
                                                       Self::Error> {
        let RelaData { offset, sym, kind, addend } = rela;

        convert_to(offset, sym, kind, addend)
    }
}

impl From<X86Reloc<u32>> for RelaData<u32, Elf32> {
    #[inline]
    fn from(rel: X86Reloc<u32>) -> RelaData<u32, Elf32> {
        match rel {
            X86Reloc::None =>
                RelaData { offset: 0, sym: 0, kind: 0, addend: 0 },
            X86Reloc::Abs32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 1, addend: addend },
            X86Reloc::PC32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 2, addend: addend },
            X86Reloc::GOT32 { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 3, addend: addend },
            X86Reloc::PLTRel { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 4, addend: addend },
            X86Reloc::Copy { sym } =>
                RelaData { offset: 0, sym: sym, kind: 5 , addend: 0 },
            X86Reloc::GlobalData { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 6, addend: 0 },
            X86Reloc::JumpSlot { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 7, addend: 0 },
            X86Reloc::Relative { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 8, addend: addend },
            X86Reloc::GOTRel { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 9, addend: addend },
            X86Reloc::GOTPC { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 10, addend: addend },
            X86Reloc::PLTAbs { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 11, addend: addend },
            X86Reloc::Abs16 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 20, addend: addend },
            X86Reloc::PC16 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 21, addend: addend },
            X86Reloc::Abs8 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 22, addend: addend },
            X86Reloc::PC8 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 23, addend: addend },
            X86Reloc::Size { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 38, addend: addend },
        }
    }
}

impl<'a> WithSymtab<'a, LittleEndian, Elf32> for X86RelocRaw {
    type Result = X86RelocRawSym;
    type Error = RelocSymtabError<Elf32>;

    #[inline]
    fn with_symtab(self, symtab: Symtab<'a, LittleEndian, Elf32>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86Reloc::None => Ok(X86Reloc::None),
            X86Reloc::Abs32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::Abs32 { offset: offset, sym: symdata,
                                                 addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::PC32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::PC32 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::GOT32 { offset, addend } =>
                Ok(X86Reloc::GOT32 { offset: offset, addend: addend }),
            X86Reloc::PLTRel { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::PLTRel { offset: offset, sym: symdata,
                                                  addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::Copy { sym } => match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::Copy { sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::GlobalData { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::GlobalData { offset: offset,
                                                      sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::JumpSlot { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::JumpSlot { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::Relative { offset, addend } =>
                Ok(X86Reloc::Relative { offset: offset, addend: addend }),
            X86Reloc::GOTRel { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::GOTRel { offset: offset, sym: symdata,
                                                  addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::GOTPC { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::GOTPC { offset: offset, sym: symdata,
                                                 addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::PLTAbs { offset, addend } =>
                Ok(X86Reloc::PLTAbs { offset: offset, addend: addend }),
            X86Reloc::Abs16 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::Abs16 { offset: offset, sym: symdata,
                                                 addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::PC16 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::PC16 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::Abs8 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::Abs8 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::PC8 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::PC8 { offset: offset, sym: symdata,
                                               addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Reloc::Size { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Reloc::Size { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                }
        }
    }
}

impl<'a> WithStrtab<'a> for X86RelocRawSym {
    type Result = X86RelocStrDataSym<'a>;
    type Error = u32;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86Reloc::None => Ok(X86Reloc::None),
            X86Reloc::Abs32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::Abs32 { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::PC32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::PC32 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::GOT32 { offset, addend } =>
                Ok(X86Reloc::GOT32 { offset: offset, addend: addend }),
            X86Reloc::PLTRel { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::PLTRel { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::Copy { sym } => match sym.with_strtab(strtab) {
                Ok(symdata) => {
                    Ok(X86Reloc::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86Reloc::GlobalData { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::GlobalData { offset: offset,
                                                  sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::JumpSlot { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::JumpSlot { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::Relative { offset, addend } =>
                Ok(X86Reloc::Relative { offset: offset, addend: addend }),
            X86Reloc::GOTRel { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::GOTRel { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::GOTPC { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::GOTPC { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::PLTAbs { offset, addend } =>
                Ok(X86Reloc::PLTAbs { offset: offset, addend: addend }),
            X86Reloc::Abs16 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::Abs16 { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::PC16 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::PC16 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::Abs8 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::Abs8 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::PC8 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::PC8 { offset: offset, sym: symdata,
                                           addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::Size { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Reloc::Size { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                }
        }
    }
}

impl<'a> TryFrom<X86RelocStrDataSym<'a>> for X86RelocStrSym<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86RelocStrDataSym<'a>) ->
        Result<X86RelocStrSym<'a>, Self::Error> {
        match reloc {
            X86Reloc::None => Ok(X86Reloc::None),
            X86Reloc::Abs32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::Abs32 { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::PC32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::PC32 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::GOT32 { offset, addend } =>
                Ok(X86Reloc::GOT32 { offset: offset, addend: addend }),
            X86Reloc::PLTRel { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::PLTRel { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::Copy { sym } => match sym.try_into() {
                Ok(symdata) => {
                    Ok(X86Reloc::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86Reloc::GlobalData { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::GlobalData { offset: offset,
                                                  sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::JumpSlot { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::JumpSlot { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::Relative { offset, addend } =>
                Ok(X86Reloc::Relative { offset: offset, addend: addend }),
            X86Reloc::GOTRel { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::GOTRel { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::GOTPC { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::GOTPC { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::PLTAbs { offset, addend } =>
                Ok(X86Reloc::PLTAbs { offset: offset, addend: addend }),
            X86Reloc::Abs16 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::Abs16 { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::PC16 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::PC16 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::Abs8 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::Abs8 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::PC8 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::PC8 { offset: offset, sym: symdata,
                                           addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Reloc::Size { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Reloc::Size { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                }
        }
    }
}

impl<'a> From<X86RelocStrDataSym<'a>> for X86RelocStrData<'a> {
    #[inline]
    fn from(reloc: X86RelocStrDataSym<'a>) -> X86RelocStrData<'a> {
        match reloc {
            X86Reloc::None => X86Reloc::None,
            X86Reloc::Abs32 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::Abs32 { offset: offset, sym: name, addend: addend },
            X86Reloc::PC32 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::PC32 { offset: offset, sym: name, addend: addend },
            X86Reloc::GOT32 { offset, addend } =>
                X86Reloc::GOT32 { offset: offset, addend: addend },
            X86Reloc::PLTRel { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::PLTRel { offset: offset, sym: name, addend: addend },
            X86Reloc::Copy { sym: SymData { name, .. } } =>
                X86Reloc::Copy { sym: name },
            X86Reloc::GlobalData { sym: SymData { name, .. }, offset } =>
                X86Reloc::GlobalData { offset: offset, sym: name },
            X86Reloc::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86Reloc::JumpSlot { offset: offset, sym: name },
            X86Reloc::Relative { offset, addend } =>
                X86Reloc::Relative { offset: offset, addend: addend },
            X86Reloc::GOTRel { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::GOTRel { offset: offset, sym: name, addend: addend },
            X86Reloc::GOTPC { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::GOTPC { offset: offset, sym: name, addend: addend },
            X86Reloc::PLTAbs { offset, addend } =>
                X86Reloc::PLTAbs { offset: offset, addend: addend },
            X86Reloc::Abs16 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::Abs16 { offset: offset, sym: name, addend: addend },
            X86Reloc::PC16 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::PC16 { offset: offset, sym: name, addend: addend },
            X86Reloc::Abs8 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::Abs8 { offset: offset, sym: name, addend: addend },
            X86Reloc::PC8 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::PC8 { offset: offset, sym: name, addend: addend },
            X86Reloc::Size { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::Size { offset: offset, sym: name, addend: addend }
        }
    }
}

impl<'a> TryFrom<X86RelocStrData<'a>> for X86RelocStr<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86RelocStrData<'a>) ->
        Result<X86RelocStr<'a>, Self::Error> {
        match reloc {
            X86Reloc::None => Ok(X86Reloc::None),
            X86Reloc::Abs32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::Abs32 { offset: offset, sym: Some(name),
                                     addend: addend }),
            X86Reloc::Abs32 { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::Abs32 { sym: None, offset, addend } =>
                Ok(X86Reloc::Abs32 { offset: offset, sym: None,
                                     addend: addend }),
            X86Reloc::PC32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::PC32 { offset: offset, sym: Some(name),
                                    addend: addend }),
            X86Reloc::PC32 { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::PC32 { sym: None, offset, addend } =>
                Ok(X86Reloc::PC32 { offset: offset, sym: None,
                                    addend: addend }),
            X86Reloc::GOT32 { offset, addend } =>
                Ok(X86Reloc::GOT32 { offset: offset, addend: addend }),
            X86Reloc::PLTRel { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::PLTRel { offset: offset, sym: Some(name),
                                      addend: addend }),
            X86Reloc::PLTRel { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::PLTRel { sym: None, offset, addend } =>
                Ok(X86Reloc::PLTRel { offset: offset, sym: None,
                                      addend: addend }),
            X86Reloc::Copy { sym: Some(Ok(name)) } =>
                Ok(X86Reloc::Copy { sym: Some(name) }),
            X86Reloc::Copy { sym: Some(Err(err)) } => Err(err),
            X86Reloc::Copy { sym: None } => Ok(X86Reloc::Copy { sym: None }),
            X86Reloc::GlobalData { sym: Some(Ok(name)), offset } =>
                Ok(X86Reloc::GlobalData { offset: offset, sym: Some(name) }),
            X86Reloc::GlobalData { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::GlobalData { sym: None, offset } =>
                Ok(X86Reloc::GlobalData { offset: offset, sym: None }),
            X86Reloc::JumpSlot { sym: Some(Ok(name)), offset } =>
                Ok(X86Reloc::JumpSlot { offset: offset, sym: Some(name) }),
            X86Reloc::JumpSlot { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::JumpSlot { sym: None, offset } =>
                Ok(X86Reloc::JumpSlot { offset: offset, sym: None }),
            X86Reloc::Relative { offset, addend } =>
                Ok(X86Reloc::Relative { offset: offset, addend: addend }),
            X86Reloc::GOTRel { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::GOTRel { offset: offset, sym: Some(name),
                                      addend: addend }),
            X86Reloc::GOTRel { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::GOTRel { sym: None, offset, addend } =>
                Ok(X86Reloc::GOTRel { offset: offset, sym: None,
                                      addend: addend }),
            X86Reloc::GOTPC { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::GOTPC { offset: offset, sym: Some(name),
                                     addend: addend }),
            X86Reloc::GOTPC { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::GOTPC { sym: None, offset, addend } =>
                Ok(X86Reloc::GOTPC { offset: offset, sym: None,
                                     addend: addend }),
            X86Reloc::PLTAbs { offset, addend } =>
                Ok(X86Reloc::PLTAbs { offset: offset, addend: addend }),
            X86Reloc::Abs16 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::Abs16 { offset: offset, sym: Some(name),
                                     addend: addend }),
            X86Reloc::Abs16 { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::Abs16 { sym: None, offset, addend } =>
                Ok(X86Reloc::Abs16 { offset: offset, sym: None,
                                     addend: addend }),
            X86Reloc::PC16 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::PC16 { offset: offset, sym: Some(name),
                                    addend: addend }),
            X86Reloc::PC16 { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::PC16 { sym: None, offset, addend } =>
                Ok(X86Reloc::PC16 { offset: offset, sym: None,
                                    addend: addend }),
            X86Reloc::Abs8 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::Abs8 { offset: offset, sym: Some(name),
                                    addend: addend }),
            X86Reloc::Abs8 { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::Abs8 { sym: None, offset, addend } =>
                Ok(X86Reloc::Abs8 { offset: offset, sym: None,
                                    addend: addend }),
            X86Reloc::PC8 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::PC8 { offset: offset, sym: Some(name),
                                   addend: addend }),
            X86Reloc::PC8 { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::PC8 { sym: None, offset, addend } =>
                Ok(X86Reloc::PC8 { offset: offset, sym: None,
                                   addend: addend }),
            X86Reloc::Size { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Reloc::Size { offset: offset, sym: Some(name),
                                    addend: addend }),
            X86Reloc::Size { sym: Some(Err(err)), .. } => Err(err),
            X86Reloc::Size { sym: None, offset, addend } =>
                Ok(X86Reloc::Size { offset: offset, sym: None,
                                    addend: addend })
        }
    }
}

impl<'a> From<X86RelocStrSym<'a>> for X86RelocStr<'a> {
    #[inline]
    fn from(reloc: X86RelocStrSym<'a>) -> X86RelocStr<'a> {
        match reloc {
            X86Reloc::None => X86Reloc::None,
            X86Reloc::Abs32 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::Abs32 { offset: offset, sym: name, addend: addend },
            X86Reloc::PC32 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::PC32 { offset: offset, sym: name, addend: addend },
            X86Reloc::GOT32 { offset, addend } =>
                X86Reloc::GOT32 { offset: offset, addend: addend },
            X86Reloc::PLTRel { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::PLTRel { offset: offset, sym: name, addend: addend },
            X86Reloc::Copy { sym: SymData { name, .. } } =>
                X86Reloc::Copy { sym: name },
            X86Reloc::GlobalData { sym: SymData { name, .. }, offset } =>
                X86Reloc::GlobalData { offset: offset, sym: name },
            X86Reloc::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86Reloc::JumpSlot { offset: offset, sym: name },
            X86Reloc::Relative { offset, addend } =>
                X86Reloc::Relative { offset: offset, addend: addend },
            X86Reloc::GOTRel { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::GOTRel { offset: offset, sym: name, addend: addend },
            X86Reloc::GOTPC { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::GOTPC { offset: offset, sym: name, addend: addend },
            X86Reloc::PLTAbs { offset, addend } =>
                X86Reloc::PLTAbs { offset: offset, addend: addend },
            X86Reloc::Abs16 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::Abs16 { offset: offset, sym: name, addend: addend },
            X86Reloc::PC16 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::PC16 { offset: offset, sym: name, addend: addend },
            X86Reloc::Abs8 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::Abs8 { offset: offset, sym: name, addend: addend },
            X86Reloc::PC8 { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::PC8 { offset: offset, sym: name, addend: addend },
            X86Reloc::Size { sym: SymData { name, .. }, offset, addend } =>
                X86Reloc::Size { offset: offset, sym: name, addend: addend }
        }
    }
}
