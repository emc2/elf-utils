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
use crate::elf::ElfClass;
use crate::reloc::ArchReloc;
use crate::reloc::BasicRelocParams;
use crate::reloc::Reloc;
use crate::reloc::RelocParams;
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
/// [RelData](crate::reloc::RelData) with [Elf32](crate::Elf32) as
/// the [ElfClass](crate::ElfClass) type argument using the
/// [TryFrom](core::convert::TryFrom) instances for easier handling.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86Rel<Name> {
    /// Null relocation.
    None,
    /// 32-bit absolute offset.
    ///
    /// Sets the 4-byte word at `offset` to `sym + addend`.
    Abs32 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name
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
        sym: Name
    },
    /// 16-bit absolute offset.
    ///
    /// Set the 2-byte word at `offset` to `sym + addend`.
    Abs16 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name
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
        sym: Name
    },
    /// 8-bit absolute offset.
    ///
    /// Set the 1-byte word at `offset` to `sym + addend`.
    Abs8 {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name
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
        sym: Name
    },
    /// 32-bit Global Offset Table index.
    ///
    /// Set the 4-byte word at `offset` to the sum of the address of
    /// the Global Offset Table and `addend`.
    GOT32 {
        /// Offset in the section.
        offset: u32
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
        sym: Name
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
        offset: u32
    },
    /// 32-bit absolute offset to a Global Offset Table entry.
    ///
    /// Set the 4-byte word at `offset` to the relative
    /// address of `sym + addend` from the Global Offset Table.
    GOTRel {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name
    },
    /// 32-bit PC-relative offset to a Global Offset Table entry.
    ///
    /// Set the 4-byte word at `offset` relative address of Global
    /// Offset Table address added to `addend` from the address of the
    /// word at `offset`.
    GOTPC {
        /// Offset in the section.
        offset: u32
    },
    /// 32-bit absolute offset to a Procedure Linkage Table entry.
    ///
    /// Set the 4-byte word at `offset` to the sum of the address of
    /// the Procedure Linkage Table and `addend`.
    PLTAbs {
        /// Offset in the section.
        offset: u32
    },
    /// Symbol size.
    ///
    /// Set the 4-byte word at `offset` to the sum of the size of the
    /// symbol and `addend`.
    Size {
        /// Offset in the section.
        offset: u32,
        /// Symbol reference.
        sym: Name
    }
}

/// Relocation entries for 32-bit x86 architectures (aka. IA-32,
/// i386), with explicit addends.
///
/// This datatype provides a semantic-level presentation of the x86
/// relocation entries.  These can be converted to and from
/// [RelaData](crate::reloc::RelaData) with [Elf32](crate::Elf32) as
/// the [ElfClass](crate::ElfClass) type argument using the
/// [TryFrom](core::convert::TryFrom) instances for easier handling.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86Rela<Name> {
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

/// Type synonym for [X86Rel] as projected from a [Rel](crate::reloc::Rel).
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [Rel](crate::reloc::Rel).
pub type X86RelRaw = X86Rel<u32>;

/// Type synonym for [X86Rel] with [SymDataRaw] as the symbol type.
///
/// This is obtained directly from the [WithSymtab] instance acting on a
/// [X86RelRaw].
pub type X86RelRawSym = X86Rel<SymDataRaw<Elf32>>;

/// Type synonym for [X86Rel] with [SymDataStrData] as the symbol type.
///
/// This is obtained directly from the [WithStrtab] instance acting on
/// a [X86RelRawSym].
pub type X86RelStrDataSym<'a> = X86Rel<SymDataStrData<'a, Elf32>>;

/// Type synonym for [X86Rel] with [SymDataStr] as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelStrDataSym].
pub type X86RelStrData<'a> = X86Rel<Option<Result<&'a str, &'a [u8]>>>;

/// Type synonym for [X86Rel] with UTF-8 decoded string data as the
/// symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelStrDataSym].
pub type X86RelStrSym<'a> = X86Rel<SymDataStr<'a, Elf32>>;

/// Type synonym for [X86Rel] with a `&'a str`s as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelStrSym].
pub type X86RelStr<'a> = X86Rel<Option<&'a str>>;

/// Errors that can occur converting a
/// [RelData](crate::reloc::RelData) to a [X86Rel].
///
/// At present, this can only happen with a bad tag value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum X86RelocError {
    /// Unknown tag value.
    BadTag(u8)
}

/// Errors that can occur during relocation.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86RelocApplyError {
    /// Bad symbol base.
    BadSymBase(SymBase<u16, u16>),
    /// Out-of-bounds symbol index.
    BadSymIdx(u16),
    /// No GOT is present.
    NoGOT,
    /// No PLT is present.
    NoPLT,
    /// Copy relocation is present.
    Copy
}

/// Errors that can occur when loading an x86-specific relocation.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86RelocLoadError<'a> {
    /// Error parsing the raw data.
    Raw(X86RelocError),
    /// Error applying symbol table.
    Symtab(RelocSymtabError<Elf32>),
    /// Error applying string table.
    Strtab(u32),
    /// UTF-8 decode error
    UTF8(&'a [u8])
}


/// Type synonym for [X86Rela] as projected from a [Rel](crate::reloc::Rel).
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [Rel](crate::reloc::Rel).
pub type X86RelaRaw = X86Rela<u32>;

/// Type synonym for [X86Rela] with [SymDataRaw] as the symbol type.
///
/// This is obtained directly from the [WithSymtab] instance acting on a
/// [X86RelaRaw].
pub type X86RelaRawSym = X86Rela<SymDataRaw<Elf32>>;

/// Type synonym for [X86Rela] with [SymDataStrData] as the symbol type.
///
/// This is obtained directly from the [WithStrtab] instance acting on
/// a [X86RelaRawSym].
pub type X86RelaStrDataSym<'a> = X86Rela<SymDataStrData<'a, Elf32>>;

/// Type synonym for [X86Rela] with [SymDataStr] as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelaStrDataSym].
pub type X86RelaStrData<'a> = X86Rela<Option<Result<&'a str, &'a [u8]>>>;

/// Type synonym for [X86Rela] with UTF-8 decoded string data as the
/// symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelaStrDataSym].
pub type X86RelaStrSym<'a> = X86Rela<SymDataStr<'a, Elf32>>;

/// Type synonym for [X86Rela] with a `&'a str`s as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86RelaStrSym].
pub type X86RelaStr<'a> = X86Rela<Option<&'a str>>;

impl<Name> Display for X86Rel<Name>
    where Name: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86Rel::None => write!(f, "none"),
            X86Rel::Abs32 { offset, sym } =>
                write!(f, ".section[{:x}..{:x}] += &{}",
                       offset, offset + 4, sym),
            X86Rel::PC32 { offset, sym } =>
                write!(f, ".section[{}..{}] += &{} - (&.section + {})",
                       offset, offset + 4, sym, offset),
            X86Rel::Abs16 { offset, sym } =>
                write!(f, ".section[{}..{}] += &{}",
                       offset, offset + 2, sym),
            X86Rel::PC16 { offset, sym } =>
                write!(f, ".section[{}..{}] += &{} - (&.section + {})",
                       offset, offset + 2, sym, offset),
            X86Rel::Abs8 { offset, sym } =>
                write!(f, ".section[{}] += &{}", offset, sym),
            X86Rel::PC8 { offset, sym } =>
                write!(f, ".section[{}] += &{} - (&.section + {})",
                       offset, sym, offset),
            X86Rel::GOT32 { offset } =>
                write!(f, ".section[{}..{}] += &.got",
                       offset, offset + 4),
            X86Rel::PLTRel { offset, .. } =>
                write!(f, ".section[{}..{}] += &.plt - (&.section + {})",
                       offset, offset + 4, offset),
            X86Rel::Copy { sym } => write!(f, "copy {}", sym),
            X86Rel::GlobalData { offset, sym } =>
                write!(f, ".got[{}..{}] <- &{}", offset, offset + 4, sym),
            X86Rel::JumpSlot { offset, sym } =>
                write!(f, ".plt[{}..{}] <- &{}", offset, offset + 4, sym),
            X86Rel::Relative { offset } =>
                write!(f, ".section[{}..{}] += &base",
                       offset, offset + 4),
            X86Rel::GOTRel { offset, sym } =>
                write!(f, ".section[{}..{}] += &{} - &.got",
                       offset, offset + 4, sym),
            X86Rel::GOTPC { offset, .. } =>
                write!(f, ".section[{}..{}] <- &.got - (&.section + {})",
                       offset, offset + 4, offset),
            X86Rel::PLTAbs { offset } =>
                write!(f, ".section[{}..{}] += &.plt", offset, offset + 4),
            X86Rel::Size { offset, sym } =>
                write!(f, ".section[{}..{}] += sizeof({})",
                       offset, offset + 4, sym),
        }
    }
}

impl<Name> Display for X86Rela<Name>
    where Name: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86Rela::None => write!(f, "none"),
            X86Rela::Abs32 { offset, sym, addend } =>
                write!(f, ".section[{:x}..{:x}] <- &{} + {:x}",
                       offset, offset + 4, sym, addend),
            X86Rela::PC32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 4, sym, addend, offset),
            X86Rela::Abs16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 2, sym, addend),
            X86Rela::PC16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 2, sym, addend, offset),
            X86Rela::Abs8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- &{} + {}",
                       offset, sym, addend),
            X86Rela::PC8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- (&{} + {}) - (&.section + {})",
                       offset, sym, addend, offset),
            X86Rela::GOT32 { offset, addend } =>
                write!(f, ".section[{}..{}] <- &.got + {}",
                       offset, offset + 4, addend),
            X86Rela::PLTRel { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.plt + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86Rela::Copy { sym } => write!(f, "copy {}", sym),
            X86Rela::GlobalData { offset, sym } =>
                write!(f, ".got[{}..{}] <- &{}", offset, offset + 4, sym),
            X86Rela::JumpSlot { offset, sym } =>
                write!(f, ".plt[{}..{}] <- &{}", offset, offset + 4, sym),
            X86Rela::Relative { offset, addend } =>
                write!(f, ".section[{}..{}] <- &base + {}",
                       offset, offset + 4, addend),
            X86Rela::GOTRel { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - &.got",
                       offset, offset + 4, sym, addend),
            X86Rela::GOTPC { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.got + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86Rela::PLTAbs { offset, addend } =>
                write!(f, ".section[{}..{}] <- &.plt + {}",
                       offset, offset + 4, addend),
            X86Rela::Size { offset, sym, addend } =>
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

impl Display for X86RelocApplyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86RelocApplyError::BadSymBase(symbase) => {
                write!(f, "symbol base {} cannot be interpreted", symbase)
            },
            X86RelocApplyError::BadSymIdx(idx) => {
                write!(f, "symbol index {} out of bounds", idx)
            },
            X86RelocApplyError::NoGOT => write!(f, "no GOT present"),
            X86RelocApplyError::NoPLT => write!(f, "no PLT present"),
            X86RelocApplyError::Copy => {
                write!(f, "cannot apply copy relocation")
            }
        }
    }
}

impl<'a> Display for X86RelocLoadError<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86RelocLoadError::Raw(err) => Display::fmt(err, f),
            X86RelocLoadError::Symtab(err) => Display::fmt(err, f),
            X86RelocLoadError::Strtab(err) => Display::fmt(err, f),
            X86RelocLoadError::UTF8(_) => write!(f, "UTF-8 decode error")
        }
    }
}

impl<Name> Reloc<LittleEndian, Elf32>
    for X86Rel<SymData<Name, u16, Elf32>> {
    type Params = BasicRelocParams<Elf32>;
    type RelocError = X86RelocApplyError;

    fn reloc<'a, F>(&self, target: &mut [u8], params: &Self::Params,
                    target_base: u32, section_base: F) ->
        Result<(), Self::RelocError>
        where F: FnOnce(u16) -> Option<u32> {
        match self {
            X86Rel::None => Ok(()),
            X86Rel::Abs32 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                            offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i32;
                let addend = Elf32::read_word
                    ::<LittleEndian>(&target[range.clone()]) as i32;
                let value = base + (*value as i32) + addend;

                Elf32::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86Rel::Abs32 { sym: SymData { section: SymBase::Index(idx),
                                           value, .. },
                            offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i32;
                    let addend = Elf32::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let value = base + (*value as i32) + addend;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::Abs32 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::PC32 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                           offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i32;
                let addend = Elf32::read_word
                    ::<LittleEndian>(&target[range.clone()]) as i32;
                let sym_value = base + (*value as i32) + addend;
                let pc = (params.img_base() + target_base + *offset) as i32;
                let value = sym_value - pc;

                Elf32::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86Rel::PC32 { sym: SymData { section: SymBase::Index(idx),
                                             value, .. },
                           offset } =>  match section_base(*idx) {
                Some(section_base) => {

                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i32;
                    let addend = Elf32::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let value = sym_value - pc;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::PC32 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::Abs16 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                            offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i32;
                let addend = Elf32::read_half
                    ::<LittleEndian>(&target[range.clone()]) as i32;
                let value = base + (*value as i32) + addend;

                Elf32::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86Rel::Abs16 { sym: SymData { section: SymBase::Index(idx),
                                             value, .. },
                            offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 2;
                    let base = (params.img_base() + section_base) as i32;
                    let addend = Elf32::read_half
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let value = base + (*value as i32) + addend;

                    Elf32::write_half::<LittleEndian>(&mut target[range],
                                                      value as u16);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::Abs16 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::PC16 { sym: SymData { section: SymBase::Absolute,
                                          value, .. },
                           offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i32;
                let addend = Elf32::read_half
                    ::<LittleEndian>(&target[range.clone()]) as i32;
                let sym_value = base + (*value as i32) + addend;
                let pc = (params.img_base() + target_base + *offset) as i32;
                let value = sym_value - pc;

                Elf32::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86Rel::PC16 { sym: SymData { section: SymBase::Index(idx),
                                          value, .. },
                           offset } =>  match section_base(*idx) {
                Some(section_base) => {

                    let range = (*offset as usize) .. (*offset as usize) + 2;
                    let base = (params.img_base() + section_base) as i32;
                    let addend = Elf32::read_half
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let value = sym_value - pc;

                    Elf32::write_half::<LittleEndian>(&mut target[range],
                                                      value as u16);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::PC16 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::Abs8 { sym: SymData { section: SymBase::Absolute,
                                          value, .. },
                           offset } => {
                let base = params.img_base() as i32;
                let addend = target[base as usize] as i32;
                let value = base + (*value as i32) + addend;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86Rel::Abs8 { sym: SymData { section: SymBase::Index(idx),
                                          value, .. },
                           offset } => match section_base(*idx) {
                Some(section_base) => {
                    let base = (params.img_base() + section_base) as i32;
                    let addend = target[base as usize] as i32;
                    let value = base + (*value as i32) + addend;

                    target[*offset as usize] = value as u8;

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::Abs8 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::PC8 { sym: SymData { section: SymBase::Absolute,
                                         value, .. },
                          offset } => {
                let base = params.img_base() as i32;
                let addend = target[base as usize] as i32;
                let sym_value = base + (*value as i32) + addend;
                let pc = (params.img_base() + target_base + *offset) as i32;
                let value = sym_value - pc;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86Rel::PC8 { sym: SymData { section: SymBase::Index(idx),
                                         value, .. },
                          offset } =>  match section_base(*idx) {
                Some(section_base) => {

                    let base = (params.img_base() + section_base) as i32;
                    let addend = target[base as usize] as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let value = sym_value - pc;

                    target[*offset as usize] = value as u8;

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::PC8 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::GOT32 { offset } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let addend = Elf32::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let value = ((got as i32) + addend) as u32;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value);

                    Ok(())
                },
                None => Err(X86RelocApplyError::NoGOT)
            },
            X86Rel::PLTRel { offset, .. } => match params.plt() {
                Some(plt) => {

                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let addend = Elf32::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let value = ((plt as i32) + addend) - pc;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                }
                None => Err(X86RelocApplyError::NoPLT)
            },
            X86Rel::Copy { .. } => Err(X86RelocApplyError::Copy),
            X86Rel::GlobalData { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i32;
                let value = base + (*value as i32);

                Elf32::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86Rel::GlobalData { sym: SymData { section: SymBase::Index(idx),
                                                value, .. },
                                 offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i32;
                    let value = base + (*value as i32);

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::GlobalData { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::JumpSlot { sym: SymData { section: SymBase::Absolute,
                                              value, .. },
                               offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i32;
                let value = base + (*value as i32);

                Elf32::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86Rel::JumpSlot { sym: SymData { section: SymBase::Index(idx),
                                              value, .. },
                               offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i32;
                    let value = base + (*value as i32);

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::JumpSlot { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::Relative { offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let addend = Elf32::read_word
                    ::<LittleEndian>(&target[range.clone()]) as i32;
                let value = ((params.img_base() as i32) + addend) as u32;

                Elf32::write_word::<LittleEndian>(&mut target[range], value);

                Ok(())
            },
            X86Rel::GOTRel { sym: SymData { section: SymBase::Absolute,
                                            value, .. },
                             offset } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = params.img_base() as i32;
                    let got_base = got as i32;
                    let addend = Elf32::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let value = sym_value - got_base;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::NoGOT)
            },
            X86Rel::GOTRel { sym: SymData { section: SymBase::Index(idx),
                                            value, .. },
                             offset } => match (section_base(*idx),
                                                params.got()) {
                (Some(section_base), Some(got)) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let got_base = got as i32;
                    let base = (params.img_base() + section_base) as i32;
                    let addend = Elf32::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let value = sym_value - got_base;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                (None, _) => Err(X86RelocApplyError::NoGOT),
                (_, None) => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rel::GOTRel { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rel::GOTPC { offset } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let addend = Elf32::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let value = ((got as i32) + addend) - pc;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::NoGOT)
            },
            X86Rel::PLTAbs { offset } => match params.plt() {
                Some(plt) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let addend = Elf32::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i32;
                    let value = ((plt as i32) + addend) as u32;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value);

                    Ok(())
                },
                None => Err(X86RelocApplyError::NoPLT)
            },
            X86Rel::Size { sym: SymData { size, .. }, offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let addend = Elf32::read_word
                    ::<LittleEndian>(&target[range.clone()]) as i32;
                let value = ((*size as i32) + addend) as u32;

                Elf32::write_word::<LittleEndian>(&mut target[range], value);

                Ok(())
            }
        }
    }
}

impl<Name> Reloc<LittleEndian, Elf32>
    for X86Rela<SymData<Name, u16, Elf32>> {
    type Params = BasicRelocParams<Elf32>;
    type RelocError = X86RelocApplyError;

    fn reloc<'a, F>(&self, target: &mut [u8], params: &Self::Params,
                    target_base: u32, section_base: F) ->
        Result<(), Self::RelocError>
        where F: FnOnce(u16) -> Option<u32> {
        match self {
            X86Rela::None => Ok(()),
            X86Rela::Abs32 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                              offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i32;
                let value = base + (*value as i32) + addend;

                Elf32::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86Rela::Abs32 { sym: SymData { section: SymBase::Index(idx),
                                             value, .. },
                              offset, addend } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i32;
                    let value = base + (*value as i32) + addend;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::Abs32 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::PC32 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                             offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i32;
                let sym_value = base + (*value as i32) + addend;
                let pc = (params.img_base() + target_base + *offset) as i32;
                let value = sym_value - pc;

                Elf32::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86Rela::PC32 { sym: SymData { section: SymBase::Index(idx),
                                             value, .. },
                             offset, addend } =>  match section_base(*idx) {
                Some(section_base) => {

                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let value = sym_value - pc;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::PC32 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::Abs16 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                              offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i32;
                let value = base + (*value as i32) + addend;

                Elf32::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86Rela::Abs16 { sym: SymData { section: SymBase::Index(idx),
                                             value, .. },
                              offset, addend } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 2;
                    let base = (params.img_base() + section_base) as i32;
                    let value = base + (*value as i32) + addend;

                    Elf32::write_half::<LittleEndian>(&mut target[range],
                                                      value as u16);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::Abs16 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::PC16 { sym: SymData { section: SymBase::Absolute,
                                            value, .. },
                             offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i32;
                let sym_value = base + (*value as i32) + addend;
                let pc = (params.img_base() + target_base + *offset) as i32;
                let value = sym_value - pc;

                Elf32::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86Rela::PC16 { sym: SymData { section: SymBase::Index(idx),
                                            value, .. },
                             offset, addend } =>  match section_base(*idx) {
                Some(section_base) => {

                    let range = (*offset as usize) .. (*offset as usize) + 2;
                    let base = (params.img_base() + section_base) as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let value = sym_value - pc;

                    Elf32::write_half::<LittleEndian>(&mut target[range],
                                                      value as u16);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::PC16 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::Abs8 { sym: SymData { section: SymBase::Absolute,
                                            value, .. },
                             offset, addend } => {
                let base = params.img_base() as i32;
                let value = base + (*value as i32) + addend;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86Rela::Abs8 { sym: SymData { section: SymBase::Index(idx),
                                            value, .. },
                              offset, addend } => match section_base(*idx) {
                Some(section_base) => {
                    let base = (params.img_base() + section_base) as i32;
                    let value = base + (*value as i32) + addend;

                    target[*offset as usize] = value as u8;

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::Abs8 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::PC8 { sym: SymData { section: SymBase::Absolute,
                                           value, .. },
                            offset, addend } => {
                let base = params.img_base() as i32;
                let sym_value = base + (*value as i32) + addend;
                let pc = (params.img_base() + target_base + *offset) as i32;
                let value = sym_value - pc;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86Rela::PC8 { sym: SymData { section: SymBase::Index(idx),
                                           value, .. },
                            offset, addend } =>  match section_base(*idx) {
                Some(section_base) => {

                    let base = (params.img_base() + section_base) as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let value = sym_value - pc;

                    target[*offset as usize] = value as u8;

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::PC8 { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::GOT32 { offset, addend } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let value = ((got as i32) + addend) as u32;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value);

                    Ok(())
                },
                None => Err(X86RelocApplyError::NoGOT)
            },
            X86Rela::PLTRel { offset, addend, .. } =>  match params.plt() {
                Some(plt) => {

                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let value = ((plt as i32) + addend) - pc;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                }
                None => Err(X86RelocApplyError::NoPLT)
            },
            X86Rela::Copy { .. } => Err(X86RelocApplyError::Copy),
            X86Rela::GlobalData { sym: SymData { section: SymBase::Absolute,
                                                  value, .. },
                                   offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i32;
                let value = base + (*value as i32);

                Elf32::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86Rela::GlobalData { sym: SymData { section: SymBase::Index(idx),
                                                  value, .. },
                                   offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i32;
                    let value = base + (*value as i32);

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::GlobalData { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::JumpSlot { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i32;
                let value = base + (*value as i32);

                Elf32::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86Rela::JumpSlot { sym: SymData { section: SymBase::Index(idx),
                                                value, .. },
                                 offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i32;
                    let value = base + (*value as i32);

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::JumpSlot { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::Relative { offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let value = ((params.img_base() as i32) + addend) as u32;

                Elf32::write_word::<LittleEndian>(&mut target[range], value);

                Ok(())
            },
            X86Rela::GOTRel { sym: SymData { section: SymBase::Absolute,
                                              value, .. },
                               offset, addend } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = params.img_base() as i32;
                    let got_base = got as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let value = sym_value - got_base;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::NoGOT)
            },
            X86Rela::GOTRel { sym: SymData { section: SymBase::Index(idx),
                                              value, .. },
                               offset, addend } => match (section_base(*idx),
                                                          params.got()) {
                (Some(section_base), Some(got)) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let got_base = got as i32;
                    let base = (params.img_base() + section_base) as i32;
                    let sym_value = base + (*value as i32) + addend;
                    let value = sym_value - got_base;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                (None, _) => Err(X86RelocApplyError::NoGOT),
                (_, None) => Err(X86RelocApplyError::BadSymIdx(*idx))
            },
            X86Rela::GOTRel { sym: SymData { section, .. }, .. } =>
                Err(X86RelocApplyError::BadSymBase(*section)),
            X86Rela::GOTPC { offset, addend } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let pc = (params.img_base() + target_base + *offset) as i32;
                    let value = ((got as i32) + addend) - pc;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86RelocApplyError::NoGOT)
            },
            X86Rela::PLTAbs { offset, addend } => match params.plt() {
                Some(plt) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let value = ((plt as i32) + addend) as u32;

                    Elf32::write_word::<LittleEndian>(&mut target[range],
                                                      value);

                    Ok(())
                },
                None => Err(X86RelocApplyError::NoPLT)
            },
            X86Rela::Size { sym: SymData { size, .. }, offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let value = ((*size as i32) + addend) as u32;

                Elf32::write_word::<LittleEndian>(&mut target[range], value);

                Ok(())
            }
        }
    }
}

impl<Name> TryFrom<RelData<Name, Elf32>> for X86Rel<Name> {
    type Error = X86RelocError;

    #[inline]
    fn try_from(rel: RelData<Name, Elf32>) -> Result<X86Rel<Name>,
                                                     X86RelocError> {
        let RelData { offset, sym, kind } = rel;

        match kind {
            0 => Ok(X86Rel::None),
            1 => Ok(X86Rel::Abs32 { offset: offset, sym: sym }),
            2 => Ok(X86Rel::PC32 { offset: offset, sym: sym }),
            3 => Ok(X86Rel::GOT32 { offset: offset }),
            4 => Ok(X86Rel::PLTRel { offset: offset, sym: sym }),
            5 => Ok(X86Rel::Copy { sym: sym }),
            6 => Ok(X86Rel::GlobalData { offset: offset, sym: sym }),
            7 => Ok(X86Rel::JumpSlot { offset: offset, sym: sym }),
            8 => Ok(X86Rel::Relative { offset: offset }),
            9 => Ok(X86Rel::GOTRel { offset: offset, sym: sym }),
            10 => Ok(X86Rel::GOTPC { offset: offset }),
            11 => Ok(X86Rel::PLTAbs { offset: offset }),
            20 => Ok(X86Rel::Abs16 { offset: offset, sym: sym }),
            21 => Ok(X86Rel::PC16 { offset: offset, sym: sym }),
            22 => Ok(X86Rel::Abs8 { offset: offset, sym: sym }),
            23 => Ok(X86Rel::PC8 { offset: offset, sym: sym }),
            38 => Ok(X86Rel::Size { offset: offset, sym: sym }),
            tag => Err(X86RelocError::BadTag(tag))
        }
    }
}

impl From<X86Rel<u32>> for RelData<u32, Elf32> {
    #[inline]
    fn from(rel: X86Rel<u32>) -> RelData<u32, Elf32> {
        match rel {
            X86Rel::None => RelData { offset: 0, sym: 0, kind: 0 },
            X86Rel::Abs32 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 1 },
            X86Rel::PC32 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 2 },
            X86Rel::GOT32 { offset } =>
                RelData { offset: offset, sym: 0, kind: 3 },
            X86Rel::PLTRel { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 4 },
            X86Rel::Copy { sym } =>
                RelData { offset: 0, sym: sym, kind: 5 },
            X86Rel::GlobalData { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 6 },
            X86Rel::JumpSlot { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 7 },
            X86Rel::Relative { offset } =>
                RelData { offset: offset, sym: 0, kind: 8 },
            X86Rel::GOTRel { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 9 },
            X86Rel::GOTPC { offset } =>
                RelData { offset: offset, sym: 0, kind: 10 },
            X86Rel::PLTAbs { offset } =>
                RelData { offset: offset, sym: 0, kind: 11 },
            X86Rel::Abs16 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 20 },
            X86Rel::PC16 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 21 },
            X86Rel::Abs8 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 22 },
            X86Rel::PC8 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 23 },
            X86Rel::Size { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 38 },
        }
    }
}

impl<Name> TryFrom<RelaData<Name, Elf32>> for X86Rela<Name> {
    type Error = X86RelocError;

    #[inline]
    fn try_from(rela: RelaData<Name, Elf32>) -> Result<X86Rela<Name>,
                                                       Self::Error> {
        let RelaData { offset, sym, kind, addend } = rela;

        match kind {
            0 => Ok(X86Rela::None),
            1 => Ok(X86Rela::Abs32 { offset: offset, sym: sym,
                                     addend: addend }),
            2 => Ok(X86Rela::PC32 { offset: offset, sym: sym,
                                    addend: addend }),
            3 => Ok(X86Rela::GOT32 { offset: offset, addend: addend }),
            4 => Ok(X86Rela::PLTRel { offset: offset, sym: sym,
                                      addend: addend }),
            5 => Ok(X86Rela::Copy { sym: sym }),
            6 => Ok(X86Rela::GlobalData { offset: offset, sym: sym }),
            7 => Ok(X86Rela::JumpSlot { offset: offset, sym: sym }),
            8 => Ok(X86Rela::Relative { offset: offset, addend: addend }),
            9 => Ok(X86Rela::GOTRel { offset: offset, sym: sym,
                                      addend: addend }),
            10 => Ok(X86Rela::GOTPC { offset: offset, addend: addend }),
            11 => Ok(X86Rela::PLTAbs { offset: offset, addend: addend }),
            20 => Ok(X86Rela::Abs16 { offset: offset, sym: sym,
                                      addend: addend }),
            21 => Ok(X86Rela::PC16 { offset: offset, sym: sym,
                                     addend: addend }),
            22 => Ok(X86Rela::Abs8 { offset: offset, sym: sym,
                                     addend: addend }),
            23 => Ok(X86Rela::PC8 { offset: offset, sym: sym,
                                    addend: addend }),
            38 => Ok(X86Rela::Size { offset: offset, sym: sym,
                                     addend: addend }),
            tag => Err(X86RelocError::BadTag(tag))
        }
    }
}

impl From<X86Rela<u32>> for RelaData<u32, Elf32> {
    #[inline]
    fn from(rel: X86Rela<u32>) -> RelaData<u32, Elf32> {
        match rel {
            X86Rela::None =>
                RelaData { offset: 0, sym: 0, kind: 0, addend: 0 },
            X86Rela::Abs32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 1, addend: addend },
            X86Rela::PC32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 2, addend: addend },
            X86Rela::GOT32 { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 3, addend: addend },
            X86Rela::PLTRel { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 4, addend: addend },
            X86Rela::Copy { sym } =>
                RelaData { offset: 0, sym: sym, kind: 5 , addend: 0 },
            X86Rela::GlobalData { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 6, addend: 0 },
            X86Rela::JumpSlot { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 7, addend: 0 },
            X86Rela::Relative { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 8, addend: addend },
            X86Rela::GOTRel { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 9, addend: addend },
            X86Rela::GOTPC { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 10, addend: addend },
            X86Rela::PLTAbs { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 11, addend: addend },
            X86Rela::Abs16 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 20, addend: addend },
            X86Rela::PC16 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 21, addend: addend },
            X86Rela::Abs8 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 22, addend: addend },
            X86Rela::PC8 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 23, addend: addend },
            X86Rela::Size { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 38, addend: addend },
        }
    }
}

impl<'a> WithSymtab<'a, LittleEndian, Elf32> for X86RelRaw {
    type Result = X86RelRawSym;
    type Error = RelocSymtabError<Elf32>;

    #[inline]
    fn with_symtab(self, symtab: Symtab<'a, LittleEndian, Elf32>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86Rel::None => Ok(X86Rel::None),
            X86Rel::Abs32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::Abs32 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::PC32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::PC32 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::GOT32 { offset } =>
                Ok(X86Rel::GOT32 { offset: offset }),
            X86Rel::PLTRel { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::PLTRel { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::Copy { sym } => match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::Copy { sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::GlobalData { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::GlobalData { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::JumpSlot { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::JumpSlot { offset: offset,
                                                  sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::Relative { offset } =>
                Ok(X86Rel::Relative { offset: offset }),
            X86Rel::GOTRel { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::GOTRel { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::GOTPC { offset } =>
                Ok(X86Rel::GOTPC { offset: offset }),
            X86Rel::PLTAbs { offset } =>
                Ok(X86Rel::PLTAbs { offset: offset }),
            X86Rel::Abs16 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::Abs16 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::PC16 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::PC16 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::Abs8 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::Abs8 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::PC8 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::PC8 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rel::Size { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rel::Size { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                }
        }
    }
}

impl<'a> WithSymtab<'a, LittleEndian, Elf32> for X86RelaRaw {
    type Result = X86RelaRawSym;
    type Error = RelocSymtabError<Elf32>;

    #[inline]
    fn with_symtab(self, symtab: Symtab<'a, LittleEndian, Elf32>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86Rela::None => Ok(X86Rela::None),
            X86Rela::Abs32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::Abs32 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::PC32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::PC32 { offset: offset, sym: symdata,
                                               addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::GOT32 { offset, addend } =>
                Ok(X86Rela::GOT32 { offset: offset, addend: addend }),
            X86Rela::PLTRel { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::PLTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::Copy { sym } => match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::Copy { sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::GlobalData { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::GlobalData { offset: offset,
                                                     sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::JumpSlot { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::JumpSlot { offset: offset,
                                                   sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::Relative { offset, addend } =>
                Ok(X86Rela::Relative { offset: offset, addend: addend }),
            X86Rela::GOTRel { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::GOTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::GOTPC { offset, addend } =>
                Ok(X86Rela::GOTPC { offset: offset, addend: addend }),
            X86Rela::PLTAbs { offset, addend } =>
                Ok(X86Rela::PLTAbs { offset: offset, addend: addend }),
            X86Rela::Abs16 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::Abs16 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::PC16 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::PC16 { offset: offset, sym: symdata,
                                               addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::Abs8 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::Abs8 { offset: offset, sym: symdata,
                                               addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::PC8 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::PC8 { offset: offset, sym: symdata,
                                              addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86Rela::Size { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86Rela::Size { offset: offset, sym: symdata,
                                               addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                }
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf32> for X86RelRawSym {
    type Ent = RelData<u32, Elf32>;
    type LoadError = X86RelocLoadError<'a>;

    #[inline]
    fn from_relent(ent: RelData<u32, Elf32>,
                   symtab: Symtab<'a, LittleEndian, Elf32>,
                   _strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let raw: X86RelRaw = match X86Rel::try_from(ent) {
            Ok(raw) => Ok(raw),
            Err(err) => Err(X86RelocLoadError::Raw(err))
        }?;

        match raw.with_symtab(symtab) {
            Ok(out) => Ok(out),
            Err(err) => Err(X86RelocLoadError::Symtab(err))
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf32> for X86RelaRawSym {
    type Ent = RelaData<u32, Elf32>;
    type LoadError = X86RelocLoadError<'a>;

    #[inline]
    fn from_relent(ent: RelaData<u32, Elf32>,
                   symtab: Symtab<'a, LittleEndian, Elf32>,
                   _strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let raw: X86RelaRaw = match X86Rela::try_from(ent) {
            Ok(raw) => Ok(raw),
            Err(err) => Err(X86RelocLoadError::Raw(err))
        }?;

        match raw.with_symtab(symtab) {
            Ok(out) => Ok(out),
            Err(err) => Err(X86RelocLoadError::Symtab(err))
        }
    }
}

impl<'a> WithStrtab<'a> for X86RelRawSym {
    type Result = X86RelStrDataSym<'a>;
    type Error = u32;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86Rel::None => Ok(X86Rel::None),
            X86Rel::Abs32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::Abs32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::PC32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::PC32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::GOT32 { offset } =>
                Ok(X86Rel::GOT32 { offset: offset }),
            X86Rel::PLTRel { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::PLTRel { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::Copy { sym } => match sym.with_strtab(strtab) {
                Ok(symdata) => {
                    Ok(X86Rel::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86Rel::GlobalData { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::GlobalData { offset: offset,
                                                sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::JumpSlot { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::JumpSlot { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::Relative { offset } =>
                Ok(X86Rel::Relative { offset: offset }),
            X86Rel::GOTRel { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::GOTRel { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::GOTPC { offset } =>
                Ok(X86Rel::GOTPC { offset: offset }),
            X86Rel::PLTAbs { offset } =>
                Ok(X86Rel::PLTAbs { offset: offset }),
            X86Rel::Abs16 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::Abs16 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::PC16 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::PC16 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::Abs8 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::Abs8 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::PC8 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::PC8 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::Size { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rel::Size { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                }
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf32> for X86RelStrDataSym<'a> {
    type Ent = RelData<u32, Elf32>;
    type LoadError = X86RelocLoadError<'a>;

    fn from_relent(ent: RelData<u32, Elf32>,
                   symtab: Symtab<'a, LittleEndian, Elf32>,
                   strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let raw: X86RelRawSym = X86Rel::from_relent(ent, symtab, strtab)?;

        match raw.with_strtab(strtab) {
            Ok(out) => Ok(out),
            Err(err) => Err(X86RelocLoadError::Strtab(err))
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf32> for X86RelaStrDataSym<'a> {
    type Ent = RelaData<u32, Elf32>;
    type LoadError = X86RelocLoadError<'a>;

    fn from_relent(ent: RelaData<u32, Elf32>,
                   symtab: Symtab<'a, LittleEndian, Elf32>,
                   strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let raw: X86RelaRawSym = X86Rela::from_relent(ent, symtab, strtab)?;

        match raw.with_strtab(strtab) {
            Ok(out) => Ok(out),
            Err(err) => Err(X86RelocLoadError::Strtab(err))
        }
    }
}

impl<'a> WithStrtab<'a> for X86RelaRawSym {
    type Result = X86RelaStrDataSym<'a>;
    type Error = u32;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86Rela::None => Ok(X86Rela::None),
            X86Rela::Abs32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::Abs32 { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::PC32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::PC32 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::GOT32 { offset, addend } =>
                Ok(X86Rela::GOT32 { offset: offset, addend: addend }),
            X86Rela::PLTRel { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::PLTRel { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::Copy { sym } => match sym.with_strtab(strtab) {
                Ok(symdata) => {
                    Ok(X86Rela::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86Rela::GlobalData { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::GlobalData { offset: offset,
                                                  sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::JumpSlot { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::JumpSlot { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::Relative { offset, addend } =>
                Ok(X86Rela::Relative { offset: offset, addend: addend }),
            X86Rela::GOTRel { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::GOTRel { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::GOTPC { offset, addend } =>
                Ok(X86Rela::GOTPC { offset: offset, addend: addend }),
            X86Rela::PLTAbs { offset, addend } =>
                Ok(X86Rela::PLTAbs { offset: offset, addend: addend }),
            X86Rela::Abs16 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::Abs16 { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::PC16 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::PC16 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::Abs8 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::Abs8 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::PC8 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::PC8 { offset: offset, sym: symdata,
                                           addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::Size { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86Rela::Size { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                }
        }
    }
}

impl<'a> TryFrom<X86RelStrDataSym<'a>> for X86RelStrSym<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86RelStrDataSym<'a>) ->
        Result<X86RelStrSym<'a>, Self::Error> {
        match reloc {
            X86Rel::None => Ok(X86Rel::None),
            X86Rel::Abs32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::Abs32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::PC32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::PC32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::GOT32 { offset } =>
                Ok(X86Rel::GOT32 { offset: offset }),
            X86Rel::PLTRel { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::PLTRel { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::Copy { sym } => match sym.try_into() {
                Ok(symdata) => {
                    Ok(X86Rel::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86Rel::GlobalData { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::GlobalData { offset: offset,
                                                sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::JumpSlot { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::JumpSlot { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::Relative { offset } =>
                Ok(X86Rel::Relative { offset: offset }),
            X86Rel::GOTRel { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::GOTRel { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::GOTPC { offset } =>
                Ok(X86Rel::GOTPC { offset: offset }),
            X86Rel::PLTAbs { offset } =>
                Ok(X86Rel::PLTAbs { offset: offset }),
            X86Rel::Abs16 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::Abs16 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::PC16 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::PC16 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::Abs8 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::Abs8 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::PC8 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::PC8 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rel::Size { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rel::Size { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                }
        }
    }
}

impl<'a> TryFrom<X86RelaStrDataSym<'a>> for X86RelaStrSym<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86RelaStrDataSym<'a>) ->
        Result<X86RelaStrSym<'a>, Self::Error> {
        match reloc {
            X86Rela::None => Ok(X86Rela::None),
            X86Rela::Abs32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::Abs32 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::PC32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::PC32 { offset: offset, sym: symdata,
                                           addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::GOT32 { offset, addend } =>
                Ok(X86Rela::GOT32 { offset: offset, addend: addend }),
            X86Rela::PLTRel { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::PLTRel { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::Copy { sym } => match sym.try_into() {
                Ok(symdata) => {
                    Ok(X86Rela::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86Rela::GlobalData { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::GlobalData { offset: offset,
                                                 sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::JumpSlot { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::JumpSlot { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::Relative { offset, addend } =>
                Ok(X86Rela::Relative { offset: offset, addend: addend }),
            X86Rela::GOTRel { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::GOTRel { offset: offset, sym: symdata,
                                             addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::GOTPC { offset, addend } =>
                Ok(X86Rela::GOTPC { offset: offset, addend: addend }),
            X86Rela::PLTAbs { offset, addend } =>
                Ok(X86Rela::PLTAbs { offset: offset, addend: addend }),
            X86Rela::Abs16 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::Abs16 { offset: offset, sym: symdata,
                                            addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::PC16 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::PC16 { offset: offset, sym: symdata,
                                           addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::Abs8 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::Abs8 { offset: offset, sym: symdata,
                                           addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::PC8 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::PC8 { offset: offset, sym: symdata,
                                          addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86Rela::Size { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86Rela::Size { offset: offset, sym: symdata,
                                           addend: addend })
                    },
                    Err(err) => Err(err)
                }
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf32> for X86RelStrSym<'a> {
    type Ent = RelData<u32, Elf32>;
    type LoadError = X86RelocLoadError<'a>;

    #[inline]
    fn from_relent(ent: RelData<u32, Elf32>,
                   symtab: Symtab<'a, LittleEndian, Elf32>,
                   strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let sym: X86RelStrDataSym = X86Rel::from_relent(ent, symtab, strtab)?;

        match sym.try_into() {
            Ok(out) => Ok(out),
            Err(err) => Err(X86RelocLoadError::UTF8(err))
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf32> for X86RelaStrSym<'a> {
    type Ent = RelaData<u32, Elf32>;
    type LoadError = X86RelocLoadError<'a>;

    #[inline]
    fn from_relent(ent: RelaData<u32, Elf32>,
                   symtab: Symtab<'a, LittleEndian, Elf32>,
                   strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let sym: X86RelaStrDataSym = X86Rela::from_relent(ent, symtab, strtab)?;

        match sym.try_into() {
            Ok(out) => Ok(out),
            Err(err) => Err(X86RelocLoadError::UTF8(err))
        }
    }
}

impl<'a> From<X86RelStrDataSym<'a>> for X86RelStrData<'a> {
    #[inline]
    fn from(reloc: X86RelStrDataSym<'a>) -> X86RelStrData<'a> {
        match reloc {
            X86Rel::None => X86Rel::None,
            X86Rel::Abs32 { sym: SymData { name, .. }, offset } =>
                X86Rel::Abs32 { offset: offset, sym: name },
            X86Rel::PC32 { sym: SymData { name, .. }, offset } =>
                X86Rel::PC32 { offset: offset, sym: name },
            X86Rel::GOT32 { offset } =>
                X86Rel::GOT32 { offset: offset },
            X86Rel::PLTRel { sym: SymData { name, .. }, offset } =>
                X86Rel::PLTRel { offset: offset, sym: name },
            X86Rel::Copy { sym: SymData { name, .. } } =>
                X86Rel::Copy { sym: name },
            X86Rel::GlobalData { sym: SymData { name, .. }, offset } =>
                X86Rel::GlobalData { offset: offset, sym: name },
            X86Rel::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86Rel::JumpSlot { offset: offset, sym: name },
            X86Rel::Relative { offset } =>
                X86Rel::Relative { offset: offset },
            X86Rel::GOTRel { sym: SymData { name, .. }, offset } =>
                X86Rel::GOTRel { offset: offset, sym: name },
            X86Rel::GOTPC { offset } =>
                X86Rel::GOTPC { offset: offset },
            X86Rel::PLTAbs { offset } =>
                X86Rel::PLTAbs { offset: offset },
            X86Rel::Abs16 { sym: SymData { name, .. }, offset } =>
                X86Rel::Abs16 { offset: offset, sym: name },
            X86Rel::PC16 { sym: SymData { name, .. }, offset } =>
                X86Rel::PC16 { offset: offset, sym: name },
            X86Rel::Abs8 { sym: SymData { name, .. }, offset } =>
                X86Rel::Abs8 { offset: offset, sym: name },
            X86Rel::PC8 { sym: SymData { name, .. }, offset } =>
                X86Rel::PC8 { offset: offset, sym: name },
            X86Rel::Size { sym: SymData { name, .. }, offset } =>
                X86Rel::Size { offset: offset, sym: name }
        }
    }
}

impl<'a> From<X86RelaStrDataSym<'a>> for X86RelaStrData<'a> {
    #[inline]
    fn from(reloc: X86RelaStrDataSym<'a>) -> X86RelaStrData<'a> {
        match reloc {
            X86Rela::None => X86Rela::None,
            X86Rela::Abs32 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::Abs32 { offset: offset, sym: name, addend: addend },
            X86Rela::PC32 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::PC32 { offset: offset, sym: name, addend: addend },
            X86Rela::GOT32 { offset, addend } =>
                X86Rela::GOT32 { offset: offset, addend: addend },
            X86Rela::PLTRel { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::PLTRel { offset: offset, sym: name, addend: addend },
            X86Rela::Copy { sym: SymData { name, .. } } =>
                X86Rela::Copy { sym: name },
            X86Rela::GlobalData { sym: SymData { name, .. }, offset } =>
                X86Rela::GlobalData { offset: offset, sym: name },
            X86Rela::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86Rela::JumpSlot { offset: offset, sym: name },
            X86Rela::Relative { offset, addend } =>
                X86Rela::Relative { offset: offset, addend: addend },
            X86Rela::GOTRel { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::GOTRel { offset: offset, sym: name, addend: addend },
            X86Rela::GOTPC { offset, addend } =>
                X86Rela::GOTPC { offset: offset, addend: addend },
            X86Rela::PLTAbs { offset, addend } =>
                X86Rela::PLTAbs { offset: offset, addend: addend },
            X86Rela::Abs16 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::Abs16 { offset: offset, sym: name, addend: addend },
            X86Rela::PC16 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::PC16 { offset: offset, sym: name, addend: addend },
            X86Rela::Abs8 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::Abs8 { offset: offset, sym: name, addend: addend },
            X86Rela::PC8 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::PC8 { offset: offset, sym: name, addend: addend },
            X86Rela::Size { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::Size { offset: offset, sym: name, addend: addend }
        }
    }
}

impl<'a> TryFrom<X86RelStrData<'a>> for X86RelStr<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86RelStrData<'a>) ->
        Result<X86RelStr<'a>, Self::Error> {
        match reloc {
            X86Rel::None => Ok(X86Rel::None),
            X86Rel::Abs32 { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::Abs32 { offset: offset, sym: Some(name) }),
            X86Rel::Abs32 { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::Abs32 { sym: None, offset } =>
                Ok(X86Rel::Abs32 { offset: offset, sym: None }),
            X86Rel::PC32 { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::PC32 { offset: offset, sym: Some(name) }),
            X86Rel::PC32 { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::PC32 { sym: None, offset } =>
                Ok(X86Rel::PC32 { offset: offset, sym: None }),
            X86Rel::GOT32 { offset } => Ok(X86Rel::GOT32 { offset: offset }),
            X86Rel::PLTRel { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::PLTRel { offset: offset, sym: Some(name) }),
            X86Rel::PLTRel { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::PLTRel { sym: None, offset } =>
                Ok(X86Rel::PLTRel { offset: offset, sym: None }),
            X86Rel::Copy { sym: Some(Ok(name)) } =>
                Ok(X86Rel::Copy { sym: Some(name) }),
            X86Rel::Copy { sym: Some(Err(err)) } => Err(err),
            X86Rel::Copy { sym: None } => Ok(X86Rel::Copy { sym: None }),
            X86Rel::GlobalData { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::GlobalData { offset: offset, sym: Some(name) }),
            X86Rel::GlobalData { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::GlobalData { sym: None, offset } =>
                Ok(X86Rel::GlobalData { offset: offset, sym: None }),
            X86Rel::JumpSlot { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::JumpSlot { offset: offset, sym: Some(name) }),
            X86Rel::JumpSlot { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::JumpSlot { sym: None, offset } =>
                Ok(X86Rel::JumpSlot { offset: offset, sym: None }),
            X86Rel::Relative { offset } =>
                Ok(X86Rel::Relative { offset: offset }),
            X86Rel::GOTRel { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::GOTRel { offset: offset, sym: Some(name) }),
            X86Rel::GOTRel { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::GOTRel { sym: None, offset } =>
                Ok(X86Rel::GOTRel { offset: offset, sym: None }),
            X86Rel::GOTPC { offset } => Ok(X86Rel::GOTPC { offset: offset }),
            X86Rel::PLTAbs { offset } => Ok(X86Rel::PLTAbs { offset: offset }),
            X86Rel::Abs16 { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::Abs16 { offset: offset, sym: Some(name) }),
            X86Rel::Abs16 { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::Abs16 { sym: None, offset } =>
                Ok(X86Rel::Abs16 { offset: offset, sym: None }),
            X86Rel::PC16 { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::PC16 { offset: offset, sym: Some(name) }),
            X86Rel::PC16 { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::PC16 { sym: None, offset } =>
                Ok(X86Rel::PC16 { offset: offset, sym: None }),
            X86Rel::Abs8 { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::Abs8 { offset: offset, sym: Some(name) }),
            X86Rel::Abs8 { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::Abs8 { sym: None, offset } =>
                Ok(X86Rel::Abs8 { offset: offset, sym: None }),
            X86Rel::PC8 { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::PC8 { offset: offset, sym: Some(name) }),
            X86Rel::PC8 { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::PC8 { sym: None, offset } =>
                Ok(X86Rel::PC8 { offset: offset, sym: None }),
            X86Rel::Size { sym: Some(Ok(name)), offset } =>
                Ok(X86Rel::Size { offset: offset, sym: Some(name) }),
            X86Rel::Size { sym: Some(Err(err)), .. } => Err(err),
            X86Rel::Size { sym: None, offset } =>
                Ok(X86Rel::Size { offset: offset, sym: None })
        }
    }
}

impl<'a> TryFrom<X86RelaStrData<'a>> for X86RelaStr<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86RelaStrData<'a>) ->
        Result<X86RelaStr<'a>, Self::Error> {
            match reloc {
            X86Rela::None => Ok(X86Rela::None),
            X86Rela::Abs32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::Abs32 { offset: offset, sym: Some(name),
                                    addend: addend }),
            X86Rela::Abs32 { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::Abs32 { sym: None, offset, addend } =>
                Ok(X86Rela::Abs32 { offset: offset, sym: None,
                                    addend: addend }),
            X86Rela::PC32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::PC32 { offset: offset, sym: Some(name),
                                   addend: addend }),
            X86Rela::PC32 { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::PC32 { sym: None, offset, addend } =>
                Ok(X86Rela::PC32 { offset: offset, sym: None,
                                   addend: addend }),
            X86Rela::GOT32 { offset, addend } =>
                Ok(X86Rela::GOT32 { offset: offset, addend: addend }),
            X86Rela::PLTRel { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::PLTRel { offset: offset, sym: Some(name),
                                     addend: addend }),
            X86Rela::PLTRel { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::PLTRel { sym: None, offset, addend } =>
                Ok(X86Rela::PLTRel { offset: offset, sym: None,
                                     addend: addend }),
            X86Rela::Copy { sym: Some(Ok(name)) } =>
                Ok(X86Rela::Copy { sym: Some(name) }),
            X86Rela::Copy { sym: Some(Err(err)) } => Err(err),
            X86Rela::Copy { sym: None } => Ok(X86Rela::Copy { sym: None }),
            X86Rela::GlobalData { sym: Some(Ok(name)), offset } =>
                Ok(X86Rela::GlobalData { offset: offset, sym: Some(name) }),
            X86Rela::GlobalData { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::GlobalData { sym: None, offset } =>
                Ok(X86Rela::GlobalData { offset: offset, sym: None }),
            X86Rela::JumpSlot { sym: Some(Ok(name)), offset } =>
                Ok(X86Rela::JumpSlot { offset: offset, sym: Some(name) }),
            X86Rela::JumpSlot { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::JumpSlot { sym: None, offset } =>
                Ok(X86Rela::JumpSlot { offset: offset, sym: None }),
            X86Rela::Relative { offset, addend } =>
                Ok(X86Rela::Relative { offset: offset, addend: addend }),
            X86Rela::GOTRel { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::GOTRel { offset: offset, sym: Some(name),
                                     addend: addend }),
            X86Rela::GOTRel { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::GOTRel { sym: None, offset, addend } =>
                Ok(X86Rela::GOTRel { offset: offset, sym: None,
                                     addend: addend }),
            X86Rela::GOTPC { offset, addend } =>
                Ok(X86Rela::GOTPC { offset: offset, addend: addend }),
            X86Rela::PLTAbs { offset, addend } =>
                Ok(X86Rela::PLTAbs { offset: offset, addend: addend }),
            X86Rela::Abs16 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::Abs16 { offset: offset, sym: Some(name),
                                    addend: addend }),
            X86Rela::Abs16 { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::Abs16 { sym: None, offset, addend } =>
                Ok(X86Rela::Abs16 { offset: offset, sym: None,
                                    addend: addend }),
            X86Rela::PC16 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::PC16 { offset: offset, sym: Some(name),
                                   addend: addend }),
            X86Rela::PC16 { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::PC16 { sym: None, offset, addend } =>
                Ok(X86Rela::PC16 { offset: offset, sym: None,
                                   addend: addend }),
            X86Rela::Abs8 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::Abs8 { offset: offset, sym: Some(name),
                                   addend: addend }),
            X86Rela::Abs8 { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::Abs8 { sym: None, offset, addend } =>
                Ok(X86Rela::Abs8 { offset: offset, sym: None,
                                   addend: addend }),
            X86Rela::PC8 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::PC8 { offset: offset, sym: Some(name),
                                  addend: addend }),
            X86Rela::PC8 { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::PC8 { sym: None, offset, addend } =>
                Ok(X86Rela::PC8 { offset: offset, sym: None,
                                  addend: addend }),
            X86Rela::Size { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86Rela::Size { offset: offset, sym: Some(name),
                                   addend: addend }),
            X86Rela::Size { sym: Some(Err(err)), .. } => Err(err),
            X86Rela::Size { sym: None, offset, addend } =>
                Ok(X86Rela::Size { offset: offset, sym: None,
                                   addend: addend })
        }
    }
}

impl<'a> From<X86RelStrSym<'a>> for X86RelStr<'a> {
    #[inline]
    fn from(reloc: X86RelStrSym<'a>) -> X86RelStr<'a> {
        match reloc {
            X86Rel::None => X86Rel::None,
            X86Rel::Abs32 { sym: SymData { name, .. }, offset } =>
                X86Rel::Abs32 { offset: offset, sym: name },
            X86Rel::PC32 { sym: SymData { name, .. }, offset } =>
                X86Rel::PC32 { offset: offset, sym: name },
            X86Rel::GOT32 { offset } =>
                X86Rel::GOT32 { offset: offset },
            X86Rel::PLTRel { sym: SymData { name, .. }, offset } =>
                X86Rel::PLTRel { offset: offset, sym: name },
            X86Rel::Copy { sym: SymData { name, .. } } =>
                X86Rel::Copy { sym: name },
            X86Rel::GlobalData { sym: SymData { name, .. }, offset } =>
                X86Rel::GlobalData { offset: offset, sym: name },
            X86Rel::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86Rel::JumpSlot { offset: offset, sym: name },
            X86Rel::Relative { offset } =>
                X86Rel::Relative { offset: offset },
            X86Rel::GOTRel { sym: SymData { name, .. }, offset } =>
                X86Rel::GOTRel { offset: offset, sym: name },
            X86Rel::GOTPC { offset } =>
                X86Rel::GOTPC { offset: offset },
            X86Rel::PLTAbs { offset } =>
                X86Rel::PLTAbs { offset: offset },
            X86Rel::Abs16 { sym: SymData { name, .. }, offset } =>
                X86Rel::Abs16 { offset: offset, sym: name },
            X86Rel::PC16 { sym: SymData { name, .. }, offset } =>
                X86Rel::PC16 { offset: offset, sym: name },
            X86Rel::Abs8 { sym: SymData { name, .. }, offset } =>
                X86Rel::Abs8 { offset: offset, sym: name },
            X86Rel::PC8 { sym: SymData { name, .. }, offset } =>
                X86Rel::PC8 { offset: offset, sym: name },
            X86Rel::Size { sym: SymData { name, .. }, offset } =>
                X86Rel::Size { offset: offset, sym: name }
        }
    }
}

impl<'a> From<X86RelaStrSym<'a>> for X86RelaStr<'a> {
    #[inline]
    fn from(reloc: X86RelaStrSym<'a>) -> X86RelaStr<'a> {
        match reloc {
            X86Rela::None => X86Rela::None,
            X86Rela::Abs32 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::Abs32 { offset: offset, sym: name, addend: addend },
            X86Rela::PC32 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::PC32 { offset: offset, sym: name, addend: addend },
            X86Rela::GOT32 { offset, addend } =>
                X86Rela::GOT32 { offset: offset, addend: addend },
            X86Rela::PLTRel { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::PLTRel { offset: offset, sym: name, addend: addend },
            X86Rela::Copy { sym: SymData { name, .. } } =>
                X86Rela::Copy { sym: name },
            X86Rela::GlobalData { sym: SymData { name, .. }, offset } =>
                X86Rela::GlobalData { offset: offset, sym: name },
            X86Rela::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86Rela::JumpSlot { offset: offset, sym: name },
            X86Rela::Relative { offset, addend } =>
                X86Rela::Relative { offset: offset, addend: addend },
            X86Rela::GOTRel { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::GOTRel { offset: offset, sym: name, addend: addend },
            X86Rela::GOTPC { offset, addend } =>
                X86Rela::GOTPC { offset: offset, addend: addend },
            X86Rela::PLTAbs { offset, addend } =>
                X86Rela::PLTAbs { offset: offset, addend: addend },
            X86Rela::Abs16 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::Abs16 { offset: offset, sym: name, addend: addend },
            X86Rela::PC16 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::PC16 { offset: offset, sym: name, addend: addend },
            X86Rela::Abs8 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::Abs8 { offset: offset, sym: name, addend: addend },
            X86Rela::PC8 { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::PC8 { offset: offset, sym: name, addend: addend },
            X86Rela::Size { sym: SymData { name, .. }, offset, addend } =>
                X86Rela::Size { offset: offset, sym: name, addend: addend }
        }
    }
}
