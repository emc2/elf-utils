//! Relocation types for 64-bit x86-64 architecture.
//!
//! This module provides the `X86_64Reloc` type, which describes the
//! relocation entries for the AA-64 (aka. x86-64) architecture.
//! These can be converted to and from
//! [RelData](crate::reloc::RelData) or
//! [RelaData](crate::reloc::RelaData) with [Elf64](crate::Elf64) as
//! the [ElfClass](crate::ElfClass) type argument using the
//! [TryFrom](core::convert::TryFrom) instances for easier handling.
use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::Display;
use core::fmt::Formatter;
use crate::elf::Elf64;
use crate::elf::ElfClass;
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

/// Relocation entries for 64-bit x86 architectures (aka. AA-64, x86-64).
///
/// This datatype provides a semantic-level presentation of the x86
/// relocation entries.  These can be converted to and from
/// [RelData](crate::reloc::RelData) or
/// [RelaData](crate::reloc::RelaData) with [Elf64](crate::Elf64) as
/// the [ElfClass](crate::ElfClass) type argument using the
/// [TryFrom](core::convert::TryFrom) instances for easier handling.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86_64Reloc<Name> {
    None,
    /// 64-bit absolute offset.
    ///
    /// Sets the 8-byte word at `offset` to `sym + addend`.
    Abs64 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 32-bit PC-relative offset.
    ///
    /// Set the 4-byte word at `offset` to the relative address of
    /// `sym + addend` (computed by subtracting the offset or
    /// address of the target word from `sym + addend`).
    PC32 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 32-bit Global Offset Table index.
    ///
    /// Set the 4-byte word at `offset` to the sum of the address of
    /// the Global Offset Table and `addend`.
    GOT32 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// The addend argument.
        addend: i64
    },
    /// Procedure Linkage Table index.
    ///
    /// Set the 4-byte word at `offset` to the relative address of the
    /// sum of the address of the Procedure Linkage Table and `addend`
    /// (computed by subtracting the offset or address of the target
    /// word from the sum of the address of the Procedure Linkage
    /// Table and `addend`).
    PLTRel {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
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
        /// Offset in the GOT at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    },
    /// Procedure Linkage Table jump-slot fill.
    ///
    /// Set a Procedure Linkage Table entry to the address of `sym`.
    JumpSlot {
        /// Offset in the PLT at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    },
    /// 64-bit offset relative to the image base.
    ///
    /// Set the 8-byte word at `offset` to the sum of the base address
    /// and `addend`.
    Relative {
        /// Offset in the section at which to apply.
        offset: u64,
        /// The addend argument.
        addend: i64
    },
    /// 64-bit PC-relative offset to a Global Offset Table entry.
    ///
    /// Set the 8-byte word at `offset` relative address of Global
    /// Offset Table address added to `addend` from the address of the
    /// word at `offset`.
    GOTPC {
        /// Offset in the section at which to apply.
        offset: u64,
        /// The addend argument.
        addend: i64
    },
    /// 32-bit absolute offset.
    ///
    /// Sets the 4-byte word at `offset` to `sym + addend`.
    Abs32 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 32-bit absolute offset, signed addend.
    ///
    /// Sets the 4-byte word at `offset` to `sym + addend`.
    Abs32Signed {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 16-bit absolute offset.
    ///
    /// Set the 2-byte word at `offset` to `sym + addend`.
    Abs16 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 16-bit PC-relative offset.
    ///
    /// Set the 2-byte word at `offset` to the relative address of
    /// `sym + addend` (computed by subtracting the offset or
    /// address of the target word from `sym + addend`).
    PC16 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 8-bit absolute offset.
    ///
    /// Set the 1-byte word at `offset` to `sym + addend`.
    Abs8 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 8-bit PC-relative offset.
    ///
    /// Set the 1-byte word at `offset` to the relative address of
    /// `sym + addend` (computed by subtracting the offset or
    /// address of the target word from `sym + addend`).
    PC8 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    DTPMod {
        offset: u64,
        sym: Name
    },
    DTPOff {
        offset: u64,
        sym: Name
    },
    /// Offset to variable in thread-local storage.
    TPOff {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    },
    TLSGD {
        offset: u64,
        sym: Name
    },
    TLSLD {
        offset: u64,
        sym: Name
    },
    DTPOff32 {
        offset: u64,
        sym: Name
    },
    GOTTPOff {
        offset: u64,
        sym: Name
    },
    /// Offset to variable in thread-local storage.
    TPOff32 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    },
    /// 64-bit PC-relative offset.
    ///
    /// Set the 8-byte word at `offset` to the relative address of
    /// `sym + addend` (computed by subtracting the offset or
    /// address of the target word from `sym + addend`).
    PC64 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 64-bit absolute offset to a Global Offset Table entry.
    ///
    /// Set the 8-byte word at `offset` to the relative
    /// address of `sym + addend` from the Global Offset Table.
    GOTRel {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// 32-bit PC-relative offset to a Global Offset Table entry.
    ///
    /// Set the 4-byte word at `offset` relative address of Global
    /// Offset Table address added to `addend` from the address of the
    /// word at `offset`.
    GOTPC32 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// The addend argument.
        addend: i64
    },
    /// 32-bit Symbol size.
    ///
    /// Set the 4-byte word at `offset` to the sum of the size of the
    /// symbol and `addend`.
    Size32 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    },
    /// Symbol size.
    ///
    /// Set the 8-byte word at `offset` to the sum of the size of the
    /// symbol and `addend`.
    Size {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name,
        /// The addend argument.
        addend: i64
    }
}

/// Type synonym for [X86_64Reloc] as projected from a
/// [Rela](crate::reloc::Rela).
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [Rela](crate::reloc::Rela).
pub type X86_64RelocRaw = X86_64Reloc<u32>;

/// Type synonym for [X86_64Reloc] with [SymDataRaw] as the symbol type.
///
/// This is obtained directly from the [WithSymtab] instance acting on a
/// [X86_64RelocRaw].
pub type X86_64RelocRawSym = X86_64Reloc<SymDataRaw<Elf64>>;

/// Type synonym for [X86_64Reloc] with [SymDataStrData] as the symbol type.
///
/// This is obtained directly from the
/// [WithStrtab](crate::strtab::WithStrtab) instance acting on a
/// [X86_64RelocRawSym].
pub type X86_64RelocStrDataSym<'a> = X86_64Reloc<SymDataStrData<'a, Elf64>>;

/// Type synonym for [X86_64Reloc] with [SymDataStr] as the symbol
/// type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelocStrDataSym].
pub type X86_64RelocStrData<'a> =
    X86_64Reloc<Option<Result<&'a str, &'a [u8]>>>;

/// Type synonym for [X86_64Reloc] with UTF-8 decoded string data as the
/// symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelocStrDataSym].
pub type X86_64RelocStrSym<'a> = X86_64Reloc<SymDataStr<'a, Elf64>>;

/// Type synonym for [X86_64Reloc] with a `&'a str`s as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelocStrSym].
pub type X86_64RelocStr<'a> = X86_64Reloc<Option<&'a str>>;

/// Errors that can occur converting an [X86_64Reloc] to a
/// [RelData](crate::reloc::RelData).
///
/// At present, this can only happen with a non-zero addend.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum X86_64ToRelError {
    /// Non-zero addend.
    BadAddend(i64)
}

/// Errors that can occur converting a [RelData](crate::reloc::RelData) or
/// [RelaData](crate::reloc::RelaData) to a [X86_64Reloc].
///
/// At present, this can only happen with a bad tag value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum X86_64RelocError {
    /// Unknown tag value.
    BadTag(u32)
}

/// Errors that can occur during relocation.
pub enum X86_64RelocApplyError {
    /// Bad symbol base.
    BadSymBase(SymBase<u16, u16>),
    /// Out-of-bounds symbol index.
    BadSymIdx(u16),
    /// TLS relocation we can't process.
    BadTLS,
    /// No GOT is present.
    NoGOT,
    /// No PLT is present.
    NoPLT,
    /// Copy relocation is present.
    Copy
}

impl<Name> Display for X86_64Reloc<Name>
    where Name: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86_64Reloc::None => write!(f, "none"),
            X86_64Reloc::Abs64 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 4, sym, addend),
            X86_64Reloc::PC32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 4, sym, addend, offset),
            X86_64Reloc::GOT32 { offset, addend } =>
                write!(f, ".section[{}..{}] <- &.got + {}",
                       offset, offset + 4, addend),
            X86_64Reloc::PLTRel { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.plt + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86_64Reloc::Copy { sym } => write!(f, "copy {}", sym),
            X86_64Reloc::GlobalData { offset, sym } =>
                write!(f, ".got[{}..{}] <- &{}", offset, offset + 8, sym),
            X86_64Reloc::JumpSlot { offset, sym } =>
                write!(f, ".plt[{}..{}] <- &{}", offset, offset + 8, sym),
            X86_64Reloc::Relative { offset, addend } =>
                write!(f, ".section[{}..{}] <- &base + {}",
                       offset, offset + 8, addend),
            X86_64Reloc::GOTPC { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.got + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86_64Reloc::Abs32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 4, sym, addend),
            X86_64Reloc::Abs32Signed { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 4, sym, addend),
            X86_64Reloc::Abs16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 2, sym, addend),
            X86_64Reloc::PC16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 2, sym, addend, offset),
            X86_64Reloc::Abs8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- &{} + {}",
                       offset, sym, addend),
            X86_64Reloc::PC8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- (&{} + {}) - (&.section + {})",
                       offset, sym, addend, offset),
            X86_64Reloc::DTPMod { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local module for {}"),
                       offset, offset + 8, sym),
            X86_64Reloc::DTPOff { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local offset for {}"),
                       offset, offset + 8, sym),
            X86_64Reloc::TPOff { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- initial execution ",
                                  "thread-local offset for {}"),
                       offset, offset + 8, sym),
            X86_64Reloc::TLSGD { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- general dynamic GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Reloc::TLSLD { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- local dynamic GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Reloc::DTPOff32 { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local offset for {}, 32-bit"),
                       offset, offset + 4, sym),
            X86_64Reloc::GOTTPOff { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- initial execution GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Reloc::TPOff32 { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- initial execution ",
                                  "thread-local offset for {}, 32-bit"),
                       offset, offset + 4, sym),
            X86_64Reloc::PC64 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 8, sym, addend, offset),
            X86_64Reloc::GOTRel { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - &.got",
                       offset, offset + 8, sym, addend),
            X86_64Reloc::GOTPC32 { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- &.got + {} + (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86_64Reloc::Size32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- sizeof({}) + {}",
                       offset, offset + 4, sym, addend),
            X86_64Reloc::Size { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- sizeof({}) + {}",
                       offset, offset + 8, sym, addend),
        }
    }
}

impl Display for X86_64RelocApplyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86_64RelocApplyError::BadSymBase(symbase) => {
                write!(f, "symbol base {} cannot be interpreted", symbase)
            },
            X86_64RelocApplyError::BadSymIdx(idx) => {
                write!(f, "symbol index {} out of bounds", idx)
            },
            X86_64RelocApplyError::BadTLS => {
                write!(f, "cannot apply thread-local storage relocation")
            }
            X86_64RelocApplyError::NoGOT => write!(f, "no GOT present"),
            X86_64RelocApplyError::NoPLT => write!(f, "no PLT present"),
            X86_64RelocApplyError::Copy => {
                write!(f, "cannot apply copy relocation")
            }
        }
    }
}

impl Display for X86_64RelocError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86_64RelocError::BadTag(tag) => write!(f, "bad tag value {}", tag)
        }
    }
}

impl Display for X86_64ToRelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86_64ToRelError::BadAddend(addend) =>
                write!(f, "non-zero addend value {}", addend)
        }
    }
}

impl<Name> Reloc<LittleEndian, Elf64>
    for X86_64Reloc<SymData<Name, u16, Elf64>> {
    type Params = BasicRelocParams<Elf64>;
    type Error = X86_64RelocApplyError;

    fn reloc<'a, F>(&self, target: &mut [u8], params: &Self::Params,
                    target_base: u64, section_base: F) ->
        Result<(), Self::Error>
        where F: FnOnce(u16) -> Option<u64> {
        match self {
            X86_64Reloc::None => Ok(()),
            X86_64Reloc::Abs64 { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + addend;

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Reloc::Abs64 { sym: SymData { section: SymBase::Index(idx),
                                                value, .. },
                                 offset, addend } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = (params.img_base() + section_base) as i64;
                    let value = base + (*value as i64) + addend;

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::Abs64 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::PC32 { sym: SymData { section: SymBase::Absolute,
                                               value, .. },
                                offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Reloc::PC32 { sym: SymData { section: SymBase::Index(idx),
                                               value, .. },
                                offset, addend } =>  match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i64;
                    let sym_value = base + (*value as i64) + *addend;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = sym_value - pc;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::PC32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::GOT32 { offset, addend } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let value = (got as i64) + *addend;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Reloc::PLTRel { offset, addend, .. } =>  match params.plt() {
                Some(plt) => {

                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = ((plt as i64) + *addend) - pc;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                }
                None => Err(X86_64RelocApplyError::NoPLT)
            },
            X86_64Reloc::Copy { .. } => Err(X86_64RelocApplyError::Copy),
            X86_64Reloc::GlobalData { sym: SymData { section: SymBase::Absolute,
                                                     value, .. },
                                      offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Reloc::GlobalData { sym: SymData {
                                             section: SymBase::Index(idx),
                                             value, ..
                                      },
                                      offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = (params.img_base() + section_base) as i64;
                    let value = base + (*value as i64);

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::GlobalData { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::JumpSlot { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Reloc::JumpSlot { sym: SymData { section: SymBase::Index(idx),
                                                   value, .. },
                                    offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = (params.img_base() + section_base) as i64;
                    let value = base + (*value as i64);

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::JumpSlot { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::Relative { offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let value = ((params.img_base() as i64) + addend) as u64;

                Elf64::write_addr::<LittleEndian>(&mut target[range], value);

                Ok(())
            },
            X86_64Reloc::GOTPC { offset, addend } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = ((got as i64) + *addend) - pc;

                    Elf64::write_offset::<LittleEndian>(&mut target[range],
                                                        value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Reloc::Abs32 { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                              offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + *addend;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Reloc::Abs32 { sym: SymData { section: SymBase::Index(idx),
                                                value, .. },
                              offset, addend } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i64;
                    let value = base + (*value as i64) + *addend;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::Abs32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::Abs32Signed { sym: SymData {
                                                section: SymBase::Absolute,
                                                value, ..
                                            },
                                       offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + *addend;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Reloc::Abs32Signed { sym: SymData {
                                                section: SymBase::Index(idx),
                                                value, ..
                                            },
                                       offset, addend } =>
                match section_base(*idx) {
                    Some(section_base) => {
                        let range = (*offset as usize) ..
                                    (*offset as usize) + 4;
                        let base = (params.img_base() + section_base) as i64;
                        let value = base + (*value as i64) + *addend;

                        Elf64::write_word::<LittleEndian>(&mut target[range],
                                                          value as u32);

                        Ok(())
                    },
                    None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
                },
            X86_64Reloc::Abs32Signed { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::Abs16 { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + addend;

                Elf64::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86_64Reloc::Abs16 { sym: SymData { section: SymBase::Index(idx),
                                                value, .. },
                                 offset, addend } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 2;
                    let base = (params.img_base() + section_base) as i64;
                    let value = base + (*value as i64) + addend;

                    Elf64::write_half::<LittleEndian>(&mut target[range],
                                                      value as u16);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::Abs16 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::PC16 { sym: SymData { section: SymBase::Absolute,
                                               value, .. },
                                offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                Elf64::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86_64Reloc::PC16 { sym: SymData { section: SymBase::Index(idx),
                                               value, .. },
                                offset, addend } =>  match section_base(*idx) {
                Some(section_base) => {

                    let range = (*offset as usize) .. (*offset as usize) + 2;
                    let base = (params.img_base() + section_base) as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = sym_value - pc;

                    Elf64::write_half::<LittleEndian>(&mut target[range],
                                                      value as u16);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::PC16 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::Abs8 { sym: SymData { section: SymBase::Absolute,
                                               value, .. },
                                offset, addend } => {
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + addend;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86_64Reloc::Abs8 { sym: SymData { section: SymBase::Index(idx),
                                               value, .. },
                                offset, addend } => match section_base(*idx) {
                Some(section_base) => {
                    let base = (params.img_base() + section_base) as i64;
                    let value = base + (*value as i64) + addend;

                    target[*offset as usize] = value as u8;

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::Abs8 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::PC8 { sym: SymData { section: SymBase::Absolute,
                                              value, .. },
                               offset, addend } => {
                let base = params.img_base() as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86_64Reloc::PC8 { sym: SymData { section: SymBase::Index(idx),
                                              value, .. },
                               offset, addend } =>  match section_base(*idx) {
                Some(section_base) => {

                    let base = (params.img_base() + section_base) as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = sym_value - pc;

                    target[*offset as usize] = value as u8;

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::PC8 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::DTPMod { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Reloc::DTPOff { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Reloc::TLSGD { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Reloc::TLSLD { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Reloc::DTPOff32 { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Reloc::GOTTPOff { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Reloc::TPOff { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Reloc::TPOff { sym: SymData { section: SymBase::Index(idx),
                                                value, .. },
                                 offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = (params.img_base() + section_base) as i64;
                    let value = base + (*value as i64);

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::TPOff { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::TPOff32 { sym: SymData { section: SymBase::Absolute,
                                                  value, .. },
                                   offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Reloc::TPOff32 { sym: SymData { section: SymBase::Index(idx),
                                                  value, .. },
                                   offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i64;
                    let value = base + (*value as i64);

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::TPOff32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::PC64 { sym: SymData { section: SymBase::Absolute,
                                               value, .. },
                                offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Reloc::PC64 { sym: SymData { section: SymBase::Index(idx),
                                               value, .. },
                                offset, addend } =>  match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = (params.img_base() + section_base) as i64;
                    let sym_value = base + (*value as i64) + *addend;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = sym_value - pc;

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::PC64 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::GOTRel { sym: SymData { section: SymBase::Absolute,
                                                 value, .. },
                                  offset, addend } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = params.img_base() as i64;
                    let got_base = got as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let value = sym_value - got_base;

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Reloc::GOTRel { sym: SymData { section: SymBase::Index(idx),
                                              value, .. },
                               offset, addend } => match (section_base(*idx),
                                                          params.got()) {
                (Some(section_base), Some(got)) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let got_base = got as i64;
                    let base = (params.img_base() + section_base) as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let value = sym_value - got_base;

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                (None, _) => Err(X86_64RelocApplyError::NoGOT),
                (_, None) => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Reloc::GOTRel { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Reloc::GOTPC32 { offset, addend } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = ((got as i64) + *addend) - pc;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Reloc::Size32 { sym: SymData { size, .. },
                                  offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let value = (*size as i64) + addend;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Reloc::Size { sym: SymData { size, .. }, offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let value = (*size as i64) + addend;

                Elf64::write_offset::<LittleEndian>(&mut target[range],
                                                    value as u64);

                Ok(())
            }
        }
    }
}

fn convert_to<Name>(offset: u64, sym: Name, kind: u32, addend: i64) ->
    Result<X86_64Reloc<Name>, X86_64RelocError> {
    match kind {
        0 => Ok(X86_64Reloc::None),
        1 => Ok(X86_64Reloc::Abs64 { offset, sym, addend }),
        2 => Ok(X86_64Reloc::PC32 { offset, sym, addend }),
        3 => Ok(X86_64Reloc::GOT32 { offset, addend }),
        4 => Ok(X86_64Reloc::PLTRel { offset, sym, addend }),
        5 => Ok(X86_64Reloc::Copy { sym }),
        6 => Ok(X86_64Reloc::GlobalData { offset, sym }),
        7 => Ok(X86_64Reloc::JumpSlot { offset, sym }),
        8 => Ok(X86_64Reloc::Relative { offset, addend }),
        9 => Ok(X86_64Reloc::GOTPC { offset, addend }),
        10 => Ok(X86_64Reloc::Abs32 { offset, sym, addend }),
        11 => Ok(X86_64Reloc::Abs32Signed { offset, sym, addend }),
        12 => Ok(X86_64Reloc::Abs16 { offset, sym, addend }),
        13 => Ok(X86_64Reloc::PC16 { offset, sym, addend }),
        14 => Ok(X86_64Reloc::Abs8 { offset, sym, addend }),
        15 => Ok(X86_64Reloc::PC8 { offset, sym, addend }),
        16 => Ok(X86_64Reloc::DTPMod { offset, sym }),
        17 => Ok(X86_64Reloc::DTPOff { offset, sym }),
        18 => Ok(X86_64Reloc::TPOff { offset, sym }),
        19 => Ok(X86_64Reloc::TLSGD { offset, sym }),
        20 => Ok(X86_64Reloc::TLSLD { offset, sym }),
        21 => Ok(X86_64Reloc::DTPOff32 { offset, sym }),
        22 => Ok(X86_64Reloc::GOTTPOff { offset, sym }),
        23 => Ok(X86_64Reloc::TPOff32 { offset, sym }),
        24 => Ok(X86_64Reloc::PC64 { offset, sym, addend }),
        25 => Ok(X86_64Reloc::GOTRel { offset, sym, addend }),
        26 => Ok(X86_64Reloc::GOTPC32 { offset, addend }),
        32 => Ok(X86_64Reloc::Size32 { offset, sym, addend }),
        33 => Ok(X86_64Reloc::Size { offset, sym, addend }),
        tag => Err(X86_64RelocError::BadTag(tag))
    }
}

impl<Name> TryFrom<RelData<Name, Elf64>> for X86_64Reloc<Name> {
    type Error = X86_64RelocError;

    #[inline]
    fn try_from(rela: RelData<Name, Elf64>) -> Result<X86_64Reloc<Name>,
                                                      Self::Error> {
        let RelData { offset, sym, kind } = rela;

        convert_to(offset, sym, kind, 0)
    }
}

impl TryFrom<X86_64Reloc<u32>> for RelData<u32, Elf64> {
    type Error = X86_64ToRelError;

    #[inline]
    fn try_from(rel: X86_64Reloc<u32>) -> Result<RelData<u32, Elf64>,
                                                 Self::Error> {
        match rel {
            X86_64Reloc::None =>
                Ok(RelData { offset: 0, sym: 0, kind: 0 }),
            X86_64Reloc::Abs64 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 1 }),
            X86_64Reloc::Abs64 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::PC32 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 2 }),
            X86_64Reloc::PC32 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::GOT32 { offset, addend: 0 } =>
                Ok(RelData { offset: offset, sym: 0, kind: 3 }),
            X86_64Reloc::GOT32 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::PLTRel { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 4 }),
            X86_64Reloc::PLTRel { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::Copy { sym } =>
                Ok(RelData { offset: 0, sym: sym, kind: 5 }),
            X86_64Reloc::GlobalData { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 6 }),
            X86_64Reloc::JumpSlot { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 7 }),
            X86_64Reloc::Relative { offset, addend: 0 } =>
                Ok(RelData { offset: offset, sym: 0, kind: 8 }),
            X86_64Reloc::Relative { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::GOTPC { offset, addend: 0 } =>
                Ok(RelData { offset: offset, sym: 0, kind: 9 }),
            X86_64Reloc::GOTPC { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::Abs32 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 10 }),
            X86_64Reloc::Abs32 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::Abs32Signed { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 11 }),
            X86_64Reloc::Abs32Signed { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::Abs16 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 12 }),
            X86_64Reloc::Abs16 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::PC16 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 13 }),
            X86_64Reloc::PC16 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::Abs8 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 14 }),
            X86_64Reloc::Abs8 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::PC8 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 15 }),
            X86_64Reloc::PC8 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::DTPMod { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 16 }),
            X86_64Reloc::DTPOff { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 17 }),
            X86_64Reloc::TPOff { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 18 }),
            X86_64Reloc::TLSGD { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 19 }),
            X86_64Reloc::TLSLD { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 20 }),
            X86_64Reloc::DTPOff32 { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 21 }),
            X86_64Reloc::GOTTPOff { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 22 }),
            X86_64Reloc::TPOff32 { offset, sym } =>
                Ok(RelData { offset: offset, sym: sym, kind: 23 }),
            X86_64Reloc::PC64 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 24 }),
            X86_64Reloc::PC64 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::GOTRel { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 25 }),
            X86_64Reloc::GOTRel { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::GOTPC32 { offset, addend: 0 } =>
                Ok(RelData { offset: offset, sym: 0, kind: 26 }),
            X86_64Reloc::GOTPC32 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::Size32 { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 32 }),
            X86_64Reloc::Size32 { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend)),
            X86_64Reloc::Size { offset, sym, addend: 0 } =>
                Ok(RelData { offset: offset, sym: sym, kind: 33 }),
            X86_64Reloc::Size { addend, .. } =>
                Err(X86_64ToRelError::BadAddend(addend))
        }
    }
}

impl<Name> TryFrom<RelaData<Name, Elf64>> for X86_64Reloc<Name> {
    type Error = X86_64RelocError;

    #[inline]
    fn try_from(rela: RelaData<Name, Elf64>) -> Result<X86_64Reloc<Name>,
                                                      Self::Error> {
        let RelaData { offset, sym, kind, addend } = rela;

        convert_to(offset, sym, kind, addend)
    }
}

impl From<X86_64Reloc<u32>> for RelaData<u32, Elf64> {
    #[inline]
    fn from(rel: X86_64Reloc<u32>) -> RelaData<u32, Elf64> {
        match rel {
            X86_64Reloc::None =>
                RelaData { offset: 0, sym: 0, kind: 0, addend: 0 },
            X86_64Reloc::Abs64 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 1, addend: addend },
            X86_64Reloc::PC32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 2, addend: addend },
            X86_64Reloc::GOT32 { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 3, addend: addend },
            X86_64Reloc::PLTRel { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 4, addend: addend },
            X86_64Reloc::Copy { sym } =>
                RelaData { offset: 0, sym: sym, kind: 5 , addend: 0 },
            X86_64Reloc::GlobalData { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 6, addend: 0 },
            X86_64Reloc::JumpSlot { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 7, addend: 0 },
            X86_64Reloc::Relative { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 8, addend: addend },
            X86_64Reloc::GOTPC { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 9, addend: addend },
            X86_64Reloc::Abs32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 10, addend: addend },
            X86_64Reloc::Abs32Signed { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 11, addend: addend },
            X86_64Reloc::Abs16 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 12, addend: addend },
            X86_64Reloc::PC16 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 13, addend: addend },
            X86_64Reloc::Abs8 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 14, addend: addend },
            X86_64Reloc::PC8 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 15, addend: addend },
            X86_64Reloc::DTPMod { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 16, addend: 0 },
            X86_64Reloc::DTPOff { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 17, addend: 0 },
            X86_64Reloc::TPOff { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 18, addend: 0 },
            X86_64Reloc::TLSGD { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 19, addend: 0 },
            X86_64Reloc::TLSLD { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 20, addend: 0 },
            X86_64Reloc::DTPOff32 { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 21, addend: 0 },
            X86_64Reloc::GOTTPOff { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 22, addend: 0 },
            X86_64Reloc::TPOff32 { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 23, addend: 0 },
            X86_64Reloc::PC64 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 24, addend: addend },
            X86_64Reloc::GOTRel { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 25, addend: addend },
            X86_64Reloc::GOTPC32 { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 26, addend: addend },
            X86_64Reloc::Size32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 32, addend: addend },
            X86_64Reloc::Size { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 33, addend: addend },
        }
    }
}

impl<'a> WithSymtab<'a, LittleEndian, Elf64> for X86_64RelocRaw {
    type Result = X86_64Reloc<SymDataRaw<Elf64>>;
    type Error = RelocSymtabError<Elf64>;

    #[inline]
    fn with_symtab(self, symtab: Symtab<'a, LittleEndian, Elf64>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86_64Reloc::None => Ok(X86_64Reloc::None),
            X86_64Reloc::Abs64 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::Abs64 { offset: offset,
                                                    sym: symdata,
                                                    addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::PC32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::PC32 { offset: offset, sym: symdata,
                                                   addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::GOT32 { offset, addend } =>
                Ok(X86_64Reloc::GOT32 { offset: offset, addend: addend }),
            X86_64Reloc::PLTRel { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::PLTRel { offset: offset,
                                                     sym: symdata,
                                                     addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::Copy { sym } => match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::Copy { sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::GlobalData { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::GlobalData { offset: offset,
                                                         sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::JumpSlot { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::JumpSlot { offset: offset,
                                                       sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::Relative { offset, addend } =>
                Ok(X86_64Reloc::Relative { offset: offset, addend: addend }),
            X86_64Reloc::GOTPC { offset, addend } =>
                Ok(X86_64Reloc::GOTPC { offset: offset, addend: addend }),
            X86_64Reloc::Abs32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::Abs32 { offset: offset,
                                                    sym: symdata,
                                                    addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::Abs32Signed { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::Abs32Signed { offset: offset,
                                                          sym: symdata,
                                                          addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::Abs16 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::Abs16 { offset: offset,
                                                    sym: symdata,
                                                    addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::PC16 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::PC16 { offset: offset, sym: symdata,
                                                   addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::Abs8 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::Abs8 { offset: offset,
                                                    sym: symdata,
                                                    addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::PC8 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::PC8 { offset: offset, sym: symdata,
                                                  addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::DTPMod { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::DTPMod { offset: offset,
                                                     sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::DTPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::DTPOff { offset: offset,
                                                     sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::TPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::TPOff { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::TLSGD { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::TLSGD { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::TLSLD { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::TLSLD { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::DTPOff32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::DTPOff32 { offset: offset,
                                                       sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::GOTTPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::GOTTPOff { offset: offset,
                                                       sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::TPOff32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::TPOff32 { offset: offset,
                                                      sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::PC64 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::PC64 { offset: offset, sym: symdata,
                                                   addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::GOTRel { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::GOTRel { offset: offset,
                                                     sym: symdata,
                                                     addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::GOTPC32 { offset, addend } =>
                Ok(X86_64Reloc::GOTPC32 { offset: offset, addend: addend }),
            X86_64Reloc::Size32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::Size32 { offset: offset,
                                                     sym: symdata,
                                                     addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Reloc::Size { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Reloc::Size { offset: offset, sym: symdata,
                                                   addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                }
        }
    }
}

impl<'a> WithStrtab<'a> for X86_64RelocRawSym {
    type Result = X86_64RelocStrDataSym<'a>;
    type Error = u32;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86_64Reloc::None => Ok(X86_64Reloc::None),
            X86_64Reloc::Abs64 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs64 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                    Err(err) => Err(err)
                    },
            X86_64Reloc::PC32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PC32 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::GOT32 { offset, addend } =>
                Ok(X86_64Reloc::GOT32 { offset: offset, addend: addend }),
            X86_64Reloc::PLTRel { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PLTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Copy { sym } => match sym.with_strtab(strtab) {
                Ok(symdata) => {
                    Ok(X86_64Reloc::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86_64Reloc::GlobalData { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::GlobalData { offset: offset,
                                                     sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::JumpSlot { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::JumpSlot { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Relative { offset, addend } =>
                Ok(X86_64Reloc::Relative { offset: offset, addend: addend }),
            X86_64Reloc::GOTPC { offset, addend } =>
                Ok(X86_64Reloc::GOTPC { offset: offset, addend: addend }),
            X86_64Reloc::Abs32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs32 { offset: offset, sym: symdata,
                                                addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Abs32Signed { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs32Signed { offset: offset,
                                                      sym: symdata,
                                                      addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Abs16 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs16 { offset: offset, sym: symdata,
                                                addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::PC16 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PC16 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Abs8 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs8 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::PC8 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PC8 { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::DTPMod { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::DTPMod { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::DTPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::DTPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::TPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::TPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::TLSGD { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::TLSGD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::TLSLD { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::TLSLD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::DTPOff32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::DTPOff32 { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::GOTTPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::GOTTPOff { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::TPOff32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::TPOff32 { offset: offset,
                                                  sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::PC64 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PC64 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::GOTRel { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::GOTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::GOTPC32 { offset, addend } =>
                Ok(X86_64Reloc::GOTPC32 { offset: offset, addend: addend }),
            X86_64Reloc::Size32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Size32 { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Size { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Size { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
        }
    }
}

impl<'a> TryFrom<X86_64RelocStrDataSym<'a>> for X86_64RelocStrSym<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86_64RelocStrDataSym<'a>) ->
        Result<X86_64RelocStrSym<'a>, Self::Error> {
        match reloc {
            X86_64Reloc::None => Ok(X86_64Reloc::None),
            X86_64Reloc::Abs64 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs64 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                    Err(err) => Err(err)
                    },
            X86_64Reloc::PC32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PC32 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::GOT32 { offset, addend } =>
                Ok(X86_64Reloc::GOT32 { offset: offset, addend: addend }),
            X86_64Reloc::PLTRel { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PLTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Copy { sym } => match sym.try_into() {
                Ok(symdata) => {
                    Ok(X86_64Reloc::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86_64Reloc::GlobalData { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::GlobalData { offset: offset,
                                                     sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::JumpSlot { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::JumpSlot { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Relative { offset, addend } =>
                Ok(X86_64Reloc::Relative { offset: offset, addend: addend }),
            X86_64Reloc::GOTPC { offset, addend } =>
                Ok(X86_64Reloc::GOTPC { offset: offset, addend: addend }),
            X86_64Reloc::Abs32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs32 { offset: offset, sym: symdata,
                                                addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Abs32Signed { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs32Signed { offset: offset,
                                                      sym: symdata,
                                                      addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Abs16 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs16 { offset: offset, sym: symdata,
                                                addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::PC16 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PC16 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Abs8 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Abs8 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::PC8 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PC8 { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::DTPMod { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::DTPMod { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::DTPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::DTPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::TPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::TPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::TLSGD { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::TLSGD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::TLSLD { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::TLSLD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::DTPOff32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::DTPOff32 { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::GOTTPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::GOTTPOff { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::TPOff32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::TPOff32 { offset: offset,
                                                  sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::PC64 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::PC64 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::GOTRel { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::GOTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::GOTPC32 { offset, addend } =>
                Ok(X86_64Reloc::GOTPC32 { offset: offset, addend: addend }),
            X86_64Reloc::Size32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Size32 { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Reloc::Size { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Reloc::Size { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
        }
    }
}

impl<'a> From<X86_64RelocStrDataSym<'a>> for X86_64RelocStrData<'a> {
    #[inline]
    fn from(reloc: X86_64RelocStrDataSym<'a>) -> X86_64RelocStrData<'a> {
        match reloc {
            X86_64Reloc::None => X86_64Reloc::None,
            X86_64Reloc::Abs64 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Abs64 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Reloc::PC32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PC32 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::GOT32 { offset, addend } =>
                X86_64Reloc::GOT32 { offset: offset, addend: addend },
            X86_64Reloc::PLTRel { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PLTRel { offset: offset, sym: name,
                                      addend: addend },
            X86_64Reloc::Copy { sym: SymData { name, .. } } =>
                X86_64Reloc::Copy { sym: name },
            X86_64Reloc::GlobalData { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::GlobalData { offset: offset, sym: name },
            X86_64Reloc::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::JumpSlot { offset: offset, sym: name },
            X86_64Reloc::Relative { offset, addend } =>
                X86_64Reloc::Relative { offset: offset, addend: addend },
            X86_64Reloc::GOTPC { offset, addend } =>
                X86_64Reloc::GOTPC { offset: offset, addend: addend },
            X86_64Reloc::Abs32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Abs32 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Reloc::Abs32Signed { sym: SymData { name, .. }, offset,
                                       addend } =>
                X86_64Reloc::Abs32Signed { offset: offset, sym: name,
                                           addend: addend },
            X86_64Reloc::Abs16 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Abs16 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Reloc::PC16 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PC16 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::Abs8 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Abs8 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::PC8 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PC8 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::DTPMod { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::DTPMod { offset: offset, sym: name },
            X86_64Reloc::DTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::DTPOff { offset: offset, sym: name },
            X86_64Reloc::TPOff { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::TPOff { offset: offset, sym: name },
            X86_64Reloc::TLSGD { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::TLSGD { offset: offset, sym: name },
            X86_64Reloc::TLSLD { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::TLSLD { offset: offset, sym: name },
            X86_64Reloc::DTPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::DTPOff32 { offset: offset, sym: name },
            X86_64Reloc::GOTTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::GOTTPOff { offset: offset, sym: name },
            X86_64Reloc::TPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::TPOff32 { offset: offset, sym: name },
            X86_64Reloc::PC64 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PC64 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::GOTRel { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::GOTRel { offset: offset, sym: name,
                                      addend: addend },
            X86_64Reloc::GOTPC32 { offset, addend } =>
                X86_64Reloc::GOTPC32 { offset: offset, addend: addend },
            X86_64Reloc::Size32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Size32 { offset: offset, sym: name,
                                      addend: addend },
            X86_64Reloc::Size { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Size { offset: offset, sym: name, addend: addend }
        }
    }
}

impl<'a> TryFrom<X86_64RelocStrData<'a>> for X86_64RelocStr<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86_64RelocStrData<'a>) ->
        Result<X86_64RelocStr<'a>, Self::Error> {
        match reloc {
            X86_64Reloc::None => Ok(X86_64Reloc::None),
            X86_64Reloc::Abs64 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::Abs64 { offset: offset, sym: Some(name),
                                        addend: addend }),
            X86_64Reloc::Abs64 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::Abs64 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::Abs64 { offset: offset, sym: None,
                                        addend: addend }),
            X86_64Reloc::PC32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::PC32 { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Reloc::PC32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::PC32 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::PC32 { offset: offset, sym: None,
                                       addend: addend }),
            X86_64Reloc::GOT32 { offset, addend } =>
                Ok(X86_64Reloc::GOT32 { offset: offset, addend: addend }),
            X86_64Reloc::PLTRel { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::PLTRel { offset: offset, sym: Some(name),
                                         addend: addend }),
            X86_64Reloc::PLTRel { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::PLTRel { sym: None, offset, addend } =>
                Ok(X86_64Reloc::PLTRel { offset: offset, sym: None,
                                         addend: addend }),
            X86_64Reloc::Copy { sym: Some(Ok(name)) } =>
                Ok(X86_64Reloc::Copy { sym: Some(name) }),
            X86_64Reloc::Copy { sym: Some(Err(err)) } => Err(err),
            X86_64Reloc::Copy { sym: None } =>
                Ok(X86_64Reloc::Copy { sym: None }),
            X86_64Reloc::GlobalData { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::GlobalData { offset: offset, sym: Some(name) }),
            X86_64Reloc::GlobalData { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::GlobalData { sym: None, offset } =>
                Ok(X86_64Reloc::GlobalData { offset: offset, sym: None }),
            X86_64Reloc::JumpSlot { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::JumpSlot { offset: offset, sym: Some(name) }),
            X86_64Reloc::JumpSlot { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::JumpSlot { sym: None, offset } =>
                Ok(X86_64Reloc::JumpSlot { offset: offset, sym: None }),
            X86_64Reloc::Relative { offset, addend } =>
                Ok(X86_64Reloc::Relative { offset: offset, addend: addend }),
            X86_64Reloc::GOTPC { offset, addend } =>
                Ok(X86_64Reloc::GOTPC { offset: offset, addend: addend }),
            X86_64Reloc::Abs32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::Abs32 { offset: offset, sym: Some(name),
                                        addend: addend }),
            X86_64Reloc::Abs32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::Abs32 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::Abs32 { offset: offset, sym: None,
                                        addend: addend }),
            X86_64Reloc::Abs32Signed { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::Abs32Signed { offset: offset, sym: Some(name),
                                              addend: addend }),
            X86_64Reloc::Abs32Signed { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::Abs32Signed { sym: None, offset, addend } =>
                Ok(X86_64Reloc::Abs32Signed { offset: offset, sym: None,
                                              addend: addend }),
            X86_64Reloc::Abs16 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::Abs16 { offset: offset, sym: Some(name),
                                        addend: addend }),
            X86_64Reloc::Abs16 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::Abs16 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::Abs16 { offset: offset, sym: None,
                                        addend: addend }),
            X86_64Reloc::PC16 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::PC16 { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Reloc::PC16 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::PC16 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::PC16 { offset: offset, sym: None,
                                       addend: addend }),
            X86_64Reloc::Abs8 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::Abs8 { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Reloc::Abs8 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::Abs8 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::Abs8 { offset: offset, sym: None,
                                       addend: addend }),
            X86_64Reloc::PC8 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::PC8 { offset: offset, sym: Some(name),
                                      addend: addend }),
            X86_64Reloc::PC8 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::PC8 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::PC8 { offset: offset, sym: None,
                                      addend: addend }),
            X86_64Reloc::DTPMod { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::DTPMod { offset: offset, sym: Some(name) }),
            X86_64Reloc::DTPMod { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::DTPMod { sym: None, offset } =>
                Ok(X86_64Reloc::DTPMod { offset: offset, sym: None }),
            X86_64Reloc::DTPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::DTPOff { offset: offset, sym: Some(name) }),
            X86_64Reloc::DTPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::DTPOff { sym: None, offset } =>
                Ok(X86_64Reloc::DTPOff { offset: offset, sym: None }),
            X86_64Reloc::TPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::TPOff { offset: offset, sym: Some(name) }),
            X86_64Reloc::TPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::TPOff { sym: None, offset } =>
                Ok(X86_64Reloc::TPOff { offset: offset, sym: None }),
            X86_64Reloc::TLSGD { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::TLSGD { offset: offset, sym: Some(name) }),
            X86_64Reloc::TLSGD { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::TLSGD { sym: None, offset } =>
                Ok(X86_64Reloc::TLSGD { offset: offset, sym: None }),
            X86_64Reloc::TLSLD { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::TLSLD { offset: offset, sym: Some(name) }),
            X86_64Reloc::TLSLD { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::TLSLD { sym: None, offset } =>
                Ok(X86_64Reloc::TLSLD { offset: offset, sym: None }),
            X86_64Reloc::DTPOff32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::DTPOff32 { offset: offset, sym: Some(name) }),
            X86_64Reloc::DTPOff32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::DTPOff32 { sym: None, offset } =>
                Ok(X86_64Reloc::DTPOff32 { offset: offset, sym: None }),
            X86_64Reloc::GOTTPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::GOTTPOff { offset: offset, sym: Some(name) }),
            X86_64Reloc::GOTTPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::GOTTPOff { sym: None, offset } =>
                Ok(X86_64Reloc::GOTTPOff { offset: offset, sym: None }),
            X86_64Reloc::TPOff32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Reloc::TPOff32 { offset: offset, sym: Some(name) }),
            X86_64Reloc::TPOff32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::TPOff32 { sym: None, offset } =>
                Ok(X86_64Reloc::TPOff32 { offset: offset, sym: None }),
            X86_64Reloc::PC64 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::PC64 { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Reloc::PC64 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::PC64 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::PC64 { offset: offset, sym: None,
                                       addend: addend }),
            X86_64Reloc::GOTRel { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::GOTRel { offset: offset, sym: Some(name),
                                         addend: addend }),
            X86_64Reloc::GOTRel { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::GOTRel { sym: None, offset, addend } =>
                Ok(X86_64Reloc::GOTRel { offset: offset, sym: None,
                                         addend: addend }),
            X86_64Reloc::GOTPC32 { offset, addend } =>
                Ok(X86_64Reloc::GOTPC32 { offset: offset, addend: addend }),
            X86_64Reloc::Size32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::Size32 { offset: offset, sym: Some(name),
                                         addend: addend }),
            X86_64Reloc::Size32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::Size32 { sym: None, offset, addend } =>
                Ok(X86_64Reloc::Size32 { offset: offset, sym: None,
                                         addend: addend }),
            X86_64Reloc::Size { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Reloc::Size { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Reloc::Size { sym: Some(Err(err)), .. } => Err(err),
            X86_64Reloc::Size { sym: None, offset, addend } =>
                Ok(X86_64Reloc::Size { offset: offset, sym: None,
                                       addend: addend })
        }
    }
}

impl<'a> From<X86_64RelocStrSym<'a>> for X86_64RelocStr<'a> {
    #[inline]
    fn from(reloc: X86_64RelocStrSym<'a>) -> X86_64RelocStr<'a> {
        match reloc {
            X86_64Reloc::None => X86_64Reloc::None,
            X86_64Reloc::Abs64 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Abs64 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Reloc::PC32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PC32 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::GOT32 { offset, addend } =>
                X86_64Reloc::GOT32 { offset: offset, addend: addend },
            X86_64Reloc::PLTRel { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PLTRel { offset: offset, sym: name,
                                      addend: addend },
            X86_64Reloc::Copy { sym: SymData { name, .. } } =>
                X86_64Reloc::Copy { sym: name },
            X86_64Reloc::GlobalData { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::GlobalData { offset: offset, sym: name },
            X86_64Reloc::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::JumpSlot { offset: offset, sym: name },
            X86_64Reloc::Relative { offset, addend } =>
                X86_64Reloc::Relative { offset: offset, addend: addend },
            X86_64Reloc::GOTPC { offset, addend } =>
                X86_64Reloc::GOTPC { offset: offset, addend: addend },
            X86_64Reloc::Abs32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Abs32 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Reloc::Abs32Signed { sym: SymData { name, .. }, offset,
                                       addend } =>
                X86_64Reloc::Abs32Signed { offset: offset, sym: name,
                                           addend: addend },
            X86_64Reloc::Abs16 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Abs16 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Reloc::PC16 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PC16 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::Abs8 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Abs8 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::PC8 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PC8 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::DTPMod { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::DTPMod { offset: offset, sym: name },
            X86_64Reloc::DTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::DTPOff { offset: offset, sym: name },
            X86_64Reloc::TPOff { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::TPOff { offset: offset, sym: name },
            X86_64Reloc::TLSGD { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::TLSGD { offset: offset, sym: name },
            X86_64Reloc::TLSLD { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::TLSLD { offset: offset, sym: name },
            X86_64Reloc::DTPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::DTPOff32 { offset: offset, sym: name },
            X86_64Reloc::GOTTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::GOTTPOff { offset: offset, sym: name },
            X86_64Reloc::TPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Reloc::TPOff32 { offset: offset, sym: name },
            X86_64Reloc::PC64 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::PC64 { offset: offset, sym: name, addend: addend },
            X86_64Reloc::GOTRel { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::GOTRel { offset: offset, sym: name,
                                      addend: addend },
            X86_64Reloc::GOTPC32 { offset, addend } =>
                X86_64Reloc::GOTPC32 { offset: offset, addend: addend },
            X86_64Reloc::Size32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Size32 { offset: offset, sym: name,
                                      addend: addend },
            X86_64Reloc::Size { sym: SymData { name, .. }, offset, addend } =>
                X86_64Reloc::Size { offset: offset, sym: name, addend: addend }
        }
    }
}
