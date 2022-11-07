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

/// Relocation entries for 64-bit x86 architectures (aka. AA-64, x86-64).
///
/// This datatype provides a semantic-level presentation of the x86
/// relocation entries.  These can be converted to and from
/// [RelData](crate::reloc::RelData) with [Elf64](crate::Elf64) as
/// the [ElfClass](crate::ElfClass) type argument using the
/// [TryFrom](core::convert::TryFrom) instances for easier handling.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86_64Rel<Name> {
    None,
    /// 64-bit absolute offset.
    ///
    /// Sets the 8-byte word at `offset` to `sym + addend`.
    Abs64 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
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
        sym: Name
    },
    /// 32-bit Global Offset Table index.
    ///
    /// Set the 4-byte word at `offset` to the sum of the address of
    /// the Global Offset Table and `addend`.
    GOT32 {
        /// Offset in the section at which to apply.
        offset: u64
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
        offset: u64
    },
    /// 64-bit PC-relative offset to a Global Offset Table entry.
    ///
    /// Set the 8-byte word at `offset` relative address of Global
    /// Offset Table address added to `addend` from the address of the
    /// word at `offset`.
    GOTPC {
        /// Offset in the section at which to apply.
        offset: u64
    },
    /// 32-bit absolute offset.
    ///
    /// Sets the 4-byte word at `offset` to `sym + addend`.
    Abs32 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    },
    /// 32-bit absolute offset, signed addend.
    ///
    /// Sets the 4-byte word at `offset` to `sym + addend`.
    Abs32Signed {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    },
    /// 16-bit absolute offset.
    ///
    /// Set the 2-byte word at `offset` to `sym + addend`.
    Abs16 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
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
        sym: Name
    },
    /// 8-bit absolute offset.
    ///
    /// Set the 1-byte word at `offset` to `sym + addend`.
    Abs8 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
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
        sym: Name
    },
    /// 64-bit absolute offset to a Global Offset Table entry.
    ///
    /// Set the 8-byte word at `offset` to the relative
    /// address of `sym + addend` from the Global Offset Table.
    GOTRel {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    },
    /// 32-bit PC-relative offset to a Global Offset Table entry.
    ///
    /// Set the 4-byte word at `offset` relative address of Global
    /// Offset Table address added to `addend` from the address of the
    /// word at `offset`.
    GOTPC32 {
        /// Offset in the section at which to apply.
        offset: u64
    },
    /// 32-bit Symbol size.
    ///
    /// Set the 4-byte word at `offset` to the sum of the size of the
    /// symbol and `addend`.
    Size32 {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    },
    /// Symbol size.
    ///
    /// Set the 8-byte word at `offset` to the sum of the size of the
    /// symbol and `addend`.
    Size {
        /// Offset in the section at which to apply.
        offset: u64,
        /// Symbol reference.
        sym: Name
    }
}

/// Relocation entries for 64-bit x86 architectures (aka. AA-64,
/// x86-64) with explicit addends.
///
/// This datatype provides a semantic-level presentation of the x86
/// relocation entries.  These can be converted to and from
/// [RelaData](crate::reloc::RelaData) with [Elf64](crate::Elf64) as
/// the [ElfClass](crate::ElfClass) type argument using the
/// [TryFrom](core::convert::TryFrom) instances for easier handling.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86_64Rela<Name> {
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

/// Type synonym for [X86_64Rel] as projected from a
/// [Rela](crate::reloc::Rela).
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [Rela](crate::reloc::Rela).
pub type X86_64RelRaw = X86_64Rel<u32>;

/// Type synonym for [X86_64Rel] with [SymDataRaw] as the symbol type.
///
/// This is obtained directly from the [WithSymtab] instance acting on a
/// [X86_64RelRaw].
pub type X86_64RelRawSym = X86_64Rel<SymDataRaw<Elf64>>;

/// Type synonym for [X86_64Rel] with [SymDataStrData] as the symbol type.
///
/// This is obtained directly from the
/// [WithStrtab](crate::strtab::WithStrtab) instance acting on a
/// [X86_64RelRawSym].
pub type X86_64RelStrDataSym<'a> = X86_64Rel<SymDataStrData<'a, Elf64>>;

/// Type synonym for [X86_64Rel] with [SymDataStr] as the symbol
/// type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelStrDataSym].
pub type X86_64RelStrData<'a> =
    X86_64Rel<Option<Result<&'a str, &'a [u8]>>>;

/// Type synonym for [X86_64Rel] with UTF-8 decoded string data as the
/// symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelStrDataSym].
pub type X86_64RelStrSym<'a> = X86_64Rel<SymDataStr<'a, Elf64>>;

/// Type synonym for [X86_64Rel] with a `&'a str`s as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelStrSym].
pub type X86_64RelStr<'a> = X86_64Rel<Option<&'a str>>;

/// Type synonym for [X86_64Rela] as projected from a
/// [Rela](crate::reloc::Rela).
///
/// This is obtained directly from the [TryFrom] insance acting on a
/// [Rela](crate::reloc::Rela).
pub type X86_64RelaRaw = X86_64Rela<u32>;

/// Type synonym for [X86_64Rela] with [SymDataRaw] as the symbol type.
///
/// This is obtained directly from the [WithSymtab] instance acting on a
/// [X86_64RelaRaw].
pub type X86_64RelaRawSym = X86_64Rela<SymDataRaw<Elf64>>;

/// Type synonym for [X86_64Rela] with [SymDataStrData] as the symbol type.
///
/// This is obtained directly from the
/// [WithStrtab](crate::strtab::WithStrtab) instance acting on a
/// [X86_64RelaRawSym].
pub type X86_64RelaStrDataSym<'a> = X86_64Rela<SymDataStrData<'a, Elf64>>;

/// Type synonym for [X86_64Rela] with [SymDataStr] as the symbol
/// type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelaStrDataSym].
pub type X86_64RelaStrData<'a> =
    X86_64Rela<Option<Result<&'a str, &'a [u8]>>>;

/// Type synonym for [X86_64Rela] with UTF-8 decoded string data as the
/// symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelaStrDataSym].
pub type X86_64RelaStrSym<'a> = X86_64Rela<SymDataStr<'a, Elf64>>;

/// Type synonym for [X86_64Rela] with a `&'a str`s as the symbol type.
///
/// This is obtained directly from the [TryFrom] instance acting on
/// a [X86_64RelaStrSym].
pub type X86_64RelaStr<'a> = X86_64Rela<Option<&'a str>>;

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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

/// Errors that can occur when loading an x86-specific relocation.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum X86_64RelocLoadError<'a> {
    /// Error parsing the raw data.
    Raw(X86_64RelocError),
    /// Error applying symbol table.
    Symtab(RelocSymtabError<Elf64>),
    /// Error applying string table.
    Strtab(u32),
    /// UTF-8 decode error
    UTF8(&'a [u8])
}

impl<Name> Display for X86_64Rel<Name>
    where Name: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86_64Rel::None => write!(f, "none"),
            X86_64Rel::Abs64 { offset, sym } =>
                write!(f, ".section[{}..{}] += &{}",
                       offset, offset + 4, sym),
            X86_64Rel::PC32 { offset, sym } =>
                write!(f, ".section[{}..{}] += &{} - (&.section + {})",
                       offset, offset + 4, sym, offset),
            X86_64Rel::GOT32 { offset } =>
                write!(f, ".section[{}..{}] <- &.got",
                       offset, offset + 4),
            X86_64Rel::PLTRel { offset, .. } =>
                write!(f, ".section[{}..{}] <- &.plt - (&.section + {})",
                       offset, offset + 4, offset),
            X86_64Rel::Copy { sym } => write!(f, "copy {}", sym),
            X86_64Rel::GlobalData { offset, sym } =>
                write!(f, ".got[{}..{}] <- &{}", offset, offset + 8, sym),
            X86_64Rel::JumpSlot { offset, sym } =>
                write!(f, ".plt[{}..{}] <- &{}", offset, offset + 8, sym),
            X86_64Rel::Relative { offset } =>
                write!(f, ".section[{}..{}] <- &base",
                       offset, offset + 8),
            X86_64Rel::GOTPC { offset, .. } =>
                write!(f, ".section[{}..{}] <- &.got - (&.section + {})",
                       offset, offset + 4, offset),
            X86_64Rel::Abs32 { offset, sym } =>
                write!(f, ".section[{}..{}] <- &{}",
                       offset, offset + 4, sym),
            X86_64Rel::Abs32Signed { offset, sym } =>
                write!(f, ".section[{}..{}] <- &{}",
                       offset, offset + 4, sym),
            X86_64Rel::Abs16 { offset, sym } =>
                write!(f, ".section[{}..{}] <- &{}",
                       offset, offset + 2, sym),
            X86_64Rel::PC16 { offset, sym } =>
                write!(f, ".section[{}..{}] <- &{} - (&.section + {})",
                       offset, offset + 2, sym, offset),
            X86_64Rel::Abs8 { offset, sym } =>
                write!(f, ".section[{}] <- &{}",
                       offset, sym,),
            X86_64Rel::PC8 { offset, sym } =>
                write!(f, ".section[{}] <- &{} - (&.section + {})",
                       offset, sym, offset),
            X86_64Rel::DTPMod { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local module for {}"),
                       offset, offset + 8, sym),
            X86_64Rel::DTPOff { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local offset for {}"),
                       offset, offset + 8, sym),
            X86_64Rel::TPOff { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- initial execution ",
                                  "thread-local offset for {}"),
                       offset, offset + 8, sym),
            X86_64Rel::TLSGD { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- general dynamic GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Rel::TLSLD { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- local dynamic GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Rel::DTPOff32 { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local offset for {}, 32-bit"),
                       offset, offset + 4, sym),
            X86_64Rel::GOTTPOff { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- initial execution GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Rel::TPOff32 { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- initial execution ",
                                  "thread-local offset for {}, 32-bit"),
                       offset, offset + 4, sym),
            X86_64Rel::PC64 { offset, sym } =>
                write!(f, ".section[{}..{}] <- &{} - (&.section + {})",
                       offset, offset + 8, sym, offset),
            X86_64Rel::GOTRel { offset, sym } =>
                write!(f, ".section[{}..{}] <- &{} - &.got",
                       offset, offset + 8, sym),
            X86_64Rel::GOTPC32 { offset, .. } =>
                write!(f, ".section[{}..{}] <- &.got + (&.section + {})",
                       offset, offset + 4, offset),
            X86_64Rel::Size32 { offset, sym } =>
                write!(f, ".section[{}..{}] <- sizeof({})",
                       offset, offset + 4, sym),
            X86_64Rel::Size { offset, sym } =>
                write!(f, ".section[{}..{}] <- sizeof({})",
                       offset, offset + 8, sym),
        }
    }
}

impl<Name> Display for X86_64Rela<Name>
    where Name: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86_64Rela::None => write!(f, "none"),
            X86_64Rela::Abs64 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 4, sym, addend),
            X86_64Rela::PC32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 4, sym, addend, offset),
            X86_64Rela::GOT32 { offset, addend } =>
                write!(f, ".section[{}..{}] <- &.got + {}",
                       offset, offset + 4, addend),
            X86_64Rela::PLTRel { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.plt + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86_64Rela::Copy { sym } => write!(f, "copy {}", sym),
            X86_64Rela::GlobalData { offset, sym } =>
                write!(f, ".got[{}..{}] <- &{}", offset, offset + 8, sym),
            X86_64Rela::JumpSlot { offset, sym } =>
                write!(f, ".plt[{}..{}] <- &{}", offset, offset + 8, sym),
            X86_64Rela::Relative { offset, addend } =>
                write!(f, ".section[{}..{}] <- &base + {}",
                       offset, offset + 8, addend),
            X86_64Rela::GOTPC { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- (&.got + {}) - (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86_64Rela::Abs32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 4, sym, addend),
            X86_64Rela::Abs32Signed { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 4, sym, addend),
            X86_64Rela::Abs16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- &{} + {}",
                       offset, offset + 2, sym, addend),
            X86_64Rela::PC16 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 2, sym, addend, offset),
            X86_64Rela::Abs8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- &{} + {}",
                       offset, sym, addend),
            X86_64Rela::PC8 { offset, sym, addend } =>
                write!(f, ".section[{}] <- (&{} + {}) - (&.section + {})",
                       offset, sym, addend, offset),
            X86_64Rela::DTPMod { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local module for {}"),
                       offset, offset + 8, sym),
            X86_64Rela::DTPOff { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local offset for {}"),
                       offset, offset + 8, sym),
            X86_64Rela::TPOff { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- initial execution ",
                                  "thread-local offset for {}"),
                       offset, offset + 8, sym),
            X86_64Rela::TLSGD { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- general dynamic GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Rela::TLSLD { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- local dynamic GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Rela::DTPOff32 { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- general dynamic ",
                                  "thread-local offset for {}, 32-bit"),
                       offset, offset + 4, sym),
            X86_64Rela::GOTTPOff { offset, sym } =>
                write!(f, concat!(".got[{}..{}] <- initial execution GOT ",
                                  "tls_index entries for {}"),
                       offset, offset + 8, sym),
            X86_64Rela::TPOff32 { offset, sym } =>
                write!(f, concat!(".section[{}..{}] <- initial execution ",
                                  "thread-local offset for {}, 32-bit"),
                       offset, offset + 4, sym),
            X86_64Rela::PC64 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - (&.section + {})",
                       offset, offset + 8, sym, addend, offset),
            X86_64Rela::GOTRel { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- (&{} + {}) - &.got",
                       offset, offset + 8, sym, addend),
            X86_64Rela::GOTPC32 { offset, addend, .. } =>
                write!(f, ".section[{}..{}] <- &.got + {} + (&.section + {})",
                       offset, offset + 4, addend, offset),
            X86_64Rela::Size32 { offset, sym, addend } =>
                write!(f, ".section[{}..{}] <- sizeof({}) + {}",
                       offset, offset + 4, sym, addend),
            X86_64Rela::Size { offset, sym, addend } =>
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

impl<'a> Display for X86_64RelocLoadError<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            X86_64RelocLoadError::Raw(err) => Display::fmt(err, f),
            X86_64RelocLoadError::Symtab(err) => Display::fmt(err, f),
            X86_64RelocLoadError::Strtab(err) => Display::fmt(err, f),
            X86_64RelocLoadError::UTF8(_) => write!(f, "UTF-8 decode error")
        }
    }
}

impl<Name> Reloc<LittleEndian, Elf64>
    for X86_64Rel<SymData<Name, u16, Elf64>> {
    type Params = BasicRelocParams<Elf64>;
    type RelocError = X86_64RelocApplyError;

    fn reloc<'a, F>(&self, target: &mut [u8], params: &Self::Params,
                    target_base: u64, section_base: F) ->
        Result<(), Self::RelocError>
        where F: FnOnce(u16) -> Option<u64> {
        match self {
            X86_64Rel::None => Ok(()),
            X86_64Rel::Abs64 { sym: SymData { section: SymBase::Absolute,
                                              value, .. },
                               offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let addend = Elf64::read_addr
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let value = base + (*value as i64) + addend;

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rel::Abs64 { sym: SymData { section: SymBase::Index(idx),
                                              value, .. },
                               offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = (params.img_base() + section_base) as i64;
                    let addend = Elf64::read_addr
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let value = base + (*value as i64) + addend;

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::Abs64 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::PC32 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                              offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let addend = Elf64::read_word
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Rel::PC32 { sym: SymData { section: SymBase::Index(idx),
                                             value, .. },
                              offset } =>  match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i64;
                    let addend = Elf64::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = sym_value - pc;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::PC32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::GOT32 { offset } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let addend = Elf64::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let value = (got as i64) + addend;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Rel::PLTRel { offset, .. } =>  match params.plt() {
                Some(plt) => {

                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let addend = Elf64::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let value = ((plt as i64) + addend) - pc;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                }
                None => Err(X86_64RelocApplyError::NoPLT)
            },
            X86_64Rel::Copy { .. } => Err(X86_64RelocApplyError::Copy),
            X86_64Rel::GlobalData { sym: SymData { section: SymBase::Absolute,
                                                   value, .. },
                                    offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rel::GlobalData { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rel::GlobalData { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::JumpSlot { sym: SymData { section: SymBase::Absolute,
                                                 value, .. },
                                  offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rel::JumpSlot { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rel::JumpSlot { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::Relative { offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let addend = Elf64::read_addr
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let value = ((params.img_base() as i64) + addend) as u64;

                Elf64::write_addr::<LittleEndian>(&mut target[range], value);

                Ok(())
            },
            X86_64Rel::GOTPC { offset } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let addend = Elf64::read_addr
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let value = ((got as i64) + addend) - pc;

                    Elf64::write_offset::<LittleEndian>(&mut target[range],
                                                        value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Rel::Abs32 { sym: SymData { section: SymBase::Absolute,
                                              value, .. },
                               offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let addend = Elf64::read_word
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let value = base + (*value as i64) + addend;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Rel::Abs32 { sym: SymData { section: SymBase::Index(idx),
                                                value, .. },
                              offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let base = (params.img_base() + section_base) as i64;
                    let addend = Elf64::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let value = base + (*value as i64) + addend;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::Abs32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::Abs32Signed { sym: SymData { section: SymBase::Absolute,
                                                    value, .. },
                                     offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let addend = Elf64::read_word
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let value = base + (*value as i64) + addend;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Rel::Abs32Signed { sym: SymData {
                                                section: SymBase::Index(idx),
                                                value, ..
                                            },
                                       offset } =>
                match section_base(*idx) {
                    Some(section_base) => {
                        let range = (*offset as usize) ..
                                    (*offset as usize) + 4;
                        let base = (params.img_base() + section_base) as i64;
                        let addend = Elf64::read_word
                            ::<LittleEndian>(&target[range.clone()]) as i64;
                        let value = base + (*value as i64) + addend;

                        Elf64::write_word::<LittleEndian>(&mut target[range],
                                                          value as u32);

                        Ok(())
                    },
                    None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
                },
            X86_64Rel::Abs32Signed { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::Abs16 { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i64;
                let addend = Elf64::read_half
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let value = base + (*value as i64) + addend;

                Elf64::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86_64Rel::Abs16 { sym: SymData { section: SymBase::Index(idx),
                                                value, .. },
                                 offset } => match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 2;
                    let base = (params.img_base() + section_base) as i64;
                    let addend = Elf64::read_half
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let value = base + (*value as i64) + addend;

                    Elf64::write_half::<LittleEndian>(&mut target[range],
                                                      value as u16);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::Abs16 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::PC16 { sym: SymData { section: SymBase::Absolute,
                                               value, .. },
                                offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i64;
                let addend = Elf64::read_half
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                Elf64::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86_64Rel::PC16 { sym: SymData { section: SymBase::Index(idx),
                                               value, .. },
                                offset } =>  match section_base(*idx) {
                Some(section_base) => {

                    let range = (*offset as usize) .. (*offset as usize) + 2;
                    let base = (params.img_base() + section_base) as i64;
                    let addend = Elf64::read_half
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = sym_value - pc;

                    Elf64::write_half::<LittleEndian>(&mut target[range],
                                                      value as u16);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::PC16 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::Abs8 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                              offset } => {
                let base = params.img_base() as i64;
                let addend = target[*offset as usize] as i64;
                let value = base + (*value as i64) + addend;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86_64Rel::Abs8 { sym: SymData { section: SymBase::Index(idx),
                                               value, .. },
                                offset } => match section_base(*idx) {
                Some(section_base) => {
                    let base = (params.img_base() + section_base) as i64;
                    let addend = target[*offset as usize] as i64;
                    let value = base + (*value as i64) + addend;

                    target[*offset as usize] = value as u8;

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::Abs8 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::PC8 { sym: SymData { section: SymBase::Absolute,
                                              value, .. },
                               offset } => {
                let base = params.img_base() as i64;
                let addend = target[*offset as usize] as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86_64Rel::PC8 { sym: SymData { section: SymBase::Index(idx),
                                              value, .. },
                               offset } =>  match section_base(*idx) {
                Some(section_base) => {

                    let base = (params.img_base() + section_base) as i64;
                    let addend = target[*offset as usize] as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = sym_value - pc;

                    target[*offset as usize] = value as u8;

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::PC8 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::DTPMod { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rel::DTPOff { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rel::TLSGD { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rel::TLSLD { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rel::DTPOff32 { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rel::GOTTPOff { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rel::TPOff { sym: SymData { section: SymBase::Absolute,
                                              value, .. },
                               offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rel::TPOff { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rel::TPOff { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::TPOff32 { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Rel::TPOff32 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rel::TPOff32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::PC64 { sym: SymData { section: SymBase::Absolute,
                                             value, .. },
                              offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let addend = Elf64::read_addr
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rel::PC64 { sym: SymData { section: SymBase::Index(idx),
                                               value, .. },
                                offset } =>  match section_base(*idx) {
                Some(section_base) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = (params.img_base() + section_base) as i64;
                    let addend = Elf64::read_addr
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let value = sym_value - pc;

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::PC64 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::GOTRel { sym: SymData { section: SymBase::Absolute,
                                                 value, .. },
                                  offset } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let base = params.img_base() as i64;
                    let got_base = got as i64;
                    let addend = Elf64::read_addr
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let value = sym_value - got_base;

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Rel::GOTRel { sym: SymData { section: SymBase::Index(idx),
                                              value, .. },
                               offset } => match (section_base(*idx),
                                                          params.got()) {
                (Some(section_base), Some(got)) => {
                    let range = (*offset as usize) .. (*offset as usize) + 8;
                    let got_base = got as i64;
                    let base = (params.img_base() + section_base) as i64;
                    let addend = Elf64::read_addr
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let sym_value = base + (*value as i64) + addend;
                    let value = sym_value - got_base;

                    Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                      value as u64);

                    Ok(())
                },
                (None, _) => Err(X86_64RelocApplyError::NoGOT),
                (_, None) => Err(X86_64RelocApplyError::BadSymIdx(*idx))
            },
            X86_64Rel::GOTRel { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rel::GOTPC32 { offset } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let pc = (params.img_base() + target_base + *offset) as i64;
                    let addend = Elf64::read_word
                        ::<LittleEndian>(&target[range.clone()]) as i64;
                    let value = ((got as i64) + addend) - pc;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Rel::Size32 { sym: SymData { size, .. },
                                  offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let addend = Elf64::read_word
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let value = (*size as i64) + addend;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Rel::Size { sym: SymData { size, .. }, offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let addend = Elf64::read_addr
                    ::<LittleEndian>(&target[range.clone()]) as i64;
                let value = (*size as i64) + addend;

                Elf64::write_offset::<LittleEndian>(&mut target[range],
                                                    value as u64);

                Ok(())
            }
        }
    }
}

impl<Name> Reloc<LittleEndian, Elf64>
    for X86_64Rela<SymData<Name, u16, Elf64>> {
    type Params = BasicRelocParams<Elf64>;
    type RelocError = X86_64RelocApplyError;

    fn reloc<'a, F>(&self, target: &mut [u8], params: &Self::Params,
                    target_base: u64, section_base: F) ->
        Result<(), Self::RelocError>
        where F: FnOnce(u16) -> Option<u64> {
        match self {
            X86_64Rela::None => Ok(()),
            X86_64Rela::Abs64 { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + addend;

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rela::Abs64 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::Abs64 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::PC32 { sym: SymData { section: SymBase::Absolute,
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
            X86_64Rela::PC32 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::PC32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::GOT32 { offset, addend } => match params.got() {
                Some(got) => {
                    let range = (*offset as usize) .. (*offset as usize) + 4;
                    let value = (got as i64) + *addend;

                    Elf64::write_word::<LittleEndian>(&mut target[range],
                                                      value as u32);

                    Ok(())
                },
                None => Err(X86_64RelocApplyError::NoGOT)
            },
            X86_64Rela::PLTRel { offset, addend, .. } =>  match params.plt() {
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
            X86_64Rela::Copy { .. } => Err(X86_64RelocApplyError::Copy),
            X86_64Rela::GlobalData { sym: SymData { section: SymBase::Absolute,
                                                     value, .. },
                                      offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rela::GlobalData { sym: SymData {
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
            X86_64Rela::GlobalData { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::JumpSlot { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rela::JumpSlot { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::JumpSlot { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::Relative { offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let value = ((params.img_base() as i64) + addend) as u64;

                Elf64::write_addr::<LittleEndian>(&mut target[range], value);

                Ok(())
            },
            X86_64Rela::GOTPC { offset, addend } => match params.got() {
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
            X86_64Rela::Abs32 { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                              offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + *addend;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Rela::Abs32 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::Abs32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::Abs32Signed { sym: SymData {
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
            X86_64Rela::Abs32Signed { sym: SymData {
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
            X86_64Rela::Abs32Signed { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::Abs16 { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 2;
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + addend;

                Elf64::write_half::<LittleEndian>(&mut target[range],
                                                  value as u16);

                Ok(())
            },
            X86_64Rela::Abs16 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::Abs16 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::PC16 { sym: SymData { section: SymBase::Absolute,
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
            X86_64Rela::PC16 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::PC16 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::Abs8 { sym: SymData { section: SymBase::Absolute,
                                               value, .. },
                                offset, addend } => {
                let base = params.img_base() as i64;
                let value = base + (*value as i64) + addend;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86_64Rela::Abs8 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::Abs8 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::PC8 { sym: SymData { section: SymBase::Absolute,
                                              value, .. },
                               offset, addend } => {
                let base = params.img_base() as i64;
                let sym_value = base + (*value as i64) + addend;
                let pc = (params.img_base() + target_base + *offset) as i64;
                let value = sym_value - pc;

                target[*offset as usize] = value as u8;

                Ok(())
            },
            X86_64Rela::PC8 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::PC8 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::DTPMod { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rela::DTPOff { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rela::TLSGD { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rela::TLSLD { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rela::DTPOff32 { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rela::GOTTPOff { .. } => Err(X86_64RelocApplyError::BadTLS),
            X86_64Rela::TPOff { sym: SymData { section: SymBase::Absolute,
                                                value, .. },
                                 offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_addr::<LittleEndian>(&mut target[range],
                                                  value as u64);

                Ok(())
            },
            X86_64Rela::TPOff { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::TPOff { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::TPOff32 { sym: SymData { section: SymBase::Absolute,
                                                  value, .. },
                                   offset } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let base = params.img_base() as i64;
                let value = base + (*value as i64);

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Rela::TPOff32 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::TPOff32 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::PC64 { sym: SymData { section: SymBase::Absolute,
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
            X86_64Rela::PC64 { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::PC64 { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::GOTRel { sym: SymData { section: SymBase::Absolute,
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
            X86_64Rela::GOTRel { sym: SymData { section: SymBase::Index(idx),
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
            X86_64Rela::GOTRel { sym: SymData { section, .. }, .. } =>
                Err(X86_64RelocApplyError::BadSymBase(*section)),
            X86_64Rela::GOTPC32 { offset, addend } => match params.got() {
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
            X86_64Rela::Size32 { sym: SymData { size, .. },
                                  offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 4;
                let value = (*size as i64) + addend;

                Elf64::write_word::<LittleEndian>(&mut target[range],
                                                  value as u32);

                Ok(())
            },
            X86_64Rela::Size { sym: SymData { size, .. }, offset, addend } => {
                let range = (*offset as usize) .. (*offset as usize) + 8;
                let value = (*size as i64) + addend;

                Elf64::write_offset::<LittleEndian>(&mut target[range],
                                                    value as u64);

                Ok(())
            }
        }
    }
}

impl<Name> TryFrom<RelData<Name, Elf64>> for X86_64Rel<Name> {
    type Error = X86_64RelocError;

    #[inline]
    fn try_from(rela: RelData<Name, Elf64>) -> Result<X86_64Rel<Name>,
                                                      Self::Error> {
        let RelData { offset, sym, kind } = rela;

        match kind {
            0 => Ok(X86_64Rel::None),
            1 => Ok(X86_64Rel::Abs64 { offset, sym }),
            2 => Ok(X86_64Rel::PC32 { offset, sym }),
            3 => Ok(X86_64Rel::GOT32 { offset }),
            4 => Ok(X86_64Rel::PLTRel { offset, sym }),
            5 => Ok(X86_64Rel::Copy { sym }),
            6 => Ok(X86_64Rel::GlobalData { offset, sym }),
            7 => Ok(X86_64Rel::JumpSlot { offset, sym }),
            8 => Ok(X86_64Rel::Relative { offset }),
            9 => Ok(X86_64Rel::GOTPC { offset }),
            10 => Ok(X86_64Rel::Abs32 { offset, sym }),
            11 => Ok(X86_64Rel::Abs32Signed { offset, sym }),
            12 => Ok(X86_64Rel::Abs16 { offset, sym }),
            13 => Ok(X86_64Rel::PC16 { offset, sym }),
            14 => Ok(X86_64Rel::Abs8 { offset, sym }),
            15 => Ok(X86_64Rel::PC8 { offset, sym }),
            16 => Ok(X86_64Rel::DTPMod { offset, sym }),
            17 => Ok(X86_64Rel::DTPOff { offset, sym }),
            18 => Ok(X86_64Rel::TPOff { offset, sym }),
            19 => Ok(X86_64Rel::TLSGD { offset, sym }),
            20 => Ok(X86_64Rel::TLSLD { offset, sym }),
            21 => Ok(X86_64Rel::DTPOff32 { offset, sym }),
            22 => Ok(X86_64Rel::GOTTPOff { offset, sym }),
            23 => Ok(X86_64Rel::TPOff32 { offset, sym }),
            24 => Ok(X86_64Rel::PC64 { offset, sym }),
            25 => Ok(X86_64Rel::GOTRel { offset, sym }),
            26 => Ok(X86_64Rel::GOTPC32 { offset }),
            32 => Ok(X86_64Rel::Size32 { offset, sym }),
            33 => Ok(X86_64Rel::Size { offset, sym }),
            tag => Err(X86_64RelocError::BadTag(tag))
        }
    }
}

impl From<X86_64Rel<u32>> for RelData<u32, Elf64> {
    #[inline]
    fn from(rel: X86_64Rel<u32>) -> RelData<u32, Elf64> {
        match rel {
            X86_64Rel::None =>
                RelData { offset: 0, sym: 0, kind: 0 },
            X86_64Rel::Abs64 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 1 },
            X86_64Rel::PC32 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 2 },
            X86_64Rel::GOT32 { offset } =>
                RelData { offset: offset, sym: 0, kind: 3 },
            X86_64Rel::PLTRel { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 4 },
            X86_64Rel::Copy { sym } =>
                RelData { offset: 0, sym: sym, kind: 5 },
            X86_64Rel::GlobalData { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 6 },
            X86_64Rel::JumpSlot { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 7 },
            X86_64Rel::Relative { offset } =>
                RelData { offset: offset, sym: 0, kind: 8 },
            X86_64Rel::GOTPC { offset } =>
                RelData { offset: offset, sym: 0, kind: 9 },
            X86_64Rel::Abs32 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 10 },
            X86_64Rel::Abs32Signed { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 11 },
            X86_64Rel::Abs16 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 12 },
            X86_64Rel::PC16 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 13 },
            X86_64Rel::Abs8 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 14 },
            X86_64Rel::PC8 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 15 },
            X86_64Rel::DTPMod { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 16 },
            X86_64Rel::DTPOff { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 17 },
            X86_64Rel::TPOff { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 18 },
            X86_64Rel::TLSGD { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 19 },
            X86_64Rel::TLSLD { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 20 },
            X86_64Rel::DTPOff32 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 21 },
            X86_64Rel::GOTTPOff { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 22 },
            X86_64Rel::TPOff32 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 23 },
            X86_64Rel::PC64 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 24 },
            X86_64Rel::GOTRel { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 25 },
            X86_64Rel::GOTPC32 { offset } =>
                RelData { offset: offset, sym: 0, kind: 26 },
            X86_64Rel::Size32 { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 32 },
            X86_64Rel::Size { offset, sym } =>
                RelData { offset: offset, sym: sym, kind: 33 },
        }
    }
}

impl<Name> TryFrom<RelaData<Name, Elf64>> for X86_64Rela<Name> {
    type Error = X86_64RelocError;

    #[inline]
    fn try_from(rela: RelaData<Name, Elf64>) -> Result<X86_64Rela<Name>,
                                                      Self::Error> {
        let RelaData { offset, sym, kind, addend } = rela;

        match kind {
            0 => Ok(X86_64Rela::None),
            1 => Ok(X86_64Rela::Abs64 { offset, sym, addend }),
            2 => Ok(X86_64Rela::PC32 { offset, sym, addend }),
            3 => Ok(X86_64Rela::GOT32 { offset, addend }),
            4 => Ok(X86_64Rela::PLTRel { offset, sym, addend }),
            5 => Ok(X86_64Rela::Copy { sym }),
            6 => Ok(X86_64Rela::GlobalData { offset, sym }),
            7 => Ok(X86_64Rela::JumpSlot { offset, sym }),
            8 => Ok(X86_64Rela::Relative { offset, addend }),
            9 => Ok(X86_64Rela::GOTPC { offset, addend }),
            10 => Ok(X86_64Rela::Abs32 { offset, sym, addend }),
            11 => Ok(X86_64Rela::Abs32Signed { offset, sym, addend }),
            12 => Ok(X86_64Rela::Abs16 { offset, sym, addend }),
            13 => Ok(X86_64Rela::PC16 { offset, sym, addend }),
            14 => Ok(X86_64Rela::Abs8 { offset, sym, addend }),
            15 => Ok(X86_64Rela::PC8 { offset, sym, addend }),
            16 => Ok(X86_64Rela::DTPMod { offset, sym }),
            17 => Ok(X86_64Rela::DTPOff { offset, sym }),
            18 => Ok(X86_64Rela::TPOff { offset, sym }),
            19 => Ok(X86_64Rela::TLSGD { offset, sym }),
            20 => Ok(X86_64Rela::TLSLD { offset, sym }),
            21 => Ok(X86_64Rela::DTPOff32 { offset, sym }),
            22 => Ok(X86_64Rela::GOTTPOff { offset, sym }),
            23 => Ok(X86_64Rela::TPOff32 { offset, sym }),
            24 => Ok(X86_64Rela::PC64 { offset, sym, addend }),
            25 => Ok(X86_64Rela::GOTRel { offset, sym, addend }),
            26 => Ok(X86_64Rela::GOTPC32 { offset, addend }),
            32 => Ok(X86_64Rela::Size32 { offset, sym, addend }),
            33 => Ok(X86_64Rela::Size { offset, sym, addend }),
            tag => Err(X86_64RelocError::BadTag(tag))
        }
    }
}

impl From<X86_64Rela<u32>> for RelaData<u32, Elf64> {
    #[inline]
    fn from(rel: X86_64Rela<u32>) -> RelaData<u32, Elf64> {
        match rel {
            X86_64Rela::None =>
                RelaData { offset: 0, sym: 0, kind: 0, addend: 0 },
            X86_64Rela::Abs64 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 1, addend: addend },
            X86_64Rela::PC32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 2, addend: addend },
            X86_64Rela::GOT32 { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 3, addend: addend },
            X86_64Rela::PLTRel { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 4, addend: addend },
            X86_64Rela::Copy { sym } =>
                RelaData { offset: 0, sym: sym, kind: 5 , addend: 0 },
            X86_64Rela::GlobalData { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 6, addend: 0 },
            X86_64Rela::JumpSlot { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 7, addend: 0 },
            X86_64Rela::Relative { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 8, addend: addend },
            X86_64Rela::GOTPC { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 9, addend: addend },
            X86_64Rela::Abs32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 10, addend: addend },
            X86_64Rela::Abs32Signed { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 11, addend: addend },
            X86_64Rela::Abs16 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 12, addend: addend },
            X86_64Rela::PC16 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 13, addend: addend },
            X86_64Rela::Abs8 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 14, addend: addend },
            X86_64Rela::PC8 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 15, addend: addend },
            X86_64Rela::DTPMod { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 16, addend: 0 },
            X86_64Rela::DTPOff { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 17, addend: 0 },
            X86_64Rela::TPOff { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 18, addend: 0 },
            X86_64Rela::TLSGD { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 19, addend: 0 },
            X86_64Rela::TLSLD { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 20, addend: 0 },
            X86_64Rela::DTPOff32 { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 21, addend: 0 },
            X86_64Rela::GOTTPOff { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 22, addend: 0 },
            X86_64Rela::TPOff32 { offset, sym } =>
                RelaData { offset: offset, sym: sym, kind: 23, addend: 0 },
            X86_64Rela::PC64 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 24, addend: addend },
            X86_64Rela::GOTRel { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 25, addend: addend },
            X86_64Rela::GOTPC32 { offset, addend } =>
                RelaData { offset: offset, sym: 0, kind: 26, addend: addend },
            X86_64Rela::Size32 { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 32, addend: addend },
            X86_64Rela::Size { offset, sym, addend } =>
                RelaData { offset: offset, sym: sym, kind: 33, addend: addend },
        }
    }
}

impl<'a> WithSymtab<'a, LittleEndian, Elf64> for X86_64RelRaw {
    type Result = X86_64Rel<SymDataRaw<Elf64>>;
    type Error = RelocSymtabError<Elf64>;

    #[inline]
    fn with_symtab(self, symtab: Symtab<'a, LittleEndian, Elf64>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86_64Rel::None => Ok(X86_64Rel::None),
            X86_64Rel::Abs64 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::Abs64 { offset: offset,
                                                  sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::PC32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::PC32 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::GOT32 { offset } =>
                Ok(X86_64Rel::GOT32 { offset: offset }),
            X86_64Rel::PLTRel { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::PLTRel { offset: offset,
                                                   sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::Copy { sym } => match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::Copy { sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::GlobalData { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::GlobalData { offset: offset,
                                                       sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::JumpSlot { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::JumpSlot { offset: offset,
                                                     sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::Relative { offset } =>
                Ok(X86_64Rel::Relative { offset: offset }),
            X86_64Rel::GOTPC { offset } =>
                Ok(X86_64Rel::GOTPC { offset: offset }),
            X86_64Rel::Abs32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::Abs32 { offset: offset,
                                                  sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::Abs32Signed { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::Abs32Signed { offset: offset,
                                                        sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::Abs16 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::Abs16 { offset: offset,
                                                  sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::PC16 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::PC16 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::Abs8 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::Abs8 { offset: offset,
                                                 sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::PC8 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::PC8 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::DTPMod { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::DTPMod { offset: offset,
                                                   sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::DTPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::DTPOff { offset: offset,
                                                   sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::TPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::TPOff { offset: offset,
                                                  sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::TLSGD { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::TLSGD { offset: offset,
                                                  sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::TLSLD { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::TLSLD { offset: offset,
                                                  sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::DTPOff32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::DTPOff32 { offset: offset,
                                                     sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::GOTTPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::GOTTPOff { offset: offset,
                                                     sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::TPOff32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::TPOff32 { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::PC64 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::PC64 { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::GOTRel { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::GOTRel { offset: offset,
                                                   sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::GOTPC32 { offset } =>
                Ok(X86_64Rel::GOTPC32 { offset: offset }),
            X86_64Rel::Size32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::Size32 { offset: offset,
                                                   sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rel::Size { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rel::Size { offset: offset, sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                }
        }
    }
}

impl<'a> WithSymtab<'a, LittleEndian, Elf64> for X86_64RelaRaw {
    type Result = X86_64Rela<SymDataRaw<Elf64>>;
    type Error = RelocSymtabError<Elf64>;

    #[inline]
    fn with_symtab(self, symtab: Symtab<'a, LittleEndian, Elf64>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86_64Rela::None => Ok(X86_64Rela::None),
            X86_64Rela::Abs64 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::Abs64 { offset: offset,
                                                    sym: symdata,
                                                    addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::PC32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::PC32 { offset: offset, sym: symdata,
                                                   addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::GOT32 { offset, addend } =>
                Ok(X86_64Rela::GOT32 { offset: offset, addend: addend }),
            X86_64Rela::PLTRel { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::PLTRel { offset: offset,
                                                     sym: symdata,
                                                     addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::Copy { sym } => match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::Copy { sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::GlobalData { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::GlobalData { offset: offset,
                                                         sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::JumpSlot { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::JumpSlot { offset: offset,
                                                       sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::Relative { offset, addend } =>
                Ok(X86_64Rela::Relative { offset: offset, addend: addend }),
            X86_64Rela::GOTPC { offset, addend } =>
                Ok(X86_64Rela::GOTPC { offset: offset, addend: addend }),
            X86_64Rela::Abs32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::Abs32 { offset: offset,
                                                    sym: symdata,
                                                    addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::Abs32Signed { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::Abs32Signed { offset: offset,
                                                          sym: symdata,
                                                          addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::Abs16 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::Abs16 { offset: offset,
                                                    sym: symdata,
                                                    addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::PC16 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::PC16 { offset: offset, sym: symdata,
                                                   addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::Abs8 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::Abs8 { offset: offset,
                                                    sym: symdata,
                                                    addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::PC8 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::PC8 { offset: offset, sym: symdata,
                                                  addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::DTPMod { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::DTPMod { offset: offset,
                                                     sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::DTPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::DTPOff { offset: offset,
                                                     sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::TPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::TPOff { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::TLSGD { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::TLSGD { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::TLSLD { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::TLSLD { offset: offset,
                                                    sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::DTPOff32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::DTPOff32 { offset: offset,
                                                       sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::GOTTPOff { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::GOTTPOff { offset: offset,
                                                       sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::TPOff32 { offset, sym } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::TPOff32 { offset: offset,
                                                      sym: symdata })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::PC64 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::PC64 { offset: offset, sym: symdata,
                                                   addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::GOTRel { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::GOTRel { offset: offset,
                                                     sym: symdata,
                                                     addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::GOTPC32 { offset, addend } =>
                Ok(X86_64Rela::GOTPC32 { offset: offset, addend: addend }),
            X86_64Rela::Size32 { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::Size32 { offset: offset,
                                                     sym: symdata,
                                                     addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                },
            X86_64Rela::Size { offset, sym, addend } =>
                match symtab.idx(sym as usize) {
                    Some(sym) => match sym.try_into() {
                        Ok(symdata) => {
                            Ok(X86_64Rela::Size { offset: offset, sym: symdata,
                                                   addend: addend })
                        },
                        Err(err) => Err(RelocSymtabError::SymError(err))
                    },
                    None => Err(RelocSymtabError::BadIdx(sym))
                }
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf64> for X86_64RelRawSym {
    type Ent = RelData<u32, Elf64>;
    type LoadError = X86_64RelocLoadError<'a>;

    #[inline]
    fn from_relent(ent: RelData<u32, Elf64>,
                   symtab: Symtab<'a, LittleEndian, Elf64>,
                   _strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let raw: X86_64RelRaw = match X86_64Rel::try_from(ent) {
            Ok(raw) => Ok(raw),
            Err(err) => Err(X86_64RelocLoadError::Raw(err))
        }?;

        match raw.with_symtab(symtab) {
            Ok(out) => Ok(out),
            Err(err) => Err(X86_64RelocLoadError::Symtab(err))
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf64> for X86_64RelaRawSym {
    type Ent = RelaData<u32, Elf64>;
    type LoadError = X86_64RelocLoadError<'a>;

    #[inline]
    fn from_relent(ent: RelaData<u32, Elf64>,
                   symtab: Symtab<'a, LittleEndian, Elf64>,
                   _strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let raw: X86_64RelaRaw = match X86_64Rela::try_from(ent) {
            Ok(raw) => Ok(raw),
            Err(err) => Err(X86_64RelocLoadError::Raw(err))
        }?;

        match raw.with_symtab(symtab) {
            Ok(out) => Ok(out),
            Err(err) => Err(X86_64RelocLoadError::Symtab(err))
        }
    }
}

impl<'a> WithStrtab<'a> for X86_64RelRawSym {
    type Result = X86_64RelStrDataSym<'a>;
    type Error = u32;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86_64Rel::None => Ok(X86_64Rel::None),
            X86_64Rel::Abs64 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs64 { offset: offset, sym: symdata })
                        },
                    Err(err) => Err(err)
                    },
            X86_64Rel::PC32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PC32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::GOT32 { offset } =>
                Ok(X86_64Rel::GOT32 { offset: offset }),
            X86_64Rel::PLTRel { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PLTRel { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Copy { sym } => match sym.with_strtab(strtab) {
                Ok(symdata) => {
                    Ok(X86_64Rel::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86_64Rel::GlobalData { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::GlobalData { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::JumpSlot { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::JumpSlot { offset: offset,
                                                 sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Relative { offset } =>
                Ok(X86_64Rel::Relative { offset: offset }),
            X86_64Rel::GOTPC { offset } =>
                Ok(X86_64Rel::GOTPC { offset: offset }),
            X86_64Rel::Abs32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Abs32Signed { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs32Signed { offset: offset,
                                                    sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Abs16 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs16 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::PC16 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PC16 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Abs8 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs8 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::PC8 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PC8 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::DTPMod { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::DTPMod { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::DTPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::DTPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::TPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::TPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::TLSGD { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::TLSGD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::TLSLD { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::TLSLD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::DTPOff32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::DTPOff32 { offset: offset,
                                                 sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::GOTTPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::GOTTPOff { offset: offset,
                                                 sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::TPOff32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::TPOff32 { offset: offset,
                                                sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::PC64 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PC64 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::GOTRel { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::GOTRel { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::GOTPC32 { offset } =>
                Ok(X86_64Rel::GOTPC32 { offset: offset }),
            X86_64Rel::Size32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Size32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Size { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Size { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
        }
    }
}

impl<'a> WithStrtab<'a> for X86_64RelaRawSym {
    type Result = X86_64RelaStrDataSym<'a>;
    type Error = u32;

    #[inline]
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error> {
        match self {
            X86_64Rela::None => Ok(X86_64Rela::None),
            X86_64Rela::Abs64 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs64 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                    Err(err) => Err(err)
                    },
            X86_64Rela::PC32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PC32 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::GOT32 { offset, addend } =>
                Ok(X86_64Rela::GOT32 { offset: offset, addend: addend }),
            X86_64Rela::PLTRel { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PLTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Copy { sym } => match sym.with_strtab(strtab) {
                Ok(symdata) => {
                    Ok(X86_64Rela::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86_64Rela::GlobalData { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::GlobalData { offset: offset,
                                                     sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::JumpSlot { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::JumpSlot { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Relative { offset, addend } =>
                Ok(X86_64Rela::Relative { offset: offset, addend: addend }),
            X86_64Rela::GOTPC { offset, addend } =>
                Ok(X86_64Rela::GOTPC { offset: offset, addend: addend }),
            X86_64Rela::Abs32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs32 { offset: offset, sym: symdata,
                                                addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Abs32Signed { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs32Signed { offset: offset,
                                                      sym: symdata,
                                                      addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Abs16 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs16 { offset: offset, sym: symdata,
                                                addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::PC16 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PC16 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Abs8 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs8 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::PC8 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PC8 { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::DTPMod { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::DTPMod { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::DTPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::DTPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::TPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::TPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::TLSGD { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::TLSGD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::TLSLD { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::TLSLD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::DTPOff32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::DTPOff32 { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::GOTTPOff { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::GOTTPOff { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::TPOff32 { offset, sym } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::TPOff32 { offset: offset,
                                                  sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::PC64 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PC64 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::GOTRel { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::GOTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::GOTPC32 { offset, addend } =>
                Ok(X86_64Rela::GOTPC32 { offset: offset, addend: addend }),
            X86_64Rela::Size32 { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Size32 { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Size { offset, sym, addend } =>
                match sym.with_strtab(strtab) {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Size { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
        }
    }
}


impl<'a> ArchReloc<'a, LittleEndian, Elf64> for X86_64RelStrDataSym<'a> {
    type Ent = RelData<u32, Elf64>;
    type LoadError = X86_64RelocLoadError<'a>;

    fn from_relent(ent: RelData<u32, Elf64>,
                   symtab: Symtab<'a, LittleEndian, Elf64>,
                   strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let raw: X86_64RelRawSym = X86_64Rel::from_relent(ent, symtab, strtab)?;

        match raw.with_strtab(strtab) {
            Ok(out) => Ok(out),
            Err(err) => Err(X86_64RelocLoadError::Strtab(err))
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf64> for X86_64RelaStrDataSym<'a> {
    type Ent = RelaData<u32, Elf64>;
    type LoadError = X86_64RelocLoadError<'a>;

    fn from_relent(ent: RelaData<u32, Elf64>,
                   symtab: Symtab<'a, LittleEndian, Elf64>,
                   strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let raw: X86_64RelaRawSym = X86_64Rela::from_relent(ent, symtab,
                                                            strtab)?;

        match raw.with_strtab(strtab) {
            Ok(out) => Ok(out),
            Err(err) => Err(X86_64RelocLoadError::Strtab(err))
        }
    }
}

impl<'a> TryFrom<X86_64RelStrDataSym<'a>> for X86_64RelStrSym<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86_64RelStrDataSym<'a>) ->
        Result<X86_64RelStrSym<'a>, Self::Error> {
        match reloc {
            X86_64Rel::None => Ok(X86_64Rel::None),
            X86_64Rel::Abs64 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs64 { offset: offset, sym: symdata })
                        },
                    Err(err) => Err(err)
                    },
            X86_64Rel::PC32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PC32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::GOT32 { offset } =>
                Ok(X86_64Rel::GOT32 { offset: offset }),
            X86_64Rel::PLTRel { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PLTRel { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Copy { sym } => match sym.try_into() {
                Ok(symdata) => {
                    Ok(X86_64Rel::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86_64Rel::GlobalData { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::GlobalData { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::JumpSlot { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::JumpSlot { offset: offset,
                                                 sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Relative { offset } =>
                Ok(X86_64Rel::Relative { offset: offset }),
            X86_64Rel::GOTPC { offset } =>
                Ok(X86_64Rel::GOTPC { offset: offset }),
            X86_64Rel::Abs32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Abs32Signed { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs32Signed { offset: offset,
                                                    sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Abs16 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs16 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::PC16 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PC16 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Abs8 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Abs8 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::PC8 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PC8 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::DTPMod { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::DTPMod { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::DTPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::DTPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::TPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::TPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::TLSGD { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::TLSGD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::TLSLD { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::TLSLD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::DTPOff32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::DTPOff32 { offset: offset,
                                                 sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::GOTTPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::GOTTPOff { offset: offset,
                                                 sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::TPOff32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::TPOff32 { offset: offset,
                                                sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::PC64 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::PC64 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::GOTRel { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::GOTRel { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::GOTPC32 { offset } =>
                Ok(X86_64Rel::GOTPC32 { offset: offset }),
            X86_64Rel::Size32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Size32 { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rel::Size { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rel::Size { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
        }
    }
}

impl<'a> TryFrom<X86_64RelaStrDataSym<'a>> for X86_64RelaStrSym<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86_64RelaStrDataSym<'a>) ->
        Result<X86_64RelaStrSym<'a>, Self::Error> {
        match reloc {
            X86_64Rela::None => Ok(X86_64Rela::None),
            X86_64Rela::Abs64 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs64 { offset: offset, sym: symdata,
                                                addend: addend })
                        },
                    Err(err) => Err(err)
                    },
            X86_64Rela::PC32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PC32 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::GOT32 { offset, addend } =>
                Ok(X86_64Rela::GOT32 { offset: offset, addend: addend }),
            X86_64Rela::PLTRel { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PLTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Copy { sym } => match sym.try_into() {
                Ok(symdata) => {
                    Ok(X86_64Rela::Copy { sym: symdata })
                },
                Err(err) => Err(err)
            },
            X86_64Rela::GlobalData { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::GlobalData { offset: offset,
                                                     sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::JumpSlot { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::JumpSlot { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Relative { offset, addend } =>
                Ok(X86_64Rela::Relative { offset: offset, addend: addend }),
            X86_64Rela::GOTPC { offset, addend } =>
                Ok(X86_64Rela::GOTPC { offset: offset, addend: addend }),
            X86_64Rela::Abs32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs32 { offset: offset, sym: symdata,
                                                addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Abs32Signed { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs32Signed { offset: offset,
                                                      sym: symdata,
                                                      addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Abs16 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs16 { offset: offset, sym: symdata,
                                                addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::PC16 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PC16 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Abs8 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Abs8 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::PC8 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PC8 { offset: offset, sym: symdata,
                                              addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::DTPMod { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::DTPMod { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::DTPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::DTPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::TPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::TPOff { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::TLSGD { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::TLSGD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::TLSLD { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::TLSLD { offset: offset, sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::DTPOff32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::DTPOff32 { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::GOTTPOff { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::GOTTPOff { offset: offset,
                                                   sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::TPOff32 { offset, sym } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::TPOff32 { offset: offset,
                                                  sym: symdata })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::PC64 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::PC64 { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::GOTRel { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::GOTRel { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::GOTPC32 { offset, addend } =>
                Ok(X86_64Rela::GOTPC32 { offset: offset, addend: addend }),
            X86_64Rela::Size32 { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Size32 { offset: offset, sym: symdata,
                                                 addend: addend })
                    },
                    Err(err) => Err(err)
                },
            X86_64Rela::Size { offset, sym, addend } =>
                match sym.try_into() {
                    Ok(symdata) => {
                        Ok(X86_64Rela::Size { offset: offset, sym: symdata,
                                               addend: addend })
                    },
                    Err(err) => Err(err)
                },
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf64> for X86_64RelStrSym<'a> {
    type Ent = RelData<u32, Elf64>;
    type LoadError = X86_64RelocLoadError<'a>;

    #[inline]
    fn from_relent(ent: RelData<u32, Elf64>,
                   symtab: Symtab<'a, LittleEndian, Elf64>,
                   strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let sym: X86_64RelStrDataSym = X86_64Rel::from_relent(ent, symtab,
                                                              strtab)?;

        match sym.try_into() {
            Ok(out) => Ok(out),
            Err(err) => Err(X86_64RelocLoadError::UTF8(err))
        }
    }
}

impl<'a> ArchReloc<'a, LittleEndian, Elf64> for X86_64RelaStrSym<'a> {
    type Ent = RelaData<u32, Elf64>;
    type LoadError = X86_64RelocLoadError<'a>;

    #[inline]
    fn from_relent(ent: RelaData<u32, Elf64>,
                   symtab: Symtab<'a, LittleEndian, Elf64>,
                   strtab: Strtab<'a>) -> Result<Self, Self::LoadError> {
        let sym: X86_64RelaStrDataSym = X86_64Rela::from_relent(ent, symtab,
                                                                strtab)?;

        match sym.try_into() {
            Ok(out) => Ok(out),
            Err(err) => Err(X86_64RelocLoadError::UTF8(err))
        }
    }
}

impl<'a> From<X86_64RelStrDataSym<'a>> for X86_64RelStrData<'a> {
    #[inline]
    fn from(reloc: X86_64RelStrDataSym<'a>) -> X86_64RelStrData<'a> {
        match reloc {
            X86_64Rel::None => X86_64Rel::None,
            X86_64Rel::Abs64 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs64 { offset: offset, sym: name },
            X86_64Rel::PC32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PC32 { offset: offset, sym: name },
            X86_64Rel::GOT32 { offset } =>
                X86_64Rel::GOT32 { offset: offset },
            X86_64Rel::PLTRel { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PLTRel { offset: offset, sym: name },
            X86_64Rel::Copy { sym: SymData { name, .. } } =>
                X86_64Rel::Copy { sym: name },
            X86_64Rel::GlobalData { sym: SymData { name, .. }, offset } =>
                X86_64Rel::GlobalData { offset: offset, sym: name },
            X86_64Rel::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86_64Rel::JumpSlot { offset: offset, sym: name },
            X86_64Rel::Relative { offset } =>
                X86_64Rel::Relative { offset: offset },
            X86_64Rel::GOTPC { offset } =>
                X86_64Rel::GOTPC { offset: offset },
            X86_64Rel::Abs32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs32 { offset: offset, sym: name },
            X86_64Rel::Abs32Signed { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs32Signed { offset: offset, sym: name },
            X86_64Rel::Abs16 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs16 { offset: offset, sym: name },
            X86_64Rel::PC16 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PC16 { offset: offset, sym: name },
            X86_64Rel::Abs8 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs8 { offset: offset, sym: name },
            X86_64Rel::PC8 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PC8 { offset: offset, sym: name },
            X86_64Rel::DTPMod { sym: SymData { name, .. }, offset } =>
                X86_64Rel::DTPMod { offset: offset, sym: name },
            X86_64Rel::DTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rel::DTPOff { offset: offset, sym: name },
            X86_64Rel::TPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rel::TPOff { offset: offset, sym: name },
            X86_64Rel::TLSGD { sym: SymData { name, .. }, offset } =>
                X86_64Rel::TLSGD { offset: offset, sym: name },
            X86_64Rel::TLSLD { sym: SymData { name, .. }, offset } =>
                X86_64Rel::TLSLD { offset: offset, sym: name },
            X86_64Rel::DTPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::DTPOff32 { offset: offset, sym: name },
            X86_64Rel::GOTTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rel::GOTTPOff { offset: offset, sym: name },
            X86_64Rel::TPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::TPOff32 { offset: offset, sym: name },
            X86_64Rel::PC64 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PC64 { offset: offset, sym: name },
            X86_64Rel::GOTRel { sym: SymData { name, .. }, offset } =>
                X86_64Rel::GOTRel { offset: offset, sym: name },
            X86_64Rel::GOTPC32 { offset } =>
                X86_64Rel::GOTPC32 { offset: offset },
            X86_64Rel::Size32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Size32 { offset: offset, sym: name },
            X86_64Rel::Size { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Size { offset: offset, sym: name }
        }
    }
}

impl<'a> From<X86_64RelaStrDataSym<'a>> for X86_64RelaStrData<'a> {
    #[inline]
    fn from(reloc: X86_64RelaStrDataSym<'a>) -> X86_64RelaStrData<'a> {
        match reloc {
            X86_64Rela::None => X86_64Rela::None,
            X86_64Rela::Abs64 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Abs64 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Rela::PC32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PC32 { offset: offset, sym: name, addend: addend },
            X86_64Rela::GOT32 { offset, addend } =>
                X86_64Rela::GOT32 { offset: offset, addend: addend },
            X86_64Rela::PLTRel { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PLTRel { offset: offset, sym: name,
                                      addend: addend },
            X86_64Rela::Copy { sym: SymData { name, .. } } =>
                X86_64Rela::Copy { sym: name },
            X86_64Rela::GlobalData { sym: SymData { name, .. }, offset } =>
                X86_64Rela::GlobalData { offset: offset, sym: name },
            X86_64Rela::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86_64Rela::JumpSlot { offset: offset, sym: name },
            X86_64Rela::Relative { offset, addend } =>
                X86_64Rela::Relative { offset: offset, addend: addend },
            X86_64Rela::GOTPC { offset, addend } =>
                X86_64Rela::GOTPC { offset: offset, addend: addend },
            X86_64Rela::Abs32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Abs32 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Rela::Abs32Signed { sym: SymData { name, .. }, offset,
                                       addend } =>
                X86_64Rela::Abs32Signed { offset: offset, sym: name,
                                           addend: addend },
            X86_64Rela::Abs16 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Abs16 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Rela::PC16 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PC16 { offset: offset, sym: name, addend: addend },
            X86_64Rela::Abs8 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Abs8 { offset: offset, sym: name, addend: addend },
            X86_64Rela::PC8 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PC8 { offset: offset, sym: name, addend: addend },
            X86_64Rela::DTPMod { sym: SymData { name, .. }, offset } =>
                X86_64Rela::DTPMod { offset: offset, sym: name },
            X86_64Rela::DTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rela::DTPOff { offset: offset, sym: name },
            X86_64Rela::TPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rela::TPOff { offset: offset, sym: name },
            X86_64Rela::TLSGD { sym: SymData { name, .. }, offset } =>
                X86_64Rela::TLSGD { offset: offset, sym: name },
            X86_64Rela::TLSLD { sym: SymData { name, .. }, offset } =>
                X86_64Rela::TLSLD { offset: offset, sym: name },
            X86_64Rela::DTPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Rela::DTPOff32 { offset: offset, sym: name },
            X86_64Rela::GOTTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rela::GOTTPOff { offset: offset, sym: name },
            X86_64Rela::TPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Rela::TPOff32 { offset: offset, sym: name },
            X86_64Rela::PC64 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PC64 { offset: offset, sym: name, addend: addend },
            X86_64Rela::GOTRel { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::GOTRel { offset: offset, sym: name,
                                      addend: addend },
            X86_64Rela::GOTPC32 { offset, addend } =>
                X86_64Rela::GOTPC32 { offset: offset, addend: addend },
            X86_64Rela::Size32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Size32 { offset: offset, sym: name,
                                      addend: addend },
            X86_64Rela::Size { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Size { offset: offset, sym: name, addend: addend }
        }
    }
}

impl<'a> TryFrom<X86_64RelStrData<'a>> for X86_64RelStr<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86_64RelStrData<'a>) ->
        Result<X86_64RelStr<'a>, Self::Error> {
        match reloc {
            X86_64Rel::None => Ok(X86_64Rel::None),
            X86_64Rel::Abs64 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::Abs64 { offset: offset, sym: Some(name) }),
            X86_64Rel::Abs64 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::Abs64 { sym: None, offset } =>
                Ok(X86_64Rel::Abs64 { offset: offset, sym: None }),
            X86_64Rel::PC32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::PC32 { offset: offset, sym: Some(name) }),
            X86_64Rel::PC32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::PC32 { sym: None, offset } =>
                Ok(X86_64Rel::PC32 { offset: offset, sym: None }),
            X86_64Rel::GOT32 { offset } =>
                Ok(X86_64Rel::GOT32 { offset: offset }),
            X86_64Rel::PLTRel { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::PLTRel { offset: offset, sym: Some(name) }),
            X86_64Rel::PLTRel { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::PLTRel { sym: None, offset } =>
                Ok(X86_64Rel::PLTRel { offset: offset, sym: None }),
            X86_64Rel::Copy { sym: Some(Ok(name)) } =>
                Ok(X86_64Rel::Copy { sym: Some(name) }),
            X86_64Rel::Copy { sym: Some(Err(err)) } => Err(err),
            X86_64Rel::Copy { sym: None } =>
                Ok(X86_64Rel::Copy { sym: None }),
            X86_64Rel::GlobalData { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::GlobalData { offset: offset, sym: Some(name) }),
            X86_64Rel::GlobalData { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::GlobalData { sym: None, offset } =>
                Ok(X86_64Rel::GlobalData { offset: offset, sym: None }),
            X86_64Rel::JumpSlot { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::JumpSlot { offset: offset, sym: Some(name) }),
            X86_64Rel::JumpSlot { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::JumpSlot { sym: None, offset } =>
                Ok(X86_64Rel::JumpSlot { offset: offset, sym: None }),
            X86_64Rel::Relative { offset } =>
                Ok(X86_64Rel::Relative { offset: offset }),
            X86_64Rel::GOTPC { offset } =>
                Ok(X86_64Rel::GOTPC { offset: offset }),
            X86_64Rel::Abs32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::Abs32 { offset: offset, sym: Some(name) }),
            X86_64Rel::Abs32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::Abs32 { sym: None, offset } =>
                Ok(X86_64Rel::Abs32 { offset: offset, sym: None }),
            X86_64Rel::Abs32Signed { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::Abs32Signed { offset: offset, sym: Some(name) }),
            X86_64Rel::Abs32Signed { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::Abs32Signed { sym: None, offset } =>
                Ok(X86_64Rel::Abs32Signed { offset: offset, sym: None }),
            X86_64Rel::Abs16 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::Abs16 { offset: offset, sym: Some(name) }),
            X86_64Rel::Abs16 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::Abs16 { sym: None, offset } =>
                Ok(X86_64Rel::Abs16 { offset: offset, sym: None }),
            X86_64Rel::PC16 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::PC16 { offset: offset, sym: Some(name) }),
            X86_64Rel::PC16 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::PC16 { sym: None, offset } =>
                Ok(X86_64Rel::PC16 { offset: offset, sym: None }),
            X86_64Rel::Abs8 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::Abs8 { offset: offset, sym: Some(name) }),
            X86_64Rel::Abs8 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::Abs8 { sym: None, offset } =>
                Ok(X86_64Rel::Abs8 { offset: offset, sym: None }),
            X86_64Rel::PC8 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::PC8 { offset: offset, sym: Some(name) }),
            X86_64Rel::PC8 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::PC8 { sym: None, offset } =>
                Ok(X86_64Rel::PC8 { offset: offset, sym: None }),
            X86_64Rel::DTPMod { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::DTPMod { offset: offset, sym: Some(name) }),
            X86_64Rel::DTPMod { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::DTPMod { sym: None, offset } =>
                Ok(X86_64Rel::DTPMod { offset: offset, sym: None }),
            X86_64Rel::DTPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::DTPOff { offset: offset, sym: Some(name) }),
            X86_64Rel::DTPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::DTPOff { sym: None, offset } =>
                Ok(X86_64Rel::DTPOff { offset: offset, sym: None }),
            X86_64Rel::TPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::TPOff { offset: offset, sym: Some(name) }),
            X86_64Rel::TPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::TPOff { sym: None, offset } =>
                Ok(X86_64Rel::TPOff { offset: offset, sym: None }),
            X86_64Rel::TLSGD { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::TLSGD { offset: offset, sym: Some(name) }),
            X86_64Rel::TLSGD { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::TLSGD { sym: None, offset } =>
                Ok(X86_64Rel::TLSGD { offset: offset, sym: None }),
            X86_64Rel::TLSLD { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::TLSLD { offset: offset, sym: Some(name) }),
            X86_64Rel::TLSLD { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::TLSLD { sym: None, offset } =>
                Ok(X86_64Rel::TLSLD { offset: offset, sym: None }),
            X86_64Rel::DTPOff32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::DTPOff32 { offset: offset, sym: Some(name) }),
            X86_64Rel::DTPOff32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::DTPOff32 { sym: None, offset } =>
                Ok(X86_64Rel::DTPOff32 { offset: offset, sym: None }),
            X86_64Rel::GOTTPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::GOTTPOff { offset: offset, sym: Some(name) }),
            X86_64Rel::GOTTPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::GOTTPOff { sym: None, offset } =>
                Ok(X86_64Rel::GOTTPOff { offset: offset, sym: None }),
            X86_64Rel::TPOff32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::TPOff32 { offset: offset, sym: Some(name) }),
            X86_64Rel::TPOff32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::TPOff32 { sym: None, offset } =>
                Ok(X86_64Rel::TPOff32 { offset: offset, sym: None }),
            X86_64Rel::PC64 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::PC64 { offset: offset, sym: Some(name) }),
            X86_64Rel::PC64 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::PC64 { sym: None, offset } =>
                Ok(X86_64Rel::PC64 { offset: offset, sym: None }),
            X86_64Rel::GOTRel { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::GOTRel { offset: offset, sym: Some(name) }),
            X86_64Rel::GOTRel { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::GOTRel { sym: None, offset } =>
                Ok(X86_64Rel::GOTRel { offset: offset, sym: None }),
            X86_64Rel::GOTPC32 { offset } =>
                Ok(X86_64Rel::GOTPC32 { offset: offset }),
            X86_64Rel::Size32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::Size32 { offset: offset, sym: Some(name) }),
            X86_64Rel::Size32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::Size32 { sym: None, offset } =>
                Ok(X86_64Rel::Size32 { offset: offset, sym: None }),
            X86_64Rel::Size { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rel::Size { offset: offset, sym: Some(name) }),
            X86_64Rel::Size { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rel::Size { sym: None, offset } =>
                Ok(X86_64Rel::Size { offset: offset, sym: None })
        }
    }
}

impl<'a> TryFrom<X86_64RelaStrData<'a>> for X86_64RelaStr<'a> {
    type Error = &'a [u8];

    #[inline]
    fn try_from(reloc: X86_64RelaStrData<'a>) ->
        Result<X86_64RelaStr<'a>, Self::Error> {
        match reloc {
            X86_64Rela::None => Ok(X86_64Rela::None),
            X86_64Rela::Abs64 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::Abs64 { offset: offset, sym: Some(name),
                                        addend: addend }),
            X86_64Rela::Abs64 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::Abs64 { sym: None, offset, addend } =>
                Ok(X86_64Rela::Abs64 { offset: offset, sym: None,
                                        addend: addend }),
            X86_64Rela::PC32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::PC32 { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Rela::PC32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::PC32 { sym: None, offset, addend } =>
                Ok(X86_64Rela::PC32 { offset: offset, sym: None,
                                       addend: addend }),
            X86_64Rela::GOT32 { offset, addend } =>
                Ok(X86_64Rela::GOT32 { offset: offset, addend: addend }),
            X86_64Rela::PLTRel { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::PLTRel { offset: offset, sym: Some(name),
                                         addend: addend }),
            X86_64Rela::PLTRel { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::PLTRel { sym: None, offset, addend } =>
                Ok(X86_64Rela::PLTRel { offset: offset, sym: None,
                                         addend: addend }),
            X86_64Rela::Copy { sym: Some(Ok(name)) } =>
                Ok(X86_64Rela::Copy { sym: Some(name) }),
            X86_64Rela::Copy { sym: Some(Err(err)) } => Err(err),
            X86_64Rela::Copy { sym: None } =>
                Ok(X86_64Rela::Copy { sym: None }),
            X86_64Rela::GlobalData { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::GlobalData { offset: offset, sym: Some(name) }),
            X86_64Rela::GlobalData { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::GlobalData { sym: None, offset } =>
                Ok(X86_64Rela::GlobalData { offset: offset, sym: None }),
            X86_64Rela::JumpSlot { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::JumpSlot { offset: offset, sym: Some(name) }),
            X86_64Rela::JumpSlot { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::JumpSlot { sym: None, offset } =>
                Ok(X86_64Rela::JumpSlot { offset: offset, sym: None }),
            X86_64Rela::Relative { offset, addend } =>
                Ok(X86_64Rela::Relative { offset: offset, addend: addend }),
            X86_64Rela::GOTPC { offset, addend } =>
                Ok(X86_64Rela::GOTPC { offset: offset, addend: addend }),
            X86_64Rela::Abs32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::Abs32 { offset: offset, sym: Some(name),
                                        addend: addend }),
            X86_64Rela::Abs32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::Abs32 { sym: None, offset, addend } =>
                Ok(X86_64Rela::Abs32 { offset: offset, sym: None,
                                        addend: addend }),
            X86_64Rela::Abs32Signed { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::Abs32Signed { offset: offset, sym: Some(name),
                                              addend: addend }),
            X86_64Rela::Abs32Signed { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::Abs32Signed { sym: None, offset, addend } =>
                Ok(X86_64Rela::Abs32Signed { offset: offset, sym: None,
                                              addend: addend }),
            X86_64Rela::Abs16 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::Abs16 { offset: offset, sym: Some(name),
                                        addend: addend }),
            X86_64Rela::Abs16 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::Abs16 { sym: None, offset, addend } =>
                Ok(X86_64Rela::Abs16 { offset: offset, sym: None,
                                        addend: addend }),
            X86_64Rela::PC16 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::PC16 { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Rela::PC16 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::PC16 { sym: None, offset, addend } =>
                Ok(X86_64Rela::PC16 { offset: offset, sym: None,
                                       addend: addend }),
            X86_64Rela::Abs8 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::Abs8 { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Rela::Abs8 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::Abs8 { sym: None, offset, addend } =>
                Ok(X86_64Rela::Abs8 { offset: offset, sym: None,
                                       addend: addend }),
            X86_64Rela::PC8 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::PC8 { offset: offset, sym: Some(name),
                                      addend: addend }),
            X86_64Rela::PC8 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::PC8 { sym: None, offset, addend } =>
                Ok(X86_64Rela::PC8 { offset: offset, sym: None,
                                      addend: addend }),
            X86_64Rela::DTPMod { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::DTPMod { offset: offset, sym: Some(name) }),
            X86_64Rela::DTPMod { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::DTPMod { sym: None, offset } =>
                Ok(X86_64Rela::DTPMod { offset: offset, sym: None }),
            X86_64Rela::DTPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::DTPOff { offset: offset, sym: Some(name) }),
            X86_64Rela::DTPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::DTPOff { sym: None, offset } =>
                Ok(X86_64Rela::DTPOff { offset: offset, sym: None }),
            X86_64Rela::TPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::TPOff { offset: offset, sym: Some(name) }),
            X86_64Rela::TPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::TPOff { sym: None, offset } =>
                Ok(X86_64Rela::TPOff { offset: offset, sym: None }),
            X86_64Rela::TLSGD { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::TLSGD { offset: offset, sym: Some(name) }),
            X86_64Rela::TLSGD { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::TLSGD { sym: None, offset } =>
                Ok(X86_64Rela::TLSGD { offset: offset, sym: None }),
            X86_64Rela::TLSLD { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::TLSLD { offset: offset, sym: Some(name) }),
            X86_64Rela::TLSLD { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::TLSLD { sym: None, offset } =>
                Ok(X86_64Rela::TLSLD { offset: offset, sym: None }),
            X86_64Rela::DTPOff32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::DTPOff32 { offset: offset, sym: Some(name) }),
            X86_64Rela::DTPOff32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::DTPOff32 { sym: None, offset } =>
                Ok(X86_64Rela::DTPOff32 { offset: offset, sym: None }),
            X86_64Rela::GOTTPOff { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::GOTTPOff { offset: offset, sym: Some(name) }),
            X86_64Rela::GOTTPOff { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::GOTTPOff { sym: None, offset } =>
                Ok(X86_64Rela::GOTTPOff { offset: offset, sym: None }),
            X86_64Rela::TPOff32 { sym: Some(Ok(name)), offset } =>
                Ok(X86_64Rela::TPOff32 { offset: offset, sym: Some(name) }),
            X86_64Rela::TPOff32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::TPOff32 { sym: None, offset } =>
                Ok(X86_64Rela::TPOff32 { offset: offset, sym: None }),
            X86_64Rela::PC64 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::PC64 { offset: offset, sym: Some(name),
                                       addend: addend }),
            X86_64Rela::PC64 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::PC64 { sym: None, offset, addend } =>
                Ok(X86_64Rela::PC64 { offset: offset, sym: None,
                                       addend: addend }),
            X86_64Rela::GOTRel { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::GOTRel { offset: offset, sym: Some(name),
                                         addend: addend }),
            X86_64Rela::GOTRel { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::GOTRel { sym: None, offset, addend } =>
                Ok(X86_64Rela::GOTRel { offset: offset, sym: None,
                                         addend: addend }),
            X86_64Rela::GOTPC32 { offset, addend } =>
                Ok(X86_64Rela::GOTPC32 { offset: offset, addend: addend }),
            X86_64Rela::Size32 { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::Size32 { offset: offset, sym: Some(name),
                                         addend: addend }),
            X86_64Rela::Size32 { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::Size32 { sym: None, offset, addend } =>
                Ok(X86_64Rela::Size32 { offset: offset, sym: None,
                                        addend: addend }),
            X86_64Rela::Size { sym: Some(Ok(name)), offset, addend } =>
                Ok(X86_64Rela::Size { offset: offset, sym: Some(name),
                                      addend: addend }),
            X86_64Rela::Size { sym: Some(Err(err)), .. } => Err(err),
            X86_64Rela::Size { sym: None, offset, addend } =>
                Ok(X86_64Rela::Size { offset: offset, sym: None,
                                      addend: addend })
        }
    }
}

impl<'a> From<X86_64RelStrSym<'a>> for X86_64RelStr<'a> {
    #[inline]
    fn from(reloc: X86_64RelStrSym<'a>) -> X86_64RelStr<'a> {
        match reloc {
            X86_64Rel::None => X86_64Rel::None,
            X86_64Rel::Abs64 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs64 { offset: offset, sym: name },
            X86_64Rel::PC32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PC32 { offset: offset, sym: name },
            X86_64Rel::GOT32 { offset } =>
                X86_64Rel::GOT32 { offset: offset },
            X86_64Rel::PLTRel { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PLTRel { offset: offset, sym: name },
            X86_64Rel::Copy { sym: SymData { name, .. } } =>
                X86_64Rel::Copy { sym: name },
            X86_64Rel::GlobalData { sym: SymData { name, .. }, offset } =>
                X86_64Rel::GlobalData { offset: offset, sym: name },
            X86_64Rel::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86_64Rel::JumpSlot { offset: offset, sym: name },
            X86_64Rel::Relative { offset } =>
                X86_64Rel::Relative { offset: offset },
            X86_64Rel::GOTPC { offset } =>
                X86_64Rel::GOTPC { offset: offset },
            X86_64Rel::Abs32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs32 { offset: offset, sym: name },
            X86_64Rel::Abs32Signed { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs32Signed { offset: offset, sym: name },
            X86_64Rel::Abs16 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs16 { offset: offset, sym: name },
            X86_64Rel::PC16 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PC16 { offset: offset, sym: name },
            X86_64Rel::Abs8 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Abs8 { offset: offset, sym: name },
            X86_64Rel::PC8 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PC8 { offset: offset, sym: name },
            X86_64Rel::DTPMod { sym: SymData { name, .. }, offset } =>
                X86_64Rel::DTPMod { offset: offset, sym: name },
            X86_64Rel::DTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rel::DTPOff { offset: offset, sym: name },
            X86_64Rel::TPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rel::TPOff { offset: offset, sym: name },
            X86_64Rel::TLSGD { sym: SymData { name, .. }, offset } =>
                X86_64Rel::TLSGD { offset: offset, sym: name },
            X86_64Rel::TLSLD { sym: SymData { name, .. }, offset } =>
                X86_64Rel::TLSLD { offset: offset, sym: name },
            X86_64Rel::DTPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::DTPOff32 { offset: offset, sym: name },
            X86_64Rel::GOTTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rel::GOTTPOff { offset: offset, sym: name },
            X86_64Rel::TPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::TPOff32 { offset: offset, sym: name },
            X86_64Rel::PC64 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::PC64 { offset: offset, sym: name },
            X86_64Rel::GOTRel { sym: SymData { name, .. }, offset } =>
                X86_64Rel::GOTRel { offset: offset, sym: name },
            X86_64Rel::GOTPC32 { offset } =>
                X86_64Rel::GOTPC32 { offset: offset },
            X86_64Rel::Size32 { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Size32 { offset: offset, sym: name },
            X86_64Rel::Size { sym: SymData { name, .. }, offset } =>
                X86_64Rel::Size { offset: offset, sym: name }
        }
    }
}

impl<'a> From<X86_64RelaStrSym<'a>> for X86_64RelaStr<'a> {
    #[inline]
    fn from(reloc: X86_64RelaStrSym<'a>) -> X86_64RelaStr<'a> {
        match reloc {
            X86_64Rela::None => X86_64Rela::None,
            X86_64Rela::Abs64 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Abs64 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Rela::PC32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PC32 { offset: offset, sym: name, addend: addend },
            X86_64Rela::GOT32 { offset, addend } =>
                X86_64Rela::GOT32 { offset: offset, addend: addend },
            X86_64Rela::PLTRel { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PLTRel { offset: offset, sym: name,
                                      addend: addend },
            X86_64Rela::Copy { sym: SymData { name, .. } } =>
                X86_64Rela::Copy { sym: name },
            X86_64Rela::GlobalData { sym: SymData { name, .. }, offset } =>
                X86_64Rela::GlobalData { offset: offset, sym: name },
            X86_64Rela::JumpSlot { sym: SymData { name, .. }, offset } =>
                X86_64Rela::JumpSlot { offset: offset, sym: name },
            X86_64Rela::Relative { offset, addend } =>
                X86_64Rela::Relative { offset: offset, addend: addend },
            X86_64Rela::GOTPC { offset, addend } =>
                X86_64Rela::GOTPC { offset: offset, addend: addend },
            X86_64Rela::Abs32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Abs32 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Rela::Abs32Signed { sym: SymData { name, .. }, offset,
                                       addend } =>
                X86_64Rela::Abs32Signed { offset: offset, sym: name,
                                           addend: addend },
            X86_64Rela::Abs16 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Abs16 { offset: offset, sym: name,
                                     addend: addend },
            X86_64Rela::PC16 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PC16 { offset: offset, sym: name, addend: addend },
            X86_64Rela::Abs8 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Abs8 { offset: offset, sym: name, addend: addend },
            X86_64Rela::PC8 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PC8 { offset: offset, sym: name, addend: addend },
            X86_64Rela::DTPMod { sym: SymData { name, .. }, offset } =>
                X86_64Rela::DTPMod { offset: offset, sym: name },
            X86_64Rela::DTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rela::DTPOff { offset: offset, sym: name },
            X86_64Rela::TPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rela::TPOff { offset: offset, sym: name },
            X86_64Rela::TLSGD { sym: SymData { name, .. }, offset } =>
                X86_64Rela::TLSGD { offset: offset, sym: name },
            X86_64Rela::TLSLD { sym: SymData { name, .. }, offset } =>
                X86_64Rela::TLSLD { offset: offset, sym: name },
            X86_64Rela::DTPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Rela::DTPOff32 { offset: offset, sym: name },
            X86_64Rela::GOTTPOff { sym: SymData { name, .. }, offset } =>
                X86_64Rela::GOTTPOff { offset: offset, sym: name },
            X86_64Rela::TPOff32 { sym: SymData { name, .. }, offset } =>
                X86_64Rela::TPOff32 { offset: offset, sym: name },
            X86_64Rela::PC64 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::PC64 { offset: offset, sym: name, addend: addend },
            X86_64Rela::GOTRel { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::GOTRel { offset: offset, sym: name,
                                      addend: addend },
            X86_64Rela::GOTPC32 { offset, addend } =>
                X86_64Rela::GOTPC32 { offset: offset, addend: addend },
            X86_64Rela::Size32 { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Size32 { offset: offset, sym: name,
                                      addend: addend },
            X86_64Rela::Size { sym: SymData { name, .. }, offset, addend } =>
                X86_64Rela::Size { offset: offset, sym: name, addend: addend }
        }
    }
}
