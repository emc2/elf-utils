use byteorder::BigEndian;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::LowerHex;
use core::hash::Hash;
use core::marker::PhantomData;
use core::ops::Add;
use core::ops::BitAnd;
use core::ops::Mul;
use crate::prog_hdr::ProgHdrs;
use crate::prog_hdr::ProgHdrsError;
use crate::prog_hdr::ProgHdrOffsets;
use crate::section_hdr::SectionHdrs;
use crate::section_hdr::SectionHdrOffsets;
use crate::section_hdr::SectionHdrsError;

const ELF_MAGIC: [u8; 4] = [ 0x7f, 'E' as u8, 'L' as u8, 'F' as u8 ];
const ELF_CLASS_OFFSET: usize = 0x04;
const ELF_ENDIAN_OFFSET: usize = 0x05;
const ELF_VERSION_OFFSET: usize = 0x06;
const ELF_ABI_OFFSET: usize = 0x07;
const ELF_ABI_VERSION_OFFSET: usize = 0x08;
const ELF_IDENT_END: usize = 0x10;

const ELF_VERSION: u8 = 1;

/// Trait for ELF byte orderings.
pub trait ElfByteOrder: ByteOrder {
    /// Code identifying the byte order.
    const BYTE_ORDER_CODE: u8;
}

/// Trait defining ELF sizes and types.
pub trait ElfClass: Copy + PartialEq + PartialOrd {
    /// A half-word.
    type Half: Copy + Debug + Display + Eq + From<u8> + From<u16> + Hash +
               Into<u16> + LowerHex + Ord + PartialEq + PartialOrd +
               TryInto<usize>;
    /// A full-word.
    type Word: BitAnd<Output = Self::Word> + Copy + Debug + Display + Eq +
               From<u8> + From<u32> + Hash + Into<u32> + LowerHex +
               Ord + PartialEq + PartialOrd + TryInto<usize>;
    /// A memory address.
    type Addr: Copy + Debug + Display + Eq + From<u8> + Hash +
               LowerHex + PartialEq + PartialOrd + TryFrom<usize> +
               TryInto<usize>;
    /// An offset (into the file or memory).
    type Offset: Add<Output = Self::Offset> + BitAnd<Output = Self::Offset> +
                 Copy + Debug + Display + Eq + From<u8> + Hash + LowerHex +
                 Mul<Output = Self::Offset> + Ord + PartialEq + PartialOrd +
                 TryFrom<usize> + TryInto<usize>;
    /// An addend (a signed offset).
    type Addend: Copy + Debug + Display + Eq + From<u8> + Hash + LowerHex +
                 Ord + PartialEq + PartialOrd + TryInto<usize>;

    /// Size of a half-word.
    const HALF_SIZE: usize;
    /// Size of a full word.
    const WORD_SIZE: usize;
    /// Alignment of a word.
    const WORD_ALIGN: Self::Offset;
    /// Size of a memory address.
    const ADDR_SIZE: usize;
    /// Alignment of an address.
    const ADDR_ALIGN: Self::Offset;
    /// Size of an offset.
    const OFFSET_SIZE: usize;
    /// Alignment of an offset.
    const OFFSET_ALIGN: Self::Offset;
    /// Size of an addend.
    const ADDEND_SIZE: usize;

    /// The type code for this ELF class.
    const TYPE_CODE: u8;

    /// Read a half-word value.
    fn read_half<B: ByteOrder>(data: &[u8], byteorder: PhantomData<B>) ->
        Self::Half;
    /// Read a word value.
    fn read_word<B: ByteOrder>(data: &[u8], byteorder: PhantomData<B>) ->
        Self::Word;
    /// Read an address value.
    fn read_addr<B: ByteOrder>(data: &[u8], byteorder: PhantomData<B>) ->
        Self::Addr;
    /// Read an offset value.
    fn read_offset<B: ByteOrder>(data: &[u8], byteorder: PhantomData<B>) ->
        Self::Offset;
    /// Read an addend value.
    fn read_addend<B: ByteOrder>(data: &[u8], byteorder: PhantomData<B>) ->
        Self::Addend;

    /// Write a half-word value.
    fn write_half<B: ByteOrder>(data: &mut [u8], val: Self::Half,
                                byteorder: PhantomData<B>);
    /// Write a word value.
    fn write_word<B: ByteOrder>(data: &mut [u8], val: Self::Word,
                                byteorder: PhantomData<B>);
    /// Write an address value.
    fn write_addr<B: ByteOrder>(data: &mut [u8], val: Self::Addr,
                                byteorder: PhantomData<B>);
    /// Write an offset value.
    fn write_offset<B: ByteOrder>(data: &mut [u8], val: Self::Offset,
                                  byteorder: PhantomData<B>);
    /// Write an addend value.
    fn write_addend<B: ByteOrder>(data: &mut [u8], val: Self::Addend,
                                  byteorder: PhantomData<B>);
}

/// Trait for ELF header offsets for `Class`.  This defines the
/// offsets and sizes of all fields in the binary ELF format.
pub trait ElfHdrOffsets: ElfClass + ProgHdrOffsets + SectionHdrOffsets {
    /// Start of the ELF header type field.
    const E_TYPE_START: usize = ELF_IDENT_END;
    /// Size of the ELF header type field.
    const E_TYPE_SIZE: usize;
    /// End of the ELF header type field.
    const E_TYPE_END: usize = Self::E_TYPE_START + Self::E_TYPE_SIZE;

    /// Start of the ELF header machine type code.
    const E_MACHINE_START: usize = Self::E_TYPE_END;
    /// Size of the ELF header machine type code.
    const E_MACHINE_SIZE: usize;
    /// End of the ELF header machine type code.
    const E_MACHINE_END: usize = Self::E_MACHINE_START + Self::E_MACHINE_SIZE;

    /// Start of the ELF header version field.
    const E_VERSION_START: usize = Self::E_MACHINE_END;
    /// Size of the ELF header version field.
    const E_VERSION_SIZE: usize;
    /// End of the ELF header version field.
    const E_VERSION_END: usize = Self::E_VERSION_START + Self::E_VERSION_SIZE;

    /// Start of the ELF header start address field.
    const E_ENTRY_START: usize = Self::E_VERSION_END;
    /// Size of the ELF header start address field.
    const E_ENTRY_SIZE: usize = Self::ADDR_SIZE;
    /// End of the ELF header start address field.
    const E_ENTRY_END: usize = Self::E_ENTRY_START + Self::E_ENTRY_SIZE;

    /// Start of the ELF header program header offset field.
    const E_PHOFF_START: usize = Self::E_ENTRY_END;
    /// Size of the ELF header program header offset field.
    const E_PHOFF_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF header program header offset field.
    const E_PHOFF_END: usize = Self::E_PHOFF_START + Self::E_PHOFF_SIZE;

    /// Start of the ELF header section header offset field.
    const E_SHOFF_START: usize = Self::E_PHOFF_END;
    /// Size of the ELF header section header offset field.
    const E_SHOFF_SIZE: usize = Self::OFFSET_SIZE;
    /// End of the ELF header section header offset field.
    const E_SHOFF_END: usize = Self::E_SHOFF_START + Self::E_SHOFF_SIZE;

    /// Start of the ELF header flags field.
    const E_FLAGS_START: usize = Self::E_SHOFF_END;
    /// Size of the ELF header flags field.
    const E_FLAGS_SIZE: usize;
    /// End of the ELF header flags field.
    const E_FLAGS_END: usize = Self::E_FLAGS_START + Self::E_FLAGS_SIZE;

    /// Start of the ELF header size field.
    const E_EHSIZE_START: usize = Self::E_FLAGS_END;
    /// Size of the ELF header size field.
    const E_EHSIZE_SIZE: usize;
    /// End of the ELF header size field.
    const E_EHSIZE_END: usize = Self::E_EHSIZE_START + Self::E_EHSIZE_SIZE;

    /// Start of the ELF header program header entry size field.
    const E_PHENTSIZE_START: usize = Self::E_EHSIZE_END;
    /// Size of the ELF header program header entry size field.
    const E_PHENTSIZE_SIZE: usize;
    /// End of the ELF header program header entry size field.
    const E_PHENTSIZE_END: usize = Self::E_PHENTSIZE_START +
                                   Self::E_PHENTSIZE_SIZE;

    /// Start of the ELF header program header entry count field.
    const E_PHNUM_START: usize = Self::E_PHENTSIZE_END;
    /// Size of the ELF header program header entry count field.
    const E_PHNUM_SIZE: usize;
    /// End of the ELF header program header entry count field.
    const E_PHNUM_END: usize = Self::E_PHNUM_START + Self::E_PHNUM_SIZE;

    /// Start of the ELF header section header entry size field.
    const E_SHENTSIZE_START: usize = Self::E_PHNUM_END;
    /// Size of the ELF header section header entry size field.
    const E_SHENTSIZE_SIZE: usize;
    /// End of the ELF header section header entry size field.
    const E_SHENTSIZE_END: usize = Self::E_SHENTSIZE_START +
                                   Self::E_SHENTSIZE_SIZE;

    /// Start of the ELF header section header entry count field.
    const E_SHNUM_START: usize = Self::E_SHENTSIZE_END;
    /// Size of the ELF header section header entry count field.
    const E_SHNUM_SIZE: usize;
    /// End of the ELF header section header entry count field.
    const E_SHNUM_END: usize = Self::E_SHNUM_START + Self::E_SHNUM_SIZE;

    /// Start of the ELF header section header string table index field.
    const E_SHSTRTAB_START: usize = Self::E_SHNUM_END;
    /// Size of the ELF header section header string table index field.
    const E_SHSTRTAB_SIZE: usize;
    /// End of the ELF header section header string table index field.
    const E_SHSTRTAB_END: usize = Self::E_SHSTRTAB_START +
                                  Self::E_SHSTRTAB_SIZE;

    /// Size of an ELF header.
    const ELF_HDR_SIZE: usize = Self::E_SHSTRTAB_END;
    /// Size of an ELF header as a `Half`.
    const ELF_HDR_SIZE_HALF: Self::Half;
}

/// Trait for types that can be converted using the entire ELF data.
pub trait WithElfData<'a> {
    /// Result of coversion using the ELF data.
    type Result;
    /// Errors that can occur in conversion.
    type Error;

    /// Covert this type using the entire ELF data, represented in `data`.
    fn with_elf_data(self, data: &'a [u8]) -> Result<Self::Result, Self::Error>;
}

/// Sizes for 32-bit ELF data.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Elf32;

/// Sizes for 64-bit ELF data.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Elf64;

/// In-place read-only ELF header.
///
/// An ELF header table is the top-level descriptor for an ELF file.
///
/// An `Elf` is essentially a 'handle' for raw ELF data.  It provides
/// a reference to the program header table and section header table.
///
/// An `Elf` can be created from raw data using the
/// [TryFrom](core::convert::TryFrom) instance.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use core::marker::PhantomData;
/// use elf_utils::Elf;
/// use elf_utils::Elf64;
/// use elf_utils::ElfArch;
/// use elf_utils::ElfABI;
/// use elf_utils::ElfClass;
/// use elf_utils::ElfError;
/// use elf_utils::ElfHdrData;
/// use elf_utils::ElfHdrDataError;
/// use elf_utils::ElfHdrDataRaw;
/// use elf_utils::ElfKind;
/// use elf_utils::ElfTable;
///
/// const ELF64_EXEC_ELF_HDR: [u8; 64] = [
///     0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x09,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
///     0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
///     0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
/// ];
///
/// let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
///     Elf::try_from(&ELF64_EXEC_ELF_HDR[0..]);
///
/// assert!(elf.is_ok());
///
/// let hdr: ElfHdrDataRaw<LittleEndian, Elf64> =
///     elf.unwrap().try_into().unwrap();
///
/// assert_eq!(hdr, ElfHdrData { byteorder: PhantomData, abi: ElfABI::FreeBSD,
///                              abi_version: 0, kind: ElfKind::Executable,
///                              arch: ElfArch::X86_64,  entry: 0x20b940,
///                              flags: 0, section_hdr_strtab: 30,
///                              prog_hdrs: Some(ElfTable { offset: 64,
///                                                         num_ents: 11 }),
///                              section_hdrs: ElfTable { offset: 162968,
///                                                       num_ents: 31 } });
/// ```
pub struct Elf<'a, B: ByteOrder, Offsets: ElfHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    /// The binary data.  There MUST be an ELF header here.
    data: &'a [u8]
}

pub struct ElfMut<'a, B: ByteOrder, Offsets: ElfHdrOffsets> {
    byteorder: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    /// The binary data.  There MUST be an ELF header here.
    data: &'a mut [u8]
}

/// ELF ABI codes.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum ElfABI {
    /// System V.
    SysV,
    /// Hewlett-Packard HP-UX.
    HPUX,
    /// NetBSD.
    NetBSD,
    /// Linux, historically GNU.
    Linux,
    /// GNU HURD.
    Hurd,
    /// 86 Open Common IA-32 ABI
    Open86,
    /// Sun Solaris
    Solaris,
    /// IBM AIX.
    AIX,
    /// IRIX
    IRIX,
    /// FreeBSD
    FreeBSD,
    /// Compaq True64 UNIX
    Tru64,
    /// Novell Modesto.
    Modesto,
    /// OpenBSD.
    OpenBSD,
    /// Open VMS.
    OpenVMS,
    /// Hewlett-Packard Non-Stop Kernel.
    NonStop,
    /// Amiga Research OS.
    AROS,
    /// Fenix OS.
    FenixOS,
    /// Nuxi CloudABI.
    CloudABI,
    /// Stratus Technologies OpenVOS.
    OpenVOS,
    /// ARM ABI
    ARM,
    /// Standalone Executable
    Standalone,
    /// Other ABIs.
    Other(u8),
}

/// ELF Architecture Codes.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum ElfArch {
    /// No machine.
    None,
    /// AT&T We 32100
    We32100,
    /// Sun SPARC.
    SPARC,
    /// Intel 386.
    I386,
    /// Motorola 68000.
    M68K,
    /// Motorola 88000.
    M88K,
    /// Intel MCU.
    IMCU,
    /// Intel 80860.
    I860,
    /// MIPS I.
    MIPS,
    /// IBM System/370.
    System370,
    /// MIPS RS4000 Big Endian.
    MIPS_RS4000_BE,
    /// Hewlett-Packard PA-RISC
    PARISC,
    /// Fujitsu VPP5500
    VPP5500,
    /// Sun Enhanced SPARC.
    SPARC32Plus,
    /// Intel 80960.
    I960,
    /// IBM PowerPC.
    PowerPC,
    /// IBM PowerPC 64.
    PowerPC64,
    /// IBM System/390.
    System390,
    /// IBM SPU.
    SPU,
    /// NEC V800,
    V800,
    /// Fujitsu FR20.
    FR20,
    /// TRW RH-32.
    RH32,
    /// Motorola RCE.
    RCE,
    /// 32-bit ARM.
    AArch32,
    /// DEC Alpha.
    Alpha,
    /// Hitachi Super H.
    SuperH,
    /// Sun SPARC Version 9.
    SPARCv9,
    /// Siemens TriCore.
    TriCore,
    /// Argonaut Technologies Argonaut Risc Core.
    ARC,
    /// Hitachi H8/300
    H8_300,
    /// Hitachi H8/300H
    H8_300_H,
    /// Hitachi H8S
    H8S,
    /// Hitachi H8/500
    H8_500,
    /// Intel IA-64.
    IA64,
    /// Stanford MIPS-X.
    MIPS_X,
    /// Motorola ColdFire.
    ColdFire,
    /// Motorola M68HC12.
    M68HC12,
    /// Fujitsu MultiMedia Accelerator.
    MMA,
    /// Siemens PCP
    PCP,
    /// Sony nCPU.
    NCPU,
    /// Denso NDR1
    NDR1,
    /// Motorola Star*Core.
    StarCore,
    /// Toyota ME16.
    ME16,
    /// STMicroelectronics ST100.
    ST100,
    /// Advanced Logic Corporation TinyJ.
    TinyJ,
    /// AMD x86-64.
    X86_64,
    /// Sony DSP.
    DSP,
    /// DEC PDP-10.
    PDP10,
    /// DEC PDP-11.
    PDP11,
    /// Siemens FX66 Microcontroller.
    FX66,
    /// STMicroelectronics ST9+ Microcontroller.
    ST9Plus,
    /// STMicroelectronics ST7 Microcontroller.
    ST7,
    /// Motorola MC68HC16 Microcontroller.
    MC68HC16,
    /// Motorola MC68HC11 Microcontroller.
    MC68HC11,
    /// Motorola MC68HC08 Microcontroller.
    MC68HC08,
    /// Motorola MC68HC05 Microcontroller.
    MC68HC05,
    /// Silicon Graphics SVx.
    SVX,
    /// STMicroelectronics ST19 Microcontroller.
    ST19,
    /// Digital VAX.
    VAX,
    /// Axis Communications CRIS Processor.
    CRIS,
    /// Infineon Technologies Javelin Processor.
    Javelin,
    /// Element 14 DSP processor.
    Firepath,
    /// LSI Logic DSP processor.
    ZSP,
    /// Donald Knuth's MMIX Architecture.
    MMIX,
    /// Harvard University machine-independent object files.
    HUMIO,
    /// SiTera Prism.
    Prism,
    /// Amtel AVR microcontroller.
    AVR,
    /// Fujitsu FR30.
    FR30,
    /// Mitsubishi D10V.
    D10V,
    /// Mitsubishi D30V.
    D30V,
    /// NEC v850,
    V850,
    /// Mitsubishi M32R.
    M32R,
    /// Matsushita MN10300.
    MN10300,
    /// Matsushita MN10200.
    MN10200,
    /// picoJava.
    PicoJava,
    /// OpenRISC.
    OpenRISC,
    /// ARC International ARCompact.
    ARCompact,
    /// Tensilica Xtensa.
    Xtensa,
    /// Alphamosaic VideoCore.
    VideoCore,
    /// Thompson Media General Purpose Processor.
    GPP,
    /// National Semiconductor 32000.
    NS32000,
    /// Tenor Network TPC.
    TPC,
    /// Trebia SNP 1000.
    SNP1000,
    /// STMicroelectronics ST200.
    ST200,
    /// Ubicom IP2xxx microcontroller family.
    IP2k,
    /// MAX Processor.
    MAX,
    /// National Semiconductor CompactRISC.
    CompactRISC,
    /// Fujitsu F2MC16.
    F2MC16,
    /// Texas Instruments MSP430 microcontroller.
    MSP430,
    /// Analog Devices Blackfin DSP processor.
    Blackfin,
    /// Seiko Epson S1C33 family.
    S1C33,
    /// Sharp embedded processor.
    Sharp,
    /// Arca RISC processor.
    Arca,
    /// PKU-Unity/Peking University Unicore.
    Unicore,
    /// eXcess embedded CPU.
    EXcess,
    /// Icera Semiconductor Deep eXecution Processor.
    DXP,
    /// Altera NiosII soft-core processor.
    Nios2,
    /// National Semiconductor CompactRISC CRX.
    CRX,
    /// Motorola XGATE.
    XGATE,
    /// Infineon C16x.
    C16x,
    /// Renesas M16C series.
    M16C,
    /// Microchip technology dsPIC30F DSP controller.
    DSPIC30F,
    /// Freescale Communication Engine RISC core.
    FCE,
    /// Renesas M32C series.
    M32C,
    /// Altium TSK3000.
    TSK3000,
    /// Freescale RS08.
    RS08,
    /// Analog Devices SHARC DSP family.
    SHARC,
    /// Cyan Technology eCOG2.
    ECOG2,
    /// Sunplus S+core7.
    SPlusCore7,
    /// New Japan Radio 24-bit DSP processor.
    DSP24,
    /// Broadcom VideoCoreIII.
    VideoCore3,
    /// Lattice FPGA RISC processor.
    Lattice,
    /// Seiko Epson C17 family.
    C17,
    /// Texas Instruments TMS320C6000 DSP family.
    TMS320C6000,
    /// Texas Instruments TMS320C2000 DSP family.
    TMS320C2000,
    /// Texas Instruments TMS320C55xx DSP family.
    TMS320C5500,
    /// Texas Instruments Application-Specific 32-bit RISC Processor.
    APR32,
    /// Texas Instruments Programmable Realtime Unit.
    PRU,
    /// STMicroelectronics VLIW DSP.
    MMDSPPlus,
    /// Cypress M8C.
    CypressM8C,
    /// Renesas R32C series.
    R32C,
    /// NXP Semiconductors TriMedia architecture.
    TriMedia,
    /// QualComm Hexagon.
    Hexagon,
    /// Intel 8051.
    I8051,
    /// STMicroelectronics STxP7x family.
    STxP7x,
    /// Andes Technology embedded RISC processor family.
    NDS32,
    /// Cyan Technology eCOG1X family.
    ECOG1X,
    /// Dallas Semiconductor MAXQ30 microcontroller.
    MAXQ30,
    /// New Japan Radio 16-bit DSP.
    XIM016,
    /// M2000 Reconfigurable RISC processor.
    M2000,
    /// Cray NV2 vector architecture.
    NV2,
    /// Renesas RX family.
    RX,
    /// Imagination Technologies META hardware architecture.
    METAG,
    /// MCST Elbrus general-purpose hardware architecture.
    Elbrus,
    /// Cyan Technologies eCOG16 family.
    ECOG16,
    /// National Semiconductor CompactRISC CR16.
    CR16,
    /// Freescale Extended Time Processing Unit.
    ETPU,
    /// Infineon Technologies SLE9X.
    SLE9X,
    /// Intel L10M.
    L10M,
    /// Intel K10M.
    K10M,
    /// ARM 64-bit architecture.
    AArch64,
    /// Amtel Corporation 32-bit processor family.
    AVR32,
    /// STMicroelectronics STM8.
    STM8,
    /// Tilera TILE64 manycore architecture family.
    TILE64,
    /// Tilera TILEPro manycore architecture family.
    TILEPro,
    /// Xilinx MicroBlaze RISC soft processor.
    MicroBlaze,
    /// NVIDIA CUDA architecture.
    CUDA,
    /// Tilera TILE-Gx manycore architecture family.
    TILEGx,
    /// CloudShield architecture family.
    CloudShield,
    /// KIPO-KAIST Core-A 1st generation.
    CoreA1,
    /// KIPO-KAIST Core-A 2nd generation.
    CoreA2,
    /// Synopsis ARCompact V2.
    ARCompactV2,
    /// Open8 RISC soft processor.
    Open8,
    /// Renesas RL78 family.
    RL78,
    /// Broadcom VideoCore V processor.
    VideoCore5,
    /// Renesas 78KOR family.
    R78KOR,
    /// Freescale 56800EX digital signal controller.
    F56800EX,
    /// Beyond BA1 architecture.
    BA1,
    /// Beyond BA2 architecture.
    BA2,
    /// XMOS xCORE family.
    XCORE,
    /// Microchip PICr family.
    PICr,
    /// KM211 KM32 processor.
    KM32,
    /// KM211 KMX32 processor.
    KMX32,
    /// KM211 KMX16 processor.
    KMX16,
    /// KM211 KMX8 processor.
    KMX8,
    /// KM211 KVARC processor.
    KVARC,
    /// Paneve CDP family.
    CDP,
    /// Cognitive Smart Memory Processor.
    COGE,
    /// Bluechip Systems CoolEngine.
    CoolEngine,
    /// Nanoradio Optimized RISC.
    NORC,
    /// CSR Kalimba family.
    Kalimba,
    /// Zilog Z80,
    Z80,
    /// Controls and Data Services VISIUMcore.
    VISIUMcore,
    /// FTDI Chip FT32.
    FT32,
    /// Moxie processor family.
    Moxie,
    /// AMD GPU architecture.
    AMDGPU,
    /// RISC-V architecture.
    RISCV,
    /// Lanai 32-bit processor.
    Lanai,
    /// Berkeley Packet Filter virtual machine.
    BPF,
    /// NEC SX-Aurora VE.
    SXAuroraVE,
    /// Unknown code.
    Other(u16)
}

/// Class of ELF data.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ElfKind {
    None,
    /// Relocatable object file.
    Relocatable,
    /// Executable file.
    Executable,
    /// Shared object file.
    Dynamic,
    /// Core file.
    Core,
    /// Architecture-specific.
    ArchSpecific(u16)
}

/// Offsets and number of entries in an ELF table.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ElfTable<Class: ElfClass> {
    /// Offset into the ELF data of the table.
    pub offset: Class::Offset,
    /// Number of entries in the table.
    pub num_ents: Class::Half
}

/// Contents of the ELF data projected into a usable form.
///
/// The easiest way to obtain this type is to use the [TryFrom]
/// instance on an [Elf].  This will produce an instance having
/// [ElfTable] as teh program and section header table
/// representations, and [Offsets::Half](ElfClass::Half) as the
/// section header string table representation.
///
/// The projected representation can be converted to one using
/// [ProgHdrs](crate::prog_hdr::ProgHdrs) and
/// [SectionHdrs](crate::section_hdr::SectionHdrs) as the
/// representation of program and section headers using the
/// [WithElfData] instance.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ElfHdrData<B: ByteOrder, Class: ElfClass, P, S, T> {
    /// `PhantomData` for the byte order.
    pub byteorder: PhantomData<B>,
    /// OS ABI for this ELF data.
    pub abi: ElfABI,
    /// OS ABI version for this ELF data.
    pub abi_version: u8,
    /// ELF data kind (see `ElfKind`).
    pub kind: ElfKind,
    /// Processor architecture
    pub arch: ElfArch,
    /// Entry point for execution.
    pub entry: Class::Addr,
    /// Processor-specific flags.
    pub flags: Class::Word,
    /// Program header table, or `None`
    pub prog_hdrs: Option<P>,
    /// Section header table.
    pub section_hdrs: S,
    /// Section header string table.
    pub section_hdr_strtab: T
}

/// Type alias for [ElfHdrData] as projected from an [Elf].
///
/// This is obtained directly from the [TryFrom] insance acting on an
/// [Elf].  This is also used in [Elf::create] and [Elf::create_split].
pub type ElfHdrDataRaw<B, Class> =
    ElfHdrData<B, Class, ElfTable<Class>, ElfTable<Class>,
               <Class as ElfClass>::Half>;

/// Type alias for [ElfHdrData] with `&[u8]` buffers for section and
/// program header tables.
///
/// This is produced from an [ElfHdrDataRaw] using the [WithElfData]
/// instance.
pub type ElfHdrDataBufs<'a, B, Class> =
    ElfHdrData<B, Class, &'a [u8], &'a [u8], <Class as ElfClass>::Half>;

/// Type alias for [ElfHdrData] with
/// [ProgHdrs](crate::prog_hdr::ProgHdrs) and
/// [SectionHdrs](crate::section_hdr::SectionHdrs) as program and
/// section header types.
///
/// This is produced from an [ElfHdrDataBufs] with the [TryInto] instance.
pub type ElfHdrDataHdrs<'a, B, Class> =
    ElfHdrData<B, Class, ProgHdrs<'a, B, Class>,
               SectionHdrs<'a, B, Class>, <Class as ElfClass>::Half>;

pub struct ElfHdrMut<'a, B: ByteOrder, Offsets: ElfHdrOffsets> {
    byte_ord: PhantomData<B>,
    offsets: PhantomData<Offsets>,
    data: &'a mut [u8]
}

/// A wrapper for all known ELF classes and byte orders.
///
/// This type allows ELF data with an unknown class and byte order to
/// be converted to an appropriate [Elf] instantiation using the
/// [TryFrom] instance.
///
/// # Examples
///
/// ```
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use core::convert::TryInto;
/// use core::marker::PhantomData;
/// use elf_utils::Elf;
/// use elf_utils::Elf64;
/// use elf_utils::ElfArch;
/// use elf_utils::ElfABI;
/// use elf_utils::ElfClass;
/// use elf_utils::ElfError;
/// use elf_utils::ElfHdrData;
/// use elf_utils::ElfHdrDataError;
/// use elf_utils::ElfHdrDataRaw;
/// use elf_utils::ElfKind;
/// use elf_utils::ElfMux;
/// use elf_utils::ElfTable;
///
/// const ELF64_EXEC_ELF_HDR: [u8; 64] = [
///     0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x09,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
///     0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
///     0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
/// ];
///
/// let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
///     Elf::try_from(&ELF64_EXEC_ELF_HDR[0..]);
///
/// assert!(elf.is_ok());
///
/// let elf = ElfMux::try_from(&ELF64_EXEC_ELF_HDR[0..])
///     .expect("Expected success");
/// let elf = match elf {
///     ElfMux::Elf64LE(elf) => elf,
///     ElfMux::Elf64BE(_) => panic!("Expected little-endian"),
///     ElfMux::Elf32LE(_) => panic!("Expected 64-bit"),
///     ElfMux::Elf32BE(_) => panic!("Expected 64-bit little-endian")
/// };
///
/// let hdr: ElfHdrDataRaw<LittleEndian, Elf64> =
///     elf.try_into().unwrap();
///
/// assert_eq!(hdr, ElfHdrData { byteorder: PhantomData, abi: ElfABI::FreeBSD,
///                              abi_version: 0, kind: ElfKind::Executable,
///                              arch: ElfArch::X86_64,  entry: 0x20b940,
///                              flags: 0, section_hdr_strtab: 30,
///                              prog_hdrs: Some(ElfTable { offset: 64,
///                                                         num_ents: 11 }),
///                              section_hdrs: ElfTable { offset: 162968,
///                                                       num_ents: 31 } });
/// ```
pub enum ElfMux<'a> {
    /// 32-bit big-endian.
    Elf32BE(Elf<'a, BigEndian, Elf32>),
    /// 32-bit little-endian.
    Elf32LE(Elf<'a, LittleEndian, Elf32>),
    /// 64-bit big-endian.
    Elf64BE(Elf<'a, BigEndian, Elf64>),
    /// 64-bit little-endian.
    Elf64LE(Elf<'a, LittleEndian, Elf64>)
}

/// Errors that can occur when parsing an ELF header.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ElfError {
    /// Data was too short to contain an ELF Header
    TooShort,
    /// Bad magic values.
    BadMagic,
    /// Unknown ELF version.
    BadVersion(u8),
    /// Endianness code is not little or big.
    BadEndian(u8),
    /// Class code is not 32 or 64 bit.
    BadClass(u8)
}

/// Errors that can occur when projecting an [Elf] into [ElfHdrData].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ElfHdrDataError<Class: ElfClass> {
    /// Program header size was incorrect.
    BadProgHdrEntSize(Class::Half),
    /// Section header size was incorrect.
    BadSectionHdrEntSize(Class::Half),
    /// Elf type code was not recognized.
    BadKind(Class::Half)
}

/// Errors that can occur when converting an `ElfHdrData` with raw
/// offsets to one with slices.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ElfHdrWithDataError<Class: ElfClass> {
    /// Program header table is out of bounds.
    ProgHdrOutOfBounds(Class::Offset),
    /// Section header table is out of bound.
    SectionHdrOutOfBounds(Class::Offset)
}

/// Errors that can occur when converting an `ElfHdrData` with raw
/// slices to one with [ProgHdrs](crate::prog_hdr::ProgHdrs) and
/// [SectionHdrs](crate::section_hdr::SectionHdrs).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ElfHdrTableError {
    /// Error instantiating program header table.
    BadProgHdr(ProgHdrsError),
    /// Error instantiating section header table.
    BadSectionHdr(SectionHdrsError),
}

fn project<'a, B, Offsets>(data: &'a [u8], byteorder: PhantomData<B>,
                           _offsets: PhantomData<Offsets>) ->
    Result<ElfHdrData<B, Offsets, ElfTable<Offsets>,
                      ElfTable<Offsets>, Offsets::Half>,
           ElfHdrDataError<Offsets>>
    where Offsets: ElfHdrOffsets,
          B: ByteOrder {
    let ph_offset = Offsets::read_offset(&data[Offsets::E_PHOFF_START ..
                                               Offsets::E_PHOFF_END],
                                         byteorder);
    let ph_entsize = Offsets::read_half(&data[Offsets::E_PHENTSIZE_START ..
                                              Offsets::E_PHENTSIZE_END],
                                        byteorder);
    let ph_num = Offsets::read_half(&data[Offsets::E_PHNUM_START ..
                                          Offsets::E_PHNUM_END],
                                    byteorder);

    let prog_hdrs = if ph_offset == (0 as u8).into() &&
                       ph_num == (0 as u8).into() {
        None
    } else if ph_entsize != (0 as u8).into() &&
              ph_entsize.into() as usize != Offsets::PROG_HDR_SIZE {
        return Err(ElfHdrDataError::BadProgHdrEntSize(ph_entsize))
    } else {
        Some(ElfTable { offset: ph_offset, num_ents: ph_num })
    };

    let sh_offset = Offsets::read_offset(&data[Offsets::E_SHOFF_START ..
                                               Offsets::E_SHOFF_END],
                                         byteorder);
    let sh_entsize = Offsets::read_half(&data[Offsets::E_SHENTSIZE_START ..
                                              Offsets::E_SHENTSIZE_END],
                                        byteorder);
    let sh_num = Offsets::read_half(&data[Offsets::E_SHNUM_START ..
                                          Offsets::E_SHNUM_END],
                                    byteorder);

    let section_hdrs = if sh_entsize.into() as usize !=
                          Offsets::SECTION_HDR_SIZE {
        return Err(ElfHdrDataError::BadSectionHdrEntSize(sh_entsize))
    } else {
        ElfTable { offset: sh_offset, num_ents: sh_num }
    };

    let kind = Offsets::read_half(&data[Offsets::E_TYPE_START ..
                                        Offsets::E_TYPE_END],
                                  byteorder);

    match kind.into().try_into() {
        Ok(kind) => {
            let abi = data[ELF_ABI_OFFSET].into();
            let abi_version = data[ELF_ABI_VERSION_OFFSET];
            let arch = Offsets::read_half(&data[Offsets::E_MACHINE_START ..
                                                Offsets::E_MACHINE_END],
                                          byteorder).into();
            let entry = Offsets::read_addr(&data[Offsets::E_ENTRY_START ..
                                                 Offsets::E_ENTRY_END],
                                           byteorder);
            let flags = Offsets::read_word(&data[Offsets::E_FLAGS_START ..
                                                 Offsets::E_FLAGS_END],
                                           byteorder);
            let strtab = Offsets::read_half(&data[Offsets::E_SHSTRTAB_START ..
                                                  Offsets::E_SHSTRTAB_END],
                                            byteorder);

            Ok(ElfHdrData { abi: abi, abi_version: abi_version, kind: kind,
                            arch: arch.into(), entry: entry, flags: flags,
                            byteorder: PhantomData, section_hdrs: section_hdrs,
                            section_hdr_strtab: strtab, prog_hdrs: prog_hdrs })
        },
        Err(_) => Err(ElfHdrDataError::BadKind(kind))
    }
}

fn check<'a>(data: &'a [u8]) -> Result<(bool, bool), ElfError> {
    // Basic checks.
    if data.len() < 16 {
        // We don't even have 16 bytes.
        return Err(ElfError::TooShort)
    }

    if data[0 .. ELF_MAGIC.len()] != ELF_MAGIC {
        // ELF signature doesn't match.
        return Err(ElfError::BadMagic)
    }

    if data[ELF_VERSION_OFFSET] != ELF_VERSION {
        // ELF version doesn't match.
        return Err(ElfError::BadVersion(data[ELF_VERSION_OFFSET]))
    }

    // Check the endianness and size.
    let endian = data[ELF_ENDIAN_OFFSET];
    let class = data[ELF_CLASS_OFFSET];

    if endian == LittleEndian::BYTE_ORDER_CODE {
        let read_u16 = LittleEndian::read_u16;

        if class == Elf64::TYPE_CODE {
            // Check that there's enough data to read the
            // header size.
            if data.len() < Elf64::E_EHSIZE_END {
                return Err(ElfError::TooShort)
            }

            let ehsize = read_u16(&data[Elf64::E_EHSIZE_START ..
                                        Elf64::E_EHSIZE_END]) as usize;

            // Check that the data is big enough for a
            // complete header.
            if data.len() < ehsize {
                return Err(ElfError::TooShort)
            }

            Ok((false, true))
        } else if class == Elf32::TYPE_CODE {
            // Check that there's enough data to read the
            // header size.
            if data.len() < Elf32::E_EHSIZE_END {
                return Err(ElfError::TooShort)
            }

            let ehsize = read_u16(&data[Elf32::E_EHSIZE_START ..
                                        Elf32::E_EHSIZE_END]) as usize;

            // Check that the data is big enough for a
            // complete header.
            if data.len() < ehsize {
                return Err(ElfError::TooShort)
            }

            Ok((false, false))
        } else {
            Err(ElfError::BadClass(class))
        }
    } else if endian == BigEndian::BYTE_ORDER_CODE {
        let read_u16 = BigEndian::read_u16;

        if class == Elf64::TYPE_CODE {
            // Check that there's enough data to read the
            // header size.
            if data.len() < Elf64::E_EHSIZE_END {
                return Err(ElfError::TooShort)
            }

            let ehsize = read_u16(&data[Elf64::E_EHSIZE_START ..
                                        Elf64::E_EHSIZE_END]) as usize;

            // Check that the data is big enough for a
            // complete header.
            if data.len() < ehsize {
                return Err(ElfError::TooShort)
            }

            Ok((true, true))
        } else if class == Elf32::TYPE_CODE {
            // Check that there's enough data to read the
            // header size.
            if data.len() < Elf32::E_EHSIZE_END {
                return Err(ElfError::TooShort)
            }

            let ehsize = read_u16(&data[Elf32::E_EHSIZE_START ..
                                        Elf32::E_EHSIZE_END]) as usize;

            // Check that the data is big enough for a
            // complete header.
            if data.len() < ehsize {
                return Err(ElfError::TooShort)
            }

            Ok((true, false))
        } else {
            Err(ElfError::BadClass(class))
        }
    } else {
        Err(ElfError::BadEndian(endian))
    }
}

fn check_known<'a, B, Offsets>(data: &'a [u8], _byteorder: PhantomData<B>,
                               _offsets: PhantomData<Offsets>) ->
    Option<ElfError>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    // Basic checks.
    if data.len() < 16 {
        // We don't even have 16 bytes.
        return Some(ElfError::TooShort)
    }

    if data[0 .. ELF_MAGIC.len()] != ELF_MAGIC {
        // ELF signature doesn't match.
        return Some(ElfError::BadMagic)
    }

    if data[ELF_VERSION_OFFSET] != ELF_VERSION {
        // ELF version doesn't match.
        return Some(ElfError::BadVersion(data[ELF_VERSION_OFFSET]))
    }

    // Check the endianness and size.
    let endian = data[ELF_ENDIAN_OFFSET];
    let class = data[ELF_CLASS_OFFSET];

    if endian != B::BYTE_ORDER_CODE {
        // Unknown endianness.
        return Some(ElfError::BadEndian(endian))
    }

    // Check the data size.
    if class != Offsets::TYPE_CODE {
        return Some(ElfError::BadClass(class))
    }

    // Check that there's enough data to read the
    // header size.
    if data.len() < Offsets::E_EHSIZE_END {
        return Some(ElfError::TooShort)
    }

    let ehsize = B::read_u16(&data[Offsets::E_EHSIZE_START ..
                                   Offsets::E_EHSIZE_END]) as usize;

    // Check that the data is big enough for a
    // complete header.
    if data.len() < ehsize {
        return Some(ElfError::TooShort)
    }

    None
}

#[inline]
fn create<'a, B, Offsets>(buf: &'a mut [u8],
                          hdr: ElfHdrData<B, Offsets, ElfTable<Offsets>,
                                          ElfTable<Offsets>, Offsets::Half>,
                          _offsets: PhantomData<Offsets>) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    if buf.len() >= Offsets::ELF_HDR_SIZE {
        let ElfHdrData { abi, abi_version, kind, arch, entry, flags,
                         byteorder, prog_hdrs, section_hdr_strtab,
                         section_hdrs: ElfTable { offset: sh_offset,
                                                  num_ents: sh_ents } } = hdr;

        for i in 0 .. ELF_MAGIC.len() {
            buf[i] = ELF_MAGIC[i];
        }

        buf[ELF_CLASS_OFFSET] = Offsets::TYPE_CODE;
        buf[ELF_ENDIAN_OFFSET] = B::BYTE_ORDER_CODE;
        buf[ELF_VERSION_OFFSET] = ELF_VERSION;
        buf[ELF_ABI_OFFSET] = abi.into();
        buf[ELF_ABI_VERSION_OFFSET] = abi_version;

        for i in ELF_ABI_VERSION_OFFSET .. ELF_IDENT_END {
            buf[i] = 0;
        }

        let kind: u16 = kind.into();
        Offsets::write_half(&mut buf[Offsets::E_TYPE_START ..
                                     Offsets::E_TYPE_END],
                            kind.into(), byteorder);

        let machine: u16 = arch.into();

        Offsets::write_half(&mut buf[Offsets::E_MACHINE_START ..
                                     Offsets::E_MACHINE_END],
                            machine.into(), byteorder);
        Offsets::write_word(&mut buf[Offsets::E_VERSION_START ..
                                     Offsets::E_VERSION_END],
                            ELF_VERSION.into(), byteorder);
        Offsets::write_addr(&mut buf[Offsets::E_ENTRY_START ..
                                     Offsets::E_ENTRY_END],
                            entry, byteorder);
        Offsets::write_offset(&mut buf[Offsets::E_SHOFF_START ..
                                       Offsets::E_SHOFF_END],
                              sh_offset, byteorder);
        Offsets::write_word(&mut buf[Offsets::E_FLAGS_START ..
                                     Offsets::E_FLAGS_END],
                            flags, byteorder);
        Offsets::write_half(&mut buf[Offsets::E_EHSIZE_START ..
                                     Offsets::E_EHSIZE_END],
                            Offsets::ELF_HDR_SIZE_HALF, byteorder);
        Offsets::write_half(&mut buf[Offsets::E_SHENTSIZE_START ..
                                     Offsets::E_SHENTSIZE_END],
                            Offsets::SECTION_HDR_SIZE_HALF, byteorder);
        Offsets::write_half(&mut buf[Offsets::E_SHNUM_START ..
                                     Offsets::E_SHNUM_END],
                            sh_ents, byteorder);
        Offsets::write_half(&mut buf[Offsets::E_SHSTRTAB_START ..
                                     Offsets::E_SHSTRTAB_END],
                            section_hdr_strtab, byteorder);

        match prog_hdrs {
            Some(ElfTable { offset: ph_offset, num_ents: ph_ents }) => {
                Offsets::write_offset(&mut buf[Offsets::E_PHOFF_START ..
                                               Offsets::E_PHOFF_END],
                                      ph_offset, byteorder);
                Offsets::write_half(&mut buf[Offsets::E_PHENTSIZE_START ..
                                             Offsets::E_PHENTSIZE_END],
                                    Offsets::PROG_HDR_SIZE_HALF, byteorder);
                Offsets::write_half(&mut buf[Offsets::E_PHNUM_START ..
                                             Offsets::E_PHNUM_END],
                                    ph_ents, byteorder);
            },
            None => {
                Offsets::write_offset(&mut buf[Offsets::E_PHOFF_START ..
                                               Offsets::E_PHOFF_END],
                                      (0 as u8).into(), byteorder);
                Offsets::write_half(&mut buf[Offsets::E_PHENTSIZE_START ..
                                             Offsets::E_PHENTSIZE_END],
                                    (0 as u8).into(), byteorder);
                Offsets::write_half(&mut buf[Offsets::E_PHNUM_START ..
                                             Offsets::E_PHNUM_END],
                                    (0 as u8).into(), byteorder);
            }
        }

        Ok(buf.split_at_mut(Offsets::ELF_HDR_SIZE))
    } else {
        Err(())
    }
}

impl<'a, B: ByteOrder> ElfHdrMut<'a, B, Elf32> {
    /// Set the OS ABI for this ELF data to `abi`.
    pub fn set_abi(&mut self, abi: ElfABI) {
        self.data[ELF_ABI_OFFSET] = abi.into()
    }

    /// Set the OS ABI version for this ELF data to `abi_version`.
    pub fn set_abi_version(&mut self, abi_version: u8) {
        self.data[ELF_ABI_VERSION_OFFSET] = abi_version
    }

    /// Set the type of this ELF data to `kind` (see `ElfKind`).
    pub fn set_kind(&mut self, kind: ElfKind) {
        B::write_u16(&mut self.data[Elf32::E_TYPE_START ..
                                    Elf32::E_TYPE_END], kind.into())
    }

    /// Set the processor architecture for this ELF data to `arch`.
    pub fn set_arch(&mut self, arch: ElfArch) {
        B::write_u16(&mut self.data[Elf32::E_MACHINE_START ..
                                    Elf32::E_MACHINE_END], arch.into())
    }

    /// Set the entry point for execution for this ELF data to `entry`.
    pub fn set_entry(&mut self, entry: u32) {
        B::write_u32(&mut self.data[Elf32::E_ENTRY_START ..
                                    Elf32::E_ENTRY_END], entry)
    }

    /// Set the processor-specific flags for this ELF data to `flags`.
    pub fn set_flags(&mut self, flags: u32) {
        B::write_u32(&mut self.data[Elf32::E_FLAGS_START ..
                                    Elf32::E_FLAGS_END], flags)
    }

}

impl<'a, B: ByteOrder> ElfHdrMut<'a, B, Elf64> {
    /// Set the OS ABI for this ELF data to `abi`.
    pub fn set_abi(&mut self, abi: ElfABI) {
        self.data[ELF_ABI_OFFSET] = abi.into()
    }

    /// Set the OS ABI version for this ELF data to `abi_version`.
    pub fn set_abi_version(&mut self, abi_version: u8) {
        self.data[ELF_ABI_VERSION_OFFSET] = abi_version
    }

    /// Set the type of this ELF data to `kind` (see `ElfKind`).
    pub fn set_kind(&mut self, kind: ElfKind) {
        B::write_u16(&mut self.data[Elf64::E_TYPE_START ..
                                    Elf64::E_TYPE_END], kind.into())
    }

    /// Set the processor architecture for this ELF data to `arch`.
    pub fn set_arch(&mut self, arch: ElfArch) {
        B::write_u16(&mut self.data[Elf64::E_MACHINE_START ..
                                    Elf64::E_MACHINE_END], arch.into())
    }

    /// Set the entry point for execution for this ELF data to `entry`.
    pub fn set_entry(&mut self, entry: u64) {
        B::write_u64(&mut self.data[Elf64::E_ENTRY_START ..
                                    Elf64::E_ENTRY_END], entry)
    }

    /// Set the processor-specific flags for this ELF data to `flags`.
    pub fn set_flags(&mut self, flags: u32) {
        B::write_u32(&mut self.data[Elf64::E_FLAGS_START ..
                                    Elf64::E_FLAGS_END], flags)
    }
}

impl Display for ElfError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfError::TooShort => write!(f, "data too short"),
            ElfError::BadMagic => write!(f, "bad magic value"),
            ElfError::BadVersion(vers) => write!(f, "bad ELF version {}", vers),
            ElfError::BadEndian(code) => write!(f, "bad endianness {}", code),
            ElfError::BadClass(code) => write!(f, "bad class {}", code),
        }
    }
}

impl<Class: ElfClass> Display for ElfHdrDataError<Class> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfHdrDataError::BadProgHdrEntSize(size) =>
                write!(f, "bad program header entry size ({})", size),
            ElfHdrDataError::BadSectionHdrEntSize(size) =>
                write!(f, "bad section header entry size ({})", size),
            ElfHdrDataError::BadKind(kind) =>
                write!(f, "bad ELF type ({})", kind),
        }
    }
}

impl<Class: ElfClass> Display for ElfHdrWithDataError<Class> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfHdrWithDataError::ProgHdrOutOfBounds(offset) =>
                write!(f, "program header table end {} is outside data",
                       offset),
            ElfHdrWithDataError::SectionHdrOutOfBounds(offset) =>
                write!(f, "section header table end {} is outside data",
                       offset)
        }
    }
}

impl Display for ElfHdrTableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfHdrTableError::BadProgHdr(err) =>
                write!(f, "bad program header data ({})", err),
            ElfHdrTableError::BadSectionHdr(err) =>
                write!(f, "bad section header data ({})", err)
        }
    }
}

impl<Class: ElfClass> Display for ElfTable<Class> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        let ElfTable { offset, num_ents } = self;

        write!(f, "offset = 0x{:x}, entries = {}", offset, num_ents)
    }
}

impl<'a, P, S, T> Display for ElfHdrData<LittleEndian, Elf32, P, S, T>
    where S: Display,
          P: Display,
          T: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfHdrData { abi, abi_version, kind, arch,
                         entry, flags, section_hdr_strtab,
                         section_hdrs, prog_hdrs: None, .. } =>
                write!(f, concat!("ELF version: 1\n",
                                  "ELF class: 32-bit, little-endian\n",
                                  "ELF type: {}\n",
                                  "Architecture: {}\n",
                                  "ABI: {}\n",
                                  "ABI version: {}\n",
                                  "Flags: {:x}\n",
                                  "Entry: {:x}\n",
                                  "Program headers: none\n",
                                  "Section headers: {}\n",
                                  "Section header string table: {}"),
                       kind, arch, abi, abi_version, flags, entry,
                       section_hdrs, section_hdr_strtab),
            ElfHdrData { abi, abi_version, kind, arch, entry, flags,
                         section_hdr_strtab, section_hdrs,
                         prog_hdrs: Some(prog_hdrs), .. } =>
                write!(f, concat!("ELF version: 1\n",
                                  "ELF class: 32-bit, little-endian\n",
                                  "ELF type: {}\n",
                                  "Architecture: {}\n",
                                  "ABI: {}\n",
                                  "ABI version: {}\n",
                                  "Flags: {:x}\n",
                                  "Entry: {:x}\n",
                                  "Program headers: {}\n",
                                  "Section headers: {}\n",
                                  "Section header string table: {}"),
                       kind, arch, abi, abi_version, flags, entry,
                       prog_hdrs, section_hdrs, section_hdr_strtab)
        }
    }
}

impl<'a, P, S, T> Display for ElfHdrData<BigEndian, Elf32, P, S, T>
    where S: Display,
          P: Display,
          T: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfHdrData { abi, abi_version, kind, arch,
                         entry, flags, section_hdr_strtab,
                         section_hdrs, prog_hdrs: None, .. } =>
                write!(f, concat!("ELF version: 1\n",
                                  "ELF class: 32-bit, little-endian\n",
                                  "ELF type: {}\n",
                                  "Architecture: {}\n",
                                  "ABI: {}\n",
                                  "ABI version: {}\n",
                                  "Flags: {:x}\n",
                                  "Entry: {:x}\n",
                                  "Program headers: none\n",
                                  "Section headers: {}\n",
                                  "Section header string table: {}"),
                       kind, arch, abi, abi_version, flags, entry,
                       section_hdrs, section_hdr_strtab),
            ElfHdrData { abi, abi_version, kind, arch, entry, flags,
                         section_hdr_strtab, section_hdrs,
                         prog_hdrs: Some(prog_hdrs), .. } =>
                write!(f, concat!("ELF version: 1\n",
                                  "ELF class: 32-bit, little-endian\n",
                                  "ELF type: {}\n",
                                  "Architecture: {}\n",
                                  "ABI: {}\n",
                                  "ABI version: {}\n",
                                  "Flags: {:x}\n",
                                  "Entry: {:x}\n",
                                  "Program headers: {}\n",
                                  "Section headers: {}\n",
                                  "Section header string table: {}"),
                       kind, arch, abi, abi_version, flags, entry,
                       prog_hdrs, section_hdrs, section_hdr_strtab)
        }
    }
}

impl<'a, P, S, T> Display for ElfHdrData<BigEndian, Elf64, P, S, T>
    where S: Display,
          P: Display,
          T: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfHdrData { abi, abi_version, kind, arch,
                         entry, flags, section_hdr_strtab,
                         section_hdrs, prog_hdrs: None, .. } =>
                write!(f, concat!("ELF version: 1\n",
                                  "ELF class: 32-bit, little-endian\n",
                                  "ELF type: {}\n",
                                  "Architecture: {}\n",
                                  "ABI: {}\n",
                                  "ABI version: {}\n",
                                  "Flags: {:x}\n",
                                  "Entry: {:x}\n",
                                  "Program headers: none\n",
                                  "Section headers: {}\n",
                                  "Section header string table: {}"),
                       kind, arch, abi, abi_version, flags, entry,
                       section_hdrs, section_hdr_strtab),
            ElfHdrData { abi, abi_version, kind, arch, entry, flags,
                         section_hdr_strtab, section_hdrs,
                         prog_hdrs: Some(prog_hdrs), .. } =>
                write!(f, concat!("ELF version: 1\n",
                                  "ELF class: 32-bit, little-endian\n",
                                  "ELF type: {}\n",
                                  "Architecture: {}\n",
                                  "ABI: {}\n",
                                  "ABI version: {}\n",
                                  "Flags: {:x}\n",
                                  "Entry: {:x}\n",
                                  "Program headers: {}\n",
                                  "Section headers: {}\n",
                                  "Section header string table: {}"),
                       kind, arch, abi, abi_version, flags, entry,
                       prog_hdrs, section_hdrs, section_hdr_strtab)
        }
    }
}

impl<'a, P, S, T> Display for ElfHdrData<LittleEndian, Elf64, P, S, T>
    where S: Display,
          P: Display,
          T: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfHdrData { abi, abi_version, kind, arch,
                         entry, flags, section_hdr_strtab,
                         section_hdrs, prog_hdrs: None, .. } =>
                write!(f, concat!("ELF version: 1\n",
                                  "ELF class: 32-bit, little-endian\n",
                                  "ELF type: {}\n",
                                  "Architecture: {}\n",
                                  "ABI: {}\n",
                                  "ABI version: {}\n",
                                  "Flags: {:x}\n",
                                  "Entry: {:x}\n",
                                  "Program headers: none\n",
                                  "Section headers: {}\n",
                                  "Section header string table: {}"),
                       kind, arch, abi, abi_version, flags, entry,
                       section_hdrs, section_hdr_strtab),
            ElfHdrData { abi, abi_version, kind, arch, entry, flags,
                         section_hdr_strtab, section_hdrs,
                         prog_hdrs: Some(prog_hdrs), .. } =>
                write!(f, concat!("ELF version: 1\n",
                                  "ELF class: 32-bit, little-endian\n",
                                  "ELF type: {}\n",
                                  "Architecture: {}\n",
                                  "ABI: {}\n",
                                  "ABI version: {}\n",
                                  "Flags: {:x}\n",
                                  "Entry: {:x}\n",
                                  "Program headers: {}\n",
                                  "Section headers: {}\n",
                                  "Section header string table: {}"),
                       kind, arch, abi, abi_version, flags, entry,
                       prog_hdrs, section_hdrs, section_hdr_strtab)
        }
    }
}

impl<'a, B, Offsets, T> WithElfData<'a>
    for ElfHdrData<B, Offsets, ElfTable<Offsets>, ElfTable<Offsets>, T>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    type Result = ElfHdrData<B, Offsets, &'a [u8], &'a [u8], T>;
    type Error = ElfHdrWithDataError<Offsets>;

    #[inline]
    fn with_elf_data(self, data: &'a [u8]) ->
        Result<ElfHdrData<B, Offsets, &'a [u8], &'a [u8], T>, Self::Error> {
        let ElfHdrData { abi, abi_version, kind, arch, entry, flags,
                         section_hdr_strtab, prog_hdrs, byteorder,
                         section_hdrs: ElfTable { offset: sh_offset,
                                                  num_ents: sh_num } } = self;

        let prog_hdrs = match prog_hdrs {
            Some(ElfTable { offset: ph_offset, num_ents: ph_num }) => {
                let size = (ph_num.into() as usize) * Offsets::PROG_HDR_SIZE;

                match ph_offset.try_into() {
                    Ok(offset) if offset + size <= data.len() =>
                        Ok(Some(&data[offset .. offset + size])),
                    _ => Err(ElfHdrWithDataError::ProgHdrOutOfBounds(ph_offset))
                }
            },
            None => Ok(None)
        };

        let sh_size = (sh_num.into() as usize) * Offsets::SECTION_HDR_SIZE;
        let section_hdrs = match sh_offset.try_into() {
            Ok(offset) if offset + sh_size <= data.len() =>
                Ok(&data[offset .. offset + sh_size]),
            _ => Err(ElfHdrWithDataError::SectionHdrOutOfBounds(sh_offset))
        };

        Ok(ElfHdrData { abi: abi, abi_version: abi_version, kind: kind,
                        section_hdr_strtab: section_hdr_strtab, flags: flags,
                        arch: arch.into(), entry: entry, prog_hdrs: prog_hdrs?,
                        section_hdrs: section_hdrs?, byteorder: byteorder })
    }
}

impl<'a, B, Offsets, T> TryFrom<ElfHdrData<B, Offsets, &'a [u8], &'a [u8], T>>
    for ElfHdrData<B, Offsets, ProgHdrs<'a, B, Offsets>,
                   SectionHdrs<'a, B, Offsets>, T>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    type Error = ElfHdrTableError;

    fn try_from(elf: ElfHdrData<B, Offsets, &'a [u8], &'a [u8], T>) ->
        Result<ElfHdrData<B, Offsets, ProgHdrs<'a, B, Offsets>,
                          SectionHdrs<'a, B, Offsets>, T>,
               Self::Error> {
        let ElfHdrData { abi, abi_version, kind, arch, entry, flags, byteorder,
                         prog_hdrs, section_hdrs, section_hdr_strtab } = elf;

        let prog_hdrs = match prog_hdrs {
            Some(prog_hdrs) => match ProgHdrs::try_from(prog_hdrs) {
                Ok(prog_hdrs) => Ok(Some(prog_hdrs)),
                Err(err) => Err(ElfHdrTableError::BadProgHdr(err))
            },
            None => Ok(None)
        };

        let section_hdrs = match SectionHdrs::try_from(section_hdrs) {
            Ok(section_hdrs) => Ok(section_hdrs),
            Err(err) => Err(ElfHdrTableError::BadSectionHdr(err))
        };

        Ok(ElfHdrData { abi: abi, abi_version: abi_version, kind: kind,
                        section_hdr_strtab: section_hdr_strtab, flags: flags,
                        prog_hdrs: prog_hdrs?, section_hdrs: section_hdrs?,
                        byteorder: byteorder, arch: arch.into(), entry: entry })
    }
}

impl<'a, B, Offsets> Elf<'a, B, Offsets>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    /// Attempt to create an `Elf` in `buf` containing the ELF header
    /// information in `hdr`.
    ///
    /// This will write the ELF header data into the buffer in the
    /// proper format for the ELF class and byte order.  Returns both
    /// the `Elf` and the remaining space if successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the ELF header doesn't fit
    /// into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use core::marker::PhantomData;
    /// use elf_utils::Elf;
    /// use elf_utils::Elf64;
    /// use elf_utils::ElfArch;
    /// use elf_utils::ElfABI;
    /// use elf_utils::ElfClass;
    /// use elf_utils::ElfHdrData;
    /// use elf_utils::ElfHdrDataError;
    /// use elf_utils::ElfHdrDataRaw;
    /// use elf_utils::ElfKind;
    /// use elf_utils::ElfTable;
    ///
    ///
    /// const ELF64_EXEC_HEADER_DATA: ElfHdrDataRaw<LittleEndian, Elf64> =
    ///     ElfHdrData {
    ///         byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
    ///         kind: ElfKind::Executable, arch: ElfArch::X86_64,
    ///         entry: 0x20b940, flags: 0, section_hdr_strtab: 30,
    ///         prog_hdrs: Some(ElfTable { offset: 64, num_ents: 11 }),
    ///         section_hdrs: ElfTable { offset: 162968, num_ents: 31 }
    /// };
    ///
    /// let mut buf: [u8; 64] = [0; 64];
    ///
    /// let res = Elf::create_split(&mut buf[0..], ELF64_EXEC_HEADER_DATA);
    ///
    /// assert!(res.is_ok());
    ///
    /// let (elf, _) = res.unwrap();
    ///
    /// let hdr: ElfHdrDataRaw<LittleEndian, Elf64> =
    ///     elf.try_into().expect("expected success");
    ///
    /// assert_eq!(hdr, ELF64_EXEC_HEADER_DATA);
    /// ```
    #[inline]
    pub fn create_split(buf: &'a mut [u8], hdr: ElfHdrDataRaw<B, Offsets>) ->
        Result<(Self, &'a mut [u8]), ()> {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;
        let (data, out) = create(buf, hdr, offsets)?;

        Ok((Elf { byteorder: byteorder, offsets: offsets, data: data }, out))
    }

    /// Attempt to create an `Elf` in `buf` containing the ELF header
    /// information in `hdr`.
    ///
    /// This will write the ELF header data into the buffer in the
    /// proper format for the ELF class and byte order.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the ELF header doesn't fit
    /// into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use core::convert::TryInto;
    /// use core::marker::PhantomData;
    /// use elf_utils::Elf;
    /// use elf_utils::Elf64;
    /// use elf_utils::ElfArch;
    /// use elf_utils::ElfABI;
    /// use elf_utils::ElfClass;
    /// use elf_utils::ElfHdrData;
    /// use elf_utils::ElfHdrDataError;
    /// use elf_utils::ElfHdrDataRaw;
    /// use elf_utils::ElfKind;
    /// use elf_utils::ElfTable;
    ///
    ///
    /// const ELF64_EXEC_HEADER_DATA: ElfHdrDataRaw<LittleEndian, Elf64> =
    ///     ElfHdrData {
    ///         byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
    ///         kind: ElfKind::Executable, arch: ElfArch::X86_64,
    ///         entry: 0x20b940, flags: 0, section_hdr_strtab: 30,
    ///         prog_hdrs: Some(ElfTable { offset: 64, num_ents: 11 }),
    ///         section_hdrs: ElfTable { offset: 162968, num_ents: 31 }
    /// };
    ///
    /// let mut buf: [u8; 64] = [0; 64];
    ///
    /// let elf = Elf::create(&mut buf[0..], ELF64_EXEC_HEADER_DATA).unwrap();
    /// let hdr: ElfHdrDataRaw<LittleEndian, Elf64> =
    ///     elf.try_into().expect("expected success");
    ///
    /// assert_eq!(hdr, ELF64_EXEC_HEADER_DATA);
    /// ```
    #[inline]
    pub fn create(buf: &'a mut [u8], hdr: ElfHdrDataRaw<B, Offsets>) ->
        Result<Self, ()>
        where Self: Sized {
        match Self::create_split(buf, hdr) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }
}


impl<'a, B, Offsets> TryFrom<Elf<'a, B, Offsets>>
    for ElfHdrData<B, Offsets, ElfTable<Offsets>,
                   ElfTable<Offsets>, Offsets::Half>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    type Error = ElfHdrDataError<Offsets>;

    fn try_from(elf: Elf<'a, B, Offsets>) ->
        Result<ElfHdrData<B, Offsets, ElfTable<Offsets>,
                          ElfTable<Offsets>, Offsets::Half>,
               Self::Error> {
        project(elf.data, elf.byteorder, elf.offsets)
    }
}

impl<'a, B, Offsets> TryFrom<ElfMut<'a, B, Offsets>>
    for ElfHdrData<B, Offsets, ElfTable<Offsets>,
                   ElfTable<Offsets>, Offsets::Half>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    type Error = ElfHdrDataError<Offsets>;

    fn try_from(elf: ElfMut<'a, B, Offsets>) ->
        Result<ElfHdrData<B, Offsets, ElfTable<Offsets>,
                          ElfTable<Offsets>, Offsets::Half>,
               Self::Error> {
        project(elf.data, elf.byteorder, elf.offsets)
    }
}

impl<'a, B, Offsets> TryFrom<&'a [u8]> for Elf<'a, B, Offsets>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    type Error = ElfError;

    /// Do some basic checks on the data to make sure it actually
    /// contains an ELF header.
    fn try_from(data: &'a [u8]) -> Result<Elf<'a, B, Offsets>, Self::Error> {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;

        match check_known(data, byteorder, offsets) {
            Some(err) => Err(err),
            None => Ok(Elf { byteorder: byteorder, offsets: offsets,
                             data: data })
        }
    }
}

impl<'a, B, Offsets> TryFrom<&'a mut [u8]> for Elf<'a, B, Offsets>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    type Error = ElfError;

    /// Do some basic checks on the data to make sure it actually
    /// contains an ELF header.
    fn try_from(data: &'a mut [u8]) ->
        Result<Elf<'a, B, Offsets>, Self::Error> {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;

        match check_known(data, byteorder, offsets) {
            Some(err) => Err(err),
            None => Ok(Elf { byteorder: byteorder, offsets: offsets,
                             data: data })
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ElfMux<'a> {
    type Error = ElfError;

    /// Do some basic checks on the data to make sure it actually
    /// contains an ELF header.
    fn try_from(data: &'a [u8]) -> Result<ElfMux<'a>, Self::Error> {
        match check(data) {
            Ok((false, false)) =>
                Ok(ElfMux::Elf32LE(Elf { byteorder: PhantomData,
                                         offsets: PhantomData,
                                         data: data })),
            Ok((false, true)) =>
                Ok(ElfMux::Elf64LE(Elf { byteorder: PhantomData,
                                         offsets: PhantomData,
                                         data: data })),
            Ok((true, false)) =>
                Ok(ElfMux::Elf32BE(Elf { byteorder: PhantomData,
                                         offsets: PhantomData,
                                         data: data })),
            Ok((true, true)) =>
                Ok(ElfMux::Elf64BE(Elf { byteorder: PhantomData,
                                         offsets: PhantomData,
                                         data: data })),
            Err(err) => Err(err)
        }
    }
}

impl<'a> TryFrom<&'a mut [u8]> for ElfMux<'a> {
    type Error = ElfError;

    /// Do some basic checks on the data to make sure it actually
    /// contains an ELF header.
    fn try_from(data: &'a mut [u8]) -> Result<ElfMux<'a>, Self::Error> {
        match check(data) {
            Ok((false, false)) =>
                Ok(ElfMux::Elf32LE(Elf { byteorder: PhantomData,
                                         offsets: PhantomData,
                                         data: data })),
            Ok((false, true)) =>
                Ok(ElfMux::Elf64LE(Elf { byteorder: PhantomData,
                                         offsets: PhantomData,
                                         data: data })),
            Ok((true, false)) =>
                Ok(ElfMux::Elf32BE(Elf { byteorder: PhantomData,
                                         offsets: PhantomData,
                                         data: data })),
            Ok((true, true)) =>
                Ok(ElfMux::Elf64BE(Elf { byteorder: PhantomData,
                                         offsets: PhantomData,
                                         data: data })),
            Err(err) => Err(err)
        }
    }
}

impl<'a, B, Offsets> TryFrom<&'a mut [u8]> for ElfMut<'a, B, Offsets>
    where Offsets: ElfHdrOffsets,
          B: ElfByteOrder {
    type Error = ElfError;

    /// Do some basic checks on the data to make sure it actually
    /// contains an ELF header.
    fn try_from(data: &'a mut [u8]) ->
        Result<ElfMut<'a, B, Offsets>, Self::Error> {
        let byteorder: PhantomData<B> = PhantomData;
        let offsets: PhantomData<Offsets> = PhantomData;

        match check_known(data, byteorder, offsets) {
            Some(err) => Err(err),
            None => Ok(ElfMut { byteorder: byteorder, offsets: offsets,
                                data: data })
        }
    }
}

impl Display for ElfKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfKind::None => write!(f, "none"),
            ElfKind::Relocatable => write!(f, "relocatable object"),
            ElfKind::Executable => write!(f, "executable"),
            ElfKind::Dynamic => write!(f, "dynamic object"),
            ElfKind::Core => write!(f, "core image"),
            ElfKind::ArchSpecific(code) =>
                write!(f, "architecture-specific ({:04x})", code)
        }
    }
}

impl From<ElfKind> for u16 {
    fn from(kind: ElfKind) -> u16 {
        match kind {
            ElfKind::None => 0,
            ElfKind::Relocatable => 1,
            ElfKind::Executable => 2,
            ElfKind::Dynamic => 3,
            ElfKind::Core => 4,
            ElfKind::ArchSpecific(code) => code
        }
    }
}

impl TryFrom<u16> for ElfKind {
    type Error = ();

    fn try_from(kind: u16) -> Result<ElfKind, ()> {
        match kind {
            0 => Ok(ElfKind::None),
            1 => Ok(ElfKind::Relocatable),
            2 => Ok(ElfKind::Executable),
            3 => Ok(ElfKind::Dynamic),
            4 => Ok(ElfKind::Core),
            _ if kind >= 0xff00 => Ok(ElfKind::ArchSpecific(kind)),
            _ => Err(())
        }
    }
}

impl Display for ElfABI {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfABI::SysV => write!(f, "System V"),
            ElfABI::HPUX => write!(f, "HP-UX"),
            ElfABI::NetBSD => write!(f, "NetBSD"),
            ElfABI::Linux => write!(f, "Linux"),
            ElfABI::Hurd => write!(f, "GNU Hurd"),
            ElfABI::Open86 => write!(f, "86 Open Common IA-32 ABI"),
            ElfABI::Solaris => write!(f, "Solaris"),
            ElfABI::AIX => write!(f, "AIX"),
            ElfABI::IRIX => write!(f, "IRIX"),
            ElfABI::FreeBSD => write!(f, "FreeBSD"),
            ElfABI::Tru64 => write!(f, "Tru64"),
            ElfABI::Modesto => write!(f, "Modesto"),
            ElfABI::OpenBSD => write!(f, "OpenBSD"),
            ElfABI::OpenVMS => write!(f, "Open VMS"),
            ElfABI::NonStop => write!(f, "HP Non-Stop Kernel"),
            ElfABI::AROS => write!(f, "Amiga Research OS"),
            ElfABI::FenixOS => write!(f, "Fenix OS"),
            ElfABI::CloudABI => write!(f, "Nuxi Cloud ABI"),
            ElfABI::OpenVOS => write!(f, "OpenVOS"),
            ElfABI::ARM => write!(f, "ARM Common ABI"),
            ElfABI::Standalone => write!(f, "Standalone Executable"),
            ElfABI::Other(code) => write!(f, "Other ({:02x})", code),
        }
    }
}

impl From<ElfABI> for u8 {
    fn from(abi: ElfABI) -> u8 {
        match abi {
            ElfABI::SysV => 0x00,
            ElfABI::HPUX => 0x01,
            ElfABI::NetBSD => 0x02,
            ElfABI::Linux => 0x03,
            ElfABI::Hurd => 0x04,
            ElfABI::Open86 => 0x05,
            ElfABI::Solaris => 0x06,
            ElfABI::AIX => 0x07,
            ElfABI::IRIX => 0x08,
            ElfABI::FreeBSD => 0x09,
            ElfABI::Tru64 => 0x0a,
            ElfABI::Modesto => 0x0b,
            ElfABI::OpenBSD => 0x0c,
            ElfABI::OpenVMS => 0x0d,
            ElfABI::NonStop => 0x0e,
            ElfABI::AROS => 0x0f,
            ElfABI::FenixOS => 0x10,
            ElfABI::CloudABI => 0x11,
            ElfABI::OpenVOS => 0x12,
            ElfABI::ARM => 0x61,
            ElfABI::Standalone => 0xff,
            ElfABI::Other(code) => code
        }
    }
}

impl From<u8> for ElfABI {
    fn from(abi: u8) -> ElfABI {
        match abi {
            0x00 => ElfABI::SysV,
            0x01 => ElfABI::HPUX,
            0x02 => ElfABI::NetBSD,
            0x03 => ElfABI::Linux,
            0x04 => ElfABI::Hurd,
            0x05 => ElfABI::Open86,
            0x06 => ElfABI::Solaris,
            0x07 => ElfABI::AIX,
            0x08 => ElfABI::IRIX,
            0x09 => ElfABI::FreeBSD,
            0x0a => ElfABI::Tru64,
            0x0b => ElfABI::Modesto,
            0x0c => ElfABI::OpenBSD,
            0x0d => ElfABI::OpenVMS,
            0x0e => ElfABI::NonStop,
            0x0f => ElfABI::AROS,
            0x10 => ElfABI::FenixOS,
            0x11 => ElfABI::CloudABI,
            0x12 => ElfABI::OpenVOS,
            0x61 => ElfABI::ARM,
            0xff => ElfABI::Standalone,
            code => ElfABI::Other(code)
        }
    }
}

impl Display for ElfArch {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            ElfArch::None => write!(f, "None"),
            ElfArch::We32100 => write!(f, "AT&T We 32100"),
            ElfArch::SPARC => write!(f, "SPARC"),
            ElfArch::I386 => write!(f, "i386"),
            ElfArch::M68K => write!(f, "Motorola 68000"),
            ElfArch::M88K => write!(f, "Motorola 88000"),
            ElfArch::IMCU => write!(f, "Intel MCU"),
            ElfArch::I860 => write!(f, "Intel 80860"),
            ElfArch::MIPS => write!(f, "MIPS"),
            ElfArch::System370 => write!(f, "IBM System/370"),
            ElfArch::MIPS_RS4000_BE => write!(f, "MIPS RS4000"),
            ElfArch::PARISC => write!(f, "PA-RISC"),
            ElfArch::VPP5500 => write!(f, "VPP5500"),
            ElfArch::SPARC32Plus => write!(f, "SPARC+"),
            ElfArch::I960 => write!(f, "Intel 80960"),
            ElfArch::PowerPC => write!(f, "PowerPC"),
            ElfArch::PowerPC64 => write!(f, "PowerPC 64-bit"),
            ElfArch::System390 => write!(f, "IBM System/390"),
            ElfArch::SPU => write!(f, "IBM SPU/SPC"),
            ElfArch::V800 => write!(f, "NEC V800"),
            ElfArch::FR20 => write!(f, "Fujitsu FR20"),
            ElfArch::RH32 => write!(f, "TRW RH-32"),
            ElfArch::RCE => write!(f, "Motorola RCE"),
            ElfArch::AArch32 => write!(f, "ARM"),
            ElfArch::Alpha => write!(f, "Alpha"),
            ElfArch::SuperH => write!(f, "Hitachi Super H"),
            ElfArch::SPARCv9 => write!(f, "SPARC v9"),
            ElfArch::TriCore => write!(f, "Siemens TriCore"),
            ElfArch::ARC => write!(f, "Argonaut ARC"),
            ElfArch::H8_300 => write!(f, "Hitachi H8/300"),
            ElfArch::H8_300_H => write!(f, "Hitachi H8/300H"),
            ElfArch::H8S => write!(f, "Hitachi H8S"),
            ElfArch::H8_500 => write!(f, "Hitachi H8/500"),
            ElfArch::IA64 => write!(f, "IA-64"),
            ElfArch::MIPS_X => write!(f, "MIPS-X"),
            ElfArch::ColdFire => write!(f, "Motorola ColdFire"),
            ElfArch::M68HC12 => write!(f, "Motorola M68HC12"),
            ElfArch::MMA => write!(f, "Fujitsu MMA Multimedia Accelerator"),
            ElfArch::PCP => write!(f, "Siemens PCP"),
            ElfArch::NCPU => write!(f, "Sony nCPU"),
            ElfArch::NDR1 => write!(f, "Denso NDR1"),
            ElfArch::StarCore => write!(f, "Motorola Star*Core"),
            ElfArch::ME16 => write!(f, "ME16"),
            ElfArch::ST100 => write!(f, "STMicroelectronics ST100"),
            ElfArch::TinyJ => write!(f, "Advanced Logic Corporation TinyJ"),
            ElfArch::X86_64 => write!(f, "x86-64"),
            ElfArch::DSP => write!(f, "Sony DSP"),
            ElfArch::PDP10 => write!(f, "PDP-10"),
            ElfArch::PDP11 => write!(f, "PDP-11"),
            ElfArch::FX66 => write!(f, "Siemens FX66"),
            ElfArch::ST9Plus => write!(f, "STMicroelectronics ST9+"),
            ElfArch::ST7 => write!(f, "STMicroelectronics ST7"),
            ElfArch::MC68HC16 => write!(f, "Motorola MC68HC16"),
            ElfArch::MC68HC11 => write!(f, "Motorola MC68HC11"),
            ElfArch::MC68HC08 => write!(f, "Motorola MC68HC08"),
            ElfArch::MC68HC05 => write!(f, "Motorola MC68HC05"),
            ElfArch::SVX => write!(f, "Silicon Graphics SVx"),
            ElfArch::ST19 => write!(f, "STMicroelectronics ST19"),
            ElfArch::VAX => write!(f, "VAX"),
            ElfArch::CRIS => write!(f, "Axis Communications Processor"),
            ElfArch::Javelin => write!(f, "Infineon Technologies DSP"),
            ElfArch::Firepath => write!(f, "Element 14 DSP"),
            ElfArch::ZSP => write!(f, "LSI Logic DSP"),
            ElfArch::MMIX => write!(f, "MMIX Educational Architecture"),
            ElfArch::HUMIO =>
                write!(f, "Harvard Machine-Independent Object File"),
            ElfArch::Prism => write!(f, "SiTera Prism"),
            ElfArch::AVR => write!(f, "Amtel AVR Microcontroller"),
            ElfArch::FR30 => write!(f, "Fujitsu FR30"),
            ElfArch::D10V => write!(f, "Mitsubishi D10V"),
            ElfArch::D30V => write!(f, "Mitsubishi D30V"),
            ElfArch::V850 => write!(f, "NEC V850"),
            ElfArch::M32R => write!(f, "Mitsubishi M32R"),
            ElfArch::MN10300 => write!(f, "Matsushita MN10300"),
            ElfArch::MN10200 => write!(f, "Matsushita MN10200"),
            ElfArch::PicoJava => write!(f, "picoJava"),
            ElfArch::OpenRISC => write!(f, "OpenRISC"),
            ElfArch::ARCompact => write!(f, "ARC International ARCompact"),
            ElfArch::Xtensa => write!(f, "Tensilica Xtensa"),
            ElfArch::VideoCore => write!(f, "VideoCore"),
            ElfArch::GPP =>
                write!(f, "Thompson Multimedia General Purpose Processor"),
            ElfArch::NS32000 => write!(f, "National Semiconductor 32000"),
            ElfArch::TPC => write!(f, "Tenor Network TPC"),
            ElfArch::SNP1000 => write!(f, "Trebia SNP 1000"),
            ElfArch::ST200 => write!(f, "STMicroelectronics ST200"),
            ElfArch::IP2k => write!(f, "Ubicom IP2xxx"),
            ElfArch::MAX => write!(f, "MAX"),
            ElfArch::CompactRISC => write!(f, "CompactRISC"),
            ElfArch::F2MC16 => write!(f, "Fujitsu F2MC16"),
            ElfArch::MSP430 => write!(f, "Texas Instruments msp430"),
            ElfArch::Blackfin => write!(f, "Blackfin DSP"),
            ElfArch::S1C33 => write!(f, "Seiko Epson S1C33"),
            ElfArch::Sharp => write!(f, "Sharp embedded processor"),
            ElfArch::Arca => write!(f, "Arca RISC processor"),
            ElfArch::Unicore =>
                write!(f, "PKU-Unity/Peking University Unicore"),
            ElfArch::EXcess => write!(f, "eXcess embedded CPU"),
            ElfArch::DXP =>
                write!(f, "Icera Semiconductor Deep eXecution Processor"),
            ElfArch::Nios2 => write!(f, "Altera Nios II"),
            ElfArch::CRX => write!(f, "CompactRISC CRX"),
            ElfArch::XGATE => write!(f, "Motorola XGATE"),
            ElfArch::C16x => write!(f, "Infineon C16x"),
            ElfArch::M16C => write!(f, "Renesas M16C"),
            ElfArch::DSPIC30F => write!(f, "Microchip Technology dsPIC30F DSP"),
            ElfArch::FCE =>
                write!(f, "Freescale Communication Engine RISC core"),
            ElfArch::M32C => write!(f, "Renesas M32C"),
            ElfArch::TSK3000 => write!(f, "Altium TSK3000"),
            ElfArch::RS08 => write!(f, "Freescale RS08"),
            ElfArch::SHARC => write!(f, "Analog Devices SHARC DSP"),
            ElfArch::ECOG2 => write!(f, "Cyan Technologies eCOG2"),
            ElfArch::SPlusCore7 => write!(f, "Sunplus S+core7"),
            ElfArch::DSP24 => write!(f, "New Japan Radio 24-bit DSP"),
            ElfArch::VideoCore3 => write!(f, "VideoCore III"),
            ElfArch::Lattice => write!(f, "Lattice FPGA RISC Processor"),
            ElfArch::C17 => write!(f, "Seiko Epson C17"),
            ElfArch::TMS320C6000 =>
                write!(f, "Texas Instruments TMS320C6000 DSP"),
            ElfArch::TMS320C2000 =>
                write!(f, "Texas Instruments TMS320C2000 DSP"),
            ElfArch::TMS320C5500 =>
                write!(f, "Texas Instruments TMS320C55xx DSP"),
            ElfArch::APR32 =>
                write!(f, concat!("Texas Instruments Application-Specific ",
                                  "32-bit RISC processor")),
            ElfArch::PRU => write!(f, concat!("Texas Instruments Programmable ",
                                              "Realtime Unit")),
            ElfArch::MMDSPPlus => write!(f, "STMicroelectronics VLIW DSP"),
            ElfArch::CypressM8C => write!(f, "Cypress M8C"),
            ElfArch::R32C => write!(f, "Renesas R32C"),
            ElfArch::TriMedia => write!(f, "TriMedia"),
            ElfArch::Hexagon => write!(f, "Hexagon"),
            ElfArch::I8051 => write!(f, "Intel 8051"),
            ElfArch::STxP7x => write!(f, "STMicroelectronics STxP7x"),
            ElfArch::NDS32 =>
                write!(f, "Andes Technology embedded RISC processor"),
            ElfArch::ECOG1X => write!(f, "Cyan Technology eCOG1X"),
            ElfArch::MAXQ30 => write!(f, "Dallas Semiconductor MAXQ30"),
            ElfArch::XIM016 => write!(f, "New Japan Radio 16-bit DSP"),
            ElfArch::M2000 => write!(f, "M2000 Reconfigurable RISC processor"),
            ElfArch::NV2 => write!(f, "Cray NV2 vector architecture"),
            ElfArch::RX => write!(f, "Renesas RX"),
            ElfArch::METAG => write!(f, "Imagination Technologies META"),
            ElfArch::Elbrus => write!(f, "Elbrus"),
            ElfArch::ECOG16 => write!(f, "Cyan Technology eCOG16"),
            ElfArch::CR16 => write!(f, "CompactRISC CR16"),
            ElfArch::ETPU =>
                write!(f, "Freescale Extended Time Processing Unit"),
            ElfArch::SLE9X => write!(f, "Infineon Technologies SLE9X"),
            ElfArch::L10M => write!(f, "Intel L10M"),
            ElfArch::K10M => write!(f, "Intel K10M"),
            ElfArch::AArch64 => write!(f, "ARM 64-bit"),
            ElfArch::AVR32 => write!(f, "Amtel Corporation 32-bit processor"),
            ElfArch::STM8 => write!(f, "STMicroelectronics STM8"),
            ElfArch::TILE64 => write!(f, "Tilera TILE64"),
            ElfArch::TILEPro => write!(f, "Tilera TILEPro"),
            ElfArch::MicroBlaze => write!(f, "Xilinx MicroBlaze"),
            ElfArch::CUDA => write!(f, "CUDA"),
            ElfArch::TILEGx => write!(f, "Tilera TILEGx"),
            ElfArch::CloudShield => write!(f, "CloudShield"),
            ElfArch::CoreA1 => write!(f, "KIPO-KAIST Core-A 1st Generation"),
            ElfArch::CoreA2 => write!(f, "KIPO-KAIST Core-A 2nd Generation"),
            ElfArch::ARCompactV2 => write!(f, "Synopsis ARCompact V2"),
            ElfArch::Open8 => write!(f, "Open8"),
            ElfArch::RL78 => write!(f, "Renesas RL78"),
            ElfArch::VideoCore5 => write!(f, "VideoCore V"),
            ElfArch::R78KOR => write!(f, "Renesas 78KOR"),
            ElfArch::F56800EX => write!(f, "Freescale 56800EX"),
            ElfArch::BA1 => write!(f, "Beyond BA1"),
            ElfArch::BA2 => write!(f, "Beyond BA2"),
            ElfArch::XCORE => write!(f, "XMOS xCORE"),
            ElfArch::PICr => write!(f, "Microchip PICr"),
            ElfArch::KM32 => write!(f, "KM211 KM32"),
            ElfArch::KMX32 => write!(f, "KM211 KMX32"),
            ElfArch::KMX16 => write!(f, "KM211 KMX16"),
            ElfArch::KMX8 => write!(f, "KM211 KMX8"),
            ElfArch::KVARC => write!(f, "KM211 KVARC"),
            ElfArch::CDP => write!(f, "Paneve CDP"),
            ElfArch::COGE => write!(f, "Cognitive Smart Memory Controller"),
            ElfArch::CoolEngine => write!(f, "Bluechip Systems CoolEngine"),
            ElfArch::NORC => write!(f, "Nanoradio Optimized RISC"),
            ElfArch::Kalimba => write!(f, "CSR Kalimba"),
            ElfArch::VISIUMcore => write!(f, "VISIUMcore"),
            ElfArch::Z80 => write!(f, "Z80"),
            ElfArch::FT32 => write!(f, "FTDI Chip FT32"),
            ElfArch::Moxie => write!(f, "Moxie"),
            ElfArch::AMDGPU => write!(f, "AMD GPU"),
            ElfArch::RISCV => write!(f, "RISC-V"),
            ElfArch::Lanai => write!(f, "Lanai processor"),
            ElfArch::BPF => write!(f, "Berkeley Packet Filter virtual machine"),
            ElfArch::SXAuroraVE => write!(f, "SX-Aurora VE"),
            ElfArch::Other(code) => write!(f, "Other ({:02x})", code),
        }
    }
}

impl From<ElfArch> for u16 {
    fn from(abi: ElfArch) -> u16 {
        match abi {
            ElfArch::None => 0,
            ElfArch::We32100 => 1,
            ElfArch::SPARC => 2,
            ElfArch::I386 => 3,
            ElfArch::M68K => 4,
            ElfArch::M88K => 5,
            ElfArch::IMCU => 6,
            ElfArch::I860 => 7,
            ElfArch::MIPS => 8,
            ElfArch::System370 => 9,
            ElfArch::MIPS_RS4000_BE => 10,
            ElfArch::PARISC => 15,
            ElfArch::VPP5500 => 17,
            ElfArch::SPARC32Plus => 18,
            ElfArch::I960 => 19,
            ElfArch::PowerPC => 20,
            ElfArch::PowerPC64 => 21,
            ElfArch::System390 => 22,
            ElfArch::SPU => 23,
            ElfArch::V800 => 36,
            ElfArch::FR20 => 37,
            ElfArch::RH32 => 38,
            ElfArch::RCE => 39,
            ElfArch::AArch32 => 40,
            ElfArch::Alpha => 41,
            ElfArch::SuperH => 42,
            ElfArch::SPARCv9 => 43,
            ElfArch::TriCore => 44,
            ElfArch::ARC => 45,
            ElfArch::H8_300 => 46,
            ElfArch::H8_300_H => 47,
            ElfArch::H8S => 48,
            ElfArch::H8_500 => 49,
            ElfArch::IA64 => 50,
            ElfArch::MIPS_X => 51,
            ElfArch::ColdFire => 52,
            ElfArch::M68HC12 => 53,
            ElfArch::MMA => 54,
            ElfArch::PCP => 55,
            ElfArch::NCPU => 56,
            ElfArch::NDR1 => 57,
            ElfArch::StarCore => 58,
            ElfArch::ME16 => 59,
            ElfArch::ST100 => 60,
            ElfArch::TinyJ => 61,
            ElfArch::X86_64 => 62,
            ElfArch::DSP => 63,
            ElfArch::PDP10 => 64,
            ElfArch::PDP11 => 65,
            ElfArch::FX66 => 66,
            ElfArch::ST9Plus => 67,
            ElfArch::ST7 => 68,
            ElfArch::MC68HC16 => 69,
            ElfArch::MC68HC11 => 70,
            ElfArch::MC68HC08 => 71,
            ElfArch::MC68HC05 => 72,
            ElfArch::SVX => 73,
            ElfArch::ST19 => 74,
            ElfArch::VAX => 75,
            ElfArch::CRIS => 76,
            ElfArch::Javelin => 77,
            ElfArch::Firepath => 78,
            ElfArch::ZSP => 79,
            ElfArch::MMIX => 80,
            ElfArch::HUMIO => 81,
            ElfArch::Prism => 82,
            ElfArch::AVR => 83,
            ElfArch::FR30 => 84,
            ElfArch::D10V => 85,
            ElfArch::D30V => 86,
            ElfArch::V850 => 87,
            ElfArch::M32R => 88,
            ElfArch::MN10300 => 89,
            ElfArch::MN10200 => 90,
            ElfArch::PicoJava => 91,
            ElfArch::OpenRISC => 92,
            ElfArch::ARCompact => 93,
            ElfArch::Xtensa => 94,
            ElfArch::VideoCore => 95,
            ElfArch::GPP => 96,
            ElfArch::NS32000 => 97,
            ElfArch::TPC => 98,
            ElfArch::SNP1000 => 99,
            ElfArch::ST200 => 100,
            ElfArch::IP2k => 101,
            ElfArch::MAX => 102,
            ElfArch::CompactRISC => 103,
            ElfArch::F2MC16 => 104,
            ElfArch::MSP430 => 105,
            ElfArch::Blackfin => 106,
            ElfArch::S1C33 => 107,
            ElfArch::Sharp => 108,
            ElfArch::Arca => 109,
            ElfArch::Unicore => 110,
            ElfArch::EXcess => 111,
            ElfArch::DXP => 112,
            ElfArch::Nios2 => 113,
            ElfArch::CRX => 114,
            ElfArch::XGATE => 115,
            ElfArch::C16x => 116,
            ElfArch::M16C => 117,
            ElfArch::DSPIC30F => 118,
            ElfArch::FCE => 119,
            ElfArch::M32C => 120,
            ElfArch::TSK3000 => 131,
            ElfArch::RS08 => 132,
            ElfArch::SHARC => 133,
            ElfArch::ECOG2 => 134,
            ElfArch::SPlusCore7 => 135,
            ElfArch::DSP24 => 136,
            ElfArch::VideoCore3 => 137,
            ElfArch::Lattice => 138,
            ElfArch::C17 => 139,
            ElfArch::TMS320C6000 => 140,
            ElfArch::TMS320C2000 => 141,
            ElfArch::TMS320C5500 => 142,
            ElfArch::APR32 => 143,
            ElfArch::PRU => 144,
            ElfArch::MMDSPPlus => 160,
            ElfArch::CypressM8C => 161,
            ElfArch::R32C => 162,
            ElfArch::TriMedia => 163,
            ElfArch::Hexagon => 164,
            ElfArch::I8051 => 165,
            ElfArch::STxP7x => 166,
            ElfArch::NDS32 => 167,
            ElfArch::ECOG1X => 168,
            ElfArch::MAXQ30 => 169,
            ElfArch::XIM016 => 170,
            ElfArch::M2000 => 171,
            ElfArch::NV2 => 172,
            ElfArch::RX => 173,
            ElfArch::METAG => 174,
            ElfArch::Elbrus => 175,
            ElfArch::ECOG16 => 176,
            ElfArch::CR16 => 177,
            ElfArch::ETPU => 178,
            ElfArch::SLE9X => 179,
            ElfArch::L10M => 180,
            ElfArch::K10M => 181,
            ElfArch::AArch64 => 183,
            ElfArch::AVR32 => 185,
            ElfArch::STM8 => 186,
            ElfArch::TILE64 => 187,
            ElfArch::TILEPro => 188,
            ElfArch::MicroBlaze => 189,
            ElfArch::CUDA => 190,
            ElfArch::TILEGx => 191,
            ElfArch::CloudShield => 192,
            ElfArch::CoreA1 => 193,
            ElfArch::CoreA2 => 194,
            ElfArch::ARCompactV2 => 195,
            ElfArch::Open8 => 196,
            ElfArch::RL78 => 197,
            ElfArch::VideoCore5 => 198,
            ElfArch::R78KOR => 199,
            ElfArch::F56800EX => 200,
            ElfArch::BA1 => 201,
            ElfArch::BA2 => 202,
            ElfArch::XCORE => 203,
            ElfArch::PICr => 204,
            ElfArch::KM32 => 210,
            ElfArch::KMX32 => 211,
            ElfArch::KMX16 => 212,
            ElfArch::KMX8 => 213,
            ElfArch::KVARC => 214,
            ElfArch::CDP => 215,
            ElfArch::COGE => 216,
            ElfArch::CoolEngine => 217,
            ElfArch::NORC => 218,
            ElfArch::Kalimba => 219,
            ElfArch::Z80 => 220,
            ElfArch::VISIUMcore => 221,
            ElfArch::FT32 => 222,
            ElfArch::Moxie => 223,
            ElfArch::AMDGPU => 224,
            ElfArch::RISCV => 243,
            ElfArch::Lanai => 244,
            ElfArch::BPF => 247,
            ElfArch::SXAuroraVE => 251,
            ElfArch::Other(code) => code
        }
    }
}

impl From<u16> for ElfArch {
    fn from(abi: u16) -> ElfArch {
        match abi {
            0 => ElfArch::None,
            1 => ElfArch::We32100,
            2 => ElfArch::SPARC,
            3 => ElfArch::I386,
            4 => ElfArch::M68K,
            5 => ElfArch::M88K,
            6 => ElfArch::IMCU,
            7 => ElfArch::I860,
            8 => ElfArch::MIPS,
            9 => ElfArch::System370,
            10 => ElfArch::MIPS_RS4000_BE,
            15 => ElfArch::PARISC,
            17 => ElfArch::VPP5500,
            18 => ElfArch::SPARC32Plus,
            19 => ElfArch::I960,
            20 => ElfArch::PowerPC,
            21 => ElfArch::PowerPC64,
            22 => ElfArch::System390,
            23 => ElfArch::SPU,
            36 => ElfArch::V800,
            37 => ElfArch::FR20,
            38 => ElfArch::RH32,
            39 => ElfArch::RCE,
            40 => ElfArch::AArch32,
            41 => ElfArch::Alpha,
            42 => ElfArch::SuperH,
            43 => ElfArch::SPARCv9,
            44 => ElfArch::TriCore,
            45 => ElfArch::ARC,
            46 => ElfArch::H8_300,
            47 => ElfArch::H8_300_H,
            48 => ElfArch::H8S,
            49 => ElfArch::H8_500,
            50 => ElfArch::IA64,
            51 => ElfArch::MIPS_X,
            52 => ElfArch::ColdFire,
            53 => ElfArch::M68HC12,
            54 => ElfArch::MMA,
            55 => ElfArch::PCP,
            56 => ElfArch::NCPU,
            57 => ElfArch::NDR1,
            58 => ElfArch::StarCore,
            59 => ElfArch::ME16,
            60 => ElfArch::ST100,
            61 => ElfArch::TinyJ,
            62 => ElfArch::X86_64,
            63 => ElfArch::DSP,
            64 => ElfArch::PDP10,
            65 => ElfArch::PDP11,
            66 => ElfArch::FX66,
            67 => ElfArch::ST9Plus,
            68 => ElfArch::ST7,
            69 => ElfArch::MC68HC16,
            70 => ElfArch::MC68HC11,
            71 => ElfArch::MC68HC08,
            72 => ElfArch::MC68HC05,
            73 => ElfArch::SVX,
            74 => ElfArch::ST19,
            75 => ElfArch::VAX,
            76 => ElfArch::CRIS,
            77 => ElfArch::Javelin,
            78 => ElfArch::Firepath,
            79 => ElfArch::ZSP,
            80 => ElfArch::MMIX,
            81 => ElfArch::HUMIO,
            82 => ElfArch::Prism,
            83 => ElfArch::AVR,
            84 => ElfArch::FR30,
            85 => ElfArch::D10V,
            86 => ElfArch::D30V,
            87 => ElfArch::V850,
            88 => ElfArch::M32R,
            89 => ElfArch::MN10300,
            90 => ElfArch::MN10200,
            91 => ElfArch::PicoJava,
            92 => ElfArch::OpenRISC,
            93 => ElfArch::ARCompact,
            94 => ElfArch::Xtensa,
            95 => ElfArch::VideoCore,
            96 => ElfArch::GPP,
            97 => ElfArch::NS32000,
            98 => ElfArch::TPC,
            99 => ElfArch::SNP1000,
            100 => ElfArch::ST200,
            101 => ElfArch::IP2k,
            102 => ElfArch::MAX,
            103 => ElfArch::CompactRISC,
            104 => ElfArch::F2MC16,
            105 => ElfArch::MSP430,
            106 => ElfArch::Blackfin,
            107 => ElfArch::S1C33,
            108 => ElfArch::Sharp,
            109 => ElfArch::Arca,
            110 => ElfArch::Unicore,
            111 => ElfArch::EXcess,
            112 => ElfArch::DXP,
            113 => ElfArch::Nios2,
            114 => ElfArch::CRX,
            115 => ElfArch::XGATE,
            116 => ElfArch::C16x,
            117 => ElfArch::M16C,
            118 => ElfArch::DSPIC30F,
            119 => ElfArch::FCE,
            120 => ElfArch::M32C,
            131 => ElfArch::TSK3000,
            132 => ElfArch::RS08,
            133 => ElfArch::SHARC,
            134 => ElfArch::ECOG2,
            135 => ElfArch::SPlusCore7,
            136 => ElfArch::DSP24,
            137 => ElfArch::VideoCore3,
            138 => ElfArch::Lattice,
            139 => ElfArch::C17,
            140 => ElfArch::TMS320C6000,
            141 => ElfArch::TMS320C2000,
            142 => ElfArch::TMS320C5500,
            143 => ElfArch::APR32,
            144 => ElfArch::PRU,
            160 => ElfArch::MMDSPPlus,
            161 => ElfArch::CypressM8C,
            162 => ElfArch::R32C,
            163 => ElfArch::TriMedia,
            164 => ElfArch::Hexagon,
            165 => ElfArch::I8051,
            166 => ElfArch::STxP7x,
            167 => ElfArch::NDS32,
            168 => ElfArch::ECOG1X,
            169 => ElfArch::MAXQ30,
            170 => ElfArch::XIM016,
            171 => ElfArch::M2000,
            172 => ElfArch::NV2,
            173 => ElfArch::RX,
            174 => ElfArch::METAG,
            175 => ElfArch::Elbrus,
            176 => ElfArch::ECOG16,
            177 => ElfArch::CR16,
            178 => ElfArch::ETPU,
            179 => ElfArch::SLE9X,
            180 => ElfArch::L10M,
            181 => ElfArch::K10M,
            183 => ElfArch::AArch64,
            185 => ElfArch::AVR32,
            186 => ElfArch::STM8,
            187 => ElfArch::TILE64,
            188 => ElfArch::TILEPro,
            189 => ElfArch::MicroBlaze,
            190 => ElfArch::CUDA,
            191 => ElfArch::TILEGx,
            192 => ElfArch::CloudShield,
            193 => ElfArch::CoreA1,
            194 => ElfArch::CoreA2,
            195 => ElfArch::ARCompactV2,
            196 => ElfArch::Open8,
            197 => ElfArch::RL78,
            198 => ElfArch::VideoCore5,
            199 => ElfArch::R78KOR,
            200 => ElfArch::F56800EX,
            201 => ElfArch::BA1,
            202 => ElfArch::BA2,
            203 => ElfArch::XCORE,
            204 => ElfArch::PICr,
            210 => ElfArch::KM32,
            211 => ElfArch::KMX32,
            212 => ElfArch::KMX16,
            213 => ElfArch::KMX8,
            214 => ElfArch::KVARC,
            215 => ElfArch::CDP,
            216 => ElfArch::COGE,
            217 => ElfArch::CoolEngine,
            218 => ElfArch::NORC,
            219 => ElfArch::Kalimba,
            220 => ElfArch::Z80,
            221 => ElfArch::VISIUMcore,
            222 => ElfArch::FT32,
            223 => ElfArch::Moxie,
            224 => ElfArch::AMDGPU,
            243 => ElfArch::RISCV,
            244 => ElfArch::Lanai,
            247 => ElfArch::BPF,
            251 => ElfArch::SXAuroraVE,
            code => ElfArch::Other(code)
        }
    }
}

impl ElfByteOrder for LittleEndian {
    const BYTE_ORDER_CODE: u8 = 1;
}

impl ElfByteOrder for BigEndian {
    const BYTE_ORDER_CODE: u8 = 2;
}

impl ElfClass for Elf32 {
    type Half = u16;
    type Word = u32;
    type Addr = u32;
    type Offset = u32;
    type Addend = i32;

    const HALF_SIZE: usize = 0x2;
    const WORD_SIZE: usize = 0x4;
    const WORD_ALIGN: Self::Offset = 0x4;
    const ADDR_SIZE: usize = 0x4;
    const ADDR_ALIGN: Self::Offset = 0x4;
    const OFFSET_SIZE: usize = 0x4;
    const OFFSET_ALIGN: Self::Offset = 0x4;
    const ADDEND_SIZE: usize = 0x4;

    const TYPE_CODE: u8 = 1;

    #[inline]
    fn read_half<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Half {
        B::read_u16(data)
    }

    #[inline]
    fn read_word<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Word {
        B::read_u32(data)
    }

    #[inline]
    fn read_addr<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Addr {
        B::read_u32(data)
    }

    #[inline]
    fn read_offset<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Offset {
        B::read_u32(data)
    }

    #[inline]
    fn read_addend<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Addend {
        B::read_i32(data)
    }

    #[inline]
    fn write_half<B: ByteOrder>(data: &mut [u8], val: Self::Half,
                                _byteorder: PhantomData<B>) {
        B::write_u16(data, val)
    }

    #[inline]
    fn write_word<B: ByteOrder>(data: &mut [u8], val: Self::Word,
                                _byteorder: PhantomData<B>) {
        B::write_u32(data, val)
    }

    #[inline]
    fn write_addr<B: ByteOrder>(data: &mut [u8], val: Self::Addr,
                                _byteorder: PhantomData<B>) {
        B::write_u32(data, val)
    }

    #[inline]
    fn write_offset<B: ByteOrder>(data: &mut [u8], val: Self::Offset,
                                  _byteorder: PhantomData<B>) {
        B::write_u32(data, val)
    }

    #[inline]
    fn write_addend<B: ByteOrder>(data: &mut [u8], val: Self::Addend,
                                  _byteorder: PhantomData<B>) {
        B::write_i32(data, val)
    }
}

impl ElfClass for Elf64 {
    type Half = u16;
    type Word = u32;
    type Addr = u64;
    type Offset = u64;
    type Addend = i64;

    const HALF_SIZE: usize = 0x2;
    const WORD_SIZE: usize = 0x4;
    const WORD_ALIGN: Self::Offset = 0x4;
    const ADDR_SIZE: usize = 0x8;
    const ADDR_ALIGN: Self::Offset = 0x8;
    const OFFSET_SIZE: usize = 0x8;
    const OFFSET_ALIGN: Self::Offset = 0x8;
    const ADDEND_SIZE: usize = 0x8;

    const TYPE_CODE: u8 = 2;

    #[inline]
    fn read_half<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Half {
        B::read_u16(data)
    }

    #[inline]
    fn read_word<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Word {
        B::read_u32(data)
    }

    #[inline]
    fn read_addr<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Addr {
        B::read_u64(data)
    }

    #[inline]
    fn read_offset<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Offset {
        B::read_u64(data)
    }

    #[inline]
    fn read_addend<B: ByteOrder>(data: &[u8], _byteorder: PhantomData<B>) ->
        Self::Addend {
        B::read_i64(data)
    }

    #[inline]
    fn write_half<B: ByteOrder>(data: &mut [u8], val: Self::Half,
                                _byteorder: PhantomData<B>) {
        B::write_u16(data, val)
    }

    #[inline]
    fn write_word<B: ByteOrder>(data: &mut [u8], val: Self::Word,
                                _byteorder: PhantomData<B>) {
        B::write_u32(data, val)
    }

    #[inline]
    fn write_addr<B: ByteOrder>(data: &mut [u8], val: Self::Addr,
                                _byteorder: PhantomData<B>) {
        B::write_u64(data, val)
    }

    #[inline]
    fn write_offset<B: ByteOrder>(data: &mut [u8], val: Self::Offset,
                                  _byteorder: PhantomData<B>) {
        B::write_u64(data, val)
    }

    #[inline]
    fn write_addend<B: ByteOrder>(data: &mut [u8], val: Self::Addend,
                                  _byteorder: PhantomData<B>) {
        B::write_i64(data, val)
    }
}

impl ElfHdrOffsets for Elf32 {
    const E_TYPE_SIZE: usize = Self::HALF_SIZE;
    const E_MACHINE_SIZE: usize = Self::HALF_SIZE;
    const E_VERSION_SIZE: usize = Self::WORD_SIZE;
    const E_FLAGS_SIZE: usize = Self::WORD_SIZE;
    const E_EHSIZE_SIZE: usize = Self::HALF_SIZE;
    const E_PHENTSIZE_SIZE: usize = Self::HALF_SIZE;
    const E_PHNUM_SIZE: usize = Self::HALF_SIZE;
    const E_SHENTSIZE_SIZE: usize = Self::HALF_SIZE;
    const E_SHNUM_SIZE: usize = Self::HALF_SIZE;
    const E_SHSTRTAB_SIZE: usize = Self::HALF_SIZE;
    const ELF_HDR_SIZE_HALF: Self::Half = Self::ELF_HDR_SIZE as u16;
}

impl ElfHdrOffsets for Elf64 {
    const E_TYPE_SIZE: usize = Self::HALF_SIZE;
    const E_MACHINE_SIZE: usize = Self::HALF_SIZE;
    const E_VERSION_SIZE: usize = Self::WORD_SIZE;
    const E_FLAGS_SIZE: usize = Self::WORD_SIZE;
    const E_EHSIZE_SIZE: usize = Self::HALF_SIZE;
    const E_PHENTSIZE_SIZE: usize = Self::HALF_SIZE;
    const E_PHNUM_SIZE: usize = Self::HALF_SIZE;
    const E_SHENTSIZE_SIZE: usize = Self::HALF_SIZE;
    const E_SHNUM_SIZE: usize = Self::HALF_SIZE;
    const E_SHSTRTAB_SIZE: usize = Self::HALF_SIZE;
    const ELF_HDR_SIZE_HALF: Self::Half = Self::ELF_HDR_SIZE as u16;
}
