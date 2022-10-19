use core::convert::TryInto;
use crate::elf::ElfClass;
use crate::prog_hdr::ProgHdrData;

pub struct LoadBuf<'a, Class: ElfClass> {
    /// Underlying memory buffer.
    mem: &'a mut [u8],
    /// Base address.
    base: Class::Addr,
    /// Adjustment to the address specified by ELF data.
    orig_addr: Class::Addr
}

pub enum LoadErr<Class: ElfClass> {
    /// The program header doesn't represent a loadable segment.
    BadHdr,
    /// Memory size could not be converted to a `usize`.
    ///
    /// This should only happen if loading a 64-bit ELF on a 32-bit
    /// architecture.
    BadMemSize(Class::Offset),
    /// The memory buffer is too small to hold the segment data.
    TooShort(usize)
}

enum SegmentOrdering<'a, Class: ElfClass> {
    Less,
    Equal(&'a LoadBuf<'a, Class>),
    Greater
}

impl<'a, Class: ElfClass> LoadBuf<'a, Class> {
    /// Create a `LoadBuf` from a memory buffer and a base address.
    ///
    /// Note: this does not guarantee that the base address matches
    /// the memory buffer.  If this is needed, it is recommended to
    /// use [from_slice](LoadBuf::from_slice) instead.
    #[inline]
    pub fn new(mem: &'a mut [u8], base: Class::Addr) -> LoadBuf<'a, Class> {
        LoadBuf { mem: mem, base: base, orig_addr: (0 as u8).into() }
    }

    /// Create a `LoadBuf` from a memory buffer.
    ///
    /// The base address will be set from the address of the memory
    /// buffer.  If a different base address is desired,
    /// [new](LoadBuf::new) should be used instead.
    #[inline]
    pub fn from_slice(mem: &'a mut [u8]) -> LoadBuf<'a, Class> {
        Self::new(mem, Class::from_ptr(mem.as_ptr()))
    }

    /// Attempt to load data from a [ProgHdrData] into this `LoadBuf`.
    #[inline]
    pub fn load<S, D>(&mut self, hdr: ProgHdrData<Class, &'a [u8], S, D>) ->
        Result<(), LoadErr<Class>> {
        match hdr {
            ProgHdrData::Load { content, mem_size, virt_addr, .. } =>
                match mem_size.try_into() {
                    Ok(mem_size) => if self.mem.len() >= mem_size {
                        self.mem.clone_from_slice(content);
                        // Generate the adjustment.
                        self.orig_addr = virt_addr;

                        Ok(())
                    } else {
                        Err(LoadErr::TooShort(mem_size))
                    },
                    Err(_) => Err(LoadErr::BadMemSize(mem_size))
                }
            _ => Err(LoadErr::BadHdr)
        }
    }

    #[inline]
    pub fn sort(arr: &mut [Self]) {
        arr.sort_unstable_by(|a, b| a.base.cmp(&b.base))
    }

    #[inline]
    fn search(&'a self, section_addr: Class::Addr) ->
        Result<SegmentOrdering<'a, Class>, usize> {
        let len = self.mem.len();

        match len.try_into() {
            Ok(mem_size) => {
                if self.orig_addr > section_addr {
                    Ok(SegmentOrdering::Less)
                } else if section_addr > self.orig_addr + mem_size {
                    Ok(SegmentOrdering::Greater)
                } else {
                    Ok(SegmentOrdering::Equal(&self))
                }
            },
            Err(_) => Err(len)
        }
    }

    pub fn load_offset(&self, section_addr: Class::Addr) ->
        Result<Option<Class::Addend>, usize> {
        match self.search(section_addr) {
            Ok(SegmentOrdering::Equal(buf)) => {
                Ok(Some(Class::addr_diff(buf.orig_addr, section_addr)))
            }
            Err(err) => Err(err),
            _ => Ok(None)
        }
    }

}
