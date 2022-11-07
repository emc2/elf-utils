use byteorder::LittleEndian;
use crate::data::dynamic::i386::PATH;
use crate::data::dynamic::i386::RELOC_PATH;
use crate::system::relocate::load_and_reloc;
use elf_utils::Elf32;
use elf_utils::reloc::x86::X86RelRawSym;
use elf_utils::reloc::x86::X86RelaRawSym;
use std::fs::read;

#[test]
fn relocate_test() {
    let data = read(PATH).expect("expected success");
    let data = data.as_slice();
    let actual = load_and_reloc::<LittleEndian, Elf32, X86RelRawSym,
                                  X86RelaRawSym>(0xba5e0000, data);
    let expected = read(RELOC_PATH).expect("expected success");

    assert_eq!(expected, actual);
}
