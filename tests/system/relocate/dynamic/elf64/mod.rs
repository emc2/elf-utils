use byteorder::LittleEndian;
use crate::data::dynamic::x86_64::PATH;
use crate::data::dynamic::x86_64::RELOC_PATH;
use crate::system::relocate::load_and_reloc;
use elf_utils::Elf64;
use elf_utils::reloc::x86_64::X86_64RelRawSym;
use elf_utils::reloc::x86_64::X86_64RelaRawSym;
use std::fs::read;

#[test]
fn relocate_test() {
    let data = read(PATH).expect("expected success");
    let data = data.as_slice();
    let actual = load_and_reloc::<LittleEndian, Elf64, X86_64RelRawSym,
                                  X86_64RelaRawSym>(0xba5e0000, data);
    let expected = read(RELOC_PATH).expect("expected success");

    assert_eq!(expected, actual);
}
