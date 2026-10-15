from pwndbg_imgui.ui.catalog import arg_regs


def test_arg_regs_by_gdb_architecture_name():
    assert arg_regs("i386:x86-64")[0] == "$rdi"
    assert arg_regs("i386")[0] == "$eax"  # not shadowed by the x86-64 entry
    assert arg_regs("aarch64")[0] == "$x0"
    assert arg_regs("arm")[0] == "$r0"
    assert arg_regs("armv7")[0] == "$r0"
    assert arg_regs("mips:isa32r2")[0] == "$a0"
    assert arg_regs("riscv:rv64")[0] == "$a0"
    assert arg_regs("sparc") == () and arg_regs(None) == ()
