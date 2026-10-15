from pwndbg_imgui.registers import register_cells

NAMES = {"rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r14", "r15", "rbp", "rsp", "rip", "eflags"}


def names(line):
    return [(line[s:e], n) for s, e, n in register_cells(line, NAMES)]


def test_one_register_per_line():
    line = "*RCX  0"
    assert register_cells(line, NAMES) == [(0, len(line), "rcx")]
    assert names(" RAX  0x7ffff7e045c0 (_IO_2_1_stdout_) ◂— 0xfbad2084") == [
        ("RAX  0x7ffff7e045c0 (_IO_2_1_stdout_) ◂— 0xfbad2084", "rax")]


def test_two_columns():
    # show-compact-regs with 2 columns: each cell is found separately
    line = "*RAX  0                       RBX  0x7fffffffcfe8 —▸ 0x7fffffffd4da"
    cells = names(line)
    assert cells == [("*RAX  0", "rax"), ("RBX  0x7fffffffcfe8 —▸ 0x7fffffffd4da", "rbx")]


def test_second_column_marker_is_part_of_its_cell():
    line = " R8   0                       *R9   0x7ffff7fca380 ◂— endbr64"
    assert names(line) == [("R8   0", "r8"), ("*R9   0x7ffff7fca380 ◂— endbr64", "r9")]


def test_values_mentioning_registers_are_not_cells():
    # pwndbg annotates with lowercase instructions and symbols; neither starts a cell
    line = " RDI  0x401136 (main+20) ◂— mov rdi, rax      RSI  1"
    assert names(line) == [("RDI  0x401136 (main+20) ◂— mov rdi, rax", "rdi"), ("RSI  1", "rsi")]
    assert names(" R14  0x403e00 (RAX_table) ◂— 0") == [("R14  0x403e00 (RAX_table) ◂— 0", "r14")]


def test_wrapped_register():
    # a value too wide for its column: pwndbg prints `NAME  ⏎` and the value on a `↪` line
    assert names(" RAX  0                       R15  ⏎") == [("RAX  0", "rax"), ("R15  ⏎", "r15")]
    assert names("↪ R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0") == [
        ("R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0", "r15")]


def test_custom_marker_and_flags():
    assert names("!!RIP  0x40116a (main+20)    EFLAGS 0x246 [ cf PF af ZF sf IF df of ]") == [
        ("!!RIP  0x40116a (main+20)", "rip"), ("EFLAGS 0x246 [ cf PF af ZF sf IF df of ]", "eflags")]


def test_non_register_lines():
    assert register_cells("", NAMES) == []
    assert register_cells("─────── REGISTERS ───────", NAMES) == []
