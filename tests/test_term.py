from pwndbg_imgui.term import _STYLES, BOLD, Term, strip_ansi


def lines(term: Term) -> list[str]:
    return [line.text for line in term.lines]


def style_at(term: Term, row: int, col: int) -> tuple[int, int, int]:
    return _STYLES[term.lines[row].styles[col]]


def test_plain_text_and_newlines():
    t = Term()
    t.feed("hello\nworld")
    assert lines(t) == ["hello", "world"]
    assert t.plain() == "hello\nworld"


def test_carriage_return_overwrites():
    t = Term()
    t.feed("abcdef\rXY")
    assert lines(t) == ["XYcdef"]


def test_backspace_moves_left():
    t = Term()
    t.feed("ab\bX")
    assert lines(t) == ["aX"]


def test_tab_expands_to_next_stop():
    t = Term()
    t.feed("ab\tc")
    assert lines(t) == ["ab      c"]


def test_sgr_basic_bright_256_and_truecolor():
    t = Term()
    t.feed("\x1b[31mr\x1b[1;92mg\x1b[38;5;200mx\x1b[48;2;1;2;3my\x1b[0mz")
    assert style_at(t, 0, 0) == (1, -1, 0)
    assert style_at(t, 0, 1) == (10, -1, BOLD)
    assert style_at(t, 0, 2) == (200, -1, BOLD)
    assert style_at(t, 0, 3) == (200, 0x1000000 | 0x010203, BOLD)
    assert style_at(t, 0, 4) == (-1, -1, 0)


def test_escape_split_across_feeds():
    t = Term()
    t.feed("ab\x1b[3")
    t.feed("1mc")
    assert lines(t) == ["abc"]
    assert style_at(t, 0, 2)[0] == 1


def test_erase_in_line():
    t = Term()
    t.feed("abcdef\r\x1b[2C\x1b[K")
    assert lines(t) == ["ab"]
    t.feed("\x1b[2K")
    assert lines(t) == [""]


def test_erase_display_clears():
    t = Term()
    t.feed("one\ntwo\x1b[2J")
    assert lines(t) == [""]


def test_scroll_up_opens_blank_lines():
    t = Term()
    t.feed("top\x1b[2Sbottom")
    assert lines(t) == ["top", "", "   bottom"]  # like a real terminal, the column is kept


def test_private_modes_and_osc_are_ignored():
    t = Term()
    t.feed("\x1b[?25l\x1b]0;window title\x07visible\x1b[?25h")
    assert lines(t) == ["visible"]


def test_control_bytes_shown_only_when_requested():
    raw = "a\x01b\udc90c"  # \udc90: an undecodable byte (surrogateescape)
    hidden, shown = Term(), Term(show_ctrl=True)
    hidden.feed(raw)
    shown.feed(raw)
    assert lines(hidden) == ["abc"]
    assert lines(shown) == ["ab\\x90c"]


def test_old_lines_are_trimmed():
    t = Term(max_lines=10)
    t.feed("".join(f"line {i}\n" for i in range(25)))
    assert len(t.lines) <= 10
    assert t.trimmed > 0
    assert t.lines[-2].text == "line 24"


def test_set_text_replaces_content():
    t = Term()
    t.feed("old")
    t.set_text("new")
    assert lines(t) == ["new"]


def test_strip_ansi():
    assert strip_ansi("\x1b[1;31mred\x1b[0m\tok\n") == "red\tok\n"
