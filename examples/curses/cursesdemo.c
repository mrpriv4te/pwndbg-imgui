/* A full-screen ncurses program, to try pwndbg-imgui --terminal-io: it draws in the
 * terminal that started the GUI, reads keys there and follows its resizes.
 *
 *   make curses && cd curses && pwndbg-imgui --terminal-io ./cursesdemo
 *
 * Arrow keys move the marker, q quits. Break on on_key() to stop at each key press.
 * With $CURSES_LOG set, every event is also appended to that file (used by check.py). */
#include <curses.h>
#include <stdio.h>
#include <stdlib.h>

static FILE *event_log;
static int y = 1, x = 1, keys;

static void note(const char *what)
{
    if (event_log) {
        fprintf(event_log, "%s rows=%d cols=%d term=%s\n", what, LINES, COLS, getenv("TERM"));
        fflush(event_log);
    }
}

static void draw(const char *last)
{
    erase();
    box(stdscr, 0, 0);
    mvprintw(0, 2, " cursesdemo: %dx%d terminal ", COLS, LINES);
    mvprintw(LINES - 1, 2, " arrows: move   q: quit   keys so far: %d   last: %s ", keys, last);
    if (y > LINES - 2) y = LINES - 2;
    if (x > COLS - 2) x = COLS - 2;
    mvaddch(y, x, ACS_DIAMOND);
    refresh();
}

static void on_key(int c)  /* one call per key, a handy breakpoint */
{
    keys++;
    if (c == KEY_UP && y > 1) y--;
    if (c == KEY_DOWN && y < LINES - 2) y++;
    if (c == KEY_LEFT && x > 1) x--;
    if (c == KEY_RIGHT && x < COLS - 2) x++;
}

int main(void)
{
    const char *path = getenv("CURSES_LOG");
    event_log = path ? fopen(path, "a") : NULL;
    initscr();
    cbreak();  /* not raw(): Ctrl-C still interrupts, as in any terminal */
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    note("start");
    draw("-");
    for (;;) {
        int c = getch();
        if (c == 'q')
            break;
        if (c == KEY_RESIZE) {
            note("resize");
            draw("(resize)");
            continue;
        }
        on_key(c);
        char name[32];
        snprintf(name, sizeof name, "%s", keyname(c));
        if (event_log) {
            fprintf(event_log, "key %s\n", name);
            fflush(event_log);
        }
        draw(name);
    }
    endwin();
    note("end");
    return 0;
}
