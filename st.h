/* See LICENSE for license details. */
#ifndef __ST_HEADER__
#define __ST_HEADER__

#include <X11/X.h>
#include <X11/XKBlib.h>
#include <X11/Xatom.h>
#include <X11/Xft/Xft.h>
#include <X11/Xlib.h>
#include <X11/Xresource.h>
#include <X11/cursorfont.h>
#include <X11/keysym.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include <stdint.h>
#include <sys/types.h>

/* macros */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define LEN(a) (sizeof(a) / sizeof(a)[0])
#define BETWEEN(x, a, b) \
    (((size_t)a) <= ((size_t)x) && ((size_t)x) <= ((size_t)b))
#define DIVCEIL(n, d) (((n) + ((d)-1)) / (d))
#define DEFAULT(a, b) (a) = (a) ? (a) : (b)
#define LIMIT(x, a, b) (x) = (x) < (a) ? (a) : (x) > (b) ? (b) : (x)
#define ATTRCMP(a, b)                                          \
    (((a).mode & (~ATTR_WRAP)) != ((b).mode & (~ATTR_WRAP)) || \
     (a).fg != (b).fg || (a).bg != (b).bg)
#define TIMEDIFF(t1, t2) \
    ((t1.tv_sec - t2.tv_sec) * 1000 + (t1.tv_nsec - t2.tv_nsec) / 1E6)
#define MODBIT(x, set, bit) ((set) ? ((x) |= (bit)) : ((x) &= ~(bit)))

#define TRUECOLOR(r, g, b) (1 << 24 | (r) << 16 | (g) << 8 | (b))
#define IS_TRUECOL(x) (1 << 24 & (x))

typedef unsigned char  uchar;
typedef unsigned int   uint;
typedef unsigned long  ulong;
typedef unsigned short ushort;

typedef uint_least32_t Rune;

#define Glyph Glyph_

typedef union {
    int         i;
    uint        ui;
    float       f;
    const void* v;
    const char* s;
} Arg;

/* types used in config.h */
typedef struct {
    uint   mod;
    KeySym keysym;
    void (*func)(const Arg*);
    const Arg arg;
} Shortcut;

typedef struct {
    uint mod;
    uint button;
    void (*func)(const Arg*);
    const Arg arg;
    uint      release;
    int       altscrn; /* 0: don't care, -1: not alt screen, 1: alt screen */
} MouseShortcut;

typedef struct {
    KeySym k;
    uint   mask;
    char*  s;
    /* three-valued logic variables: 0 indifferent, 1 on, -1 off */
    signed char appkey;    /* application keypad */
    signed char appcursor; /* application cursor */
} Key;

/* X modifiers */
#define XK_ANY_MOD UINT_MAX
#define XK_NO_MOD 0
#define XK_SWITCH_MOD (1 << 13 | 1 << 14)

enum glyph_attribute {
    ATTR_NULL       = 0,
    ATTR_BOLD       = 1 << 0,
    ATTR_FAINT      = 1 << 1,
    ATTR_ITALIC     = 1 << 2,
    ATTR_UNDERLINE  = 1 << 3,
    ATTR_BLINK      = 1 << 4,
    ATTR_REVERSE    = 1 << 5,
    ATTR_INVISIBLE  = 1 << 6,
    ATTR_STRUCK     = 1 << 7,
    ATTR_WRAP       = 1 << 8,
    ATTR_WIDE       = 1 << 9,
    ATTR_WDUMMY     = 1 << 10,
    ATTR_BOLD_FAINT = ATTR_BOLD | ATTR_FAINT,
};

enum drawing_mode {
    DRAW_NONE = 0,
    DRAW_BG   = 1 << 0,
    DRAW_FG   = 1 << 1,
};

enum selection_mode { SEL_IDLE = 0, SEL_EMPTY = 1, SEL_READY = 2 };

enum selection_type { SEL_REGULAR = 1, SEL_RECTANGULAR = 2 };

enum selection_snap { SNAP_WORD = 1, SNAP_LINE = 2 };

typedef struct {
    Rune     u;    /* character code */
    ushort   mode; /* attribute flags */
    uint32_t fg;   /* foreground  */
    uint32_t bg;   /* background  */
} Glyph;

typedef Glyph* Line;

void die(const char*, ...);
void redraw(void);
void draw(void);

void kscrolldown(const Arg*);
void kscrollup(const Arg*);
void printscreen(const Arg*);
void printsel(const Arg*);
void sendbreak(const Arg*);
void toggleprinter(const Arg*);

int    tattrset(int);
int    tisaltscr(void);
void   tnew(int, int);
void   tresize(int, int);
void   tsetdirtattr(int);
void   ttyhangup(void);
int    ttynew(const char*, char*, const char*, char**);
size_t ttyread(void);
void   ttyresize(int, int);
void   ttywrite(const char*, size_t, int);

void resettitle(void);

void  selclear(void);
void  selinit(void);
void  selstart(int, int, int);
void  selextend(int, int, int, int);
int   selected(int, int);
char* getsel(void);

size_t utf8encode(Rune, char*);

void* xmalloc(size_t);
void* xrealloc(void*, size_t);
char* xstrdup(const char*);

/* function definitions used in config.h */
void clipcopy(const Arg*);
void clippaste(const Arg*);
void numlock(const Arg*);
void selpaste(const Arg*);
void zoom(const Arg*);
void zoomabs(const Arg*);
void zoomreset(const Arg*);
void ttysend(const Arg*);

/* config.h globals */
extern char*        utmp;
extern char*        scroll;
extern char*        stty_args;
extern char*        vtiden;
extern wchar_t*     worddelimiters;
extern int          allowaltscreen;
extern int          allowwindowops;
extern char*        termname;
extern unsigned int tabspaces;
extern unsigned int defaultfg;
extern unsigned int defaultbg;
extern unsigned int defaultcs;
#define IGNORE(_ARG) (void)(_ARG)

typedef enum {
    XRES_STRING = 0,
    XRES_INT    = 1,
    XRES_FLOAT  = 2,
} xres_t;

typedef struct {
    const char* name;
    xres_t      type;
    void*       dst;
} xres_pref_t;

#endif // define __ST_HEADER__
