#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define FLEXIBLE_ARRAY_MEMBER /**/
#define FALLTHROUGH __attribute__((__fallthrough__))
#define HOUR(x) (60 * 60 * (x))
#define _C_CTYPE_LOWER_A_THRU_F_N(N)                                           \
  case 'a' + (N):                                                              \
  case 'b' + (N):                                                              \
  case 'c' + (N):                                                              \
  case 'd' + (N):                                                              \
  case 'e' + (N):                                                              \
  case 'f' + (N)
#define _C_CTYPE_LOWER_N(N)                                                    \
  _C_CTYPE_LOWER_A_THRU_F_N(N) : case 'g' + (N) :                              \
  case 'h' + (N):                                                              \
  case 'i' + (N):                                                              \
  case 'j' + (N):                                                              \
  case 'k' + (N):                                                              \
  case 'l' + (N):                                                              \
  case 'm' + (N):                                                              \
  case 'n' + (N):                                                              \
  case 'o' + (N):                                                              \
  case 'p' + (N):                                                              \
  case 'q' + (N):                                                              \
  case 'r' + (N):                                                              \
  case 's' + (N):                                                              \
  case 't' + (N):                                                              \
  case 'u' + (N):                                                              \
  case 'v' + (N):                                                              \
  case 'w' + (N):                                                              \
  case 'x' + (N):                                                              \
  case 'y' + (N):                                                              \
  case 'z' + (N)
#define _C_CTYPE_DIGIT                                                         \
  case '0':                                                                    \
  case '1':                                                                    \
  case '2':                                                                    \
  case '3':                                                                    \
  case '4':                                                                    \
  case '5':                                                                    \
  case '6':                                                                    \
  case '7':                                                                    \
  case '8':                                                                    \
  case '9'
#define _C_CTYPE_LOWER _C_CTYPE_LOWER_N(0)
#define _C_CTYPE_PUNCT                                                         \
  case '!':                                                                    \
  case '"':                                                                    \
  case '#':                                                                    \
  case '$':                                                                    \
  case '%':                                                                    \
  case '&':                                                                    \
  case '\'':                                                                   \
  case '(':                                                                    \
  case ')':                                                                    \
  case '*':                                                                    \
  case '+':                                                                    \
  case ',':                                                                    \
  case '-':                                                                    \
  case '.':                                                                    \
  case '/':                                                                    \
  case ':':                                                                    \
  case ';':                                                                    \
  case '<':                                                                    \
  case '=':                                                                    \
  case '>':                                                                    \
  case '?':                                                                    \
  case '@':                                                                    \
  case '[':                                                                    \
  case '\\':                                                                   \
  case ']':                                                                    \
  case '^':                                                                    \
  case '_':                                                                    \
  case '`':                                                                    \
  case '{':                                                                    \
  case '|':                                                                    \
  case '}':                                                                    \
  case '~'
#define _C_CTYPE_UPPER _C_CTYPE_LOWER_N('A' - 'a')

enum { LOG10_BILLION = 9 };
inline bool c_isalnum(int c) {
  switch (c) {
  _C_CTYPE_DIGIT:
  _C_CTYPE_LOWER:
  _C_CTYPE_UPPER:
    return true;
  default:
    return false;
  }
}

inline bool c_isalpha(int c) {
  switch (c) {
  _C_CTYPE_LOWER:
  _C_CTYPE_UPPER:
    return true;
  default:
    return false;
  }
}

/* The function isascii is not locale dependent.
   Its use in EBCDIC is questionable. */
inline bool c_isascii(int c) {
  switch (c) {
  case ' ':
  _C_CTYPE_CNTRL:
  _C_CTYPE_DIGIT:
  _C_CTYPE_LOWER:
  _C_CTYPE_PUNCT:
  _C_CTYPE_UPPER:
    return true;
  default:
    return false;
  }
}

inline bool c_isblank(int c) { return c == ' ' || c == '\t'; }

inline bool c_iscntrl(int c) {
  switch (c) {
  _C_CTYPE_CNTRL:
    return true;
  default:
    return false;
  }
}

inline bool c_isdigit(int c) {
  switch (c) {
  _C_CTYPE_DIGIT:
    return true;
  default:
    return false;
  }
}

inline bool c_isgraph(int c) {
  switch (c) {
  _C_CTYPE_DIGIT:
  _C_CTYPE_LOWER:
  _C_CTYPE_PUNCT:
  _C_CTYPE_UPPER:
    return true;
  default:
    return false;
  }
}

inline bool c_islower(int c) {
  switch (c) {
  _C_CTYPE_LOWER:
    return true;
  default:
    return false;
  }
}

inline bool c_isprint(int c) {
  switch (c) {
  case ' ':
  _C_CTYPE_DIGIT:
  _C_CTYPE_LOWER:
  _C_CTYPE_PUNCT:
  _C_CTYPE_UPPER:
    return true;
  default:
    return false;
  }
}

inline bool c_ispunct(int c) {
  switch (c) {
  _C_CTYPE_PUNCT:
    return true;
  default:
    return false;
  }
}

inline bool c_isspace(int c) {
  switch (c) {
  case ' ':
  case '\t':
  case '\n':
  case '\v':
  case '\f':
  case '\r':
    return true;
  default:
    return false;
  }
}

inline bool c_isupper(int c) {
  switch (c) {
  _C_CTYPE_UPPER:
    return true;
  default:
    return false;
  }
}

inline bool c_isxdigit(int c) {
  switch (c) {
  _C_CTYPE_DIGIT:
  _C_CTYPE_A_THRU_F:
    return true;
  default:
    return false;
  }
}

inline int c_tolower(int c) {
  switch (c) {
  _C_CTYPE_UPPER:
    return c - 'A' + 'a';
  default:
    return c;
  }
}

inline int c_toupper(int c) {
  switch (c) {
  _C_CTYPE_LOWER:
    return c - 'a' + 'A';
  default:
    return c;
  }
}

#define UTIME_NOW (-1)
#define UTIME_OMIT (-2)
enum {
  BILLION = 1000 * 1000 * 1000,

  Y2K = 946684800, /* Jan 1, 2000, in seconds since epoch.  */

  /* Bogus positive and negative tv_nsec values closest to valid
     range, but without colliding with UTIME_NOW or UTIME_OMIT.  */
  UTIME_BOGUS_POS = BILLION + ((UTIME_NOW == BILLION || UTIME_OMIT == BILLION)
                                   ? (1 + (UTIME_NOW == BILLION + 1) +
                                      (UTIME_OMIT == BILLION + 1))
                                   : 0),
  UTIME_BOGUS_NEG = -1 - ((UTIME_NOW == -1 || UTIME_OMIT == -1)
                              ? (1 + (UTIME_NOW == -2) + (UTIME_OMIT == -2))
                              : 0)
};

typedef ptrdiff_t idx_t;

/* A time zone rule.  */
struct tm_zone {

  struct tm_zone *next;

  char tz_is_set;

  char abbrs[FLEXIBLE_ARRAY_MEMBER];
};

enum { DEFAULT_MXFAST = 64 * sizeof(size_t) / 4 };

enum { ABBR_SIZE_MIN = DEFAULT_MXFAST - offsetof(struct tm_zone, abbrs) };

typedef struct tm_zone *timezone_t;
#define FLEXALIGNOF(type) (sizeof(type) & ~(sizeof(type) - 1))

#define nullptr NULL
#define FLEXSIZEOF(type, member, n)                                            \
  ((offsetof(type, member) + FLEXALIGNOF(type) - 1 + (n)) &                    \
   ~(FLEXALIGNOF(type) - 1))

static void extend_abbrs(char *abbrs, char const *abbr, size_t abbr_size) {
  memcpy(abbrs, abbr, abbr_size);
  abbrs[abbr_size] = '\0';
}
static timezone_t const local_tz = (timezone_t)1;

void tzfree(timezone_t tz) {
  if (tz != local_tz)
    while (tz) {
      timezone_t next = tz->next;
      free(tz);
      tz = next;
    }
}
timezone_t tzalloc(char const *name) {
  size_t name_size = name ? strlen(name) + 1 : 0;
  size_t abbr_size = name_size < ABBR_SIZE_MIN ? ABBR_SIZE_MIN : name_size + 1;
  timezone_t tz = malloc(FLEXSIZEOF(struct tm_zone, abbrs, abbr_size));
  if (tz) {
    tz->next = NULL;
#if HAVE_TZNAME && !HAVE_STRUCT_TM_TM_ZONE
    tz->tzname_copy[0] = tz->tzname_copy[1] = NULL;
#endif
    tz->tz_is_set = !!name;
    tz->abbrs[0] = '\0';
    if (name)
      extend_abbrs(tz->abbrs, name, name_size);
  }
  return tz;
}
typedef long int intmax_t;

#define INT_BITS_STRLEN_BOUND(b) (((b)*146 + 484) / 485)
#define _GL_TYPE_WIDTH(t) (sizeof(t) * CHAR_BIT)

#define TYPE_WIDTH(t) _GL_TYPE_WIDTH(t)
#define _GL_TYPE_SIGNED(t) (!((t)0 < (t)-1))

#define _GL_SIGNED_TYPE_OR_EXPR(t) _GL_TYPE_SIGNED(__typeof__(t))

#define INT_STRLEN_BOUND(t)                                                    \
  (INT_BITS_STRLEN_BOUND(TYPE_WIDTH(t) - _GL_SIGNED_TYPE_OR_EXPR(t)) +         \
   _GL_SIGNED_TYPE_OR_EXPR(t))

enum { DBGBUFSIZE = 100 };

enum { TIME_ZONE_BUFSIZE = INT_STRLEN_BOUND(intmax_t) + sizeof ":MM:SS" };
#define _GL_ARG_NONNULL(params) __attribute__((__nonnull__ params))
void gettime(struct timespec *) _GL_ARG_NONNULL((1));

static char *getenv_TZ(void) { return getenv("TZ"); }

static int setenv_TZ(char const *tz) {
  return tz ? setenv("TZ", tz, 1) : unsetenv("TZ");
}

static bool change_env(timezone_t tz) {
  if (setenv_TZ(tz->tz_is_set ? tz->abbrs : NULL) != 0)
    return false;
  tzset();
  return true;
}
void tzparse_datetime2(timezone_t tz) {
  if (tz != local_tz)
    while (tz) {
      timezone_t next = tz->next;
      free(tz);
      tz = next;
    }
}
static timezone_t set_tz(timezone_t tz) {
  char *env_tz = getenv_TZ();
  if (env_tz ? tz->tz_is_set && strcmp(tz->abbrs, env_tz) == 0 : !tz->tz_is_set)
    return local_tz;
  else {
    timezone_t old_tz = tzalloc(env_tz);
    if (!old_tz)
      return old_tz;
    if (!change_env(tz)) {
      int saved_errno = errno;
      tzfree(old_tz);
      errno = saved_errno;
      return NULL;
    }
    return old_tz;
  }
}
static bool save_abbr(timezone_t tz, struct tm *tm) {
  char const *zone = NULL;
  char *zone_copy = (char *)"";
  zone = tm->tm_zone;
  /* No need to replace null zones, or zones within the struct tm.  */
  if (!zone || ((char *)tm <= zone && zone < (char *)(tm + 1)))
    return true;

  if (*zone) {
    zone_copy = tz->abbrs;

    while (strcmp(zone_copy, zone) != 0) {
      if (!(*zone_copy || (zone_copy == tz->abbrs && tz->tz_is_set))) {
        idx_t zone_size = strlen(zone) + 1;
        if (zone_size < tz->abbrs + ABBR_SIZE_MIN - zone_copy)
          extend_abbrs(zone_copy, zone, zone_size);
        else {
          tz = tz->next = tzalloc(zone);
          if (!tz)
            return false;
          tz->tz_is_set = 0;
          zone_copy = tz->abbrs;
        }
        break;
      }

      zone_copy += strlen(zone_copy) + 1;
      if (!*zone_copy && tz->next) {
        tz = tz->next;
        zone_copy = tz->abbrs;
      }
    }
  }
  tm->tm_zone = zone_copy;
  return true;
}
static bool revert_tz(timezone_t tz) {
  if (tz == local_tz)
    return true;
  else {
    int saved_errno = errno;
    bool ok = change_env(tz);
    if (!ok)
      saved_errno = errno;
    tzfree(tz);
    errno = saved_errno;
    return ok;
  }
}
struct tm *localtime_rz(timezone_t tz, time_t const *t, struct tm *tm) {
  if (!tz)
    return gmtime_r(t, tm);
  else {
    timezone_t old_tz = set_tz(tz);
    if (old_tz) {
      bool abbr_saved = localtime_r(t, tm) && save_abbr(tz, tm);
      if (revert_tz(old_tz) && abbr_saved)
        return tm;
    }
    return NULL;
  }
}

/* Relative times.  */
typedef struct {
  /* Relative year, month, day, hour, minutes, seconds, and nanoseconds.  */
  intmax_t year;
  intmax_t month;
  intmax_t day;
  intmax_t hour;
  intmax_t minutes;
  intmax_t seconds;
  int ns;
} relative_time;
#define RELATIVE_TIME_0 ((relative_time){0, 0, 0, 0, 0, 0, 0})
typedef struct {
  char const *name;
  int type;
  int value;
} table;
typedef struct {
  bool negative;
  intmax_t value;
  idx_t digits;
} textint;
#define PARSE_DATETIME_DEBUG 1

typedef struct {
  /* The input string remaining to be parsed.  */
  const char *input;

  /* N, if this is the Nth Tuesday.  */
  intmax_t day_ordinal;

  /* Day of week; Sunday is 0.  */
  int day_number;

  /* tm_isdst flag for the local zone.  */
  int local_isdst;

  /* Time zone, in seconds east of UT.  */
  int time_zone;

  /* Style used for time.  */
  int meridian;

  /* Gregorian year, month, day, hour, minutes, seconds, and nanoseconds.  */
  textint year;
  intmax_t month;
  intmax_t day;
  intmax_t hour;
  intmax_t minutes;
  struct timespec seconds; /* includes nanoseconds */

  /* Relative year, month, day, hour, minutes, seconds, and nanoseconds.  */
  relative_time rel;

  /* Presence or counts of nonterminals of various flavors parsed so far.  */
  bool timespec_seen;
  bool rels_seen;
  idx_t dates_seen;
  idx_t days_seen;
  idx_t J_zones_seen;
  idx_t local_zones_seen;
  idx_t dsts_seen;
  idx_t times_seen;
  idx_t zones_seen;
  bool year_seen;
  bool parse_datetime_debug;

  /* Which of the 'seen' parts have been printed when debugging.  */
  bool debug_dates_seen;
  bool debug_days_seen;
  bool debug_local_zones_seen;
  bool debug_times_seen;
  bool debug_zones_seen;
  bool debug_year_seen;

  /* The user specified explicit ordinal day value.  */
  bool debug_ordinal_day_seen;

  /* Table of local time zone abbreviations, terminated by a null entry.  */
  table local_time_zone_table[3];
} parser_control;

static bool debugging(parser_control const *pc) {
  return pc->parse_datetime_debug;
}
#define TM_YEAR_BASE 1900
#define _GL_INT_NEGATE_CONVERT(e, v) ((1 ? 0 : (e)) - (v))

#define _GL_EXPR_SIGNED(e) (_GL_INT_NEGATE_CONVERT(e, 1) < 0)

#define _GL_INT_ADD_WRAPV(a, b, r) __builtin_add_overflow(a, b, r)
#define _GL_INT_SUBTRACT_WRAPV(a, b, r) __builtin_sub_overflow(a, b, r)
#define _GL_INT_CONVERT(e, v) ((1 ? 0 : (e)) + (v))
#define _GL_INT_NEGATE_RANGE_OVERFLOW(a, min, max)                             \
  ((min) < 0 ? (a) < -(max) : 0 < (a))
#define _GL_INT_MINIMUM(e)                                                     \
  (_GL_EXPR_SIGNED(e) ? ~_GL_SIGNED_INT_MAXIMUM(e) : _GL_INT_CONVERT(e, 0))
#define _GL_INT_MAXIMUM(e)                                                     \
  (_GL_EXPR_SIGNED(e) ? _GL_SIGNED_INT_MAXIMUM(e)                              \
                      : _GL_INT_NEGATE_CONVERT(e, 1))
#define _GL_SIGNED_INT_MAXIMUM(e)                                              \
  (((_GL_INT_CONVERT(e, 1) << (_GL_TYPE_WIDTH(+(e)) - 2)) - 1) * 2 + 1)

#define _GL_INT_NEGATE_OVERFLOW(a)                                             \
  _GL_INT_NEGATE_RANGE_OVERFLOW(a, _GL_INT_MINIMUM(a), _GL_INT_MAXIMUM(a))

#define _GL_INT_MULTIPLY_RANGE_OVERFLOW(a, b, tmin, tmax)                      \
  ((b) < 0 ? ((a) < 0 ? (_GL_EXPR_SIGNED(_GL_INT_CONVERT(tmax, b))             \
                             ? (a) < (tmax) / (b)                              \
                             : ((_GL_INT_NEGATE_OVERFLOW(b)                    \
                                     ? _GL_INT_CONVERT(b, tmax) >>             \
                                           (_GL_TYPE_WIDTH(+(b)) - 1)          \
                                     : (tmax) / -(b)) <= -1 - (a)))            \
              : _GL_INT_NEGATE_OVERFLOW(_GL_INT_CONVERT(b, tmin)) && (b) == -1 \
                  ? (_GL_EXPR_SIGNED(a) ? 0 < (a) + (tmin)                     \
                                        : 0 < (a) && -1 - (tmin) < (a)-1)      \
                  : (tmin) / (b) < (a))                                        \
   : (b) == 0                                                                  \
       ? 0                                                                     \
       : ((a) < 0 ? (_GL_INT_NEGATE_OVERFLOW(_GL_INT_CONVERT(a, tmin)) &&      \
                             (a) == -1                                         \
                         ? (_GL_EXPR_SIGNED(b) ? 0 < (b) + (tmin)              \
                                               : -1 - (tmin) < (b)-1)          \
                         : (tmin) / (a) < (b))                                 \
                  : (tmax) / (b) < (a)))

#define _GL_INT_MULTIPLY_WRAPV(a, b, r)                                        \
  ((!_GL_SIGNED_TYPE_OR_EXPR(*(r)) && _GL_EXPR_SIGNED(a) &&                    \
    _GL_EXPR_SIGNED(b) &&                                                      \
    _GL_INT_MULTIPLY_RANGE_OVERFLOW(a, b, 0, (__typeof__(*(r)))-1))            \
       ? ((void)__builtin_mul_overflow(a, b, r), 1)                            \
       : __builtin_mul_overflow(a, b, r))

#define ckd_add(r, a, b) ((bool)_GL_INT_ADD_WRAPV(a, b, r))
#define ckd_sub(r, a, b) ((bool)_GL_INT_SUBTRACT_WRAPV(a, b, r))
#define ckd_mul(r, a, b) ((bool)_GL_INT_MULTIPLY_WRAPV(a, b, r))

enum yytokentype {
  YYEMPTY = -2,
  YYEOF = 0,              /* "end of file"  */
  YYerror = 256,          /* error  */
  YYUNDEF = 257,          /* "invalid token"  */
  tAGO = 258,             /* tAGO  */
  tDST = 259,             /* tDST  */
  tYEAR_UNIT = 260,       /* tYEAR_UNIT  */
  tMONTH_UNIT = 261,      /* tMONTH_UNIT  */
  tHOUR_UNIT = 262,       /* tHOUR_UNIT  */
  tMINUTE_UNIT = 263,     /* tMINUTE_UNIT  */
  tSEC_UNIT = 264,        /* tSEC_UNIT  */
  tDAY_UNIT = 265,        /* tDAY_UNIT  */
  tDAY_SHIFT = 266,       /* tDAY_SHIFT  */
  tDAY = 267,             /* tDAY  */
  tDAYZONE = 268,         /* tDAYZONE  */
  tLOCAL_ZONE = 269,      /* tLOCAL_ZONE  */
  tMERIDIAN = 270,        /* tMERIDIAN  */
  tMONTH = 271,           /* tMONTH  */
  tORDINAL = 272,         /* tORDINAL  */
  tZONE = 273,            /* tZONE  */
  tSNUMBER = 274,         /* tSNUMBER  */
  tUNUMBER = 275,         /* tUNUMBER  */
  tSDECIMAL_NUMBER = 276, /* tSDECIMAL_NUMBER  */
  tUDECIMAL_NUMBER = 277  /* tUDECIMAL_NUMBER  */
};
typedef enum yytokentype yytoken_kind_t;
enum { MERam, MERpm, MER24 };

static bool to_tm_year(textint textyear, bool debug, int *tm_year) {
  intmax_t year = textyear.value;

  /* XPG4 suggests that years 00-68 map to 2000-2068, and
     years 69-99 map to 1969-1999.  */
  if (0 <= year && textyear.digits == 2) {
    year += year < 69 ? 2000 : 1900;
  }

  if (year < 0 ? ckd_sub(tm_year, -TM_YEAR_BASE, year)
               : ckd_sub(tm_year, year, TM_YEAR_BASE)) {

    return false;
  }

  return true;
}
static int to_hour(intmax_t hours, int meridian) {
  switch (meridian) {
  default: /* Pacify GCC.  */
  case MER24:
    return 0 <= hours && hours < 24 ? hours : -1;
  case MERam:
    return 0 < hours && hours < 12 ? hours : hours == 12 ? 0 : -1;
  case MERpm:
    return 0 < hours && hours < 12 ? hours + 12 : hours == 12 ? 12 : -1;
  }
}

static char const *time_zone_str(int time_zone,
                                 char time_zone_buf[TIME_ZONE_BUFSIZE]) {
  char *p = time_zone_buf;
  char sign = time_zone < 0 ? '-' : '+';
  int hour = abs(time_zone / (60 * 60));
  p += sprintf(time_zone_buf, "%c%02d", sign, hour);
  int offset_from_hour = abs(time_zone % (60 * 60));
  if (offset_from_hour != 0) {
    int mm = offset_from_hour / 60;
    int ss = offset_from_hour % 60;
    *p++ = ':';
    *p++ = '0' + mm / 10;
    *p++ = '0' + mm % 10;
    if (ss) {
      *p++ = ':';
      *p++ = '0' + ss / 10;
      *p++ = '0' + ss % 10;
    }
    *p = '\0';
  }
  return time_zone_buf;
}

static bool mktime_ok(struct tm const *tm0, struct tm const *tm1) {
  if (tm1->tm_wday < 0)
    return false;

  return !((tm0->tm_sec ^ tm1->tm_sec) | (tm0->tm_min ^ tm1->tm_min) |
           (tm0->tm_hour ^ tm1->tm_hour) | (tm0->tm_mday ^ tm1->tm_mday) |
           (tm0->tm_mon ^ tm1->tm_mon) | (tm0->tm_year ^ tm1->tm_year));
}
time_t mktime_z(timezone_t tz, struct tm *tm) {
  if (!tz)
    return timegm(tm);
  else {
    timezone_t old_tz = set_tz(tz);
    if (old_tz) {
      struct tm tm_1;
      tm_1.tm_sec = tm->tm_sec;
      tm_1.tm_min = tm->tm_min;
      tm_1.tm_hour = tm->tm_hour;
      tm_1.tm_mday = tm->tm_mday;
      tm_1.tm_mon = tm->tm_mon;
      tm_1.tm_year = tm->tm_year;
      tm_1.tm_yday = -1;
      tm_1.tm_isdst = tm->tm_isdst;
      time_t t = mktime(&tm_1);
      bool ok = 0 <= tm_1.tm_yday;
      ok = ok && save_abbr(tz, &tm_1);
      if (revert_tz(old_tz) && ok) {
        *tm = tm_1;
        return t;
      }
    }
    return -1;
  }
}

union YYSTYPE {

  intmax_t intval;
  textint textintval;
  struct timespec timespec;
  relative_time rel;
};
#define YYDPRINTF(Args) ((void)0)
#define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
#define YY_STACK_PRINT(Bottom, Top)
#define YY_REDUCE_PRINT(Rule)
#define YY_INITIAL_VALUE(Value) Value
#define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
#define YY_IGNORE_MAYBE_UNINITIALIZED_END
#define YY_IGNORE_USELESS_CAST_BEGIN
#define YY_IGNORE_USELESS_CAST_END
#define YY_ASSERT(E) ((void)(0 && (E)))
typedef union YYSTYPE YYSTYPE;
#define YYSTYPE_IS_TRIVIAL 1
#define YYSTYPE_IS_DECLARED 1
typedef int yy_state_fast_t;
#define YYPTRDIFF_T __PTRDIFF_TYPE__
#define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
#define YYMAXDEPTH 20
#define YYINITDEPTH YYMAXDEPTH

typedef __INT_LEAST8_TYPE__ yytype_int8;
enum yysymbol_kind_t {
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,              /* "end of file"  */
  YYSYMBOL_YYerror = 1,            /* error  */
  YYSYMBOL_YYUNDEF = 2,            /* "invalid token"  */
  YYSYMBOL_tAGO = 3,               /* tAGO  */
  YYSYMBOL_tDST = 4,               /* tDST  */
  YYSYMBOL_tYEAR_UNIT = 5,         /* tYEAR_UNIT  */
  YYSYMBOL_tMONTH_UNIT = 6,        /* tMONTH_UNIT  */
  YYSYMBOL_tHOUR_UNIT = 7,         /* tHOUR_UNIT  */
  YYSYMBOL_tMINUTE_UNIT = 8,       /* tMINUTE_UNIT  */
  YYSYMBOL_tSEC_UNIT = 9,          /* tSEC_UNIT  */
  YYSYMBOL_tDAY_UNIT = 10,         /* tDAY_UNIT  */
  YYSYMBOL_tDAY_SHIFT = 11,        /* tDAY_SHIFT  */
  YYSYMBOL_tDAY = 12,              /* tDAY  */
  YYSYMBOL_tDAYZONE = 13,          /* tDAYZONE  */
  YYSYMBOL_tLOCAL_ZONE = 14,       /* tLOCAL_ZONE  */
  YYSYMBOL_tMERIDIAN = 15,         /* tMERIDIAN  */
  YYSYMBOL_tMONTH = 16,            /* tMONTH  */
  YYSYMBOL_tORDINAL = 17,          /* tORDINAL  */
  YYSYMBOL_tZONE = 18,             /* tZONE  */
  YYSYMBOL_tSNUMBER = 19,          /* tSNUMBER  */
  YYSYMBOL_tUNUMBER = 20,          /* tUNUMBER  */
  YYSYMBOL_tSDECIMAL_NUMBER = 21,  /* tSDECIMAL_NUMBER  */
  YYSYMBOL_tUDECIMAL_NUMBER = 22,  /* tUDECIMAL_NUMBER  */
  YYSYMBOL_23_ = 23,               /* '@'  */
  YYSYMBOL_24_J_ = 24,             /* 'J'  */
  YYSYMBOL_25_T_ = 25,             /* 'T'  */
  YYSYMBOL_26_ = 26,               /* ':'  */
  YYSYMBOL_27_ = 27,               /* ','  */
  YYSYMBOL_28_ = 28,               /* '/'  */
  YYSYMBOL_YYACCEPT = 29,          /* $accept  */
  YYSYMBOL_spec = 30,              /* spec  */
  YYSYMBOL_timespec = 31,          /* timespec  */
  YYSYMBOL_items = 32,             /* items  */
  YYSYMBOL_item = 33,              /* item  */
  YYSYMBOL_datetime = 34,          /* datetime  */
  YYSYMBOL_iso_8601_datetime = 35, /* iso_8601_datetime  */
  YYSYMBOL_time = 36,              /* time  */
  YYSYMBOL_iso_8601_time = 37,     /* iso_8601_time  */
  YYSYMBOL_o_zone_offset = 38,     /* o_zone_offset  */
  YYSYMBOL_zone_offset = 39,       /* zone_offset  */
  YYSYMBOL_local_zone = 40,        /* local_zone  */
  YYSYMBOL_zone = 41,              /* zone  */
  YYSYMBOL_day = 42,               /* day  */
  YYSYMBOL_date = 43,              /* date  */
  YYSYMBOL_iso_8601_date = 44,     /* iso_8601_date  */
  YYSYMBOL_rel = 45,               /* rel  */
  YYSYMBOL_relunit = 46,           /* relunit  */
  YYSYMBOL_relunit_snumber = 47,   /* relunit_snumber  */
  YYSYMBOL_dayshift = 48,          /* dayshift  */
  YYSYMBOL_seconds = 49,           /* seconds  */
  YYSYMBOL_signed_seconds = 50,    /* signed_seconds  */
  YYSYMBOL_unsigned_seconds = 51,  /* unsigned_seconds  */
  YYSYMBOL_number = 52,            /* number  */
  YYSYMBOL_hybrid = 53,            /* hybrid  */
  YYSYMBOL_o_colon_minutes = 54    /* o_colon_minutes  */
};
typedef yytype_int8 yy_state_t;
typedef enum yysymbol_kind_t yysymbol_kind_t;
/* YYFINAL -- State number of the termination state.  */
#define YYFINAL 12
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST 114

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS 29
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS 26
/* YYNRULES -- Number of rules.  */
#define YYNRULES 92
/* YYNSTATES -- Number of states.  */
#define YYNSTATES 115

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK 277
#define YY_CAST(Type, Val) ((Type)(Val))
#define YY_REINTERPRET_CAST(Type, Val) ((Type)(Val))

#define YYACCEPT goto yyacceptlab
#define YYABORT goto yyabortlab
#define YYERROR goto yyerrorlab
#define YYNOMEM goto yyexhaustedlab
#define YYMALLOC malloc
#define YYFREE free

#define YYSTACK_ALLOC YYMALLOC
#define YYSTACK_FREE YYFREE
#define YYSIZE_T __SIZE_TYPE__
#define YYSIZEOF(X) YY_CAST(YYPTRDIFF_T, sizeof(X))

union yyalloc {
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

#define YYSTACK_GAP_MAXIMUM (YYSIZEOF(union yyalloc) - 1)

#define YYSTACK_BYTES(N)                                                       \
  ((N) * (YYSIZEOF(yy_state_t) + YYSIZEOF(YYSTYPE)) + YYSTACK_GAP_MAXIMUM)
#define YYCOPY(Dst, Src, Count)                                                \
  __builtin_memcpy(Dst, Src, YY_CAST(YYSIZE_T, (Count)) * sizeof(*(Src)))
#define YYSTACK_RELOCATE(Stack_alloc, Stack)                                   \
  do {                                                                         \
    YYPTRDIFF_T yynewbytes;                                                    \
    YYCOPY(&yyptr->Stack_alloc, Stack, yysize);                                \
    Stack = &yyptr->Stack_alloc;                                               \
    yynewbytes = yystacksize * YYSIZEOF(*Stack) + YYSTACK_GAP_MAXIMUM;         \
    yyptr += yynewbytes / YYSIZEOF(*yyptr);                                    \
  } while (0)

#define YYPACT_NINF (-91)

#define yypact_value_is_default(Yyn) ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) 0
static const yytype_int8 yypact[] = {
    -14, 7,   39,  -91, 37,  -91, -91, -91, -91, -91, -91, -91, -91, -91, -91,
    -91, -91, -91, -91, -91, 14,  -91, 64,  47,  67,  6,   82,  -4,  74,  75,
    -91, 76,  -91, -91, -91, -91, -91, -91, -91, -91, -91, 69,  -91, 93,  -91,
    -91, -91, -91, -91, -91, 79,  72,  -91, -91, -91, -91, -91, -91, -91, -91,
    26,  -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91, -91,
    -91, 62,  11,  80,  81,  -91, -91, -91, -91, -91, 83,  -91, -91, 84,  85,
    -91, -91, -91, -91, -91, 45,  86,  -12, -91, -91, -91, -91, 87,  18,  -91,
    -91, 88,  89,  78,  -91, 59,  -91, -91, 18,  91};
static unsigned char to_uchar(char ch) { return ch; }

static table const meridian_table[] = {{"AM", tMERIDIAN, MERam},
                                       {"A.M.", tMERIDIAN, MERam},
                                       {"PM", tMERIDIAN, MERpm},
                                       {"P.M.", tMERIDIAN, MERpm},
                                       {NULL, 0, 0}};

static table const dst_table[] = {{"DST", tDST, 0}};

static table const month_and_day_table[] = {{"JANUARY", tMONTH, 1},
                                            {"FEBRUARY", tMONTH, 2},
                                            {"MARCH", tMONTH, 3},
                                            {"APRIL", tMONTH, 4},
                                            {"MAY", tMONTH, 5},
                                            {"JUNE", tMONTH, 6},
                                            {"JULY", tMONTH, 7},
                                            {"AUGUST", tMONTH, 8},
                                            {"SEPTEMBER", tMONTH, 9},
                                            {"SEPT", tMONTH, 9},
                                            {"OCTOBER", tMONTH, 10},
                                            {"NOVEMBER", tMONTH, 11},
                                            {"DECEMBER", tMONTH, 12},
                                            {"SUNDAY", tDAY, 0},
                                            {"MONDAY", tDAY, 1},
                                            {"TUESDAY", tDAY, 2},
                                            {"TUES", tDAY, 2},
                                            {"WEDNESDAY", tDAY, 3},
                                            {"WEDNES", tDAY, 3},
                                            {"THURSDAY", tDAY, 4},
                                            {"THUR", tDAY, 4},
                                            {"THURS", tDAY, 4},
                                            {"FRIDAY", tDAY, 5},
                                            {"SATURDAY", tDAY, 6},
                                            {NULL, 0, 0}};

static table const time_units_table[] = {{"YEAR", tYEAR_UNIT, 1},
                                         {"MONTH", tMONTH_UNIT, 1},
                                         {"FORTNIGHT", tDAY_UNIT, 14},
                                         {"WEEK", tDAY_UNIT, 7},
                                         {"DAY", tDAY_UNIT, 1},
                                         {"HOUR", tHOUR_UNIT, 1},
                                         {"MINUTE", tMINUTE_UNIT, 1},
                                         {"MIN", tMINUTE_UNIT, 1},
                                         {"SECOND", tSEC_UNIT, 1},
                                         {"SEC", tSEC_UNIT, 1},
                                         {NULL, 0, 0}};

/* Assorted relative-time words.  */
static table const relative_time_table[] = {
    {"TOMORROW", tDAY_SHIFT, 1},
    {"YESTERDAY", tDAY_SHIFT, -1},
    {"TODAY", tDAY_SHIFT, 0},
    {"NOW", tDAY_SHIFT, 0},
    {"LAST", tORDINAL, -1},
    {"THIS", tORDINAL, 0},
    {"NEXT", tORDINAL, 1},
    {"FIRST", tORDINAL, 1},
    /*{ "SECOND",   tORDINAL,        2 }, */
    {"THIRD", tORDINAL, 3},
    {"FOURTH", tORDINAL, 4},
    {"FIFTH", tORDINAL, 5},
    {"SIXTH", tORDINAL, 6},
    {"SEVENTH", tORDINAL, 7},
    {"EIGHTH", tORDINAL, 8},
    {"NINTH", tORDINAL, 9},
    {"TENTH", tORDINAL, 10},
    {"ELEVENTH", tORDINAL, 11},
    {"TWELFTH", tORDINAL, 12},
    {"AGO", tAGO, -1},
    {"HENCE", tAGO, 1},
    {NULL, 0, 0}};

/* The universal time zone table.  These labels can be used even for
   timestamps that would not otherwise be valid, e.g., GMT timestamps
   oin London during summer.  */
static table const universal_time_zone_table[] = {
    {"GMT", tZONE, HOUR(0)}, /* Greenwich Mean */
    {"UT", tZONE, HOUR(0)},  /* Universal (Coordinated) */
    {"UTC", tZONE, HOUR(0)},
    {NULL, 0, 0}};

/* The time zone table.  This table is necessarily incomplete, as time
   zone abbreviations are ambiguous; e.g., Australians interpret "EST"
   as Eastern time in Australia, not as US Eastern Standard Time.
   You cannot rely on parse_datetime to handle arbitrary time zone
   abbreviations; use numeric abbreviations like "-0500" instead.  */
static table const time_zone_table[] = {
    {"WET", tZONE, HOUR(0)},                 /* Western European */
    {"WEST", tDAYZONE, HOUR(0)},             /* Western European Summer */
    {"BST", tDAYZONE, HOUR(0)},              /* British Summer */
    {"ART", tZONE, -HOUR(3)},                /* Argentina */
    {"BRT", tZONE, -HOUR(3)},                /* Brazil */
    {"BRST", tDAYZONE, -HOUR(3)},            /* Brazil Summer */
    {"NST", tZONE, -(HOUR(3) + 30 * 60)},    /* Newfoundland Standard */
    {"NDT", tDAYZONE, -(HOUR(3) + 30 * 60)}, /* Newfoundland Daylight */
    {"AST", tZONE, -HOUR(4)},                /* Atlantic Standard */
    {"ADT", tDAYZONE, -HOUR(4)},             /* Atlantic Daylight */
    {"CLT", tZONE, -HOUR(4)},                /* Chile */
    {"CLST", tDAYZONE, -HOUR(4)},            /* Chile Summer */
    {"EST", tZONE, -HOUR(5)},                /* Eastern Standard */
    {"EDT", tDAYZONE, -HOUR(5)},             /* Eastern Daylight */
    {"CST", tZONE, -HOUR(6)},                /* Central Standard */
    {"CDT", tDAYZONE, -HOUR(6)},             /* Central Daylight */
    {"MST", tZONE, -HOUR(7)},                /* Mountain Standard */
    {"MDT", tDAYZONE, -HOUR(7)},             /* Mountain Daylight */
    {"PST", tZONE, -HOUR(8)},                /* Pacific Standard */
    {"PDT", tDAYZONE, -HOUR(8)},             /* Pacific Daylight */
    {"AKST", tZONE, -HOUR(9)},               /* Alaska Standard */
    {"AKDT", tDAYZONE, -HOUR(9)},            /* Alaska Daylight */
    {"HST", tZONE, -HOUR(10)},               /* Hawaii Standard */
    {"HAST", tZONE, -HOUR(10)},              /* Hawaii-Aleutian Standard */
    {"HADT", tDAYZONE, -HOUR(10)},           /* Hawaii-Aleutian Daylight */
    {"SST", tZONE, -HOUR(12)},               /* Samoa Standard */
    {"WAT", tZONE, HOUR(1)},                 /* West Africa */
    {"CET", tZONE, HOUR(1)},                 /* Central European */
    {"CEST", tDAYZONE, HOUR(1)},             /* Central European Summer */
    {"MET", tZONE, HOUR(1)},                 /* Middle European */
    {"MEZ", tZONE, HOUR(1)},                 /* Middle European */
    {"MEST", tDAYZONE, HOUR(1)},             /* Middle European Summer */
    {"MESZ", tDAYZONE, HOUR(1)},             /* Middle European Summer */
    {"EET", tZONE, HOUR(2)},                 /* Eastern European */
    {"EEST", tDAYZONE, HOUR(2)},             /* Eastern European Summer */
    {"CAT", tZONE, HOUR(2)},                 /* Central Africa */
    {"SAST", tZONE, HOUR(2)},                /* South Africa Standard */
    {"EAT", tZONE, HOUR(3)},                 /* East Africa */
    {"MSK", tZONE, HOUR(3)},                 /* Moscow */
    {"MSD", tDAYZONE, HOUR(3)},              /* Moscow Daylight */
    {"IST", tZONE, (HOUR(5) + 30 * 60)},     /* India Standard */
    {"SGT", tZONE, HOUR(8)},                 /* Singapore */
    {"KST", tZONE, HOUR(9)},                 /* Korea Standard */
    {"JST", tZONE, HOUR(9)},                 /* Japan Standard */
    {"GST", tZONE, HOUR(10)},                /* Guam Standard */
    {"NZST", tZONE, HOUR(12)},               /* New Zealand Standard */
    {"NZDT", tDAYZONE, HOUR(12)},            /* New Zealand Daylight */
    {NULL, 0, 0}};

/* Military time zone table.

   RFC 822 got these backwards, but RFC 5322 makes the incorrect
   treatment optional, so do them the right way here.

   'J' is special, as it is local time.
   'T' is also special, as it is the separator in ISO
   8601 date and time of day representation.  */
static table const military_table[] = {
    {"A", tZONE, HOUR(1)},   {"B", tZONE, HOUR(2)},   {"C", tZONE, HOUR(3)},
    {"D", tZONE, HOUR(4)},   {"E", tZONE, HOUR(5)},   {"F", tZONE, HOUR(6)},
    {"G", tZONE, HOUR(7)},   {"H", tZONE, HOUR(8)},   {"I", tZONE, HOUR(9)},
    {"J", 'J', 0},           {"K", tZONE, HOUR(10)},  {"L", tZONE, HOUR(11)},
    {"M", tZONE, HOUR(12)},  {"N", tZONE, -HOUR(1)},  {"O", tZONE, -HOUR(2)},
    {"P", tZONE, -HOUR(3)},  {"Q", tZONE, -HOUR(4)},  {"R", tZONE, -HOUR(5)},
    {"S", tZONE, -HOUR(6)},  {"T", 'T', 0},           {"U", tZONE, -HOUR(8)},
    {"V", tZONE, -HOUR(9)},  {"W", tZONE, -HOUR(10)}, {"X", tZONE, -HOUR(11)},
    {"Y", tZONE, -HOUR(12)}, {"Z", tZONE, HOUR(0)},   {NULL, 0, 0}};
#define _GL_ATTRIBUTE_PURE __attribute__((__pure__))
static table const *_GL_ATTRIBUTE_PURE lookup_zone(parser_control const *pc,
                                                   char const *name) {
  table const *tp;

  for (tp = universal_time_zone_table; tp->name; tp++)
    if (strcmp(name, tp->name) == 0)
      return tp;

  /* Try local zone abbreviations before those in time_zone_table, as
     the local ones are more likely to be right.  */
  for (tp = pc->local_time_zone_table; tp->name; tp++)
    if (strcmp(name, tp->name) == 0)
      return tp;

  for (tp = time_zone_table; tp->name; tp++)
    if (strcmp(name, tp->name) == 0)
      return tp;

  return NULL;
}

static table const *lookup_word(parser_control const *pc, char *word) {
  char *p;
  char *q;
  idx_t wordlen;
  table const *tp;
  bool period_found;
  bool abbrev;

  /* Make it uppercase.  */
  for (p = word; *p; p++)
    *p = c_toupper(to_uchar(*p));

  for (tp = meridian_table; tp->name; tp++)
    if (strcmp(word, tp->name) == 0)
      return tp;

  /* See if we have an abbreviation for a month.  */
  wordlen = strlen(word);
  abbrev = wordlen == 3 || (wordlen == 4 && word[3] == '.');

  for (tp = month_and_day_table; tp->name; tp++)
    if ((abbrev ? strncmp(word, tp->name, 3) : strcmp(word, tp->name)) == 0)
      return tp;

  if ((tp = lookup_zone(pc, word)))
    return tp;

  if (strcmp(word, dst_table[0].name) == 0)
    return dst_table;

  for (tp = time_units_table; tp->name; tp++)
    if (strcmp(word, tp->name) == 0)
      return tp;

  /* Strip off any plural and try the units table again.  */
  if (word[wordlen - 1] == 'S') {
    word[wordlen - 1] = '\0';
    for (tp = time_units_table; tp->name; tp++)
      if (strcmp(word, tp->name) == 0)
        return tp;
    word[wordlen - 1] = 'S'; /* For "this" in relative_time_table.  */
  }

  for (tp = relative_time_table; tp->name; tp++)
    if (strcmp(word, tp->name) == 0)
      return tp;

  /* Military time zones.  */
  if (wordlen == 1)
    for (tp = military_table; tp->name; tp++)
      if (word[0] == tp->name[0])
        return tp;

  /* Drop out any periods and try the time zone table again.  */
  for (period_found = false, p = q = word; (*p = *q); q++)
    if (*q == '.')
      period_found = true;
    else
      p++;
  if (period_found && (tp = lookup_zone(pc, word)))
    return tp;

  return NULL;
}
static int yylex(union YYSTYPE *lvalp, parser_control *pc) {
  unsigned char c;

  for (;;) {
    while (c = *pc->input, c_isspace(c))
      pc->input++;

    if (c_isdigit(c) || c == '-' || c == '+') {
      char const *p = pc->input;
      int sign;
      if (c == '-' || c == '+') {
        sign = c == '-' ? -1 : 1;
        while (c = *(pc->input = ++p), c_isspace(c))
          continue;
        if (!c_isdigit(c))
          /* skip the '-' sign */
          continue;
      } else
        sign = 0;

      time_t value = 0;
      do {
        if (ckd_mul(&value, value, 10))
          return '?';
        if (ckd_add(&value, value, sign < 0 ? '0' - c : c - '0'))
          return '?';
        c = *++p;
      } while (c_isdigit(c));

      if ((c == '.' || c == ',') && c_isdigit(p[1])) {
        time_t s = value;
        int digits;

        /* Accumulate fraction, to ns precision.  */
        p++;
        int ns = *p++ - '0';
        for (digits = 2; digits <= LOG10_BILLION; digits++) {
          ns *= 10;
          if (c_isdigit(*p))
            ns += *p++ - '0';
        }

        /* Skip excess digits, truncating toward -Infinity.  */
        if (sign < 0)
          for (; c_isdigit(*p); p++)
            if (*p != '0') {
              ns++;
              break;
            }
        while (c_isdigit(*p))
          p++;

        /* Adjust to the timespec convention, which is that
           tv_nsec is always a positive offset even if tv_sec is
           negative.  */
        if (sign < 0 && ns) {
          if (ckd_sub(&s, s, 1))
            return '?';
          ns = BILLION - ns;
        }

        lvalp->timespec = (struct timespec){.tv_sec = s, .tv_nsec = ns};
        pc->input = p;
        return sign ? tSDECIMAL_NUMBER : tUDECIMAL_NUMBER;
      } else {
        lvalp->textintval.negative = sign < 0;
        lvalp->textintval.value = value;
        lvalp->textintval.digits = p - pc->input;
        pc->input = p;
        return sign ? tSNUMBER : tUNUMBER;
      }
    }

    if (c_isalpha(c)) {
      char buff[20];
      char *p = buff;
      table const *tp;

      do {
        if (p < buff + sizeof buff - 1)
          *p++ = c;
        c = *++pc->input;
      } while (c_isalpha(c) || c == '.');

      *p = '\0';
      tp = lookup_word(pc, buff);
      if (!tp) {

        return '?';
      }
      lvalp->intval = tp->value;
      return tp->type;
    }

    if (c != '(')
      return to_uchar(*pc->input++);

    idx_t count = 0;
    do {
      c = *pc->input++;
      if (c == '\0')
        return c;
      if (c == '(')
        count++;
      else if (c == ')')
        count--;
    } while (count != 0);
  }
}

#define YYTRANSLATE(YYX)                                                       \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                                            \
       ? YY_CAST(yysymbol_kind_t, yytranslate[YYX])                            \
       : YYSYMBOL_YYUNDEF)

static const yytype_int8 yytranslate[] = {
    0, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 27, 2,  2,  28, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 26, 2,
    2, 2, 2, 2, 23, 2,  2,  2,  2,  2,  2,  2,  2,  2,  24, 2,  2,  2, 2,  2,
    2, 2, 2, 2, 25, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, 2,  2,
    2, 2, 2, 2, 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  1,  2, 3,  4,
    5, 6, 7, 8, 9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22};
static const yytype_int8 yytable[] = {
    80,  68, 69, 70,  71,  72,  73, 102, 74,  1,  59,  75,  76, 108, 107,
    77,  62, 63, 64,  65,  66,  67, 78,  114, 79, 60,  5,   6,  7,   8,
    93,  62, 63, 64,  65,  66,  67, 89,  6,   12, 8,   48,  13, 14,  15,
    16,  17, 18, 19,  20,  21,  22, 89,  23,  24, 25,  26,  27, 28,  29,
    101, 30, 31, 61,  102, 81,  50, 51,  49,  84, 80,  103, 52, 53,  54,
    55,  56, 57, 102, 58,  112, 91, 92,  82,  83, 113, 112, 62, 63,  64,
    65,  66, 67, 111, 85,  26,  86, 102, 87,  88, 95,  96,  98, 97,  99,
    100, 90, 0,  109, 110, 102, 0,  0,   89,  106};

static const yytype_int8 yycheck[] = {
    27, 5,   6,  7,  8,  9,  10,  19, 12, 23, 4,  15, 16,  103, 26, 19, 5,
    6,  7,   8,  9,  10, 26, 113, 28, 19, 19, 20, 21, 22,  19,  5,  6,  7,
    8,  9,   10, 26, 20, 0,  22,  27, 5,  6,  7,  8,  9,   10,  11, 12, 13,
    14, 26,  16, 17, 18, 19, 20,  21, 22, 15, 24, 25, 25,  19,  27, 19, 20,
    4,  31,  97, 26, 5,  6,  7,   8,  9,  10, 19, 12, 108, 19,  20, 9,  9,
    26, 114, 5,  6,  7,  8,  9,   10, 15, 25, 19, 3,  19,  19,  27, 20, 20,
    85, 20,  20, 20, 60, -1, 20,  20, 19, -1, -1, 26, 28};
static const yytype_int8 yydefact[] = {
    5,  0,  0,  2,  3,  86, 88, 85, 87, 4,  83, 84, 1,  57, 60, 66, 69,
    74, 63, 82, 38, 36, 29, 0,  0,  31, 0,  89, 0,  0,  10, 32, 6,  7,
    17, 8,  22, 9,  11, 13, 12, 50, 14, 53, 75, 54, 15, 16, 39, 30, 0,
    46, 55, 58, 64, 67, 70, 61, 40, 37, 91, 33, 76, 77, 79, 80, 81, 78,
    56, 59, 65, 68, 71, 62, 41, 19, 48, 91, 0,  0,  23, 90, 72, 73, 34,
    0,  52, 45, 0,  0,  35, 44, 49, 51, 28, 26, 42, 0,  18, 47, 92, 20,
    91, 0,  24, 27, 0,  0,  26, 43, 26, 21, 25, 0,  26};
/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] = {
    0,  23, 30, 31, 32, 19, 20, 21, 22, 49, 50, 51, 0,  5,  6,  7,  8,
    9,  10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 24, 25, 33, 34,
    35, 36, 37, 40, 41, 42, 43, 44, 45, 46, 47, 48, 52, 53, 27, 4,  19,
    20, 5,  6,  7,  8,  9,  10, 12, 4,  19, 47, 5,  6,  7,  8,  9,  10,
    5,  6,  7,  8,  9,  10, 12, 15, 16, 19, 26, 28, 39, 47, 9,  9,  47,
    25, 3,  19, 27, 26, 54, 19, 20, 19, 54, 20, 20, 20, 37, 20, 20, 15,
    19, 26, 38, 39, 28, 26, 51, 20, 20, 15, 38, 26, 51};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] = {
    0,  29, 30, 30, 31, 32, 32, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 34, 35,
    36, 36, 36, 36, 37, 37, 37, 38, 38, 39, 40, 40, 41, 41, 41, 41, 41, 41, 41,
    42, 42, 42, 42, 43, 43, 43, 43, 43, 43, 43, 43, 43, 44, 45, 45, 45, 46, 46,
    46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46,
    47, 47, 47, 47, 47, 47, 48, 49, 49, 50, 50, 51, 51, 52, 53, 54, 54};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.
 */
static const yytype_int8 yyr2[] = {
    0, 2, 1, 1, 2, 0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 2, 4, 6, 1, 2,
    4, 6, 0, 1, 2, 1, 2, 1, 1, 2, 2, 3, 1, 2, 1, 2, 2, 2, 3, 5, 3, 3, 2, 4,
    2, 3, 1, 3, 2, 1, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2,
    2, 2, 1, 1, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 2};
static const yytype_int8 yypgoto[] = {
    -91, -91, -91, -91, -91, -91, -91, -91, 17,  -28, -27, -91, -91,
    -91, -91, -91, -91, -91, 38,  -91, -91, -91, -90, -91, -91, 46};
static const yytype_int8 yydefgoto[] = {0,   2,   3,  4,  32, 33, 34, 35, 36,
                                        104, 105, 37, 38, 39, 40, 41, 42, 43,
                                        44,  45,  9,  10, 11, 46, 47, 94};
static void set_hhmmss(parser_control *pc, intmax_t hour, intmax_t minutes,
                       time_t sec, int nsec) {
  pc->hour = hour;
  pc->minutes = minutes;
  pc->seconds = (struct timespec){.tv_sec = sec, .tv_nsec = nsec};
}
static bool time_zone_hhmm(parser_control *pc, textint s, intmax_t mm) {
  intmax_t n_minutes;
  bool overflow = false;

  /* If the length of S is 1 or 2 and no minutes are specified,
     interpret it as a number of hours.  */
  if (s.digits <= 2 && mm < 0)
    s.value *= 100;

  if (mm < 0)
    n_minutes = (s.value / 100) * 60 + s.value % 100;
  else {
    overflow |= ckd_mul(&n_minutes, s.value, 60);
    overflow |= (s.negative ? ckd_sub(&n_minutes, n_minutes, mm)
                            : ckd_add(&n_minutes, n_minutes, mm));
  }

  if (overflow || !(-24 * 60 <= n_minutes && n_minutes <= 24 * 60))
    return false;
  pc->time_zone = n_minutes * 60;
  return true;
}
#define SHR(a, b)                                                              \
  (-1 >> 1 == -1 ? (a) >> (b) : (a) / (1 << (b)) - ((a) % (1 << (b)) < 0))

#define STREQ(a, b) (strcmp(a, b) == 0)
static bool apply_relative_time(parser_control *pc, relative_time rel,
                                int factor) {
  if (factor < 0 ? (ckd_sub(&pc->rel.ns, pc->rel.ns, rel.ns) |
                    ckd_sub(&pc->rel.seconds, pc->rel.seconds, rel.seconds) |
                    ckd_sub(&pc->rel.minutes, pc->rel.minutes, rel.minutes) |
                    ckd_sub(&pc->rel.hour, pc->rel.hour, rel.hour) |
                    ckd_sub(&pc->rel.day, pc->rel.day, rel.day) |
                    ckd_sub(&pc->rel.month, pc->rel.month, rel.month) |
                    ckd_sub(&pc->rel.year, pc->rel.year, rel.year))
                 : (ckd_add(&pc->rel.ns, pc->rel.ns, rel.ns) |
                    ckd_add(&pc->rel.seconds, pc->rel.seconds, rel.seconds) |
                    ckd_add(&pc->rel.minutes, pc->rel.minutes, rel.minutes) |
                    ckd_add(&pc->rel.hour, pc->rel.hour, rel.hour) |
                    ckd_add(&pc->rel.day, pc->rel.day, rel.day) |
                    ckd_add(&pc->rel.month, pc->rel.month, rel.month) |
                    ckd_add(&pc->rel.year, pc->rel.year, rel.year)))
    return false;
  pc->rels_seen = true;
  return true;
}

#define TYPE_SIGNED(t) _GL_TYPE_SIGNED(t)
#define TYPE_MINIMUM(t) ((t)~TYPE_MAXIMUM(t))
#define TYPE_MAXIMUM(t)                                                        \
  ((t)(!TYPE_SIGNED(t) ? (t)-1 : ((((t)1 << (TYPE_WIDTH(t) - 2)) - 1) * 2 + 1)))

static bool time_overflow(intmax_t n) {
  return !((TYPE_SIGNED(time_t) ? TYPE_MINIMUM(time_t) <= n : 0 <= n) &&
           n <= TYPE_MAXIMUM(time_t));
}
static void digits_to_date_time(parser_control *pc, textint text_int) {
  if (pc->dates_seen && !pc->year.digits && !pc->rels_seen &&
      (pc->times_seen || 2 < text_int.digits)) {
    pc->year_seen = true;
    pc->year = text_int;
  } else {
    if (4 < text_int.digits) {
      pc->dates_seen++;
      pc->day = text_int.value % 100;
      pc->month = (text_int.value / 100) % 100;
      pc->year.value = text_int.value / 10000;
      pc->year.digits = text_int.digits - 4;
    } else {
      pc->times_seen++;
      if (text_int.digits <= 2) {
        pc->hour = text_int.value;
        pc->minutes = 0;
      } else {
        pc->hour = text_int.value / 100;
        pc->minutes = text_int.value % 100;
      }
      pc->seconds = (struct timespec){0};
      pc->meridian = MER24;
    }
  }
}
#define YY_USE(E) ((void)(E))

static void yydestruct(const char *yymsg, yysymbol_kind_t yykind,
                       YYSTYPE *yyvaluep, parser_control *pc) {
  YY_USE(yyvaluep);
  YY_USE(pc);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT(yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE(yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}

#define YY_ACCESSING_SYMBOL(State) YY_CAST(yysymbol_kind_t, yystos[State])

int yyparse(parser_control *pc) {
  /* Lookahead token kind.  */
  int yychar;

  /* The semantic value of the lookahead symbol.  */
  /* Default value used for initialization, for pacifying older GCCs
     or non-GCC compilers.  */
  YY_INITIAL_VALUE(static YYSTYPE yyval_default;)
  YYSTYPE yylval YY_INITIAL_VALUE(= yyval_default);

  /* Number of syntax errors so far.  */
  int yynerrs = 0;

  yy_state_fast_t yystate = 0;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus = 0;

  /* Refer to the stacks through separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* Their size.  */
  YYPTRDIFF_T yystacksize = YYINITDEPTH;

  /* The state stack: array, bottom, top.  */
  yy_state_t yyssa[YYINITDEPTH];
  yy_state_t *yyss = yyssa;
  yy_state_t *yyssp = yyss;

  /* The semantic value stack: array, bottom, top.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#define YYPOPSTACK(N) (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF((stderr, "Entering state %d\n", yystate));
  YY_ASSERT(0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST(yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT(yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)

  {
    /* Get the current used size of the three stacks, in elements.  */
    YYPTRDIFF_T yysize = yyssp - yyss + 1;
    {}
    if (YYMAXDEPTH <= yystacksize)
      YYNOMEM;
    yystacksize *= 2;
    if (YYMAXDEPTH < yystacksize)
      yystacksize = YYMAXDEPTH;

    {
      yy_state_t *yyss1 = yyss;
      union yyalloc *yyptr =
          YY_CAST(union yyalloc *,
                  YYSTACK_ALLOC(YY_CAST(YYSIZE_T, YYSTACK_BYTES(yystacksize))));
      if (!yyptr)
        YYNOMEM;
      YYSTACK_RELOCATE(yyss_alloc, yyss);
      YYSTACK_RELOCATE(yyvs_alloc, yyvs);
#undef YYSTACK_RELOCATE
      if (yyss1 != yyssa)
        YYSTACK_FREE(yyss1);
    }
    yyssp = yyss + yysize - 1;
    yyvsp = yyvs + yysize - 1;

    YY_IGNORE_USELESS_CAST_BEGIN
    YYDPRINTF(
        (stderr, "Stack size increased to %ld\n", YY_CAST(long, yystacksize)));
    YY_IGNORE_USELESS_CAST_END

    if (yyss + yystacksize - 1 <= yyssp)
      YYABORT;
  }

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;
/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default(yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY) {
    YYDPRINTF((stderr, "Reading a token\n"));
    yychar = yylex(&yylval, pc);
  }

  if (yychar <= YYEOF) {
    yychar = YYEOF;
    yytoken = YYSYMBOL_YYEOF;
    YYDPRINTF((stderr, "Now at end of input.\n"));
  } else if (yychar == YYerror) {
    /* The scanner already issued an error message, process directly
       to error recovery.  But do not keep the error token as
       lookahead, it is too special and may lead us to an endless
       loop in error recovery. */
    yychar = YYUNDEF;
    yytoken = YYSYMBOL_YYerror;
    goto yyerrlab1;
  } else {
    yytoken = YYTRANSLATE(yychar);
    YY_SYMBOL_PRINT("Next token is", yytoken, &yylval, &yylloc);
  }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0) {
    if (yytable_value_is_error(yyn))
      goto yyerrlab;
    yyn = -yyn;
    goto yyreduce;
  }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;

/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;

/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1 - yylen];

  YY_REDUCE_PRINT(yyn);
  switch (yyn) {
  case 4: /* timespec: '@' seconds  */

  {
    pc->seconds = (yyvsp[0].timespec);
    pc->timespec_seen = true;
  }

  break;

  case 7: /* item: datetime  */

  {
    pc->times_seen++;
    pc->dates_seen++;
  }

  break;

  case 8: /* item: time  */

  {
    pc->times_seen++;
  }

  break;

  case 9: /* item: local_zone  */

  {
    pc->local_zones_seen++;
  }

  break;

  case 10: /* item: 'J'  */

  {
    pc->J_zones_seen++;
  }

  break;

  case 11: /* item: zone  */

  {
    pc->zones_seen++;
  }

  break;

  case 12: /* item: date  */

  {
    pc->dates_seen++;
  }

  break;

  case 13: /* item: day  */

  {
    pc->days_seen++;
  }

  break;

  case 14: /* item: rel  */

  {
  }

  break;

  case 15: /* item: number  */

  {
  }

  break;

  case 16: /* item: hybrid  */

  {
  }

  break;

  case 19: /* time: tUNUMBER tMERIDIAN  */

  {
    set_hhmmss(pc, (yyvsp[-1].textintval).value, 0, 0, 0);
    pc->meridian = (yyvsp[0].intval);
  }

  break;

  case 20: /* time: tUNUMBER ':' tUNUMBER tMERIDIAN  */

  {
    set_hhmmss(pc, (yyvsp[-3].textintval).value, (yyvsp[-1].textintval).value,
               0, 0);
    pc->meridian = (yyvsp[0].intval);
  }

  break;

  case 21: /* time: tUNUMBER ':' tUNUMBER ':' unsigned_seconds tMERIDIAN  */

  {
    set_hhmmss(pc, (yyvsp[-5].textintval).value, (yyvsp[-3].textintval).value,
               (yyvsp[-1].timespec).tv_sec, (yyvsp[-1].timespec).tv_nsec);
    pc->meridian = (yyvsp[0].intval);
  }

  break;

  case 23: /* iso_8601_time: tUNUMBER zone_offset  */

  {
    set_hhmmss(pc, (yyvsp[-1].textintval).value, 0, 0, 0);
    pc->meridian = MER24;
  }

  break;

  case 24: /* iso_8601_time: tUNUMBER ':' tUNUMBER o_zone_offset  */

  {
    set_hhmmss(pc, (yyvsp[-3].textintval).value, (yyvsp[-1].textintval).value,
               0, 0);
    pc->meridian = MER24;
  }

  break;

  case 25: /* iso_8601_time: tUNUMBER ':' tUNUMBER ':' unsigned_seconds
              o_zone_offset  */

  {
    set_hhmmss(pc, (yyvsp[-5].textintval).value, (yyvsp[-3].textintval).value,
               (yyvsp[-1].timespec).tv_sec, (yyvsp[-1].timespec).tv_nsec);
    pc->meridian = MER24;
  }

  break;

  case 28: /* zone_offset: tSNUMBER o_colon_minutes  */

  {
    pc->zones_seen++;
    if (!time_zone_hhmm(pc, (yyvsp[-1].textintval), (yyvsp[0].intval)))
      YYABORT;
  }

  break;

  case 29: /* local_zone: tLOCAL_ZONE  */

  {
    pc->local_isdst = (yyvsp[0].intval);
  }

  break;

  case 30: /* local_zone: tLOCAL_ZONE tDST  */

  {
    pc->local_isdst = 1;
    pc->dsts_seen++;
  }

  break;

  case 31: /* zone: tZONE  */

  {
    pc->time_zone = (yyvsp[0].intval);
  }

  break;

  case 32: /* zone: 'T'  */

  {
    pc->time_zone = -HOUR(7);
  }

  break;

  case 33: /* zone: tZONE relunit_snumber  */

  {
    pc->time_zone = (yyvsp[-1].intval);
    if (!apply_relative_time(pc, (yyvsp[0].rel), 1))
      YYABORT;
  }

  break;

  case 34: /* zone: 'T' relunit_snumber  */

  {
    pc->time_zone = -HOUR(7);
    if (!apply_relative_time(pc, (yyvsp[0].rel), 1))
      YYABORT;
  }

  break;

  case 35: /* zone: tZONE tSNUMBER o_colon_minutes  */

  {
    if (!time_zone_hhmm(pc, (yyvsp[-1].textintval), (yyvsp[0].intval)))
      YYABORT;
    if (ckd_add(&pc->time_zone, pc->time_zone, (yyvsp[-2].intval)))
      YYABORT;
  }

  break;

  case 36: /* zone: tDAYZONE  */

  {
    pc->time_zone = (yyvsp[0].intval) + 60 * 60;
  }

  break;

  case 37: /* zone: tZONE tDST  */

  {
    pc->time_zone = (yyvsp[-1].intval) + 60 * 60;
  }

  break;

  case 38: /* day: tDAY  */

  {
    pc->day_ordinal = 0;
    pc->day_number = (yyvsp[0].intval);
  }

  break;

  case 39: /* day: tDAY ','  */

  {
    pc->day_ordinal = 0;
    pc->day_number = (yyvsp[-1].intval);
  }

  break;

  case 40: /* day: tORDINAL tDAY  */

  {
    pc->day_ordinal = (yyvsp[-1].intval);
    pc->day_number = (yyvsp[0].intval);
    pc->debug_ordinal_day_seen = true;
  }

  break;

  case 41: /* day: tUNUMBER tDAY  */

  {
    pc->day_ordinal = (yyvsp[-1].textintval).value;
    pc->day_number = (yyvsp[0].intval);
    pc->debug_ordinal_day_seen = true;
  }

  break;

  case 42: /* date: tUNUMBER '/' tUNUMBER  */

  {
    pc->month = (yyvsp[-2].textintval).value;
    pc->day = (yyvsp[0].textintval).value;
  }

  break;

  case 43: /* date: tUNUMBER '/' tUNUMBER '/' tUNUMBER  */

  {
    /* Interpret as YYYY/MM/DD if the first value has 4 or more digits,
       otherwise as MM/DD/YY.
       The goal in recognizing YYYY/MM/DD is solely to support legacy
       machine-generated dates like those in an RCS log listing.  If
       you want portability, use the ISO 8601 format.  */
    if (4 <= (yyvsp[-4].textintval).digits) {

      pc->year = (yyvsp[-4].textintval);
      pc->month = (yyvsp[-2].textintval).value;
      pc->day = (yyvsp[0].textintval).value;
    } else {

      pc->month = (yyvsp[-4].textintval).value;
      pc->day = (yyvsp[-2].textintval).value;
      pc->year = (yyvsp[0].textintval);
    }
  }

  break;

  case 44: /* date: tUNUMBER tMONTH tSNUMBER  */

  {
    /* E.g., 17-JUN-1992.  */
    pc->day = (yyvsp[-2].textintval).value;
    pc->month = (yyvsp[-1].intval);
    if (ckd_sub(&pc->year.value, 0, (yyvsp[0].textintval).value))
      YYABORT;
    pc->year.digits = (yyvsp[0].textintval).digits;
  }

  break;

  case 45: /* date: tMONTH tSNUMBER tSNUMBER  */

  {
    /* E.g., JUN-17-1992.  */
    pc->month = (yyvsp[-2].intval);
    if (ckd_sub(&pc->day, 0, (yyvsp[-1].textintval).value))
      YYABORT;
    if (ckd_sub(&pc->year.value, 0, (yyvsp[0].textintval).value))
      YYABORT;
    pc->year.digits = (yyvsp[0].textintval).digits;
  }

  break;

  case 46: /* date: tMONTH tUNUMBER  */

  {
    pc->month = (yyvsp[-1].intval);
    pc->day = (yyvsp[0].textintval).value;
  }

  break;

  case 47: /* date: tMONTH tUNUMBER ',' tUNUMBER  */

  {
    pc->month = (yyvsp[-3].intval);
    pc->day = (yyvsp[-2].textintval).value;
    pc->year = (yyvsp[0].textintval);
  }

  break;

  case 48: /* date: tUNUMBER tMONTH  */

  {
    pc->day = (yyvsp[-1].textintval).value;
    pc->month = (yyvsp[0].intval);
  }

  break;

  case 49: /* date: tUNUMBER tMONTH tUNUMBER  */

  {
    pc->day = (yyvsp[-2].textintval).value;
    pc->month = (yyvsp[-1].intval);
    pc->year = (yyvsp[0].textintval);
  }

  break;

  case 51: /* iso_8601_date: tUNUMBER tSNUMBER tSNUMBER  */

  {
    /* ISO 8601 format.  YYYY-MM-DD.  */
    pc->year = (yyvsp[-2].textintval);
    if (ckd_sub(&pc->month, 0, (yyvsp[-1].textintval).value))
      YYABORT;
    if (ckd_sub(&pc->day, 0, (yyvsp[0].textintval).value))
      YYABORT;
  }

  break;

  case 52: /* rel: relunit tAGO  */

  {
    if (!apply_relative_time(pc, (yyvsp[-1].rel), (yyvsp[0].intval)))
      YYABORT;
  }

  break;

  case 53: /* rel: relunit  */

  {
    if (!apply_relative_time(pc, (yyvsp[0].rel), 1))
      YYABORT;
  }

  break;

  case 54: /* rel: dayshift  */

  {
    if (!apply_relative_time(pc, (yyvsp[0].rel), 1))
      YYABORT;
  }

  break;

  case 55: /* relunit: tORDINAL tYEAR_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).year = (yyvsp[-1].intval);
  }

  break;

  case 56: /* relunit: tUNUMBER tYEAR_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).year = (yyvsp[-1].textintval).value;
  }

  break;

  case 57: /* relunit: tYEAR_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).year = 1;
  }

  break;

  case 58: /* relunit: tORDINAL tMONTH_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).month = (yyvsp[-1].intval);
  }

  break;

  case 59: /* relunit: tUNUMBER tMONTH_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).month = (yyvsp[-1].textintval).value;
  }

  break;

  case 60: /* relunit: tMONTH_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).month = 1;
  }

  break;

  case 61: /* relunit: tORDINAL tDAY_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    if (ckd_mul(&(yyval.rel).day, (yyvsp[-1].intval), (yyvsp[0].intval)))
      YYABORT;
  }

  break;

  case 62: /* relunit: tUNUMBER tDAY_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    if (ckd_mul(&(yyval.rel).day, (yyvsp[-1].textintval).value,
                (yyvsp[0].intval)))
      YYABORT;
  }

  break;

  case 63: /* relunit: tDAY_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).day = (yyvsp[0].intval);
  }

  break;

  case 64: /* relunit: tORDINAL tHOUR_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).hour = (yyvsp[-1].intval);
  }

  break;

  case 65: /* relunit: tUNUMBER tHOUR_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).hour = (yyvsp[-1].textintval).value;
  }

  break;

  case 66: /* relunit: tHOUR_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).hour = 1;
  }

  break;

  case 67: /* relunit: tORDINAL tMINUTE_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).minutes = (yyvsp[-1].intval);
  }

  break;

  case 68: /* relunit: tUNUMBER tMINUTE_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).minutes = (yyvsp[-1].textintval).value;
  }

  break;

  case 69: /* relunit: tMINUTE_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).minutes = 1;
  }

  break;

  case 70: /* relunit: tORDINAL tSEC_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).seconds = (yyvsp[-1].intval);
  }

  break;

  case 71: /* relunit: tUNUMBER tSEC_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).seconds = (yyvsp[-1].textintval).value;
  }

  break;

  case 72: /* relunit: tSDECIMAL_NUMBER tSEC_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).seconds = (yyvsp[-1].timespec).tv_sec;
    (yyval.rel).ns = (yyvsp[-1].timespec).tv_nsec;
  }

  break;

  case 73: /* relunit: tUDECIMAL_NUMBER tSEC_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).seconds = (yyvsp[-1].timespec).tv_sec;
    (yyval.rel).ns = (yyvsp[-1].timespec).tv_nsec;
  }

  break;

  case 74: /* relunit: tSEC_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).seconds = 1;
  }

  break;

  case 76: /* relunit_snumber: tSNUMBER tYEAR_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).year = (yyvsp[-1].textintval).value;
  }

  break;

  case 77: /* relunit_snumber: tSNUMBER tMONTH_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).month = (yyvsp[-1].textintval).value;
  }

  break;

  case 78: /* relunit_snumber: tSNUMBER tDAY_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    if (ckd_mul(&(yyval.rel).day, (yyvsp[-1].textintval).value,
                (yyvsp[0].intval)))
      YYABORT;
  }

  break;

  case 79: /* relunit_snumber: tSNUMBER tHOUR_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).hour = (yyvsp[-1].textintval).value;
  }

  break;

  case 80: /* relunit_snumber: tSNUMBER tMINUTE_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).minutes = (yyvsp[-1].textintval).value;
  }

  break;

  case 81: /* relunit_snumber: tSNUMBER tSEC_UNIT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).seconds = (yyvsp[-1].textintval).value;
  }

  break;

  case 82: /* dayshift: tDAY_SHIFT  */

  {
    (yyval.rel) = RELATIVE_TIME_0;
    (yyval.rel).day = (yyvsp[0].intval);
  }

  break;

  case 86: /* signed_seconds: tSNUMBER  */

  {
    if (time_overflow((yyvsp[0].textintval).value))
      YYABORT;
    (yyval.timespec) = (struct timespec){.tv_sec = (yyvsp[0].textintval).value};
  }

  break;

  case 88: /* unsigned_seconds: tUNUMBER  */

  {
    if (time_overflow((yyvsp[0].textintval).value))
      YYABORT;
    (yyval.timespec) = (struct timespec){.tv_sec = (yyvsp[0].textintval).value};
  }

  break;

  case 89: /* number: tUNUMBER  */

  {
    digits_to_date_time(pc, (yyvsp[0].textintval));
  }

  break;

  case 90: /* hybrid: tUNUMBER relunit_snumber  */

  {
    /* Hybrid all-digit and relative offset, so that we accept e.g.,
       "YYYYMMDD +N days" as well as "YYYYMMDD N days".  */
    digits_to_date_time(pc, (yyvsp[-1].textintval));
    if (!apply_relative_time(pc, (yyvsp[0].rel), 1))
      YYABORT;
  }

  break;

  case 91: /* o_colon_minutes: %empty  */

  {
    (yyval.intval) = -1;
  }

  break;

  case 92: /* o_colon_minutes: ':' tUNUMBER  */

  {
    (yyval.intval) = (yyvsp[0].textintval).value;
  }

  break;

  default:
    break;
  }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT("-> $$ =", YY_CAST(yysymbol_kind_t, yyr1[yyn]), &yyval,
                  &yyloc);

  YYPOPSTACK(yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
                   ? yytable[yyi]
                   : yydefgoto[yylhs]);
  }

  goto yynewstate;

/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE(yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus) {
    ++yynerrs;
  }

  if (yyerrstatus == 3) {
    /* If just tried and failed to reuse lookahead token after an
       error, discard it.  */

    if (yychar <= YYEOF) {
      /* Return failure if at end of input.  */
      if (yychar == YYEOF)
        YYABORT;
    } else {
      yydestruct("Error: discarding", yytoken, &yylval, pc);
      yychar = YYEMPTY;
    }
  }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;

/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK(yylen);
  yylen = 0;
  YY_STACK_PRINT(yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;

/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3; /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;) {
    yyn = yypact[yystate];
    if (!yypact_value_is_default(yyn)) {
      yyn += YYSYMBOL_YYerror;
      if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror) {
        yyn = yytable[yyn];
        if (0 < yyn)
          break;
      }
    }

    /* Pop the current state because it cannot handle the error token.  */
    if (yyssp == yyss)
      YYABORT;

    yydestruct("Error: popping", YY_ACCESSING_SYMBOL(yystate), yyvsp, pc);
    YYPOPSTACK(1);
    yystate = *yyssp;
    YY_STACK_PRINT(yyss, yyssp);
  }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Shift the error token.  */
  YY_SYMBOL_PRINT("Shifting", YY_ACCESSING_SYMBOL(yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;

/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;

/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyresult = 2;
  goto yyreturnlab;

/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY) {
    /* Make sure we have latest lookahead translation.  See comments at
       user semantic actions for why this is necessary.  */
    yytoken = YYTRANSLATE(yychar);
    yydestruct("Cleanup: discarding lookahead", yytoken, &yylval, pc);
  }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK(yylen);
  YY_STACK_PRINT(yyss, yyssp);
  while (yyssp != yyss) {
    yydestruct("Cleanup: popping", YY_ACCESSING_SYMBOL(+*yyssp), yyvsp, pc);
    YYPOPSTACK(1);
  }
  if (yyss != yyssa)
    YYSTACK_FREE(yyss);
  return yyresult;
}

static bool parse_datetime_body(struct timespec *result, char const *p,
                                struct timespec const *now, unsigned int flags,
                                timezone_t tzdefault, char const *tzstring) {
  struct tm tm;
  struct tm tm0;
  char time_zone_buf[TIME_ZONE_BUFSIZE];
  char dbg_tm[DBGBUFSIZE];
  bool ok = false;
  char const *input_sentinel = p + strlen(p);
  char *tz1alloc = NULL;

  /* A reasonable upper bound for the size of ordinary TZ strings.
     Use heap allocation if TZ's length exceeds this.  */
  enum { TZBUFSIZE = 100 };
  char tz1buf[TZBUFSIZE];

  struct timespec gettime_buffer;
  if (!now) {
    // gettime(&gettime_buffer);
    clock_gettime(CLOCK_REALTIME, &gettime_buffer);
    now = &gettime_buffer;
  }

  time_t Start = now->tv_sec;
  int Start_ns = now->tv_nsec;

  unsigned char c;
  while (c = *p, c_isspace(c))
    p++;

  timezone_t tz = tzdefault;

  /* Store a local copy prior to first "goto".  Without this, a prior use
     below of RELATIVE_TIME_0 on the RHS might translate to an assignment-
     to-temporary, which would trigger a -Wjump-misses-init warning.  */
  const relative_time rel_time_0 = RELATIVE_TIME_0;

  if (strncmp(p, "TZ=\"", 4) == 0) {
    char const *tzbase = p + 4;
    idx_t tzsize = 1;
    char const *s;

    for (s = tzbase; *s; s++, tzsize++)
      if (*s == '\\') {
        s++;
        if (!(*s == '\\' || *s == '"'))
          break;
      } else if (*s == '"') {
        timezone_t tz1;
        char *tz1string = tz1buf;
        char *z;
        if (TZBUFSIZE < tzsize) {
          tz1alloc = malloc(tzsize);
          if (!tz1alloc)
            goto fail;
          tz1string = tz1alloc;
        }
        z = tz1string;
        for (s = tzbase; *s != '"'; s++)
          *z++ = *(s += *s == '\\');
        *z = '\0';
        tz1 = tzalloc(tz1string);
        if (!tz1)
          goto fail;
        tz = tz1;
        tzstring = tz1string;

        p = s + 1;
        while (c = *p, c_isspace(c))
          p++;

        break;
      }
  }

  struct tm tmp;
  if (!localtime_rz(tz, &now->tv_sec, &tmp))
    goto fail;

  /* As documented, be careful to treat the empty string just like
     a date string of "0".  Without this, an empty string would be
     declared invalid when parsed during a DST transition.  */
  if (*p == '\0')
    p = "0";

  parser_control pc;
  pc.input = p;
  pc.parse_datetime_debug = (flags & PARSE_DATETIME_DEBUG) != 0;
  if (ckd_add(&pc.year.value, tmp.tm_year, TM_YEAR_BASE)) {
    goto fail;
  }
  pc.year.digits = 0;
  pc.month = tmp.tm_mon + 1;
  pc.day = tmp.tm_mday;
  pc.hour = tmp.tm_hour;
  pc.minutes = tmp.tm_min;
  pc.seconds = (struct timespec){.tv_sec = tmp.tm_sec, .tv_nsec = Start_ns};
  tm.tm_isdst = tmp.tm_isdst;

  pc.meridian = MER24;
  pc.rel = rel_time_0;
  pc.timespec_seen = false;
  pc.rels_seen = false;
  pc.dates_seen = 0;
  pc.days_seen = 0;
  pc.times_seen = 0;
  pc.J_zones_seen = 0;
  pc.local_zones_seen = 0;
  pc.dsts_seen = 0;
  pc.zones_seen = 0;
  pc.year_seen = false;
  pc.debug_dates_seen = false;
  pc.debug_days_seen = false;
  pc.debug_times_seen = false;
  pc.debug_local_zones_seen = false;
  pc.debug_zones_seen = false;
  pc.debug_year_seen = false;
  pc.debug_ordinal_day_seen = false;

  pc.local_time_zone_table[0].name = tmp.tm_zone;
  pc.local_time_zone_table[0].type = tLOCAL_ZONE;
  pc.local_time_zone_table[0].value = tmp.tm_isdst;
  pc.local_time_zone_table[1].name = NULL;

  /* Probe the names used in the next three calendar quarters, looking
     for a tm_isdst different from the one we already have.  */
  {
    int quarter;
    for (quarter = 1; quarter <= 3; quarter++) {
      time_t probe;
      if (ckd_add(&probe, Start, quarter * (90 * 24 * 60 * 60)))
        break;
      struct tm probe_tm;
      if (localtime_rz(tz, &probe, &probe_tm) && probe_tm.tm_zone &&
          probe_tm.tm_isdst != pc.local_time_zone_table[0].value) {
        {
          pc.local_time_zone_table[1].name = probe_tm.tm_zone;
          pc.local_time_zone_table[1].type = tLOCAL_ZONE;
          pc.local_time_zone_table[1].value = probe_tm.tm_isdst;
          pc.local_time_zone_table[2].name = NULL;
        }
        break;
      }
    }
  }
  if (pc.local_time_zone_table[0].name && pc.local_time_zone_table[1].name &&
      !strcmp(pc.local_time_zone_table[0].name,
              pc.local_time_zone_table[1].name)) {
    /* This locale uses the same abbreviation for standard and
       daylight times.  So if we see that abbreviation, we don't
       know whether it's daylight time.  */
    pc.local_time_zone_table[0].value = -1;
    pc.local_time_zone_table[1].name = NULL;
  }

  if (yyparse(&pc) != 0) {
    goto fail;
  }

  if (pc.timespec_seen)
    *result = pc.seconds;
  else {
    if (1 < (pc.times_seen | pc.dates_seen | pc.days_seen | pc.dsts_seen |
             (pc.J_zones_seen + pc.local_zones_seen + pc.zones_seen))) {

      goto fail;
    }

    if (!to_tm_year(pc.year, debugging(&pc), &tm.tm_year) ||
        ckd_add(&tm.tm_mon, pc.month, -1) || ckd_add(&tm.tm_mday, pc.day, 0)) {

      goto fail;
    }
    if (pc.times_seen || (pc.rels_seen && !pc.dates_seen && !pc.days_seen)) {
      tm.tm_hour = to_hour(pc.hour, pc.meridian);
      if (tm.tm_hour < 0) {
        char const *mrd = (pc.meridian == MERam   ? "am"
                           : pc.meridian == MERpm ? "pm"
                                                  : "");
        goto fail;
      }
      tm.tm_min = pc.minutes;
      tm.tm_sec = pc.seconds.tv_sec;

    } else {
      tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
      pc.seconds.tv_nsec = 0;
    }

    /* Let mktime deduce tm_isdst if we have an absolute timestamp.  */
    if (pc.dates_seen | pc.days_seen | pc.times_seen)
      tm.tm_isdst = -1;

    /* But if the input explicitly specifies local time with or without
       DST, give mktime that information.  */
    if (pc.local_zones_seen)
      tm.tm_isdst = pc.local_isdst;

    tm0.tm_sec = tm.tm_sec;
    tm0.tm_min = tm.tm_min;
    tm0.tm_hour = tm.tm_hour;
    tm0.tm_mday = tm.tm_mday;
    tm0.tm_mon = tm.tm_mon;
    tm0.tm_year = tm.tm_year;
    tm0.tm_isdst = tm.tm_isdst;
    tm.tm_wday = -1;

    Start = mktime_z(tz, &tm);

    if (!mktime_ok(&tm0, &tm)) {
      bool repaired = false;
      bool time_zone_seen = pc.zones_seen != 0;
      if (time_zone_seen) {
        /* Guard against falsely reporting errors near the time_t
           boundaries when parsing times in other time zones.  For
           example, suppose the input string "1969-12-31 23:00:00 -0100",
           the current time zone is 8 hours ahead of UTC, and the min
           time_t value is 1970-01-01 00:00:00 UTC.  Then the min
           localtime value is 1970-01-01 08:00:00, and mktime will
           therefore fail on 1969-12-31 23:00:00.  To work around the
           problem, set the time zone to 1 hour behind UTC temporarily
           by setting TZ="XXX1:00" and try mktime again.  */

        char tz2buf[sizeof "XXX" - 1 + TIME_ZONE_BUFSIZE];
        tz2buf[0] = tz2buf[1] = tz2buf[2] = 'X';
        time_zone_str(pc.time_zone, &tz2buf[3]);
        timezone_t tz2 = tzalloc(tz2buf);
        if (!tz2) {

          goto fail;
        }
        tm.tm_sec = tm0.tm_sec;
        tm.tm_min = tm0.tm_min;
        tm.tm_hour = tm0.tm_hour;
        tm.tm_mday = tm0.tm_mday;
        tm.tm_mon = tm0.tm_mon;
        tm.tm_year = tm0.tm_year;
        tm.tm_isdst = tm0.tm_isdst;
        tm.tm_wday = -1;
        Start = mktime_z(tz2, &tm);
        repaired = mktime_ok(&tm0, &tm);
        tzfree(tz2);
      }

      if (!repaired) {
        goto fail;
      }
    }

    char dbg_ord[DBGBUFSIZE];

    if (pc.days_seen && !pc.dates_seen) {
      intmax_t dayincr;
      tm.tm_yday = -1;
      intmax_t day_ordinal = (pc.day_ordinal - (0 < pc.day_ordinal &&
                                                tm.tm_wday != pc.day_number));
      if (!(ckd_mul(&dayincr, day_ordinal, 7) ||
            ckd_add(&dayincr, (pc.day_number - tm.tm_wday + 7) % 7, dayincr) ||
            ckd_add(&tm.tm_mday, dayincr, tm.tm_mday))) {
        tm.tm_isdst = -1;
        Start = mktime_z(tz, &tm);
      }

      if (tm.tm_yday < 0) {

        goto fail;
      }
    }

    /* Add relative date.  */
    if (pc.rel.year | pc.rel.month | pc.rel.day) {

      int year, month, day;
      if (ckd_add(&year, tm.tm_year, pc.rel.year) ||
          ckd_add(&month, tm.tm_mon, pc.rel.month) ||
          ckd_add(&day, tm.tm_mday, pc.rel.day)) {

        goto fail;
      }
      tm.tm_year = year;
      tm.tm_mon = month;
      tm.tm_mday = day;
      tm.tm_hour = tm0.tm_hour;
      tm.tm_min = tm0.tm_min;
      tm.tm_sec = tm0.tm_sec;
      tm.tm_isdst = tm0.tm_isdst;
      tm.tm_wday = -1;
      Start = mktime_z(tz, &tm);
      if (tm.tm_wday < 0) {

        goto fail;
      }
    }

    /* The only "output" of this if-block is an updated Start value,
       so this block must follow others that clobber Start.  */
    if (pc.zones_seen) {
      bool overflow = false;
      long int utcoff = tm.tm_gmtoff;
      intmax_t delta;
      overflow |= ckd_sub(&delta, pc.time_zone, utcoff);
      time_t t1;
      overflow |= ckd_sub(&t1, Start, delta);
      if (overflow) {
        goto fail;
      }
      Start = t1;
    }

    /* Add relative hours, minutes, and seconds.  On hosts that support
       leap seconds, ignore the possibility of leap seconds; e.g.,
       "+ 10 minutes" adds 600 seconds, even if one of them is a
       leap second.  Typically this is not what the user wants, but it's
       too hard to do it the other way, because the time zone indicator
       must be applied before relative times, and if mktime is applied
       again the time zone will be lost.  */
    {
      intmax_t orig_ns = pc.seconds.tv_nsec;
      intmax_t sum_ns = orig_ns + pc.rel.ns;
      int normalized_ns = (sum_ns % BILLION + BILLION) % BILLION;
      int d4 = (sum_ns - normalized_ns) / BILLION;
      intmax_t d1, t1, d2, t2, t3;
      time_t t4;
      if (ckd_mul(&d1, pc.rel.hour, 60 * 60) || ckd_add(&t1, Start, d1) ||
          ckd_mul(&d2, pc.rel.minutes, 60) || ckd_add(&t2, t1, d2) ||
          ckd_add(&t3, t2, pc.rel.seconds) || ckd_add(&t4, t3, d4)) {

        goto fail;
      }

      result->tv_sec = t4;
      result->tv_nsec = normalized_ns;
    }
  }

  ok = true;

fail:
  if (tz != tzdefault)
    tzfree(tz);
  free(tz1alloc);
  return ok;
}

bool parse_datetime2(struct timespec *result, char const *p,
                     struct timespec const *now, unsigned int flags,
                     timezone_t tzdefault, char const *tzstring) {
  return parse_datetime_body(result, p, now, flags, tzdefault, tzstring);
}
#define CHAR_T char
#define UCHAR_T unsigned char
#define L_(Str) Str
#define NLW(Sym) Sym
#define ABALTMON_1 _NL_ABALTMON_1

#define MEMCPY(d, s, n) memcpy(d, s, n)
#define STRLEN(s) strlen(s)
#define advance(P, N) ((P) += (N))

#define STREAM_OR_CHAR_T CHAR_T
#define STRFTIME_ARG(x) x,
#define extra_args_spec , timezone_t tz, int ns
#define extra_args , tz, ns
#define LOCALE_PARAM
#define LOCALE_ARG
#define memset_space(P, Len) (memset(P, ' ', Len), (P) += (Len))
#define memset_zero(P, Len) (memset(P, '0', Len), (P) += (Len))
#define width_add(width, n, f)                                                 \
  do {                                                                         \
    size_t _n = (n);                                                           \
    size_t _w = pad == L_('-') || width < 0 ? 0 : width;                       \
    size_t _incr = _n < _w ? _w : _n;                                          \
    if (_incr >= maxsize - i) {                                                \
      errno = ERANGE;                                                          \
      return 0;                                                                \
    }                                                                          \
    if (p) {                                                                   \
      if (_n < _w) {                                                           \
        size_t _delta = _w - _n;                                               \
        if (pad == L_('0') || pad == L_('+'))                                  \
          memset_zero(p, _delta);                                              \
        else                                                                   \
          memset_space(p, _delta);                                             \
      }                                                                        \
      f;                                                                       \
      advance(p, _n);                                                          \
    }                                                                          \
    i += _incr;                                                                \
  } while (0)
#define width_add(width, n, f)                                                 \
  do {                                                                         \
    size_t _n = (n);                                                           \
    size_t _w = pad == L_('-') || width < 0 ? 0 : width;                       \
    size_t _incr = _n < _w ? _w : _n;                                          \
    if (_incr >= maxsize - i) {                                                \
      errno = ERANGE;                                                          \
      return 0;                                                                \
    }                                                                          \
    if (p) {                                                                   \
      if (_n < _w) {                                                           \
        size_t _delta = _w - _n;                                               \
        if (pad == L_('0') || pad == L_('+'))                                  \
          memset_zero(p, _delta);                                              \
        else                                                                   \
          memset_space(p, _delta);                                             \
      }                                                                        \
      f;                                                                       \
      advance(p, _n);                                                          \
    }                                                                          \
    i += _incr;                                                                \
  } while (0)

#define width_add1(width, c) width_add(width, 1, *p = c)

#define add1(c) width_add1(width, c)
#define add(n, f) width_add(width, n, f)
#define ISDIGIT(Ch) ((unsigned int)(Ch)-L_('0') <= 9)

#define TOUPPER(Ch, L) toupper(Ch)
#define TOLOWER(Ch, L) tolower(Ch)

static CHAR_T *memcpy_lowcase(CHAR_T *dest, const CHAR_T *src,
                              size_t len LOCALE_PARAM) {
  while (len-- > 0)
    dest[len] = TOLOWER((UCHAR_T)src[len], loc);
  return dest;
}
static CHAR_T *memcpy_uppcase(CHAR_T *dest, const CHAR_T *src,
                              size_t len LOCALE_PARAM) {
  while (len-- > 0)
    dest[len] = TOUPPER((UCHAR_T)src[len], loc);
  return dest;
}
#define width_cpy(width, n, s)                                                 \
  width_add(width, n, if (to_lowcase) memcpy_lowcase(p, (s), _n LOCALE_ARG);   \
            else if (to_uppcase) memcpy_uppcase(p, (s), _n LOCALE_ARG);        \
            else MEMCPY((void *)p, (void const *)(s), _n))

#define width_cpy(width, n, s)                                                 \
  width_add(width, n, if (to_lowcase) memcpy_lowcase(p, (s), _n LOCALE_ARG);   \
            else if (to_uppcase) memcpy_uppcase(p, (s), _n LOCALE_ARG);        \
            else MEMCPY((void *)p, (void const *)(s), _n))
#define cpy(n, s) width_cpy(width, n, s)

#define ISO_WEEK_START_WDAY 1 /* Monday */
#define ISO_WEEK1_WDAY 4      /* Thursday */
#define YDAY_MINIMUM (-366)
static __inline int iso_week_days(int yday, int wday) {
  /* Add enough to the first operand of % to make it nonnegative.  */
  int big_enough_multiple_of_7 = (-YDAY_MINIMUM / 7 + 2) * 7;
  return (yday - (yday - wday + ISO_WEEK1_WDAY + big_enough_multiple_of_7) % 7 +
          ISO_WEEK1_WDAY - ISO_WEEK_START_WDAY);
}
static size_t
__strftime_internal(STREAM_OR_CHAR_T *s,
                    STRFTIME_ARG(size_t maxsize) const CHAR_T *format,
                    const struct tm *tp, bool upcase, int yr_spec, int width,
                    bool *tzset_called extra_args_spec LOCALE_PARAM) {
  int saved_errno = errno;
  int hour12 = tp->tm_hour;
  const char *zone;
  size_t i = 0;
  STREAM_OR_CHAR_T *p = s;
  const CHAR_T *f;
  zone = NULL;
  zone = (const char *)tp->tm_zone;
  if (!zone)
    zone = "";

  if (hour12 > 12)
    hour12 -= 12;
  else if (hour12 == 0)
    hour12 = 12;

  for (f = format; *f != '\0'; width = -1, f++) {
    int pad = 0;      /* Padding for number ('_', '-', '+', '0', or 0).  */
    int modifier;     /* Field modifier ('E', 'O', or 0).  */
    int digits = 0;   /* Max digits for numeric format.  */
    int number_value; /* Numeric value to be printed.  */
    unsigned int u_number_value; /* (unsigned int) number_value.  */
    bool negative_number;        /* The number is negative.  */
    bool always_output_a_sign;   /* +/- should always be output.  */
    int tz_colon_mask;           /* Bitmask of where ':' should appear.  */
    const CHAR_T *subfmt;
    CHAR_T *bufp;
    CHAR_T buf[1 + 2 /* for the two colons in a %::z or %:::z time zone */
               + (sizeof(int) < sizeof(time_t) ? INT_STRLEN_BOUND(time_t)
                                               : INT_STRLEN_BOUND(int))];
    bool to_lowcase = false;
    bool to_uppcase = upcase;
    size_t colons;
    bool change_case = false;
    int format_char;
    int subwidth;
    if (*f != L_('%')) {
      add1(*f);
      continue;
    }
    char const *percent = f;
    /* Check for flags that can modify a format.  */
    while (1) {
      switch (*++f) {
        /* This influences the number formats.  */
      case L_('_'):
      case L_('-'):
      case L_('+'):
      case L_('0'):
        pad = *f;
        continue;

        /* This changes textual output.  */
      case L_('^'):
        to_uppcase = true;
        continue;
      case L_('#'):
        change_case = true;
        continue;

      default:
        break;
      }
      break;
    }

    if (ISDIGIT(*f)) {
      width = 0;
      do {
        if (ckd_mul(&width, width, 10) || ckd_add(&width, width, *f - L_('0')))
          width = INT_MAX;
        ++f;
      } while (ISDIGIT(*f));
    }

    /* Check for modifiers.  */
    switch (*f) {
    case L_('E'):
    case L_('O'):
      modifier = *f++;
      break;

    default:
      modifier = 0;
      break;
    }

    /* Now do the specified format.  */
    format_char = *f;
    switch (format_char) {
#define DO_NUMBER(d, v)                                                        \
  do {                                                                         \
    digits = d;                                                                \
    number_value = v;                                                          \
    goto do_number;                                                            \
  } while (0)
#define DO_SIGNED_NUMBER(d, negative, v)                                       \
  DO_MAYBE_SIGNED_NUMBER(d, negative, v, do_signed_number)
#define DO_YEARISH(d, negative, v)                                             \
  DO_MAYBE_SIGNED_NUMBER(d, negative, v, do_yearish)
#define DO_MAYBE_SIGNED_NUMBER(d, negative, v, label)                          \
  do {                                                                         \
    digits = d;                                                                \
    negative_number = negative;                                                \
    u_number_value = v;                                                        \
    goto label;                                                                \
  } while (0)
#define DO_TZ_OFFSET(d, mask, v)                                               \
  do {                                                                         \
    digits = d;                                                                \
    tz_colon_mask = mask;                                                      \
    u_number_value = v;                                                        \
    goto do_tz_offset;                                                         \
  } while (0)
#define DO_NUMBER_SPACEPAD(d, v)                                               \
  do {                                                                         \
    digits = d;                                                                \
    number_value = v;                                                          \
    goto do_number_spacepad;                                                   \
  } while (0)

    case L_('%'):
      if (f - 1 != percent)
        goto bad_percent;
      add1(*f);
      break;

    case L_('a'):
      if (modifier != 0)
        goto bad_format;
      if (change_case) {
        to_uppcase = true;
        to_lowcase = false;
      }
      goto underlying_strftime;

    case 'A':
      if (modifier != 0)
        goto bad_format;
      if (change_case) {
        to_uppcase = true;
        to_lowcase = false;
      }
      goto underlying_strftime;

    case L_('b'):
    case L_('h'):
      if (change_case) {
        to_uppcase = true;
        to_lowcase = false;
      }
      if (modifier == L_('E'))
        goto bad_format;
      goto underlying_strftime;

    case L_('B'):
      if (modifier == L_('E'))
        goto bad_format;
      if (change_case) {
        to_uppcase = true;
        to_lowcase = false;
      }
      goto underlying_strftime;
    case L_('c'):
      if (modifier == L_('O'))
        goto bad_format;
      goto underlying_strftime;
    subformat:
      subwidth = -1;
    subformat_width : {
      size_t len = __strftime_internal(NULL, STRFTIME_ARG((size_t)-1) subfmt,
                                       tp, to_uppcase, pad, subwidth,
                                       tzset_called extra_args LOCALE_ARG);
      add(len, __strftime_internal(p, STRFTIME_ARG(maxsize - i) subfmt, tp,
                                   to_uppcase, pad, subwidth,
                                   tzset_called extra_args LOCALE_ARG));
    } break;
    underlying_strftime : {
      /* The relevant information is available only via the
         underlying strftime implementation, so use that.  */
      char ufmt[5];
      char *u = ufmt;
      char ubuf[1024]; /* enough for any single format in practice */
      size_t len;
      *u++ = ' ';
      *u++ = '%';
      if (modifier != 0)
        *u++ = modifier;
      *u++ = format_char;
      *u = '\0';
      len = strftime(ubuf, sizeof ubuf, ufmt, tp);
      if (len != 0)
        cpy(len - 1, ubuf + 1);
    } break;
    case L_('C'):
      if (modifier == L_('E')) {
        goto underlying_strftime;
      }

      {
        bool negative_year = tp->tm_year < -TM_YEAR_BASE;
        bool zero_thru_1899 = !negative_year & (tp->tm_year < 0);
        int century =
            ((tp->tm_year - 99 * zero_thru_1899) / 100 + TM_YEAR_BASE / 100);
        DO_YEARISH(2, negative_year, century);
      }

    case L_('x'):
      if (modifier == L_('O'))
        goto bad_format;
      goto underlying_strftime;
    case L_('D'):
      if (modifier != 0)
        goto bad_format;
      subfmt = L_("%m/%d/%y");
      goto subformat;

    case L_('d'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER(2, tp->tm_mday);

    case L_('e'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER_SPACEPAD(2, tp->tm_mday);

      /* All numeric formats set DIGITS and NUMBER_VALUE (or U_NUMBER_VALUE)
         and then jump to one of these labels.  */

    do_tz_offset:
      always_output_a_sign = true;
      goto do_number_body;

    do_yearish:
      if (pad == 0)
        pad = yr_spec;
      always_output_a_sign =
          (pad == L_('+') &&
           ((digits == 2 ? 99 : 9999) < u_number_value || digits < width));
      goto do_maybe_signed_number;

    do_number_spacepad:
      if (pad == 0)
        pad = L_('_');

    do_number:
      /* Format NUMBER_VALUE according to the MODIFIER flag.  */
      negative_number = number_value < 0;
      u_number_value = number_value;

    do_signed_number:
      always_output_a_sign = false;

    do_maybe_signed_number:
      tz_colon_mask = 0;

    do_number_body:
      /* Format U_NUMBER_VALUE according to the MODIFIER flag.
         NEGATIVE_NUMBER is nonzero if the original number was
         negative; in this case it was converted directly to
         unsigned int (i.e., modulo (UINT_MAX + 1)) without
         negating it.  */
      if (modifier == L_('O') && !negative_number) {
        goto underlying_strftime;
      }

      bufp = buf + sizeof(buf) / sizeof(buf[0]);

      if (negative_number)
        u_number_value = -u_number_value;

      do {
        if (tz_colon_mask & 1)
          *--bufp = ':';
        tz_colon_mask >>= 1;
        *--bufp = u_number_value % 10 + L_('0');
        u_number_value /= 10;
      } while (u_number_value != 0 || tz_colon_mask != 0);

    do_number_sign_and_padding:
      if (pad == 0)
        pad = L_('0');
      if (width < 0)
        width = digits;

      {
        CHAR_T sign_char = (negative_number        ? L_('-')
                            : always_output_a_sign ? L_('+')
                                                   : 0);
        int numlen = buf + sizeof buf / sizeof buf[0] - bufp;
        int shortage = width - !!sign_char - numlen;
        int padding = pad == L_('-') || shortage <= 0 ? 0 : shortage;

        if (sign_char) {
          if (pad == L_('_')) {
            if (p)
              memset_space(p, padding);
            i += padding;
            width -= padding;
          }
          width_add1(0, sign_char);
          width--;
        }

        cpy(numlen, bufp);
      }
      break;

    case L_('F'):
      if (modifier != 0)
        goto bad_format;
      if (pad == 0 && width < 0) {
        pad = L_('+');
        subwidth = 4;
      } else {
        subwidth = width - 6;
        if (subwidth < 0)
          subwidth = 0;
      }
      subfmt = L_("%Y-%m-%d");
      goto subformat_width;

    case L_('H'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER(2, tp->tm_hour);

    case L_('I'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER(2, hour12);

    case L_('k'): /* GNU extension.  */
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER_SPACEPAD(2, tp->tm_hour);

    case L_('l'): /* GNU extension.  */
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER_SPACEPAD(2, hour12);

    case L_('j'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_SIGNED_NUMBER(3, tp->tm_yday < -1, tp->tm_yday + 1U);

    case L_('M'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER(2, tp->tm_min);

    case L_('m'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_SIGNED_NUMBER(2, tp->tm_mon < -1, tp->tm_mon + 1U);
    case L_('N'): /* GNU extension.  */
      if (modifier == L_('E'))
        goto bad_format;
      {
        int n = ns, ns_digits = 9;
        if (width <= 0)
          width = ns_digits;
        int ndigs = ns_digits;
        while (width < ndigs || (1 < ndigs && n % 10 == 0))
          ndigs--, n /= 10;
        int j = ndigs;
        for (j; 0 < j; j--)
          buf[j - 1] = n % 10 + L_('0'), n /= 10;
        if (!pad)
          pad = L_('0');
        width_cpy(0, ndigs, buf);
        width_add(width - ndigs, 0, (void)0);
      }
      break;
    case L_('n'):
      add1(L_('\n'));
      break;

    case L_('P'):
      to_lowcase = true;
      format_char = L_('p');
      FALLTHROUGH;
    case L_('p'):
      if (change_case) {
        to_uppcase = false;
        to_lowcase = true;
      }
      goto underlying_strftime;
    case L_('q'): /* GNU extension.  */
      DO_SIGNED_NUMBER(1, false, ((tp->tm_mon * 11) >> 5) + 1);

    case L_('R'):
      subfmt = L_("%H:%M");
      goto subformat;

    case L_('r'):
      goto underlying_strftime;
    case L_('S'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER(2, tp->tm_sec);

    case L_('s'): /* GNU extension.  */
    {
      struct tm ltm;
      time_t t;

      ltm = *tp;
      ltm.tm_yday = -1;
      t = mktime_z(tz, &ltm);
      if (ltm.tm_yday < 0) {
        errno = EOVERFLOW;
        return 0;
      }

      /* Generate string value for T using time_t arithmetic;
         this works even if sizeof (long) < sizeof (time_t).  */

      bufp = buf + sizeof(buf) / sizeof(buf[0]);
      negative_number = t < 0;

      do {
        int d = t % 10;
        t /= 10;
        *--bufp = (negative_number ? -d : d) + L_('0');
      } while (t != 0);

      digits = 1;
      always_output_a_sign = false;
      goto do_number_sign_and_padding;
    }

    case L_('X'):
      if (modifier == L_('O'))
        goto bad_format;
      goto underlying_strftime;
    case L_('T'):
      subfmt = L_("%H:%M:%S");
      goto subformat;

    case L_('t'):
      add1(L_('\t'));
      break;

    case L_('u'):
      DO_NUMBER(1, (tp->tm_wday - 1 + 7) % 7 + 1);

    case L_('U'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER(2, (tp->tm_yday - tp->tm_wday + 7) / 7);

    case L_('V'):
    case L_('g'):
    case L_('G'):
      if (modifier == L_('E'))
        goto bad_format;
      {
        /* YEAR is a leap year if and only if (tp->tm_year + TM_YEAR_BASE)
           is a leap year, except that YEAR and YEAR - 1 both work
           correctly even when (tp->tm_year + TM_YEAR_BASE) would
           overflow.  */
        int year = (tp->tm_year + (tp->tm_year < 0 ? TM_YEAR_BASE % 400
                                                   : TM_YEAR_BASE % 400 - 400));
        int year_adjust = 0;
        int days = iso_week_days(tp->tm_yday, tp->tm_wday);

        if (days < 0) {
          /* This ISO week belongs to the previous year.  */
          year_adjust = -1;
          days = iso_week_days(tp->tm_yday + (365 + __isleap(year - 1)),
                               tp->tm_wday);
        } else {
          int d =
              iso_week_days(tp->tm_yday - (365 + __isleap(year)), tp->tm_wday);
          if (0 <= d) {
            /* This ISO week belongs to the next year.  */
            year_adjust = 1;
            days = d;
          }
        }

        switch (*f) {
        case L_('g'): {
          int yy = (tp->tm_year % 100 + year_adjust) % 100;
          DO_YEARISH(2, false,
                     (0 <= yy                                     ? yy
                      : tp->tm_year < -TM_YEAR_BASE - year_adjust ? -yy
                                                                  : yy + 100));
        }

        case L_('G'):
          DO_YEARISH(4, tp->tm_year < -TM_YEAR_BASE - year_adjust,
                     (tp->tm_year + (unsigned int)TM_YEAR_BASE + year_adjust));

        default:
          DO_NUMBER(2, days / 7 + 1);
        }
      }

    case L_('W'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER(2, (tp->tm_yday - (tp->tm_wday - 1 + 7) % 7 + 7) / 7);

    case L_('w'):
      if (modifier == L_('E'))
        goto bad_format;

      DO_NUMBER(1, tp->tm_wday);

    case L_('Y'):
      if (modifier == L_('E')) {
        goto underlying_strftime;
      }
      if (modifier == L_('O'))
        goto bad_format;

      DO_YEARISH(4, tp->tm_year < -TM_YEAR_BASE,
                 tp->tm_year + (unsigned int)TM_YEAR_BASE);

    case L_('y'):
      if (modifier == L_('E')) {
        goto underlying_strftime;
      }

      {
        int yy = tp->tm_year % 100;
        if (yy < 0)
          yy = tp->tm_year < -TM_YEAR_BASE ? -yy : yy + 100;
        DO_YEARISH(2, false, yy);
      }

    case L_('Z'):
      if (change_case) {
        to_uppcase = false;
        to_lowcase = true;
      }
      cpy(strlen(zone), zone);
      break;

    case L_(':'):
      /* :, ::, and ::: are valid only just before 'z'.
         :::: etc. are rejected later.  */
      for (colons = 1; f[colons] == L_(':'); colons++)
        continue;
      if (f[colons] != L_('z'))
        goto bad_format;
      f += colons;
      goto do_z_conversion;

    case L_('z'):
      colons = 0;

    do_z_conversion:
      if (tp->tm_isdst < 0)
        break;

      {
        int diff;
        int hour_diff;
        int min_diff;
        int sec_diff;

        diff = tp->tm_gmtoff;
        negative_number = diff < 0 || (diff == 0 && *zone == '-');
        hour_diff = diff / 60 / 60;
        min_diff = diff / 60 % 60;
        sec_diff = diff % 60;

        switch (colons) {
        case 0: /* +hhmm */
          DO_TZ_OFFSET(5, 0, hour_diff * 100 + min_diff);

        case 1:
        tz_hh_mm: /* +hh:mm */
          DO_TZ_OFFSET(6, 04, hour_diff * 100 + min_diff);

        case 2:
        tz_hh_mm_ss: /* +hh:mm:ss */
          DO_TZ_OFFSET(9, 024, hour_diff * 10000 + min_diff * 100 + sec_diff);

        case 3: /* +hh if possible, else +hh:mm, else +hh:mm:ss */
          if (sec_diff != 0)
            goto tz_hh_mm_ss;
          if (min_diff != 0)
            goto tz_hh_mm;
          DO_TZ_OFFSET(3, 0, hour_diff);

        default:
          goto bad_format;
        }
      }

    case L_('\0'): /* GNU extension: % at end of format.  */
    bad_percent:
      --f;
      FALLTHROUGH;
    default:
      /* Unknown format; output the format, including the '%',
         since this is most likely the right thing to do if a
         multibyte string has been misparsed.  */
    bad_format:
      cpy(f - percent + 1, percent);
      break;
    }
  }
  if (p && maxsize != 0)
    *p = L_('\0');
  errno = saved_errno;
  return i;
}

size_t my_strftime(STREAM_OR_CHAR_T *s, const CHAR_T *format,
                   const struct tm *tp extra_args_spec) {
  bool tzset_called = false;
  size_t maxsize = 18446744073709551615ULL;
  return __strftime_internal(s, STRFTIME_ARG(maxsize) "%s", tp, false, 0, -1,
                             &tzset_called extra_args LOCALE_ARG);
}

// static bool show_date(char const *format, struct timespec when, timezone_t
// tz) {
//   struct tm tm;
//   char *rfc_email_format = "%a, %d %b %Y %H:%M:%S %z";
//   if (localtime_rz(tz, &when.tv_sec, &tm)) {
//     if (format == rfc_email_format)
//       setlocale(LC_TIME, "C");
//     my_strftime(stdout, format, &tm, tz, when.tv_nsec);
//     if (format == rfc_email_format)
//       setlocale(LC_TIME, "");
//     fputc('\n', stdout);
//     return true;
//   }
//   return true;

// }
uint64_t gettime_buffer(char *time_str) {
  char const *tzstring = getenv("TZ");
  timezone_t tz = tzalloc(tzstring);
  bool valid_date = true;
  struct timespec when;
  int parse_datetime_flags = 0;
  char const *datestr = time_str;
  char const *format_res = "%s";

  valid_date = parse_datetime2(&when, datestr, nullptr, parse_datetime_flags,
                               tz, tzstring);
  // show_date(format_res, when, tz);
  return when.tv_sec;
  // return 0;
}

int main(void) {
  char *str = "2024-11-08 09:52:55";
  char *str_1 = "Fri, 01 Jun 2007 10:02:33 GMT";
  char *str_2 = "Fri, 01 Jun 2007 10:02:33 +0300";
  char *str_3 = "Aug 13 2004 10:02:33.00000000";
  char *str_4= "2024-03-19T15:26:00+7:00";
  struct timespec start, end;
  timespec_get(&start, TIME_UTC);
  uint64_t time = gettime_buffer(str_4);
  timespec_get(&end, TIME_UTC);
  long long ns = (end.tv_sec - start.tv_sec) * 1000000000LL +
                 (end.tv_nsec - start.tv_nsec);
  printf("time [%s]= %lu\n", str, time);
  printf("%10.3lld μs\n", ns);
  return 0;
}
