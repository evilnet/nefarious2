/** @file ircd_string.h
 * @brief Public declarations and APIs for string operations.
 * @version $Id: ircd_string.h 1478 2005-09-12 03:40:17Z entrope $
 */
#ifndef INCLUDED_ircd_string_h
#define INCLUDED_ircd_string_h

#include <stdint.h>
#include <string.h> /* for DupString()'s strcpy, strlen */

#ifndef INCLUDED_ircd_chattr_h
#include "ircd_chattr.h"
#endif

struct irc_in_addr;

/*
 * Macros
 */
/** Check whether \a x is a NULL or empty string. */
#define EmptyString(x) (!(x) || !(*x))

extern int string_has_wildcards(const char* str);

extern int string_is_valid_utf8(const char* str);
extern int string_is_valid_utf8_len(const char* str, size_t len);
extern int string_sanitize_utf8(char* str);

extern int string_contains_non_ascii (const char* str);

extern int string_character_structure_is_sane(const char* str);

extern char*       ircd_strncpy(char* dest, const char* src, size_t len);
extern int str_appendf(char* buf, size_t buflen, size_t* pos,
                       const char* fmt, ...);
extern int         ircd_strcmp(const char *a, const char *b);
extern int         ircd_strncmp(const char *a, const char *b, size_t n);
extern int csv_contains_token(const char* csv, const char* token);
extern int ircd_clienttagdeny_match(const char *deny_list, const char *tag, size_t tag_len);
extern const char *ircd_clienttagdeny_isupport(const char *in, char *out, size_t outsz);
extern int ircd_reserved_vendor_tag(const char *tag, size_t tag_len);
extern const char *ircd_strip_reserved_vendor_tags(const char *in, char *out, size_t outsz);
extern int ircd_utf8_clamp(char* s, size_t maxbytes);
extern size_t ircd_utf8_cut_len(const char* text, size_t len, size_t max);
extern size_t ircd_line_body_clamp(const char* line, size_t len, size_t body_max);
extern size_t ircd_relay_text_room(size_t source_len, size_t cmd_len,
                                   size_t target_len, size_t body_max);
extern int ircd_text_mentions(const char* text, const char* nick);
extern char* ircd_json_escape(char* dst, size_t dstlen, const char* src);
extern int         unique_name_vector(char* names, char token,
                                      char** vector, int size);
extern int         token_vector(char* names, char token,
                                char** vector, int size);
extern const char* ircd_ntoa(const struct irc_in_addr* addr);
extern const char* ircd_ntoa_r(char* buf, const struct irc_in_addr* addr);
#define ircd_aton(ADDR, STR) ipmask_parse((STR), (ADDR), NULL)
extern int ipmask_parse(const char *in, struct irc_in_addr *mask, unsigned char *bits_ptr);
extern char*       host_from_uh(char* buf, const char* userhost, size_t len);
extern char*       ircd_strtok(char** save, char* str, char* fs);

extern char*       canonize(char* buf);

extern char*       itoa(int n);
extern unsigned long ParseInterval(const char *interval);
extern int         is_timestamp(char *str);

extern const char* StripColor(const char* text);
extern int HasColor(const char* text);

extern int check_if_ipmask(const char *mask);

extern int valid_username(const char* name);
extern int valid_hostname(const char* name);
extern int valid_spoofhost(const char* host, int mask);

#define COLOR_BOLD            2   /**< Bold text */
#define COLOR_COLOR           3   /**< Color text */
#define COLOR_ITALIC          29  /**< Italic text */
#define COLOR_NORMAL          15  /**< Normal text */
#define COLOR_REVERSE         22  /**< Reverse text */
#define COLOR_UNDERLINE       31  /**< Underlined text */

/** Make \a y a duplicate \a x, a la strdup(). */
#define DupString(x, y)  (strcpy((x = (char*) MyMalloc(strlen(y) + 1)), y))


/* String classification pseudo-functions, when others are needed add them,
   strIsXxxxx(s) is true when IsXxxxx(c) is true for every char in s */

/** Test whether all characters in \a s are alphanumeric. */
#define strIsAlnum(s)     (strChattr(s) & NTL_ALNUM)
/** Test whether all characters in \a s are alphabetic. */
#define strIsAlpha(s)     (strChattr(s) & NTL_ALPHA)
/** Test whether all characters in \a s are digits. */
#define strIsDigit(s)     (strChattr(s) & NTL_DIGIT)
/** Test whether all characters in \a s are lower case. */
#define strIsLower(s)     (strChattr(s) & NTL_LOWER)
/** Test whether all characters in \a s are whitespace. */
#define strIsSpace(s)     (strChattr(s) & NTL_SPACE)
/** Test whether all characters in \a s are upper case. */
#define strIsUpper(s)     (strChattr(s) & NTL_UPPER)

/** Test whether all characters in \a s are channel name characters. */
#define strIsIrcCh(s)     (strChattr(s) & NTL_IRCCH)
/** Test whether all characters in \a s are forced to lower-case in channel names. */
#define strIsIrcCl(s)     (strChattr(s) & NTL_IRCCL)
/** Test whether all characters in \a s are valid in nicknames. */
#define strIsIrcNk(s)     (strChattr(s) & NTL_IRCNK)
/** Test whether all characters in \a s are valid in a user field. */
#define strIsIrcUi(s)     (strChattr(s) & NTL_IRCUI)
/** Test whether all characters in \a s are valid in host names. */
#define strIsIrcHn(s)     (strChattr(s) & NTL_IRCHN)
/** Test whether all characters in \a s are valid in IP addresses. */
#define strIsIrcIp(s)     (strChattr(s) & NTL_IRCIP)

/*
 * Critical small functions to inline even in separate compilation
 * when FORCEINLINE is defined (provided you have a compiler that supports
 * `inline').
 */

/** Declaration for strChattr(). */
#define NTL_HDR_strChattr   unsigned int strChattr(const char *s)

/** Body for strChattr(). */
#define NTL_SRC_strChattr   const char *rs = s; \
                            unsigned int x = ~0; \
                            while(*rs) \
                              x &= IRCD_CharAttrTab[*rs++ - CHAR_MIN]; \
                            return x;

/*
 * XXX - bleah should return 1 if different 0 if the same
 */
/** Declaration for strCasediff(). */
#define NTL_HDR_strCasediff int strCasediff(const char *a, const char *b)

/** Body for strCasediff(). */
#define NTL_SRC_strCasediff const char *ra = a; \
                            const char *rb = b; \
                            while(ToLower(*ra) == ToLower(*rb++)) \
                              if(!*ra++) \
                                return 0; \
                            return 1;

#ifndef FORCEINLINE
extern NTL_HDR_strChattr;
extern NTL_HDR_strCasediff;

#else /* FORCEINLINE */
#ifdef __cplusplus
inline NTL_HDR_strChattr { NTL_SRC_strChattr }
inline NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#else
static __inline__ NTL_HDR_strChattr { NTL_SRC_strChattr }
static __inline__ NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#endif
#endif /* FORCEINLINE */


/** The mint time a msgid carries (ms since epoch), or 0 when the string
 * is not exactly the form generate_msgid() mints (see ircd_string.c). */
extern uint64_t msgid_decode_time_ms(const char *msgid);
/** msgid_decode_time_ms(), also 0 when that time is more than
 * @a max_ahead_ms past @a now_ms (0 = no such bound): for ids clients
 * hand back as CHATHISTORY selectors.  @a now_ms is the later of the
 * wall clock and the local HLC (hlc_reference_now_ms). */
extern uint64_t msgid_decode_ref_time_ms(const char *msgid, uint64_t now_ms,
                                         uint64_t max_ahead_ms);
/** Decode a msgid's full HLC stamp (physical ms + logical counter).
 * Returns 1 on success; 0 for a legacy/foreign msgid. */
extern int msgid_decode_hlc(const char *msgid, uint64_t *ms_out, uint16_t *logical_out);

#endif /* INCLUDED_ircd_string_h */

