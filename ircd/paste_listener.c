/*
 * paste_listener.c - HTTP/TLS listener for paste content
 *
 * Implements a simple HTTPS server for serving multiline paste content.
 * Uses the existing SSL context from the IRC server.
 */

#include "config.h"

#ifdef USE_SSL

#include "paste_listener.h"
#include "ml_content.h"
#include "client.h"       /* cli_name, me */
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "listener.h"
#include "res.h"
#include "s_bsd.h"
#include "ssl.h"

/* External SSL server context - defined in ssl.c */
extern SSL_CTX *ssl_server_ctx;

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

/* ---------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------------*/

#define PASTE_MAX_REQUEST_SIZE 4096
#define PASTE_MAX_CONNECTIONS 64
#define PASTE_REQUEST_TIMEOUT 30
#define PASTE_URL_PATH_PREFIX "/p/"
#define PASTE_SECRET_LEN 8

/* Base64url alphabet for secret generation */
static const char base64url_alphabet[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Extension to language mapping for highlight.js */
static const struct {
  const char *ext;
  const char *lang;
} ext_lang_map[] = {
  { "c", "c" },
  { "h", "c" },
  { "cpp", "cpp" },
  { "cc", "cpp" },
  { "cxx", "cpp" },
  { "hpp", "cpp" },
  { "py", "python" },
  { "js", "javascript" },
  { "ts", "typescript" },
  { "json", "json" },
  { "xml", "xml" },
  { "html", "html" },
  { "htm", "html" },
  { "css", "css" },
  { "sh", "bash" },
  { "bash", "bash" },
  { "zsh", "bash" },
  { "rb", "ruby" },
  { "java", "java" },
  { "go", "go" },
  { "rs", "rust" },
  { "php", "php" },
  { "sql", "sql" },
  { "yaml", "yaml" },
  { "yml", "yaml" },
  { "toml", "toml" },
  { "ini", "ini" },
  { "conf", "ini" },
  { "md", "markdown" },
  { "markdown", "markdown" },
  { "diff", "diff" },
  { "patch", "diff" },
  { "pl", "perl" },
  { "lua", "lua" },
  { "swift", "swift" },
  { "kt", "kotlin" },
  { "scala", "scala" },
  { "r", "r" },
  { "m", "objectivec" },
  { "mm", "objectivec" },
  { NULL, NULL }
};

/* ---------------------------------------------------------------------------
 * Connection state
 * ---------------------------------------------------------------------------*/

enum paste_conn_state {
  PASTE_CONN_SSL_ACCEPT,
  PASTE_CONN_READING,
  PASTE_CONN_WRITING,
  PASTE_CONN_CLOSING
};

struct paste_conn {
  int fd;
  SSL *ssl;
  enum paste_conn_state state;
  int dying;              /**< set by paste_conn_free; awaiting ET_DESTROY */
  struct Socket socket;
  struct Timer timeout;
  char request[PASTE_MAX_REQUEST_SIZE];
  int request_len;
  char *response;
  size_t response_len;
  size_t response_sent;
  struct paste_conn *next;
  struct paste_conn *prev;
};

/* ---------------------------------------------------------------------------
 * Global state
 * ---------------------------------------------------------------------------*/

static struct paste_conn *paste_conn_list = NULL;
static int paste_conn_count = 0;

/* ---------------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------------*/

static void paste_conn_callback(struct Event *ev);
static void paste_timeout_callback(struct Event *ev);
static void paste_conn_free(struct paste_conn *conn);
static void paste_handle_request(struct paste_conn *conn);
static int paste_send_response(struct paste_conn *conn, int status,
                               const char *content_type,
                               const char *body, size_t body_len);
static char *paste_html_escape(const char *content, size_t len, size_t *out_len);

/* ---------------------------------------------------------------------------
 * Utility functions
 * ---------------------------------------------------------------------------*/

void paste_generate_secret(char *out, size_t len)
{
  unsigned char random_bytes[16];
  size_t i;

  if (len == 0)
    return;

  /* Generate cryptographic random bytes */
  if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
    /* Fallback to less secure random if OpenSSL fails */
    for (i = 0; i < sizeof(random_bytes); i++)
      random_bytes[i] = (unsigned char)(rand() & 0xFF);
  }

  /* Convert to base64url */
  for (i = 0; i < len - 1 && i < sizeof(random_bytes); i++) {
    out[i] = base64url_alphabet[random_bytes[i] & 0x3F];
  }
  out[i] = '\0';
}

/* Return the port of the first active paste listener, or 0 if none. */
int paste_listener_port(void)
{
  struct Listener *l;
  for (l = ListenerPollList; l; l = l->next) {
    if (FlagHas(&l->flags, LISTEN_PASTE) && listener_active(l))
      return l->addr.port;
  }
  return 0;
}

const char *paste_url(const char *paste_id)
{
  static char url_buf[512];
  const char *url_base = feature_str(FEAT_PASTE_URL_BASE);
  int port = paste_listener_port();

  if (url_base && url_base[0]) {
    /* Use configured URL base */
    ircd_snprintf(0, url_buf, sizeof(url_buf), "%s/p/%s", url_base, paste_id);
  } else if (port == 443) {
    /* Default HTTPS port - omit from URL */
    ircd_snprintf(0, url_buf, sizeof(url_buf), "https://%s/p/%s",
                  cli_name(&me), paste_id);
  } else {
    /* Use server name + explicit port */
    ircd_snprintf(0, url_buf, sizeof(url_buf), "https://%s:%d/p/%s",
                  cli_name(&me), port, paste_id);
  }

  return url_buf;
}

void paste_parse_filename_hint(const char *content, size_t len,
                               char *filename, size_t filename_size,
                               const char **out_content, size_t *out_len)
{
  const char *p = content;
  const char *end = content + len;
  const char *colon = NULL;
  const char *newline = NULL;
  size_t fname_len;

  filename[0] = '\0';
  *out_content = content;
  *out_len = len;

  if (!content || len == 0)
    return;

  /* Look for pattern: filename.ext:\n on first line */
  /* Filename must be: word chars, dots, dashes, ending with .ext: */
  while (p < end && *p != '\n' && *p != '\r') {
    if (*p == ':' && !colon)
      colon = p;
    p++;
  }

  if (!colon || colon == content)
    return;

  /* Check that colon is at end of line (possibly followed by \r\n or \n) */
  if (p != colon + 1 && !(p == colon + 1 && (*p == '\n' || *p == '\r')))
    return;

  /* Validate filename: must have extension, valid chars */
  fname_len = colon - content;
  if (fname_len >= filename_size || fname_len < 3)  /* a.x minimum */
    return;

  /* Check for valid filename chars and at least one dot */
  {
    const char *dot = NULL;
    const char *c;
    for (c = content; c < colon; c++) {
      if (*c == '.')
        dot = c;
      else if (!isalnum((unsigned char)*c) && *c != '_' && *c != '-')
        return;  /* Invalid char */
    }
    if (!dot || dot == content || dot == colon - 1)
      return;  /* No extension or empty extension */
  }

  /* Valid filename hint found */
  memcpy(filename, content, fname_len);
  filename[fname_len] = '\0';

  /* Skip past the hint line */
  if (p < end && *p == '\r')
    p++;
  if (p < end && *p == '\n')
    p++;

  *out_content = p;
  *out_len = end - p;
}

const char *paste_ext_to_lang(const char *filename)
{
  const char *dot;
  const char *ext;
  int i;

  if (!filename || !filename[0])
    return "plaintext";

  /* Find last dot */
  dot = strrchr(filename, '.');
  if (!dot || !dot[1])
    return "plaintext";

  ext = dot + 1;

  /* Look up extension */
  for (i = 0; ext_lang_map[i].ext; i++) {
    if (strcasecmp(ext, ext_lang_map[i].ext) == 0)
      return ext_lang_map[i].lang;
  }

  return "plaintext";
}

/* ---------------------------------------------------------------------------
 * HTML escape helper
 * ---------------------------------------------------------------------------*/

static char *paste_html_escape(const char *content, size_t len, size_t *out_len)
{
  size_t i, j, escaped_len = 0;
  char *escaped;

  /* Calculate escaped length */
  for (i = 0; i < len; i++) {
    switch (content[i]) {
      case '<': escaped_len += 4; break;  /* &lt; */
      case '>': escaped_len += 4; break;  /* &gt; */
      case '&': escaped_len += 5; break;  /* &amp; */
      case '"': escaped_len += 6; break;  /* &quot; */
      default: escaped_len++; break;
    }
  }

  escaped = MyMalloc(escaped_len + 1);
  if (!escaped) {
    *out_len = 0;
    return NULL;
  }

  /* Escape content */
  for (i = 0, j = 0; i < len; i++) {
    switch (content[i]) {
      case '<':
        memcpy(escaped + j, "&lt;", 4);
        j += 4;
        break;
      case '>':
        memcpy(escaped + j, "&gt;", 4);
        j += 4;
        break;
      case '&':
        memcpy(escaped + j, "&amp;", 5);
        j += 5;
        break;
      case '"':
        memcpy(escaped + j, "&quot;", 6);
        j += 6;
        break;
      default:
        escaped[j++] = content[i];
        break;
    }
  }
  escaped[j] = '\0';

  *out_len = j;
  return escaped;
}

/* ---------------------------------------------------------------------------
 * HTTP response generation
 * ---------------------------------------------------------------------------*/

/* HTML template for paste viewing - supports system light/dark theme */
static const char html_template_head[] =
  "<!DOCTYPE html>\n"
  "<html>\n"
  "<head>\n"
  "  <meta charset=\"utf-8\">\n"
  "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
  "  <title>%s</title>\n"  /* filename or "Paste" */
  "  <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/styles/github.min.css\" media=\"(prefers-color-scheme: light), (prefers-color-scheme: no-preference)\">\n"
  "  <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/styles/github-dark.min.css\" media=\"(prefers-color-scheme: dark)\">\n"
  "  <style>\n"
  "    body { margin: 0; padding: 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #24292e; }\n"
  "    .container { max-width: 1200px; margin: 0 auto; }\n"
  "    header { display: flex; align-items: center; margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid #d0d7de; }\n"
  "    header h1 { margin: 0; font-size: 20px; font-weight: 600; font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, monospace; }\n"
  "    pre { margin: 0; padding: 16px; background: white; border: 1px solid #d0d7de; border-radius: 6px; overflow-x: auto; }\n"
  "    code { font-size: 13px; font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, monospace; }\n"
  "    footer { margin-top: 16px; padding-top: 16px; border-top: 1px solid #d0d7de; font-size: 12px; color: #57606a; }\n"
  "    footer span { margin-right: 16px; }\n"
  "    @media (prefers-color-scheme: dark) {\n"
  "      body { background: #0d1117; color: #c9d1d9; }\n"
  "      header, footer { border-color: #30363d; }\n"
  "      pre { background: #161b22; border-color: #30363d; }\n"
  "      footer { color: #8b949e; }\n"
  "    }\n"
  "  </style>\n"
  "</head>\n"
  "<body>\n"
  "<div class=\"container\">\n"
  "<header><h1>%s</h1></header>\n"  /* filename or "Paste" */
  "<pre><code class=\"language-%s\">";  /* language */

static const char html_template_foot[] =
  "</code></pre>\n"
  "<footer><span>%lu lines</span><span>%lu chars</span><span>%s</span></footer>\n"  /* lines, chars, size */
  "</div>\n"
  "<script src=\"https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/highlight.min.js\"></script>\n"
  "<script>hljs.highlightAll();</script>\n"
  "</body>\n"
  "</html>\n";

/* Format byte size for human readability (no floats - ircd_snprintf doesn't support them) */
static void format_size(size_t bytes, char *buf, size_t buf_len)
{
  if (bytes >= 1024 * 1024) {
    /* Calculate MB with one decimal place using integer math */
    unsigned long mb_int = bytes / (1024 * 1024);
    unsigned long mb_frac = (bytes % (1024 * 1024)) * 10 / (1024 * 1024);
    ircd_snprintf(0, buf, buf_len, "%lu.%lu MB", mb_int, mb_frac);
  } else if (bytes >= 1024) {
    /* Calculate KB with one decimal place using integer math */
    unsigned long kb_int = bytes / 1024;
    unsigned long kb_frac = (bytes % 1024) * 10 / 1024;
    ircd_snprintf(0, buf, buf_len, "%lu.%lu KB", kb_int, kb_frac);
  } else {
    ircd_snprintf(0, buf, buf_len, "%lu bytes", (unsigned long)bytes);
  }
}

/* Count lines in content */
static unsigned long count_lines(const char *content, size_t len)
{
  unsigned long lines = 0;
  size_t i;

  if (!content || len == 0)
    return 0;

  for (i = 0; i < len; i++) {
    if (content[i] == '\n')
      lines++;
  }

  /* Count last line if it doesn't end with newline */
  if (len > 0 && content[len - 1] != '\n')
    lines++;

  return lines > 0 ? lines : 1;
}

static int paste_build_html_response(const char *content, size_t content_len,
                                     const char *filename, char **out,
                                     size_t *out_len)
{
  const char *lang;
  const char *title;
  char *escaped;
  size_t escaped_len;
  size_t total_len;
  unsigned long lines;
  char size_buf[32];
  char *head_buf;
  char *foot_buf;
  int head_len, foot_len;

  lang = paste_ext_to_lang(filename);
  title = (filename && filename[0]) ? filename : "Paste";

  /* Calculate stats */
  lines = count_lines(content, content_len);
  format_size(content_len, size_buf, sizeof(size_buf));

  /* Escape content for HTML */
  escaped = paste_html_escape(content, content_len, &escaped_len);
  if (!escaped)
    return -1;

  /* Build head section (title appears twice - in <title> and <h1>) */
  head_len = strlen(html_template_head) + strlen(title) * 2 + strlen(lang) + 32;
  head_buf = MyMalloc(head_len);
  if (!head_buf) {
    MyFree(escaped);
    return -1;
  }
  head_len = ircd_snprintf(0, head_buf, head_len, html_template_head, title, title, lang);

  /* Build foot section */
  foot_len = strlen(html_template_foot) + 64;
  foot_buf = MyMalloc(foot_len);
  if (!foot_buf) {
    MyFree(head_buf);
    MyFree(escaped);
    return -1;
  }
  foot_len = ircd_snprintf(0, foot_buf, foot_len, html_template_foot,
                           lines, (unsigned long)content_len, size_buf);

  /* Combine everything */
  total_len = head_len + escaped_len + foot_len;
  *out = MyMalloc(total_len + 1);
  if (!*out) {
    MyFree(foot_buf);
    MyFree(head_buf);
    MyFree(escaped);
    return -1;
  }

  memcpy(*out, head_buf, head_len);
  memcpy(*out + head_len, escaped, escaped_len);
  memcpy(*out + head_len + escaped_len, foot_buf, foot_len);
  (*out)[total_len] = '\0';
  *out_len = total_len;

  MyFree(foot_buf);
  MyFree(head_buf);
  MyFree(escaped);
  return 0;
}

static int paste_send_response(struct paste_conn *conn, int status,
                               const char *content_type,
                               const char *body, size_t body_len)
{
  char header[1024];
  int header_len;
  const char *status_text;

  switch (status) {
    case 200: status_text = "OK"; break;
    case 400: status_text = "Bad Request"; break;
    case 404: status_text = "Not Found"; break;
    case 405: status_text = "Method Not Allowed"; break;
    case 413: status_text = "Payload Too Large"; break;
    case 429: status_text = "Too Many Requests"; break;
    case 500: status_text = "Internal Server Error"; break;
    default: status_text = "Unknown"; break;
  }

  header_len = ircd_snprintf(0, header, sizeof(header),
    "HTTP/1.1 %d %s\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %zu\r\n"
    "Connection: close\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: DENY\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Content-Security-Policy: default-src 'none'; script-src cdn.jsdelivr.net 'unsafe-inline'; style-src cdn.jsdelivr.net 'unsafe-inline'\r\n"
    "\r\n",
    status, status_text, content_type, body_len);

  /* Allocate response buffer */
  conn->response = MyMalloc(header_len + body_len);
  if (!conn->response)
    return -1;

  memcpy(conn->response, header, header_len);
  if (body && body_len > 0)
    memcpy(conn->response + header_len, body, body_len);

  conn->response_len = header_len + body_len;
  conn->response_sent = 0;
  conn->state = PASTE_CONN_WRITING;

  return 0;
}

static void paste_send_error(struct paste_conn *conn, int status,
                             const char *message)
{
  paste_send_response(conn, status, "text/plain", message, strlen(message));
}

/* ---------------------------------------------------------------------------
 * Request parsing and handling
 * ---------------------------------------------------------------------------*/

static int paste_parse_request(struct paste_conn *conn, char *method,
                               size_t method_size, char *path,
                               size_t path_size, int *want_html)
{
  char *line_end;
  char *space1, *space2;
  char *p;

  *want_html = 0;

  /* Find end of request line */
  line_end = strstr(conn->request, "\r\n");
  if (!line_end)
    return -1;

  /* Parse "METHOD /path HTTP/x.x" */
  space1 = strchr(conn->request, ' ');
  if (!space1 || space1 >= line_end)
    return -1;

  space2 = strchr(space1 + 1, ' ');
  if (!space2 || space2 >= line_end)
    return -1;

  /* Extract method */
  if ((size_t)(space1 - conn->request) >= method_size)
    return -1;
  memcpy(method, conn->request, space1 - conn->request);
  method[space1 - conn->request] = '\0';

  /* Extract path */
  if ((size_t)(space2 - space1 - 1) >= path_size)
    return -1;
  memcpy(path, space1 + 1, space2 - space1 - 1);
  path[space2 - space1 - 1] = '\0';

  /* Check for ?html=1 query param */
  p = strchr(path, '?');
  if (p) {
    *p = '\0';  /* Truncate path at query string */
    if (strstr(p + 1, "html=1"))
      *want_html = 1;
  }

  /* Check Accept header for text/html */
  p = strstr(conn->request, "\r\nAccept:");
  if (p) {
    char *accept_end = strstr(p + 2, "\r\n");
    if (accept_end) {
      char accept_buf[256];
      size_t accept_len = accept_end - p - 9;  /* Skip "\r\nAccept:" */
      if (accept_len < sizeof(accept_buf)) {
        memcpy(accept_buf, p + 9, accept_len);
        accept_buf[accept_len] = '\0';
        if (strstr(accept_buf, "text/html"))
          *want_html = 1;
      }
    }
  }

  return 0;
}

/* In-place percent-decode of '%5B'/'%5D' (case-insensitive) to '[' / ']'.
 * Applied to paste_id before validation: '[' and ']' appear in P10
 * msgids (numnicks.c convert2y[62..63]) and some clients percent-encode
 * them per RFC 3986.  Limited to bracket pairs so the decoder cannot
 * be abused to smuggle '/', NUL, or other unsafe bytes past validation.
 */
static void paste_unescape_brackets(char *s)
{
  char *r = s, *w = s;
  while (*r) {
    if (*r == '%' && r[1] == '5' && r[2]) {
      if (r[2] == 'B' || r[2] == 'b') { *w++ = '['; r += 3; continue; }
      if (r[2] == 'D' || r[2] == 'd') { *w++ = ']'; r += 3; continue; }
    }
    *w++ = *r++;
  }
  *w = '\0';
}

static int paste_validate_paste_id(const char *paste_id)
{
  const char *p;
  int has_dash = 0;

  if (!paste_id || !paste_id[0])
    return 0;

  /* Check for valid chars: A-Z, a-z, 0-9, -, _, [, ].
   * '[' and ']' appear because P10 msgids embed the server numeric
   * and HLC fields encoded with the P10 base64 alphabet (numnicks.c
   * convert2y[]), which uses '[' and ']' for indices 62 and 63. */
  for (p = paste_id; *p; p++) {
    if (*p == '-')
      has_dash = 1;
    else if (!isalnum((unsigned char)*p)
             && *p != '_' && *p != '[' && *p != ']')
      return 0;
  }

  /* Must have at least one dash (msgid-secret format) */
  return has_dash;
}

static void paste_handle_request(struct paste_conn *conn)
{
  char method[16];
  char path[256];
  int want_html;
  const char *paste_id;
  const char *msgid;
  const char *sender;
  const char *target;
  size_t content_len;
  char *buf;
  size_t i;

  /* Parse request */
  if (paste_parse_request(conn, method, sizeof(method),
                          path, sizeof(path), &want_html) < 0) {
    paste_send_error(conn, 400, "Bad Request");
    return;
  }

  /* Only GET allowed */
  if (strcmp(method, "GET") != 0) {
    paste_send_error(conn, 405, "Method Not Allowed");
    return;
  }

  /* Check path prefix */
  if (strncmp(path, PASTE_URL_PATH_PREFIX,
              sizeof(PASTE_URL_PATH_PREFIX) - 1) != 0) {
    paste_send_error(conn, 404, "Not Found");
    return;
  }

  /* Extract paste_id; decode '%5B'/'%5D' so percent-encoded brackets
   * round-trip back to the literal '[' / ']' the storage key uses. */
  paste_unescape_brackets(path + sizeof(PASTE_URL_PATH_PREFIX) - 1);
  paste_id = path + sizeof(PASTE_URL_PATH_PREFIX) - 1;

  /* Validate paste_id (security: prevent path traversal, etc.) */
  if (!paste_validate_paste_id(paste_id)) {
    paste_send_error(conn, 400, "Invalid paste ID");
    return;
  }

  /* Look up paste_id -> msgid via ml_content */
  msgid = ml_content_paste_lookup(paste_id);
  if (!msgid) {
    paste_send_error(conn, 404, "Paste not found or expired");
    return;
  }

  /* Look up content by msgid */
  buf = ml_content_get(msgid, &content_len, &sender, &target);
  if (!buf) {
    paste_send_error(conn, 404, "Paste not found or expired");
    return;
  }

  /* Content starts after sender\0target\0 — ml_content_get returns the
   * full buffer with sender/target pointers into it. The actual content
   * portion starts at (target + strlen(target) + 1). */
  const char *content = target + strlen(target) + 1;

  /* Make a mutable copy of just the content for \x1F -> \n conversion */
  char *display = (char *)MyMalloc(content_len + 1);
  memcpy(display, content, content_len);
  display[content_len] = '\0';

  /* Convert \x1F (Unit Separator) to \n for HTTP display */
  for (i = 0; i < content_len; i++) {
    if (display[i] == '\x1F')
      display[i] = '\n';
  }

  /* Parse filename hint from content */
  char filename[PASTE_FILENAME_MAX];
  const char *display_content;
  size_t display_len;
  paste_parse_filename_hint(display, content_len, filename, sizeof(filename),
                            &display_content, &display_len);

  /* Send response */
  if (want_html) {
    char *html;
    size_t html_len;

    if (paste_build_html_response(display_content, display_len,
                                  filename, &html, &html_len) < 0) {
      MyFree(display);
      MyFree(buf);
      paste_send_error(conn, 500, "Internal Server Error");
      return;
    }

    paste_send_response(conn, 200, "text/html; charset=utf-8",
                        html, html_len);
    MyFree(html);
  } else {
    paste_send_response(conn, 200, "text/plain; charset=utf-8",
                        display_content, display_len);
  }

  MyFree(display);
  MyFree(buf);
}

/* ---------------------------------------------------------------------------
 * Connection handling
 * ---------------------------------------------------------------------------*/

static struct paste_conn *paste_conn_new(int fd)
{
  struct paste_conn *conn;

  if (paste_conn_count >= feature_int(FEAT_PASTE_MAX_CONNECTIONS)) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "Paste listener: too many connections (%d)", paste_conn_count);
    return NULL;
  }

  conn = MyMalloc(sizeof(*conn));
  if (!conn)
    return NULL;

  memset(conn, 0, sizeof(*conn));
  conn->fd = fd;
  conn->state = PASTE_CONN_SSL_ACCEPT;

  /* Create SSL connection */
  conn->ssl = SSL_new(ssl_server_ctx);
  if (!conn->ssl) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste listener: SSL_new failed");
    MyFree(conn);
    return NULL;
  }

  /* Disable TLS renegotiation - browsers don't like it */
#ifdef SSL_OP_NO_RENEGOTIATION
  SSL_set_options(conn->ssl, SSL_OP_NO_RENEGOTIATION);
#endif

  /* Disable client certificate verification for HTTP clients
   * (ssl_server_ctx has SSL_VERIFY_PEER which breaks browsers) */
  SSL_set_verify(conn->ssl, SSL_VERIFY_NONE, NULL);

  if (SSL_set_fd(conn->ssl, fd) != 1) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste listener: SSL_set_fd failed");
    SSL_free(conn->ssl);
    MyFree(conn);
    return NULL;
  }

  /* Add to list */
  conn->next = paste_conn_list;
  conn->prev = NULL;
  if (paste_conn_list)
    paste_conn_list->prev = conn;
  paste_conn_list = conn;
  paste_conn_count++;

  /* Set up timeout timer */
  timer_add(timer_init(&conn->timeout), paste_timeout_callback, (void *)conn,
            TT_RELATIVE, feature_int(FEAT_PASTE_REQUEST_TIMEOUT));

  return conn;
}

static void paste_conn_free(struct paste_conn *conn)
{
  if (!conn || conn->dying)
    return;

  /* Mark dying — the struct must survive until ET_DESTROY because
   * the Socket is embedded inside it.  If we MyFree(conn) now while
   * the event engine holds a reference (gh_ref > 0), the deferred
   * ET_DESTROY writes to freed memory → heap corruption. */
  conn->dying = 1;

  /* Remove from list */
  if (conn->prev)
    conn->prev->next = conn->next;
  else
    paste_conn_list = conn->next;
  if (conn->next)
    conn->next->prev = conn->prev;
  paste_conn_count--;

  /* Cancel timeout */
  if (t_active(&conn->timeout))
    timer_del(&conn->timeout);

  /* Clean up SSL — do this before socket_del/close */
  if (conn->ssl) {
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
    conn->ssl = NULL;
  }

  /* Close fd */
  if (conn->fd >= 0) {
    close(conn->fd);
    conn->fd = -1;
  }

  /* Free response buffer */
  if (conn->response) {
    MyFree(conn->response);
    conn->response = NULL;
  }

  /* socket_del marks the socket GEN_DESTROY.  If gh_ref > 0 (we're
   * inside an event callback), ET_DESTROY is deferred until the
   * engine decrements gh_ref to 0.  The conn struct stays alive
   * until then — ET_DESTROY in paste_conn_callback calls MyFree.
   * If gh_ref == 0 (shutdown path), ET_DESTROY fires synchronously
   * from within socket_del and MyFree happens immediately. */
  socket_del(&conn->socket);
}

static void paste_timeout_callback(struct Event *ev)
{
  struct paste_conn *conn;

  if (ev_type(ev) != ET_EXPIRE)
    return;

  conn = (struct paste_conn *)t_data(ev_timer(ev));
  if (!conn)
    return;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "Paste connection timeout");
  paste_conn_free(conn);
}

/* Drain anything readable from SSL — both the kernel buffer and OpenSSL's
 * own decrypted buffer.  OpenSSL can decrypt several application records
 * out of a single TLS record (and TLS 1.3 clients routinely coalesce
 * Finished + the HTTP GET into one TCP segment), so after SSL_accept
 * completes — and after every successful SSL_read — there may be data
 * sitting in SSL_pending() that will never trigger a fresh ET_READ on
 * the level-triggered epoll fd.  Mirrors the SSL_pending drain pattern
 * in s_bsd.c::read_packet.
 */
static void paste_drain_read(struct paste_conn *conn)
{
  int rc;

  for (;;) {
    rc = SSL_read(conn->ssl,
                  conn->request + conn->request_len,
                  sizeof(conn->request) - conn->request_len - 1);
    if (rc <= 0) {
      int err = SSL_get_error(conn->ssl, rc);
      if (err == SSL_ERROR_WANT_READ)
        socket_events(&conn->socket, SOCK_EVENT_READABLE);
      else if (err == SSL_ERROR_WANT_WRITE)
        socket_events(&conn->socket, SOCK_EVENT_WRITABLE);
      else
        paste_conn_free(conn);
      return;
    }

    conn->request_len += rc;
    conn->request[conn->request_len] = '\0';

    if (strstr(conn->request, "\r\n\r\n")) {
      paste_handle_request(conn);
      if (conn->state == PASTE_CONN_WRITING)
        socket_events(&conn->socket, SOCK_EVENT_WRITABLE);
      return;
    }

    if (conn->request_len >= (int)sizeof(conn->request) - 1) {
      paste_send_error(conn, 413, "Request Too Large");
      socket_events(&conn->socket, SOCK_EVENT_WRITABLE);
      return;
    }

    if (SSL_pending(conn->ssl) <= 0)
      return;  /* kernel + SSL buffers drained; wait for next ET_READ */
  }
}

static void paste_conn_callback(struct Event *ev)
{
  struct paste_conn *conn = (struct paste_conn *)s_data(ev_socket(ev));
  int rc;

  if (!conn)
    return;

  /* After paste_conn_free marks dying, ignore all events except ET_DESTROY */
  if (conn->dying) {
    if (ev_type(ev) == ET_DESTROY)
      MyFree(conn);
    return;
  }

  switch (ev_type(ev)) {
    case ET_READ:
      if (conn->state == PASTE_CONN_SSL_ACCEPT) {
        /* Complete SSL handshake */
        rc = SSL_accept(conn->ssl);
        if (rc == 1) {
          /* Handshake complete — the same TCP segment may have carried
           * the HTTP request piggybacked behind the client's Finished,
           * so drain SSL_pending() before yielding to epoll. */
          conn->state = PASTE_CONN_READING;
          socket_events(&conn->socket, SOCK_EVENT_READABLE);
          paste_drain_read(conn);
        } else {
          int err = SSL_get_error(conn->ssl, rc);
          if (err == SSL_ERROR_WANT_READ) {
            socket_events(&conn->socket, SOCK_EVENT_READABLE);
          } else if (err == SSL_ERROR_WANT_WRITE) {
            socket_events(&conn->socket, SOCK_EVENT_WRITABLE);
          } else {
            /* Handshake failed */
            paste_conn_free(conn);
          }
        }
      } else if (conn->state == PASTE_CONN_READING) {
        paste_drain_read(conn);
      }
      break;

    case ET_WRITE:
      if (conn->state == PASTE_CONN_SSL_ACCEPT) {
        /* Continue SSL handshake */
        rc = SSL_accept(conn->ssl);
        if (rc == 1) {
          conn->state = PASTE_CONN_READING;
          socket_events(&conn->socket, SOCK_EVENT_READABLE);
          paste_drain_read(conn);
        } else {
          int err = SSL_get_error(conn->ssl, rc);
          if (err == SSL_ERROR_WANT_READ) {
            socket_events(&conn->socket, SOCK_EVENT_READABLE);
          } else if (err == SSL_ERROR_WANT_WRITE) {
            socket_events(&conn->socket, SOCK_EVENT_WRITABLE);
          } else {
            paste_conn_free(conn);
          }
        }
      } else if (conn->state == PASTE_CONN_WRITING) {
        /* Write response */
        rc = SSL_write(conn->ssl,
                       conn->response + conn->response_sent,
                       conn->response_len - conn->response_sent);
        if (rc > 0) {
          conn->response_sent += rc;
          if (conn->response_sent >= conn->response_len) {
            /* Response complete */
            paste_conn_free(conn);
          }
        } else {
          int err = SSL_get_error(conn->ssl, rc);
          if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            paste_conn_free(conn);
          }
        }
      }
      break;

    case ET_EOF:
    case ET_ERROR:
      paste_conn_free(conn);
      break;

    default:
      break;
  }
}

/* ---------------------------------------------------------------------------
 * Listener accept
 * ---------------------------------------------------------------------------*/

/* Per-fd connection setup, called from accept_connection() in listener.c
 * for fds accepted on a Listener with the LISTEN_PASTE flag.
 */
void paste_accept_connection(int fd)
{
  struct paste_conn *conn;

  /* Set non-blocking */
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "Paste listener: fcntl failed: %s", strerror(errno));
    close(fd);
    return;
  }

  /* Create connection */
  conn = paste_conn_new(fd);
  if (!conn) {
    close(fd);
    return;
  }

  /* Register socket for events */
  if (!socket_add(&conn->socket, paste_conn_callback, conn,
                  SS_CONNECTED, SOCK_EVENT_READABLE, fd)) {
    paste_conn_free(conn);
    return;
  }

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "Paste listener: new connection (total: %d)", paste_conn_count);
}

/* ---------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------*/

void paste_listener_shutdown(void)
{
  struct paste_conn *conn, *next;

  /* Close all in-flight paste connections.  The listener fds themselves
   * are owned by struct Listener and reaped by close_listeners(). */
  for (conn = paste_conn_list; conn; conn = next) {
    next = conn->next;
    paste_conn_free(conn);
  }

  log_write(LS_SYSTEM, L_INFO, 0, "Paste listener: shutdown");
}

int paste_listener_active(void)
{
  return paste_listener_port() != 0;
}

#else /* !USE_SSL */

/* Stub implementations when SSL is not available */

#include "paste_listener.h"
#include "ircd_log.h"
#include <string.h>
#include <unistd.h>

void paste_listener_shutdown(void)
{
}

int paste_listener_active(void)
{
  return 0;
}

int paste_listener_port(void)
{
  return 0;
}

void paste_accept_connection(int fd)
{
  /* Paste requires SSL; close any accidentally-dispatched connection. */
  close(fd);
}

const char *paste_url(const char *paste_id)
{
  static char buf[16] = "";
  return buf;
}

void paste_generate_secret(char *out, size_t len)
{
  if (len > 0)
    out[0] = '\0';
}

void paste_parse_filename_hint(const char *content, size_t len,
                               char *filename, size_t filename_size,
                               const char **out_content, size_t *out_len)
{
  if (filename_size > 0)
    filename[0] = '\0';
  *out_content = content;
  *out_len = len;
}

const char *paste_ext_to_lang(const char *filename)
{
  return "plaintext";
}

#endif /* USE_SSL */
