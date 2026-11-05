/*
 * websocket_cmocka.c - CMocka unit tests for the WebSocket transport.
 *
 * Covers the regressions behind evilnet/nefarious2 #98 and #99:
 *   - websocket_decode_frame() with payloads of 600 bytes and
 *     WS_MAX_PAYLOAD (16384) when given a WS_MAX_PAYLOAD-sized buffer,
 *     the WS_DECODE_TOOBIG return one byte over, and the old failure
 *     mode (a BUFSIZE-sized buffer rejects a 600-byte frame).
 *   - websocket_handshake_feed() accumulating upgrade requests of 600
 *     and 2000 bytes across 512-byte reads, handing back bytes that
 *     follow the request, and rejecting a request over WS_HANDSHAKE_MAX.
 *   - parse_ws_handshake()'s Sec-WebSocket-Protocol scan, which spun
 *     forever on a header whose last token is unsupported ("chat").
 *   - websocket_frag_feed() reassembling fragmented messages: a message
 *     of exactly WS_MAX_PAYLOAD (whose NUL used to land past the buffer),
 *     overflow, a continuation with no message started, and UTF-8.
 *   - One Close per connection (§5.5.1): after a refusal's coded Close,
 *     or the answer to a client's Close, the farewell Close 1000 that
 *     exit_client() and a bouncer hold set changes nothing; a plain exit
 *     still sends its one Close.
 *   - No data frame after the Close (§5.5.1): a Close is set, not sent,
 *     and websocket_close_flush() (close_connection()) sends it after the
 *     queued lines, so exit_client()'s "ERROR :Closing Link" goes first.
 *   - RFC 6455 framing refusals: a control frame without FIN is a
 *     decode error (§5.5); websocket_frag_feed() answers a TEXT/BINARY
 *     frame inside a fragmented message and an orphan continuation with
 *     Close 1002 (§5.4), a reassembled TEXT message that is not UTF-8
 *     with Close 1007 (§8.1), and a reassembly past WS_MAX_PAYLOAD with
 *     Close 1009.  The UTF-8 check covers the whole message, past a NUL.
 *
 * websocket.c is included directly (like ircd_cloaking_cmocka.c) with
 * stubs for feature_str(), ircd_snprintf(), os_send_nonb() and
 * send_queued().
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cmocka.h>

#include "../websocket.c"

/* ---- stubs for websocket.c's external dependencies ---- */

/* Keepalive-ping additions (ws_ping_timer): websocket.c walks the
 * local client array from a periodic timer.  The harness never arms
 * the timer (feature_int returns 0 = disabled), so these exist only
 * to satisfy the linker of this standalone TU. */
int HighestFd = -1;
struct Client* LocalClientArray[MAXCONNECTIONS];

int feature_int(enum Feature feat)
{
  (void)feat;
  return 0; /* WEBSOCKET_PING_INTERVAL disabled in the harness */
}

struct Timer* timer_init(struct Timer* timer)
{
  return timer;
}

void timer_add(struct Timer* timer, EventCallBack call, void* data,
               enum TimerType type, time_t value)
{
  (void)timer; (void)call; (void)data; (void)type; (void)value;
}

const char *feature_str(enum Feature feat)
{
  (void)feat;
  return "";  /* FEAT_WEBSOCKET_ORIGIN: allow all origins */
}

/* ws_send_raw() arms writable interest when an out-of-band frame goes
 * pending inside OpenSSL; the harness has no event loop. */
void update_write(struct Client* cptr)
{
  (void)cptr;
}

/* ssl.c: the OpenSSL error queue is emptied around the TLS writes. */
void ssl_clear_errors(const char *where)
{
  (void)where;
}

int ircd_snprintf(struct Client *dest, char *buf, size_t buf_len,
                  const char *format, ...)
{
  va_list args;
  int ret;
  (void)dest;
  va_start(args, format);
  ret = vsnprintf(buf, buf_len, format, args);
  va_end(args);
  return ret;
}

/* Capture whatever websocket.c writes to the (plain) socket: the last
 * write in sent_buf, how many writes there were, and the first
 * SENT_LOG_MAX writes in order in sent_log (to check what went first). */
#define SENT_LOG_MAX 8
static char sent_buf[1024];
static int sent_len;
static int sent_count;
static unsigned char sent_log[SENT_LOG_MAX][1024];
static int sent_log_len[SENT_LOG_MAX];

IOResult os_send_nonb(int fd, const char *buf, unsigned int length,
                      unsigned int *count_out)
{
  (void)fd;
  if (length > sizeof(sent_buf) - 1)
    length = sizeof(sent_buf) - 1;
  memcpy(sent_buf, buf, length);
  sent_buf[length] = '\0';
  sent_len = length;
  if (sent_count < SENT_LOG_MAX) {
    memcpy(sent_log[sent_count], buf, length);
    sent_log_len[sent_count] = length;
  }
  sent_count++;
  *count_out = length;
  return IO_SUCCESS;
}

/* send.c: websocket_close_flush() sends the lines queued on a closing
 * connection before its Close.  A test queues one line here (the
 * "ERROR :Closing Link" exit_client() queues last); the stub frames it
 * as deliver_it() does and writes it through os_send_nonb(). */
static const char *queued_line;

void send_queued(struct Client *to)
{
  static unsigned char frame[BUFSIZE + 16];
  unsigned int n;
  int len;

  if (!queued_line)
    return;
  len = websocket_encode_frame(queued_line, (int)strlen(queued_line), frame, 1);
  queued_line = NULL;
  os_send_nonb(cli_fd(to), (const char *)frame, (unsigned int)len, &n);
}

/* ---- helpers ---- */

static void setup_client(struct Client *cli, struct Connection *con)
{
  memset(cli, 0, sizeof(*cli));
  memset(con, 0, sizeof(*con));
  cli_connect(cli) = con;
  strcpy(cli_sockhost(cli), "test.host");
  sent_len = 0;
  sent_count = 0;
  sent_buf[0] = '\0';
  memset(sent_log_len, 0, sizeof(sent_log_len));
  queued_line = NULL;
}

/* Build a masked client->server frame: FIN | opcode, payload of plen 'x'
 * bytes.  Returns the frame length. */
static int build_frame(unsigned char *frame, int opcode, int plen)
{
  static const unsigned char mask[4] = { 0x12, 0x34, 0x56, 0x78 };
  int pos = 0, i;

  frame[pos++] = 0x80 | opcode;
  if (plen < 126) {
    frame[pos++] = 0x80 | plen;
  } else if (plen < 65536) {
    frame[pos++] = 0x80 | 126;
    frame[pos++] = (plen >> 8) & 0xFF;
    frame[pos++] = plen & 0xFF;
  } else {
    frame[pos++] = 0x80 | 127;
    for (i = 7; i >= 0; i--)
      frame[pos++] = (i < 4) ? ((plen >> (i * 8)) & 0xFF) : 0;
  }
  memcpy(frame + pos, mask, 4);
  pos += 4;
  for (i = 0; i < plen; i++)
    frame[pos + i] = ('a' + (i % 26)) ^ mask[i % 4];
  return pos + plen;
}

/* Build an upgrade request padded with an X-Pad header to exactly
 * total_len bytes (including the terminating blank line). */
static int build_request(char *req, int total_len)
{
  static const char head[] =
    "GET / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Protocol: text.ircv3.net\r\n"
    "X-Pad: ";
  static const char tail[] = "\r\n\r\n";
  int pad = total_len - (int)(sizeof(head) - 1) - (int)(sizeof(tail) - 1);

  assert_true(pad >= 0);
  memcpy(req, head, sizeof(head) - 1);
  memset(req + sizeof(head) - 1, 'p', pad);
  memcpy(req + sizeof(head) - 1 + pad, tail, sizeof(tail) - 1);
  req[total_len] = '\0';
  return total_len;
}

/* Build a minimal upgrade request with NO Sec-WebSocket-Protocol header,
 * to exercise the no-subprotocol default (text). */
static int build_request_nosub(char *req)
{
  static const char r[] =
    "GET / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";
  memcpy(req, r, sizeof(r) - 1);
  return (int)(sizeof(r) - 1);
}

/* Feed 'req' to websocket_handshake_feed() in chunks of 'chunk' bytes,
 * asserting it wants more until the last chunk.  Returns the final result
 * and the consumed count of the last call. */
static int feed_in_chunks(struct Client *cli, const char *req, int len,
                          int chunk, int *last_consumed)
{
  int off = 0, result = 0, consumed = 0;

  while (off < len) {
    int n = (len - off < chunk) ? len - off : chunk;
    result = websocket_handshake_feed(cli, req + off, n, &consumed);
    off += n;
    if (off < len) {
      assert_int_equal(result, 0);
      assert_int_equal(consumed, n);
    }
  }
  *last_consumed = consumed;
  return result;
}

/* ========== websocket_decode_frame() (#98) ========== */

static void test_decode_600_byte_frame(void **state)
{
  static unsigned char frame[WS_MAX_FRAME];
  static char payload[WS_MAX_PAYLOAD + 2];
  int flen, consumed, plen, opcode, fin;
  (void)state;

  flen = build_frame(frame, WS_OPCODE_TEXT, 600);
  consumed = websocket_decode_frame(frame, flen, payload, sizeof(payload),
                                    &plen, &opcode, &fin);
  assert_int_equal(consumed, flen);
  assert_int_equal(plen, 600);
  assert_int_equal(opcode, WS_OPCODE_TEXT);
  assert_int_equal(fin, 1);
  assert_int_equal(payload[0], 'a');
  assert_int_equal(payload[599], 'a' + (599 % 26));
  assert_int_equal(payload[600], '\0');
}

static void test_decode_max_payload_frame(void **state)
{
  static unsigned char frame[WS_MAX_FRAME];
  static char payload[WS_MAX_PAYLOAD + 2];
  int flen, consumed, plen, opcode, fin;
  (void)state;

  flen = build_frame(frame, WS_OPCODE_BINARY, WS_MAX_PAYLOAD);
  assert_true(flen <= WS_MAX_FRAME);
  consumed = websocket_decode_frame(frame, flen, payload, sizeof(payload),
                                    &plen, &opcode, &fin);
  assert_int_equal(consumed, flen);
  assert_int_equal(plen, WS_MAX_PAYLOAD);
  assert_int_equal(opcode, WS_OPCODE_BINARY);
  assert_int_equal(payload[WS_MAX_PAYLOAD - 1],
                   'a' + ((WS_MAX_PAYLOAD - 1) % 26));
}

static void test_decode_over_max_is_toobig(void **state)
{
  static unsigned char frame[WS_MAX_FRAME + 1];
  static char payload[WS_MAX_PAYLOAD + 2];
  int flen, consumed, plen, opcode, fin;
  (void)state;

  flen = build_frame(frame, WS_OPCODE_TEXT, WS_MAX_PAYLOAD + 1);
  consumed = websocket_decode_frame(frame, flen, payload, sizeof(payload),
                                    &plen, &opcode, &fin);
  assert_int_equal(consumed, WS_DECODE_TOOBIG);
}

/* The pre-fix caller: a BUFSIZE + 16 buffer cannot take a 600-byte frame.
 * Documents why the buffer in read_packet() must be WS_MAX_PAYLOAD-sized. */
static void test_decode_small_buffer_rejects(void **state)
{
  static unsigned char frame[WS_MAX_FRAME];
  char payload[BUFSIZE + 16];
  int flen, consumed, plen, opcode, fin;
  (void)state;

  flen = build_frame(frame, WS_OPCODE_TEXT, 600);
  consumed = websocket_decode_frame(frame, flen, payload, sizeof(payload),
                                    &plen, &opcode, &fin);
  assert_int_equal(consumed, -1);
}

static void test_decode_incomplete_frame(void **state)
{
  static unsigned char frame[WS_MAX_FRAME];
  static char payload[WS_MAX_PAYLOAD + 2];
  int flen, consumed, plen, opcode, fin;
  (void)state;

  flen = build_frame(frame, WS_OPCODE_TEXT, 2000);
  /* Everything but the last byte: must ask for more, not error */
  consumed = websocket_decode_frame(frame, flen - 1, payload, sizeof(payload),
                                    &plen, &opcode, &fin);
  assert_int_equal(consumed, 0);
}

/* CLOSE control frame => websocket_handle_control returns 0, the signal
 * s_bsd.c's read loop keys the bouncer-hold-or-exit branch on.  The
 * hold wiring itself lives mid-socket-loop (not unit-reachable); it
 * mirrors the dead-link hold pattern the Vitest bouncer suite already
 * exercises via TCP drop.  End-to-end WS-close-while-held stays
 * unverified until something can speak WS to the bed. */
static void test_control_close_signals_teardown(void **state)
{
  struct Client cli;
  struct Connection con;
  char status[2] = { 0x03, (char)0xE8 };  /* 1000 normal closure */
  (void)state;

  setup_client(&cli, &con);
  /* PING and PONG keep the connection alive... */
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_PING, "hi", 2), 1);
  assert_true((unsigned char)sent_buf[0] == (WS_FIN | WS_OPCODE_PONG));
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_PONG, NULL, 0), 1);

  /* ...CLOSE signals teardown (return 0), and the close response that
   * goes out when the connection is flushed echoes the client's status
   * code. */
  setup_client(&cli, &con);
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_CLOSE, status, 2), 0);
  websocket_close_flush(&cli);
  assert_true((unsigned char)sent_buf[0] == (WS_FIN | WS_OPCODE_CLOSE));
  assert_int_equal(sent_buf[1], 2);
  assert_true((unsigned char)sent_buf[2] == 0x03 && (unsigned char)sent_buf[3] == 0xE8);

  /* Payload-less CLOSE also signals teardown. */
  setup_client(&cli, &con);
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_CLOSE, NULL, 0), 0);
  websocket_close_flush(&cli);
  assert_true((unsigned char)sent_buf[0] == (WS_FIN | WS_OPCODE_CLOSE));
}

/* ========== websocket_handshake_feed() (#99) ========== */

static void test_handshake_600_bytes_split_reads(void **state)
{
  struct Client cli;
  struct Connection con;
  static char req[4096];
  int len, result, consumed;
  (void)state;

  setup_client(&cli, &con);
  SetWSNeedHandshake(&cli);
  len = build_request(req, 600);
  result = feed_in_chunks(&cli, req, len, 512, &consumed);
  assert_int_equal(result, 1);
  assert_int_equal(consumed, len - 512);
  assert_true(strncmp(sent_buf, "HTTP/1.1 101 ", 13) == 0);
  assert_non_null(strstr(sent_buf, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
  assert_non_null(strstr(sent_buf, "Sec-WebSocket-Protocol: text.ircv3.net"));
  assert_true(IsWebSocket(&cli));
  assert_true(IsWSText(&cli));
  assert_false(IsWSNeedHandshake(&cli));
  assert_null(cli_ws_hs_buf(&cli));
  assert_int_equal(cli_ws_hs_len(&cli), 0);
}

static void test_handshake_2000_bytes_split_reads(void **state)
{
  struct Client cli;
  struct Connection con;
  static char req[4096];
  int len, result, consumed;
  (void)state;

  setup_client(&cli, &con);
  len = build_request(req, 2000);
  result = feed_in_chunks(&cli, req, len, 512, &consumed);
  assert_int_equal(result, 1);
  assert_int_equal(consumed, len - 3 * 512);
  assert_true(strncmp(sent_buf, "HTTP/1.1 101 ", 13) == 0);
  assert_true(IsWebSocket(&cli));
  assert_null(cli_ws_hs_buf(&cli));
}

static void test_handshake_single_read(void **state)
{
  struct Client cli;
  struct Connection con;
  static char req[4096];
  int len, result, consumed;
  (void)state;

  setup_client(&cli, &con);
  len = build_request(req, 300);
  result = websocket_handshake_feed(&cli, req, len, &consumed);
  assert_int_equal(result, 1);
  assert_int_equal(consumed, len);
  assert_true(IsWebSocket(&cli));
}

/* No Sec-WebSocket-Protocol: default is TEXT (with autodetect armed so a
 * binary first frame can still override).  Guards the pre-registration
 * NOTICE flush going out as text frames for browser-style clients. */
static void test_handshake_no_subproto_defaults_text(void **state)
{
  struct Client cli;
  struct Connection con;
  static char req[1024];
  int len, result, consumed;
  (void)state;

  setup_client(&cli, &con);
  len = build_request_nosub(req);
  result = websocket_handshake_feed(&cli, req, len, &consumed);
  assert_int_equal(result, 1);
  assert_true(IsWebSocket(&cli));
  assert_true(IsWSText(&cli));        /* default text */
  assert_true(IsWSAutodetect(&cli));  /* but still overridable by first frame */
}

/* Terminator split across reads: "\r\n\r" then "\n". */
static void test_handshake_terminator_split(void **state)
{
  struct Client cli;
  struct Connection con;
  static char req[4096];
  int len, result, consumed;
  (void)state;

  setup_client(&cli, &con);
  len = build_request(req, 700);
  result = websocket_handshake_feed(&cli, req, len - 1, &consumed);
  assert_int_equal(result, 0);
  assert_int_equal(consumed, len - 1);
  result = websocket_handshake_feed(&cli, req + len - 1, 1, &consumed);
  assert_int_equal(result, 1);
  assert_int_equal(consumed, 1);
  assert_true(IsWebSocket(&cli));
}

/* An early frame in the same read as the end of the request must be
 * reported as not consumed so the caller can decode it. */
static void test_handshake_trailing_frame_not_consumed(void **state)
{
  struct Client cli;
  struct Connection con;
  static char req[4096];
  int len, result, consumed;
  (void)state;

  setup_client(&cli, &con);
  len = build_request(req, 900);
  memcpy(req + len, "FRAME", 5);
  result = feed_in_chunks(&cli, req, len + 5, 512, &consumed);
  assert_int_equal(result, 1);
  assert_int_equal(consumed, len - 512);  /* last chunk minus the 5 frame bytes */
  assert_true(IsWebSocket(&cli));
}

static void test_handshake_too_large(void **state)
{
  struct Client cli;
  struct Connection con;
  static char req[WS_HANDSHAKE_MAX + 1024];
  int result, consumed, off = 0;
  (void)state;

  setup_client(&cli, &con);
  /* A request that never ends */
  memcpy(req, "GET / HTTP/1.1\r\nX-Pad: ", 23);
  memset(req + 23, 'p', sizeof(req) - 23);
  do {
    result = websocket_handshake_feed(&cli, req + off, 512, &consumed);
    off += 512;
  } while (result == 0 && off < (int)sizeof(req));
  assert_int_equal(result, WS_HANDSHAKE_TOOBIG);
  assert_true(off <= WS_HANDSHAKE_MAX + 512);
  assert_null(cli_ws_hs_buf(&cli));
  assert_false(IsWebSocket(&cli));
}

static void test_handshake_invalid_request(void **state)
{
  struct Client cli;
  struct Connection con;
  static const char req[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  int result, consumed;
  (void)state;

  setup_client(&cli, &con);
  result = websocket_handshake_feed(&cli, req, sizeof(req) - 1, &consumed);
  assert_int_equal(result, -1);
  assert_null(cli_ws_hs_buf(&cli));
  assert_false(IsWebSocket(&cli));
}

/* ========== parse_ws_handshake() Sec-WebSocket-Protocol ========== */

/* Run parse_ws_handshake() on a valid upgrade request carrying the given
 * extra header lines (each ending in "\r\n") and return the subprotocol
 * it chose.  The alarm turns a scan that never ends into a failed test
 * (the process dies on SIGALRM) instead of a hung run. */
static int parse_subproto(const char *extra)
{
  static char req[2048];
  char key[64], origin[256];
  int subproto = -1, valid, len;

  len = snprintf(req, sizeof(req),
                 "GET / HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                 "Sec-WebSocket-Version: 13\r\n"
                 "%s"
                 "\r\n", extra);
  assert_true(len > 0 && len < (int)sizeof(req));
  alarm(5);
  valid = parse_ws_handshake(req, len, key, &subproto, origin);
  alarm(0);
  assert_int_equal(valid, 1);
  return subproto;
}

/* A header whose last token is unsupported used to spin forever: the
 * token scan stopped at '\r', which the delimiter skip did not step
 * over, so the scan pointer never moved again. */
static void test_subproto_unsupported_only(void **state)
{
  (void)state;
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: chat\r\n"),
                   WS_SUBPROTO_NONE);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: foo, bar\r\n"),
                   WS_SUBPROTO_NONE);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: chat  \r\n"),
                   WS_SUBPROTO_NONE);
}

static void test_subproto_empty_value(void **state)
{
  (void)state;
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol:\r\n"),
                   WS_SUBPROTO_NONE);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: \r\n"),
                   WS_SUBPROTO_NONE);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: , ,\r\n"),
                   WS_SUBPROTO_NONE);
}

/* First supported token wins, wherever it sits in the list. */
static void test_subproto_first_supported_wins(void **state)
{
  (void)state;
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: text.ircv3.net\r\n"),
                   WS_SUBPROTO_TEXT);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: chat, binary.ircv3.net\r\n"),
                   WS_SUBPROTO_BINARY);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: text.ircv3.net, chat\r\n"),
                   WS_SUBPROTO_TEXT);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: binary.ircv3.net,text.ircv3.net\r\n"),
                   WS_SUBPROTO_BINARY);
}

/* Matching stays on token boundaries. */
static void test_subproto_token_boundaries(void **state)
{
  (void)state;
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: notext.ircv3.net\r\n"),
                   WS_SUBPROTO_NONE);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: text.ircv3.netx\r\n"),
                   WS_SUBPROTO_NONE);
  /* A stray '\r' inside the line is part of a token, not its end. */
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: a\rb\r\n"),
                   WS_SUBPROTO_NONE);
}

/* Several header lines: an unsupported-only line does not stop a later
 * line from choosing, an earlier choice is never overridden, and the
 * scan never reads a token off the next header line. */
static void test_subproto_multiple_headers(void **state)
{
  (void)state;
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: chat\r\n"
                                  "Sec-WebSocket-Protocol: binary.ircv3.net\r\n"),
                   WS_SUBPROTO_BINARY);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: text.ircv3.net\r\n"
                                  "Sec-WebSocket-Protocol: binary.ircv3.net\r\n"),
                   WS_SUBPROTO_TEXT);
  assert_int_equal(parse_subproto("Sec-WebSocket-Protocol: chat\r\n"
                                  "X-Other: text.ircv3.net\r\n"),
                   WS_SUBPROTO_NONE);
}

/* ========== websocket_frag_feed() fragment reassembly ========== */

static char frag_src[WS_MAX_PAYLOAD + 1];

static void fill_src(void)
{
  int i;
  for (i = 0; i < (int)sizeof(frag_src); i++)
    frag_src[i] = 'a' + (i % 26);
}

/* Fragments are joined byte for byte, and the state resets after FIN. */
static void test_frag_reassembles(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "PRIV", 4,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 0,
                                       "MSG #c", 6, &msg, &msg_len),
                   WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       " :hi", 4, &msg, &msg_len),
                   WS_FRAG_DONE);
  assert_int_equal(msg_len, 14);
  assert_memory_equal(msg, "PRIVMSG #c :hi", 15);  /* includes the NUL */
  assert_int_equal(con.con_ws_frag_len, 0);
  assert_int_equal(con.con_ws_frag_opcode, 0);
}

/* A message of exactly WS_MAX_PAYLOAD bytes is accepted, and the NUL
 * after it plus the '\n' the caller adds both land inside the buffer.
 * Before, the buffer was exactly WS_MAX_PAYLOAD bytes and the NUL went
 * one past its end. */
static void test_frag_max_payload_fits(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  fill_src();
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_BINARY, 0, frag_src,
                                       WS_MAX_PAYLOAD - 100, &msg, &msg_len),
                   WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       frag_src + WS_MAX_PAYLOAD - 100, 100,
                                       &msg, &msg_len), WS_FRAG_DONE);
  assert_int_equal(msg_len, WS_MAX_PAYLOAD);
  assert_memory_equal(msg, frag_src, WS_MAX_PAYLOAD);
  assert_int_equal(msg[msg_len], '\0');
  assert_true(msg + msg_len + 1 < con.con_ws_frag_buf + sizeof(con.con_ws_frag_buf));
}

/* The old out-of-bounds path exactly: a full first fragment, then an
 * empty final continuation. */
static void test_frag_full_then_empty_fin(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  fill_src();
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_BINARY, 0, frag_src,
                                       WS_MAX_PAYLOAD, &msg, &msg_len),
                   WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "", 0, &msg, &msg_len), WS_FRAG_DONE);
  assert_int_equal(msg_len, WS_MAX_PAYLOAD);
  assert_int_equal(msg[msg_len], '\0');
}

static void test_frag_overflow(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  fill_src();
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, frag_src,
                                       WS_MAX_PAYLOAD, &msg, &msg_len),
                   WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "x", 1, &msg, &msg_len),
                   WS_FRAG_OVERFLOW);
}

/* RFC 6455 §5.4: a CONTINUATION with no message started is refused,
 * both on a fresh connection and after a message has completed. */
static void test_frag_orphan_continuation(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "QUIT", 4, &msg, &msg_len),
                   WS_FRAG_ORPHAN);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "a", 1,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "b", 1, &msg, &msg_len), WS_FRAG_DONE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "c", 1, &msg, &msg_len),
                   WS_FRAG_ORPHAN);
}

/* A reassembled TEXT message must be UTF-8; BINARY carries any bytes. */
static void test_frag_text_utf8(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "ok \xC3", 4,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "\xA9", 1, &msg, &msg_len),
                   WS_FRAG_DONE);  /* U+00E9 split across frames */
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "bad \xFF", 5,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "", 0, &msg, &msg_len),
                   WS_FRAG_BADUTF8);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_BINARY, 0, "bad \xFF", 5,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "", 0, &msg, &msg_len),
                   WS_FRAG_DONE);
}

/* ========== RFC 6455 framing refusals ========== */

/* As build_frame(), with the FIN bit given: 0 marks a fragment. */
static int build_frame_fin(unsigned char *frame, int opcode, int plen, int fin)
{
  int len = build_frame(frame, opcode, plen);

  if (!fin)
    frame[0] &= ~WS_FIN;
  return len;
}

/* The last write to the socket was a Close frame with status 'code'. */
static void assert_close_sent(int code)
{
  assert_true(sent_len >= 4);
  assert_int_equal((unsigned char)sent_buf[0], WS_FIN | WS_OPCODE_CLOSE);
  assert_int_equal((unsigned char)sent_buf[1], sent_len - 2);
  assert_int_equal(((unsigned char)sent_buf[2] << 8) | (unsigned char)sent_buf[3],
                   code);
}

/* A refusal sets the connection's Close and sends nothing: the Close goes
 * out when the closing connection is flushed (close_connection()), after
 * the lines queued before it.  Then it is the one write, with 'code'. */
static void assert_close_at_flush(struct Client *cli, int code)
{
  assert_int_equal(sent_count, 0);
  websocket_close_flush(cli);
  assert_int_equal(sent_count, 1);
  assert_close_sent(code);
}

/* §5.5: control frames are never fragmented.  CLOSE, PING and PONG
 * without FIN are a protocol error for the decoder (the caller answers
 * Close 1002); with FIN they decode.  A data frame without FIN is still
 * a fragment.  Before, a control frame without FIN decoded as if it
 * were complete. */
static void test_decode_fragmented_control_refused(void **state)
{
  static const int ctl[] = { WS_OPCODE_CLOSE, WS_OPCODE_PING, WS_OPCODE_PONG };
  static const int data[] = { WS_OPCODE_TEXT, WS_OPCODE_BINARY,
                              WS_OPCODE_CONTINUATION };
  unsigned char frame[64];
  char payload[WS_MAX_PAYLOAD + 2];
  int len, plen, opcode, is_fin, i;
  (void)state;

  for (i = 0; i < 3; i++) {
    len = build_frame_fin(frame, ctl[i], 2, 0);
    assert_int_equal(websocket_decode_frame(frame, len, payload, sizeof(payload),
                                            &plen, &opcode, &is_fin), -1);
    len = build_frame_fin(frame, ctl[i], 2, 1);
    assert_int_equal(websocket_decode_frame(frame, len, payload, sizeof(payload),
                                            &plen, &opcode, &is_fin), len);
    assert_int_equal(opcode, ctl[i]);
    assert_int_equal(is_fin, 1);
  }
  for (i = 0; i < 3; i++) {
    len = build_frame_fin(frame, data[i], 5, 0);
    assert_int_equal(websocket_decode_frame(frame, len, payload, sizeof(payload),
                                            &plen, &opcode, &is_fin), len);
    assert_int_equal(opcode, data[i]);
    assert_int_equal(is_fin, 0);
    assert_int_equal(plen, 5);
  }
}

/* §5.4: once a fragmented message has started, only its CONTINUATION
 * frames may follow (control frames never reach websocket_frag_feed).
 * A TEXT or BINARY frame, with FIN or without, is refused with Close
 * 1002.  Before, one without FIN silently restarted the reassembly and
 * one with FIN was delivered on its own past the half-built message. */
static void test_frag_data_frame_mid_message(void **state)
{
  static const int data[] = { WS_OPCODE_TEXT, WS_OPCODE_BINARY };
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  int i, fin;
  (void)state;

  for (i = 0; i < 2; i++) {
    for (fin = 0; fin <= 1; fin++) {
      setup_client(&cli, &con);
      assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "PRIV", 4,
                                           &msg, &msg_len), WS_FRAG_MORE);
      assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 0,
                                           "MSG", 3, &msg, &msg_len),
                       WS_FRAG_MORE);
      assert_int_equal(sent_len, 0);
      assert_int_equal(websocket_frag_feed(&cli, data[i], fin, "QUIT", 4,
                                           &msg, &msg_len),
                       WS_FRAG_INTERLEAVED);
      assert_close_at_flush(&cli, 1002);
    }
  }
}

/* A new message after a completed one is not interleaving: it starts a
 * fresh reassembly and no Close goes out. */
static void test_frag_new_message_after_done(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "a", 1,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "b", 1, &msg, &msg_len), WS_FRAG_DONE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_BINARY, 0, "c", 1,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "d", 1, &msg, &msg_len), WS_FRAG_DONE);
  assert_int_equal(msg_len, 2);
  assert_memory_equal(msg, "cd", 3);
  assert_int_equal(sent_len, 0);
}

/* A reassembly past WS_MAX_PAYLOAD is answered with Close 1009, as a
 * single frame over the limit is (WS_DECODE_TOOBIG), whether the last
 * fragment or one in the middle tips it over. */
static void test_frag_overflow_sends_1009(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  fill_src();
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, frag_src,
                                       WS_MAX_PAYLOAD, &msg, &msg_len),
                   WS_FRAG_MORE);
  assert_int_equal(sent_len, 0);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "x", 1, &msg, &msg_len),
                   WS_FRAG_OVERFLOW);
  assert_close_at_flush(&cli, 1009);

  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_BINARY, 0, frag_src,
                                       WS_MAX_PAYLOAD / 2, &msg, &msg_len),
                   WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 0,
                                       frag_src, WS_MAX_PAYLOAD / 2,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(sent_len, 0);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 0,
                                       "x", 1, &msg, &msg_len),
                   WS_FRAG_OVERFLOW);
  assert_close_at_flush(&cli, 1009);
}

/* §5.4: a CONTINUATION with no message started is answered with Close
 * 1002, on a fresh connection and after a message has completed. */
static void test_frag_orphan_sends_1002(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "QUIT", 4, &msg, &msg_len),
                   WS_FRAG_ORPHAN);
  assert_close_at_flush(&cli, 1002);

  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "a", 1,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "b", 1, &msg, &msg_len), WS_FRAG_DONE);
  assert_int_equal(sent_len, 0);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 0,
                                       "c", 1, &msg, &msg_len),
                   WS_FRAG_ORPHAN);
  assert_close_at_flush(&cli, 1002);
}

/* §8.1: a reassembled TEXT message that is not UTF-8 is answered with
 * Close 1007 (§7.4.1, data inconsistent with the message type).  BINARY
 * carries any bytes, and valid UTF-8 split across frames is fine: no
 * Close for either. */
static void test_frag_badutf8_sends_1007(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "ok \xC3", 4,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "\xA9", 1, &msg, &msg_len),
                   WS_FRAG_DONE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_BINARY, 0, "bad \xFF", 5,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "", 0, &msg, &msg_len), WS_FRAG_DONE);
  assert_int_equal(sent_len, 0);

  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "bad \xFF", 5,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "", 0, &msg, &msg_len),
                   WS_FRAG_BADUTF8);
  assert_close_at_flush(&cli, 1007);
}

/* §8.1 asks about the whole reassembled TEXT message, and U+0000 is a
 * character like any other: a NUL inside it ends nothing.  The check of
 * the message as a C string stopped at the NUL, so a bad byte after one
 * was delivered; it is answered with Close 1007 like one before it. */
static void test_frag_text_nul_then_badutf8_sends_1007(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  /* A NUL in valid UTF-8 is fine: the whole message is handed back */
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "PING :a\0", 8,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "\303\251", 2, &msg, &msg_len),
                   WS_FRAG_DONE);
  assert_int_equal(msg_len, 10);
  assert_memory_equal(msg, "PING :a\0\303\251", 10);
  assert_int_equal(sent_count, 0);

  /* A bad byte after the NUL is refused */
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "PING :a\0", 8,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "\377", 1, &msg, &msg_len),
                   WS_FRAG_BADUTF8);
  assert_close_at_flush(&cli, 1007);

  /* ...and so is a sequence the NUL cuts short */
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, "PING :\303", 7,
                                       &msg, &msg_len), WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "\0", 1, &msg, &msg_len),
                   WS_FRAG_BADUTF8);
  assert_close_at_flush(&cli, 1007);
}

/* ========== One Close per connection (RFC 6455 §5.5.1) ========== */

/* A refusal's coded Close is the only one: the farewell Close 1000 that
 * exit_client() sets for every WebSocket client on the way out (and a
 * bouncer hold's, when the session holds) does not replace it, and a
 * second flush sends nothing.  Before, the client got the coded Close
 * and then a 1000. */
static void test_close_once_after_refusal(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  (void)state;

  /* A refusal websocket_frag_feed() answers itself */
  fill_src();
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, frag_src,
                                       WS_MAX_PAYLOAD, &msg, &msg_len),
                   WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "x", 1, &msg, &msg_len),
                   WS_FRAG_OVERFLOW);
  websocket_set_close(&cli, 1000, "WebSocket fragment overflow"); /* exit_client() */
  websocket_set_close(&cli, 1000, "held");                        /* a hold */
  assert_close_at_flush(&cli, 1009);
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 1);

  /* A refusal read_packet answers (a decode error) */
  setup_client(&cli, &con);
  websocket_set_close(&cli, 1002, "Protocol error");
  websocket_set_close(&cli, 1000, "WebSocket frame error");
  assert_close_at_flush(&cli, 1002);
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 1);
}

/* A plain exit (a QUIT, a KILL, a hold) still sends its one Close. */
static void test_close_once_normal_exit(void **state)
{
  struct Client cli;
  struct Connection con;
  (void)state;

  setup_client(&cli, &con);
  websocket_set_close(&cli, 1000, "Quit: bye");
  assert_close_at_flush(&cli, 1000);
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 1);
}

/* A client's Close is answered with one Close echoing its status, and
 * the farewell exit_client() (or a hold) sets after it does not replace
 * it.  Before, the client got the echo and then a 1000. */
static void test_close_once_client_initiated(void **state)
{
  struct Client cli;
  struct Connection con;
  char status[2] = { 0x03, (char)0xE9 };  /* 1001 going away */
  (void)state;

  setup_client(&cli, &con);
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_CLOSE, status, 2), 0);
  websocket_set_close(&cli, 1000, "WebSocket closed");
  assert_close_at_flush(&cli, 1001);
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 1);

  /* A Close with no status is answered with an empty one, once. */
  setup_client(&cli, &con);
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_CLOSE, NULL, 0), 0);
  websocket_set_close(&cli, 1000, "WebSocket closed");
  assert_int_equal(sent_count, 0);
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 1);
  assert_int_equal((unsigned char)sent_buf[0], WS_FIN | WS_OPCODE_CLOSE);
  assert_int_equal(sent_buf[1], 0);
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 1);
}

/* A client's Close carrying status 0 or 1005 cannot be echoed: here 0
 * means "no Close set" and 1005 an empty Close, and neither may be sent
 * (RFC 6455 §7.4.1 keeps 1005 off the wire; 0 is no status at all).  A
 * Close carrying one is a protocol error, answered with 1002.  Echoed
 * through websocket_set_close(), a 0 set nothing: the client got the
 * farewell 1000 that follows (with no farewell, no Close at all), and a
 * 1005 got an empty Close. */
static void test_close_echo_marker_codes_get_1002(void **state)
{
  static const char *bodies[] = { "\x00\x00", "\x03\xED" };  /* 0, 1005 */
  struct Client cli;
  struct Connection con;
  size_t i;
  (void)state;

  for (i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
    setup_client(&cli, &con);
    assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_CLOSE, bodies[i], 2), 0);
    websocket_set_close(&cli, 1000, "WebSocket closed");   /* exit_client() */
    assert_close_at_flush(&cli, 1002);
  }
}

/* ========== The ERROR line before the Close (RFC 6455 §5.5.1) ========== */

/* Write 'i' (in order) is a data frame carrying 'text'. */
static void assert_write_is_text(int i, const char *text)
{
  int tlen = (int)strlen(text);

  assert_true(i < sent_count && i < SENT_LOG_MAX);
  assert_int_equal(sent_log[i][0], WS_FIN | WS_OPCODE_TEXT);
  assert_int_equal(sent_log[i][1], tlen);
  assert_int_equal(sent_log_len[i], 2 + tlen);
  assert_memory_equal(sent_log[i] + 2, text, tlen);
}

/* Write 'i' (in order) is a Close frame with status 'code' and, when
 * 'reason' is not NULL, that reason. */
static void assert_write_is_close(int i, int code, const char *reason)
{
  assert_true(i < sent_count && i < SENT_LOG_MAX);
  assert_int_equal(sent_log[i][0], WS_FIN | WS_OPCODE_CLOSE);
  assert_true(sent_log_len[i] >= 4);
  assert_int_equal(sent_log[i][1], sent_log_len[i] - 2);
  assert_int_equal((sent_log[i][2] << 8) | sent_log[i][3], code);
  if (reason) {
    assert_int_equal(sent_log_len[i] - 4, (int)strlen(reason));
    assert_memory_equal(sent_log[i] + 4, reason, strlen(reason));
  }
}

#define ERROR_LINE "ERROR :Closing Link: nick by test.server (%s)"

/* After sending a Close an endpoint sends no data frame (§5.5.1).
 * exit_client() queues "ERROR :Closing Link" for every local client, and
 * web IRC clients show the quit reason from it, so it goes first: a
 * refusal's coded Close waits on the connection until close_connection()
 * flushes it, after the queued lines.  Before, the Close went out at once
 * and the ERROR text frame followed it. */
static void test_close_follows_error_on_refusal(void **state)
{
  struct Client cli;
  struct Connection con;
  char *msg = NULL;
  int msg_len = -1;
  char line[200];
  (void)state;

  fill_src();
  setup_client(&cli, &con);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_TEXT, 0, frag_src,
                                       WS_MAX_PAYLOAD, &msg, &msg_len),
                   WS_FRAG_MORE);
  assert_int_equal(websocket_frag_feed(&cli, WS_OPCODE_CONTINUATION, 1,
                                       "x", 1, &msg, &msg_len),
                   WS_FRAG_OVERFLOW);
  assert_int_equal(sent_count, 0);               /* nothing on the wire yet */
  /* exit_client(): the farewell, then the ERROR line it queues */
  websocket_set_close(&cli, 1000, "WebSocket fragment overflow");
  snprintf(line, sizeof(line), ERROR_LINE, "WebSocket fragment overflow");
  queued_line = line;
  assert_int_equal(sent_count, 0);
  websocket_close_flush(&cli);                   /* close_connection() */
  assert_int_equal(sent_count, 2);
  assert_write_is_text(0, line);
  assert_write_is_close(1, 1009, "Message too big");
}

/* A plain exit (a QUIT): the ERROR line, then the farewell Close 1000
 * carrying the exit reason. */
static void test_close_follows_error_on_exit(void **state)
{
  struct Client cli;
  struct Connection con;
  char line[200];
  (void)state;

  setup_client(&cli, &con);
  websocket_set_close(&cli, 1000, "Quit: bye");
  snprintf(line, sizeof(line), ERROR_LINE, "Quit: bye");
  queued_line = line;
  assert_int_equal(sent_count, 0);
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 2);
  assert_write_is_text(0, line);
  assert_write_is_close(1, 1000, "Quit: bye");
}

/* A client's Close: the answer waits for the flush too, so the ERROR
 * line exit_client() queues goes before it and nothing follows it. */
static void test_close_follows_error_client_initiated(void **state)
{
  struct Client cli;
  struct Connection con;
  char status[2] = { 0x03, (char)0xE9 };  /* 1001 going away */
  char line[200];
  (void)state;

  setup_client(&cli, &con);
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_CLOSE, status, 2), 0);
  assert_int_equal(sent_count, 0);
  websocket_set_close(&cli, 1000, "WebSocket closed");
  snprintf(line, sizeof(line), ERROR_LINE, "WebSocket closed");
  queued_line = line;
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 2);
  assert_write_is_text(0, line);
  assert_write_is_close(1, 1001, NULL);
}

/* A socket that died (a write error, EOF) is written to no more: the
 * flush sends no Close. */
static void test_close_not_sent_on_dead_socket(void **state)
{
  struct Client cli;
  struct Connection con;
  (void)state;

  setup_client(&cli, &con);
  websocket_set_close(&cli, 1000, "Write error: Broken pipe");
  SetFlag(&cli, FLAG_DEADSOCKET);
  websocket_close_flush(&cli);
  assert_int_equal(sent_count, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_decode_600_byte_frame),
    cmocka_unit_test(test_decode_max_payload_frame),
    cmocka_unit_test(test_decode_over_max_is_toobig),
    cmocka_unit_test(test_decode_small_buffer_rejects),
    cmocka_unit_test(test_decode_incomplete_frame),
    cmocka_unit_test(test_handshake_600_bytes_split_reads),
    cmocka_unit_test(test_handshake_2000_bytes_split_reads),
    cmocka_unit_test(test_handshake_single_read),
    cmocka_unit_test(test_handshake_no_subproto_defaults_text),
    cmocka_unit_test(test_handshake_terminator_split),
    cmocka_unit_test(test_handshake_trailing_frame_not_consumed),
    cmocka_unit_test(test_handshake_too_large),
    cmocka_unit_test(test_handshake_invalid_request),
    cmocka_unit_test(test_control_close_signals_teardown),
    cmocka_unit_test(test_subproto_unsupported_only),
    cmocka_unit_test(test_subproto_empty_value),
    cmocka_unit_test(test_subproto_first_supported_wins),
    cmocka_unit_test(test_subproto_token_boundaries),
    cmocka_unit_test(test_subproto_multiple_headers),
    cmocka_unit_test(test_frag_reassembles),
    cmocka_unit_test(test_frag_max_payload_fits),
    cmocka_unit_test(test_frag_full_then_empty_fin),
    cmocka_unit_test(test_frag_overflow),
    cmocka_unit_test(test_frag_orphan_continuation),
    cmocka_unit_test(test_frag_text_utf8),
    cmocka_unit_test(test_decode_fragmented_control_refused),
    cmocka_unit_test(test_frag_data_frame_mid_message),
    cmocka_unit_test(test_frag_new_message_after_done),
    cmocka_unit_test(test_frag_overflow_sends_1009),
    cmocka_unit_test(test_frag_orphan_sends_1002),
    cmocka_unit_test(test_frag_badutf8_sends_1007),
    cmocka_unit_test(test_frag_text_nul_then_badutf8_sends_1007),
    cmocka_unit_test(test_close_once_after_refusal),
    cmocka_unit_test(test_close_once_normal_exit),
    cmocka_unit_test(test_close_once_client_initiated),
    cmocka_unit_test(test_close_echo_marker_codes_get_1002),
    cmocka_unit_test(test_close_follows_error_on_refusal),
    cmocka_unit_test(test_close_follows_error_on_exit),
    cmocka_unit_test(test_close_follows_error_client_initiated),
    cmocka_unit_test(test_close_not_sent_on_dead_socket),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
