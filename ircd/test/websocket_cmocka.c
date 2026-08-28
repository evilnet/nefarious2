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
 *
 * websocket.c is included directly (like ircd_cloaking_cmocka.c) with
 * stubs for feature_str(), ircd_snprintf() and os_send_nonb().
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../websocket.c"

/* ---- stubs for websocket.c's external dependencies ---- */

const char *feature_str(enum Feature feat)
{
  (void)feat;
  return "";  /* FEAT_WEBSOCKET_ORIGIN: allow all origins */
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

/* Capture whatever websocket_handshake() writes to the (plain) socket */
static char sent_buf[1024];
static int sent_len;

IOResult os_send_nonb(int fd, const char *buf, unsigned int length,
                      unsigned int *count_out)
{
  (void)fd;
  if (length > sizeof(sent_buf) - 1)
    length = sizeof(sent_buf) - 1;
  memcpy(sent_buf, buf, length);
  sent_buf[length] = '\0';
  sent_len = length;
  *count_out = length;
  return IO_SUCCESS;
}

/* ---- helpers ---- */

static void setup_client(struct Client *cli, struct Connection *con)
{
  memset(cli, 0, sizeof(*cli));
  memset(con, 0, sizeof(*con));
  cli_connect(cli) = con;
  strcpy(cli_sockhost(cli), "test.host");
  sent_len = 0;
  sent_buf[0] = '\0';
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

  /* ...CLOSE signals teardown (return 0) and echoes a close response
   * with the client's status code. */
  setup_client(&cli, &con);
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_CLOSE, status, 2), 0);
  assert_true((unsigned char)sent_buf[0] == (WS_FIN | WS_OPCODE_CLOSE));
  assert_int_equal(sent_buf[1], 2);
  assert_true((unsigned char)sent_buf[2] == 0x03 && (unsigned char)sent_buf[3] == 0xE8);

  /* Payload-less CLOSE also signals teardown. */
  setup_client(&cli, &con);
  assert_int_equal(websocket_handle_control(&cli, WS_OPCODE_CLOSE, NULL, 0), 0);
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
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
