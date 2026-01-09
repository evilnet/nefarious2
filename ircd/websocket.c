/*
 * IRC - Internet Relay Chat, ircd/websocket.c
 * Copyright (C) 2024 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief WebSocket protocol support (RFC 6455).
 *
 * Implements IRCv3 WebSocket extension for browser-based IRC clients.
 * Supports both binary.ircv3.net and text.ircv3.net subprotocols.
 */
#include "config.h"

#include "websocket.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "listener.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "send.h"
#include "ssl.h"

#include <string.h>
#include <stdlib.h>

#ifdef USE_SSL
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#endif

/* WebSocket magic GUID for handshake (RFC 6455) */
#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* WebSocket opcodes */
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT         0x1
#define WS_OPCODE_BINARY       0x2
#define WS_OPCODE_CLOSE        0x8
#define WS_OPCODE_PING         0x9
#define WS_OPCODE_PONG         0xA

/* WebSocket frame flags */
#define WS_FIN  0x80
#define WS_MASK 0x80

/* Maximum WebSocket frame payload we'll accept */
#define WS_MAX_PAYLOAD 16384

/* Subprotocol types */
#define WS_SUBPROTO_NONE   0  /**< No subprotocol requested by client */
#define WS_SUBPROTO_BINARY 1
#define WS_SUBPROTO_TEXT   2

#ifdef USE_SSL
/** Base64 encode data using OpenSSL EVP.
 * @param[in] input Input data to encode.
 * @param[in] length Length of input data.
 * @param[out] output Output buffer (must be at least (length*4/3)+4 bytes).
 * @return Length of encoded data.
 */
static int base64_encode(const unsigned char *input, int length, char *output)
{
  int outlen;
  EVP_EncodeBlock((unsigned char *)output, input, length);
  outlen = ((length + 2) / 3) * 4;
  output[outlen] = '\0';
  return outlen;
}

/** Compute WebSocket accept key from client key.
 * @param[in] client_key The Sec-WebSocket-Key from client.
 * @param[out] accept_key Output buffer (at least 29 bytes).
 * @return 1 on success, 0 on failure.
 */
static int compute_accept_key(const char *client_key, char *accept_key)
{
  char combined[128];
  unsigned char hash[SHA_DIGEST_LENGTH];

  if (!client_key || strlen(client_key) < 16)
    return 0;

  /* Concatenate client key with magic GUID */
  ircd_snprintf(0, combined, sizeof(combined), "%s%s", client_key, WEBSOCKET_GUID);

  /* SHA1 hash */
  SHA1((unsigned char *)combined, strlen(combined), hash);

  /* Base64 encode */
  base64_encode(hash, SHA_DIGEST_LENGTH, accept_key);

  return 1;
}
#endif /* USE_SSL */

/** Parse HTTP headers from WebSocket handshake request.
 * @param[in] buffer Raw HTTP request data.
 * @param[in] length Length of buffer.
 * @param[out] ws_key Output buffer for Sec-WebSocket-Key (at least 64 bytes).
 * @param[out] subproto Output for selected subprotocol (WS_SUBPROTO_*).
 * @param[out] origin Output buffer for Origin header (at least 256 bytes).
 * @return 1 if valid WebSocket upgrade request, 0 otherwise.
 */
static int parse_ws_handshake(const char *buffer, int length,
                               char *ws_key, int *subproto, char *origin)
{
  const char *line, *end;
  const char *key_start;
  int found_upgrade = 0;
  int found_connection = 0;
  int found_key = 0;
  int found_version = 0;

  *subproto = WS_SUBPROTO_NONE; /* RFC 6455 §4.2.2: Don't assume subprotocol unless client requests */
  ws_key[0] = '\0';
  origin[0] = '\0';

  /* Check for GET request */
  if (length < 4 || strncmp(buffer, "GET ", 4) != 0)
    return 0;

  /* Parse headers line by line */
  line = buffer;
  while (line < buffer + length) {
    end = strstr(line, "\r\n");
    if (!end)
      break;

    /* Check for Upgrade: websocket */
    if (strncasecmp(line, "Upgrade:", 8) == 0) {
      if (strstr(line, "websocket") || strstr(line, "WebSocket"))
        found_upgrade = 1;
    }
    /* Check for Connection: Upgrade */
    else if (strncasecmp(line, "Connection:", 11) == 0) {
      if (strstr(line, "Upgrade") || strstr(line, "upgrade"))
        found_connection = 1;
    }
    /* Get Sec-WebSocket-Key */
    else if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
      key_start = line + 18;
      while (*key_start == ' ' && key_start < end)
        key_start++;
      if (key_start < end) {
        size_t keylen = end - key_start;
        if (keylen > 63) keylen = 63;
        memcpy(ws_key, key_start, keylen);
        ws_key[keylen] = '\0';
        /* Trim trailing spaces */
        while (keylen > 0 && ws_key[keylen-1] == ' ')
          ws_key[--keylen] = '\0';
        found_key = 1;
      }
    }
    /* Check Sec-WebSocket-Version */
    else if (strncasecmp(line, "Sec-WebSocket-Version:", 22) == 0) {
      if (strstr(line, "13"))
        found_version = 1;
    }
    /* Check Sec-WebSocket-Protocol for subprotocol preference */
    else if (strncasecmp(line, "Sec-WebSocket-Protocol:", 23) == 0) {
      /* Prefer text.ircv3.net if client requests it */
      if (strstr(line, "text.ircv3.net"))
        *subproto = WS_SUBPROTO_TEXT;
      else if (strstr(line, "binary.ircv3.net"))
        *subproto = WS_SUBPROTO_BINARY;
    }
    /* Get Origin header for validation */
    else if (strncasecmp(line, "Origin:", 7) == 0) {
      key_start = line + 7;
      while (*key_start == ' ' && key_start < end)
        key_start++;
      if (key_start < end) {
        size_t origlen = end - key_start;
        if (origlen > 255) origlen = 255;
        memcpy(origin, key_start, origlen);
        origin[origlen] = '\0';
        /* Trim trailing spaces */
        while (origlen > 0 && origin[origlen-1] == ' ')
          origin[--origlen] = '\0';
      }
    }

    line = end + 2;

    /* Check for end of headers */
    if (line[0] == '\r' && line[1] == '\n')
      break;
  }

  return (found_upgrade && found_connection && found_key && found_version);
}

/** Build WebSocket handshake response.
 * @param[in] accept_key The computed Sec-WebSocket-Accept value.
 * @param[in] subproto The selected subprotocol (WS_SUBPROTO_*).
 * @param[out] response Output buffer (at least 256 bytes).
 * @return Length of response.
 *
 * RFC 6455 §4.2.2: If the server does not wish to agree to one of the
 * suggested subprotocols, it MUST NOT send back a Sec-WebSocket-Protocol
 * header field in its response.
 */
static int build_ws_response(const char *accept_key, int subproto, char *response)
{
  /* RFC 6455 §4.2.2: Only include Sec-WebSocket-Protocol if client requested one */
  if (subproto == WS_SUBPROTO_NONE) {
    return ircd_snprintf(0, response, 256,
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: %s\r\n"
      "\r\n",
      accept_key);
  }

  return ircd_snprintf(0, response, 256,
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n"
    "Sec-WebSocket-Protocol: %s\r\n"
    "\r\n",
    accept_key,
    (subproto == WS_SUBPROTO_TEXT) ? "text.ircv3.net" : "binary.ircv3.net");
}

/** Validate WebSocket origin against allowed origins.
 * @param[in] origin The Origin header value from client.
 * @return 1 if origin is allowed, 0 if rejected.
 *
 * If WEBSOCKET_ORIGIN feature is empty, all origins are allowed.
 * Otherwise, the origin must match one of the space-separated patterns.
 * Patterns support '*' as a wildcard prefix (e.g., "*.example.com").
 */
static int validate_ws_origin(const char *origin)
{
  const char *allowed = feature_str(FEAT_WEBSOCKET_ORIGIN);
  const char *p, *end;
  char pattern[256];
  size_t plen, olen;

  /* Empty allowed list or "*" = allow all origins (including missing Origin header) */
  if (!allowed || !*allowed || (allowed[0] == '*' && allowed[1] == '\0'))
    return 1;

  /* No origin header = reject if origin validation is configured */
  if (!origin || !*origin) {
    Debug((DEBUG_DEBUG, "WebSocket: No Origin header, rejecting (origin validation enabled)"));
    return 0;
  }

  olen = strlen(origin);

  /* Check each space-separated pattern */
  p = allowed;
  while (*p) {
    /* Skip whitespace */
    while (*p == ' ' || *p == ',')
      p++;
    if (!*p)
      break;

    /* Find end of pattern */
    end = p;
    while (*end && *end != ' ' && *end != ',')
      end++;

    plen = end - p;
    if (plen >= sizeof(pattern))
      plen = sizeof(pattern) - 1;
    memcpy(pattern, p, plen);
    pattern[plen] = '\0';

    /* Check for wildcard prefix match (*.example.com) */
    if (pattern[0] == '*' && pattern[1] == '.') {
      /* Match suffix - origin must end with pattern (minus the *) */
      size_t suffix_len = plen - 1;  /* Length of ".example.com" */
      if (olen >= suffix_len) {
        if (strcasecmp(origin + olen - suffix_len, pattern + 1) == 0) {
          Debug((DEBUG_DEBUG, "WebSocket: Origin %s matches wildcard %s", origin, pattern));
          return 1;
        }
      }
    } else {
      /* Exact match */
      if (strcasecmp(origin, pattern) == 0) {
        Debug((DEBUG_DEBUG, "WebSocket: Origin %s matches exactly", origin));
        return 1;
      }
    }

    p = end;
  }

  Debug((DEBUG_DEBUG, "WebSocket: Origin %s not in allowed list", origin));
  return 0;
}

/** Build HTTP 403 Forbidden response for invalid origin.
 * @param[out] response Output buffer (at least 128 bytes).
 * @return Length of response.
 */
static int build_ws_forbidden_response(char *response)
{
  return ircd_snprintf(0, response, 128,
    "HTTP/1.1 403 Forbidden\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 16\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Origin forbidden");
}

/** Handle WebSocket handshake for a new connection.
 * @param[in] cptr Client attempting to connect.
 * @param[in] buffer Raw data received.
 * @param[in] length Length of data.
 * @return 1 if handshake completed successfully, 0 if more data needed, -1 on error.
 */
int websocket_handshake(struct Client *cptr, const char *buffer, int length)
{
#ifdef USE_SSL
  char ws_key[64];
  char accept_key[64];
  char response[256];
  char origin[256];
  int subproto;
  int resp_len;

  /* Check for complete HTTP request (ends with \r\n\r\n) */
  if (length < 4 || !strstr(buffer, "\r\n\r\n"))
    return 0; /* Need more data */

  /* Parse the handshake request */
  if (!parse_ws_handshake(buffer, length, ws_key, &subproto, origin)) {
    Debug((DEBUG_DEBUG, "WebSocket: Invalid handshake from %s",
           cli_sockhost(cptr)));
    return -1;
  }

  /* Validate origin if configured */
  if (!validate_ws_origin(origin)) {
    Debug((DEBUG_DEBUG, "WebSocket: Origin '%s' rejected for %s",
           origin[0] ? origin : "(none)", cli_sockhost(cptr)));
    /* Send 403 response before closing */
    resp_len = build_ws_forbidden_response(response);
    if (cli_socket(cptr).ssl) {
      SSL_write(cli_socket(cptr).ssl, response, resp_len);
    } else {
      unsigned int bytes_sent;
      os_send_nonb(cli_fd(cptr), response, resp_len, &bytes_sent);
    }
    return -1;
  }

  /* Compute accept key */
  if (!compute_accept_key(ws_key, accept_key)) {
    Debug((DEBUG_DEBUG, "WebSocket: Failed to compute accept key for %s",
           cli_sockhost(cptr)));
    return -1;
  }

  /* Build and send response */
  resp_len = build_ws_response(accept_key, subproto, response);

  /* Send handshake response directly */
  /* Note: We bypass the normal send queue for the handshake */
  /* Use SSL_write for SSL connections, os_send_nonb for plain */
  if (cli_socket(cptr).ssl) {
    int send_result = SSL_write(cli_socket(cptr).ssl, response, resp_len);
    if (send_result <= 0) {
      Debug((DEBUG_DEBUG, "WebSocket: Failed to send handshake response to %s (SSL_write returned %d)",
             cli_sockhost(cptr), send_result));
      return -1;
    }
  } else {
    unsigned int bytes_sent;
    if (os_send_nonb(cli_fd(cptr), response, resp_len, &bytes_sent) != IO_SUCCESS) {
      Debug((DEBUG_DEBUG, "WebSocket: Failed to send handshake response to %s",
             cli_sockhost(cptr)));
      return -1;
    }
  }

  /* Mark client as WebSocket and clear handshake flag */
  SetWebSocket(cptr);
  ClearWSNeedHandshake(cptr);

  /* Apply WebSocket-specific recvq limit (typically higher than regular clients
   * because WebSocket frames can bundle multiple IRC lines) */
  {
    unsigned int ws_recvq = feature_int(FEAT_WEBSOCKET_RECVQ);
    if (ws_recvq > 0)
      cli_max_recvq(cptr) = ws_recvq;
  }

  Debug((DEBUG_DEBUG, "WebSocket: Handshake complete for %s (subproto=%s)",
         cli_sockhost(cptr),
         subproto == WS_SUBPROTO_NONE ? "none" :
         subproto == WS_SUBPROTO_TEXT ? "text" : "binary"));

  return 1;
#else
  /* WebSocket requires SSL for SHA1/Base64 */
  return -1;
#endif
}

/** Decode a WebSocket frame and extract the payload.
 * @param[in] frame Raw WebSocket frame data.
 * @param[in] frame_len Length of frame data.
 * @param[out] payload Output buffer for decoded payload.
 * @param[in] payload_size Size of payload buffer.
 * @param[out] payload_len Length of decoded payload.
 * @param[out] opcode The frame opcode.
 * @param[out] is_fin Set to 1 if FIN bit is set (final fragment), 0 otherwise.
 * @return Number of bytes consumed from frame, 0 if incomplete, -1 on error.
 *
 * RFC 6455 Compliance:
 * - §5.2: RSV1-3 bits MUST be 0 unless extension negotiated (we negotiate none)
 * - §5.1: Client-to-server frames MUST be masked
 * - §5.2: Reserved opcodes (0x03-0x07, 0x0B-0x0F) MUST cause connection failure
 * - §5.5: Control frames MUST have payload length <= 125 bytes
 */
int websocket_decode_frame(const unsigned char *frame, int frame_len,
                           char *payload, int payload_size,
                           int *payload_len, int *opcode, int *is_fin)
{
  int pos = 0;
  int masked;
  int fin;
  int rsv;
  int is_control;
  unsigned long long plen;
  unsigned char mask[4];
  int i;

  *payload_len = 0;
  *opcode = 0;
  *is_fin = 0;

  /* Need at least 2 bytes for header */
  if (frame_len < 2)
    return 0;

  /* Parse first byte: FIN + RSV1-3 + opcode */
  fin = (frame[0] & WS_FIN) ? 1 : 0;
  rsv = (frame[0] >> 4) & 0x07;  /* RSV1-3 are bits 6-4 */
  *opcode = frame[0] & 0x0F;

  /* RFC 6455 §5.2: RSV bits MUST be 0 unless extension negotiated */
  if (rsv != 0) {
    Debug((DEBUG_DEBUG, "WebSocket: RSV bits set (0x%x) without extension - protocol error", rsv));
    return -1;
  }

  /* RFC 6455 §5.2: Reserved opcodes MUST cause connection failure */
  /* Data frames: 0x0-0x2 valid, 0x3-0x7 reserved */
  /* Control frames: 0x8-0xA valid, 0xB-0xF reserved */
  if ((*opcode >= 0x03 && *opcode <= 0x07) || (*opcode >= 0x0B && *opcode <= 0x0F)) {
    Debug((DEBUG_DEBUG, "WebSocket: Reserved opcode 0x%x - protocol error", *opcode));
    return -1;
  }

  is_control = (*opcode >= 0x08);

  /* Parse second byte: MASK + payload length */
  masked = (frame[1] & WS_MASK) ? 1 : 0;
  plen = frame[1] & 0x7F;
  pos = 2;

  /* RFC 6455 §5.1: Client-to-server frames MUST be masked */
  if (!masked) {
    Debug((DEBUG_DEBUG, "WebSocket: Client frame not masked - protocol error"));
    return -1;
  }

  /* Extended payload length */
  if (plen == 126) {
    if (frame_len < 4)
      return 0;
    plen = ((unsigned long long)frame[2] << 8) | frame[3];
    pos = 4;
  } else if (plen == 127) {
    if (frame_len < 10)
      return 0;
    plen = 0;
    for (i = 0; i < 8; i++)
      plen = (plen << 8) | frame[2 + i];
    pos = 10;
  }

  /* RFC 6455 §5.5: Control frames MUST have payload length <= 125 bytes */
  if (is_control && plen > 125) {
    Debug((DEBUG_DEBUG, "WebSocket: Control frame payload too large (%llu > 125) - protocol error", plen));
    return -1;
  }

  /* Sanity check payload length */
  if (plen > WS_MAX_PAYLOAD) {
    Debug((DEBUG_DEBUG, "WebSocket: Frame too large: %llu bytes", plen));
    return -1;
  }

  /* Get mask (required for client-to-server frames - we already verified masked=1 above) */
  if (frame_len < pos + 4)
    return 0;
  memcpy(mask, frame + pos, 4);
  pos += 4;

  /* Check if we have complete payload */
  if (frame_len < pos + (int)plen)
    return 0;

  /* Sanity check output buffer */
  if ((int)plen >= payload_size) {
    Debug((DEBUG_DEBUG, "WebSocket: Payload too large for buffer"));
    return -1;
  }

  /* Copy and unmask payload */
  for (i = 0; i < (int)plen; i++) {
    payload[i] = frame[pos + i] ^ mask[i % 4];
  }
  payload[plen] = '\0';
  *payload_len = (int)plen;
  *is_fin = fin;

  return pos + (int)plen;
}

/** Encode data as a WebSocket frame.
 * @param[in] data Data to encode.
 * @param[in] data_len Length of data.
 * @param[out] frame Output buffer for frame (must be data_len + 10 bytes).
 * @param[in] text_mode 1 for text frame, 0 for binary frame.
 * @return Length of encoded frame.
 */
int websocket_encode_frame(const char *data, int data_len,
                           unsigned char *frame, int text_mode)
{
  int pos = 0;
  int opcode = text_mode ? WS_OPCODE_TEXT : WS_OPCODE_BINARY;

  /* First byte: FIN + opcode */
  frame[pos++] = WS_FIN | opcode;

  /* Second byte: payload length (no mask for server-to-client) */
  if (data_len < 126) {
    frame[pos++] = (unsigned char)data_len;
  } else if (data_len < 65536) {
    frame[pos++] = 126;
    frame[pos++] = (data_len >> 8) & 0xFF;
    frame[pos++] = data_len & 0xFF;
  } else {
    frame[pos++] = 127;
    /* 64-bit length - IRC messages are never this big, but for completeness */
    frame[pos++] = 0;
    frame[pos++] = 0;
    frame[pos++] = 0;
    frame[pos++] = 0;
    frame[pos++] = (data_len >> 24) & 0xFF;
    frame[pos++] = (data_len >> 16) & 0xFF;
    frame[pos++] = (data_len >> 8) & 0xFF;
    frame[pos++] = data_len & 0xFF;
  }

  /* Copy payload (no masking for server-to-client) */
  memcpy(frame + pos, data, data_len);
  pos += data_len;

  return pos;
}

/** Handle a WebSocket control frame.
 * @param[in] cptr Client connection.
 * @param[in] opcode Frame opcode.
 * @param[in] payload Frame payload.
 * @param[in] payload_len Payload length.
 * @return 1 to continue, 0 to close connection.
 */
/** Helper to send raw WebSocket frame data (SSL-aware).
 * @param[in] cptr Client connection.
 * @param[in] data Data to send.
 * @param[in] len Length of data.
 * @return 1 on success, 0 on failure.
 */
static int ws_send_raw(struct Client *cptr, const unsigned char *data, int len)
{
#ifdef USE_SSL
  if (cli_socket(cptr).ssl) {
    int result = SSL_write(cli_socket(cptr).ssl, data, len);
    return (result > 0) ? 1 : 0;
  }
#endif
  {
    unsigned int bytes_sent;
    return (os_send_nonb(cli_fd(cptr), (char *)data, len, &bytes_sent) == IO_SUCCESS) ? 1 : 0;
  }
}

int websocket_handle_control(struct Client *cptr, int opcode,
                             const char *payload, int payload_len)
{
  unsigned char response[256];
  int resp_len;

  switch (opcode) {
    case WS_OPCODE_PING:
      /* Respond with PONG */
      response[0] = WS_FIN | WS_OPCODE_PONG;
      if (payload_len < 126) {
        response[1] = (unsigned char)payload_len;
        memcpy(response + 2, payload, payload_len);
        resp_len = 2 + payload_len;
      } else {
        /* Ping payload too large, just send empty pong */
        response[1] = 0;
        resp_len = 2;
      }
      ws_send_raw(cptr, response, resp_len);
      return 1;

    case WS_OPCODE_PONG:
      /* Client responding to our ping, nothing to do */
      return 1;

    case WS_OPCODE_CLOSE:
      /* Client initiated close - send close response */
      response[0] = WS_FIN | WS_OPCODE_CLOSE;
      if (payload_len >= 2) {
        /* Echo back the status code */
        response[1] = 2;
        response[2] = payload[0];
        response[3] = payload[1];
        resp_len = 4;
      } else {
        response[1] = 0;
        resp_len = 2;
      }
      ws_send_raw(cptr, response, resp_len);
      return 0; /* Signal to close connection */

    default:
      return 1;
  }
}
