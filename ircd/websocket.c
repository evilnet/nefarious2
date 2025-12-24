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
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "listener.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>

#ifdef USE_SSL
#include <openssl/sha.h>
#include <openssl/evp.h>
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
 * @return 1 if valid WebSocket upgrade request, 0 otherwise.
 */
static int parse_ws_handshake(const char *buffer, int length,
                               char *ws_key, int *subproto)
{
  const char *line, *end;
  const char *key_start;
  int found_upgrade = 0;
  int found_connection = 0;
  int found_key = 0;
  int found_version = 0;

  *subproto = WS_SUBPROTO_BINARY; /* Default to binary */
  ws_key[0] = '\0';

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
 */
static int build_ws_response(const char *accept_key, int subproto, char *response)
{
  const char *proto_name = (subproto == WS_SUBPROTO_TEXT)
                           ? "text.ircv3.net"
                           : "binary.ircv3.net";

  return ircd_snprintf(0, response, 256,
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n"
    "Sec-WebSocket-Protocol: %s\r\n"
    "\r\n",
    accept_key, proto_name);
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
  int subproto;
  int resp_len;

  /* Check for complete HTTP request (ends with \r\n\r\n) */
  if (length < 4 || !strstr(buffer, "\r\n\r\n"))
    return 0; /* Need more data */

  /* Parse the handshake request */
  if (!parse_ws_handshake(buffer, length, ws_key, &subproto)) {
    Debug((DEBUG_DEBUG, "WebSocket: Invalid handshake from %s",
           cli_sockhost(cptr)));
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
  if (os_send_nonb(cli_fd(cptr), response, resp_len, NULL) != IO_SUCCESS) {
    Debug((DEBUG_DEBUG, "WebSocket: Failed to send handshake response to %s",
           cli_sockhost(cptr)));
    return -1;
  }

  /* Mark client as WebSocket and clear handshake flag */
  SetWebSocket(cptr);
  ClearWSNeedHandshake(cptr);

  /* Store subprotocol preference - we'll use this when sending */
  /* For now we treat both the same on the server side */

  Debug((DEBUG_DEBUG, "WebSocket: Handshake complete for %s (subproto=%s)",
         cli_sockhost(cptr),
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
 * @return Number of bytes consumed from frame, 0 if incomplete, -1 on error.
 */
int websocket_decode_frame(const unsigned char *frame, int frame_len,
                           char *payload, int payload_size,
                           int *payload_len, int *opcode)
{
  int pos = 0;
  int masked;
  unsigned long long plen;
  unsigned char mask[4];
  int i;

  *payload_len = 0;
  *opcode = 0;

  /* Need at least 2 bytes for header */
  if (frame_len < 2)
    return 0;

  /* Parse first byte: FIN + opcode */
  *opcode = frame[0] & 0x0F;
  /* int fin = (frame[0] & WS_FIN) ? 1 : 0; */

  /* Parse second byte: MASK + payload length */
  masked = (frame[1] & WS_MASK) ? 1 : 0;
  plen = frame[1] & 0x7F;
  pos = 2;

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

  /* Sanity check payload length */
  if (plen > WS_MAX_PAYLOAD) {
    Debug((DEBUG_DEBUG, "WebSocket: Frame too large: %llu bytes", plen));
    return -1;
  }

  /* Get mask if present (client-to-server MUST be masked) */
  if (masked) {
    if (frame_len < pos + 4)
      return 0;
    memcpy(mask, frame + pos, 4);
    pos += 4;
  }

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
    if (masked)
      payload[i] = frame[pos + i] ^ mask[i % 4];
    else
      payload[i] = frame[pos + i];
  }
  payload[plen] = '\0';
  *payload_len = (int)plen;

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
      os_send_nonb(cli_fd(cptr), (char *)response, resp_len, NULL);
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
      os_send_nonb(cli_fd(cptr), (char *)response, resp_len, NULL);
      return 0; /* Signal to close connection */

    default:
      return 1;
  }
}
