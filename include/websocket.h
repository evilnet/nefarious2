/*
 * IRC - Internet Relay Chat, include/websocket.h
 * Copyright (C) 2024 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief WebSocket protocol support declarations.
 */
#ifndef INCLUDED_websocket_h
#define INCLUDED_websocket_h

struct Client;

/* WebSocket opcodes */
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT         0x1
#define WS_OPCODE_BINARY       0x2
#define WS_OPCODE_CLOSE        0x8
#define WS_OPCODE_PING         0x9
#define WS_OPCODE_PONG         0xA

/** Largest data-frame payload accepted from a client, in bytes.  Frames
 * over this are answered with Close 1009 (Message Too Big).  Callers of
 * websocket_decode_frame() must hand it a buffer larger than this. */
#define WS_MAX_PAYLOAD 16384

/** Largest complete client frame: 2-byte header + 8-byte extended length
 * + 4-byte mask + WS_MAX_PAYLOAD.  Sizes the per-connection buffer that
 * holds a partial frame between reads. */
#define WS_MAX_FRAME   (WS_MAX_PAYLOAD + 14)

/** websocket_decode_frame() return value for a frame over WS_MAX_PAYLOAD
 * (a negative value distinct from the generic -1 protocol error). */
#define WS_DECODE_TOOBIG (-2)

/** Largest HTTP upgrade request we will accumulate before giving up.
 * Browsers send 500-700 bytes routinely and a few KB with cookies. */
#define WS_HANDSHAKE_MAX 8192

/** websocket_handshake_feed() return value when the request exceeded
 * WS_HANDSHAKE_MAX without a terminating blank line. */
#define WS_HANDSHAKE_TOOBIG (-2)

/** Handle WebSocket handshake for a new connection.
 * @param[in] cptr Client attempting to connect.
 * @param[in] buffer Raw data received.
 * @param[in] length Length of data.
 * @return 1 if handshake completed successfully, 0 if more data needed, -1 on error.
 */
extern int websocket_handshake(struct Client *cptr, const char *buffer, int length);

/** Accumulate an HTTP upgrade request across reads and run the handshake
 * once the terminating blank line has arrived.
 * @param[in] cptr Client attempting to connect.
 * @param[in] data Bytes just read.
 * @param[in] len Number of bytes in \a data.
 * @param[out] consumed Number of bytes of \a data that belonged to the
 *   request; anything after them is already WebSocket frame data.
 * @return 1 if the handshake completed, 0 if more data is needed, -1 if
 *   the handshake failed, WS_HANDSHAKE_TOOBIG if the request is too big.
 */
extern int websocket_handshake_feed(struct Client *cptr, const char *data,
                                    int len, int *consumed);

/** Decode a WebSocket frame and extract the payload.
 * @param[in] frame Raw WebSocket frame data.
 * @param[in] frame_len Length of frame data.
 * @param[out] payload Output buffer for decoded payload.
 * @param[in] payload_size Size of payload buffer.
 * @param[out] payload_len Length of decoded payload.
 * @param[out] opcode The frame opcode.
 * @param[out] is_fin Set to 1 if FIN bit is set (final fragment), 0 otherwise.
 * @return Number of bytes consumed from frame, 0 if incomplete, -1 on
 *   error, WS_DECODE_TOOBIG if the payload exceeds WS_MAX_PAYLOAD.
 */
extern int websocket_decode_frame(const unsigned char *frame, int frame_len,
                                  char *payload, int payload_size,
                                  int *payload_len, int *opcode, int *is_fin);

/** Encode data as a WebSocket frame.
 * @param[in] data Data to encode.
 * @param[in] data_len Length of data.
 * @param[out] frame Output buffer for frame (must be data_len + 10 bytes).
 * @param[in] text_mode 1 for text frame, 0 for binary frame.
 * @return Length of encoded frame.
 */
extern int websocket_encode_frame(const char *data, int data_len,
                                  unsigned char *frame, int text_mode);

/** Handle a WebSocket control frame.
 * @param[in] cptr Client connection.
 * @param[in] opcode Frame opcode.
 * @param[in] payload Frame payload.
 * @param[in] payload_len Payload length.
 * @return 1 to continue, 0 to close connection.
 */
extern int websocket_handle_control(struct Client *cptr, int opcode,
                                    const char *payload, int payload_len);

/** Send a WebSocket Close frame with a status code (best effort).
 * @param[in] cptr Client connection.
 * @param[in] code RFC 6455 status code (e.g. 1009 Message Too Big).
 * @param[in] reason Optional short reason text (truncated to 123 bytes).
 */
extern void websocket_send_close(struct Client *cptr, int code,
                                 const char *reason);

#endif /* INCLUDED_websocket_h */
