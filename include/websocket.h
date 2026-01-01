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

/** Handle WebSocket handshake for a new connection.
 * @param[in] cptr Client attempting to connect.
 * @param[in] buffer Raw data received.
 * @param[in] length Length of data.
 * @return 1 if handshake completed successfully, 0 if more data needed, -1 on error.
 */
extern int websocket_handshake(struct Client *cptr, const char *buffer, int length);

/** Decode a WebSocket frame and extract the payload.
 * @param[in] frame Raw WebSocket frame data.
 * @param[in] frame_len Length of frame data.
 * @param[out] payload Output buffer for decoded payload.
 * @param[in] payload_size Size of payload buffer.
 * @param[out] payload_len Length of decoded payload.
 * @param[out] opcode The frame opcode.
 * @param[out] is_fin Set to 1 if FIN bit is set (final fragment), 0 otherwise.
 * @return Number of bytes consumed from frame, 0 if incomplete, -1 on error.
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

#endif /* INCLUDED_websocket_h */
