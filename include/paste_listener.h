/*
 * paste_listener.h - HTTP/TLS listener for paste content
 *
 * Provides a simple HTTP server for serving multiline paste content.
 * Supports TLS using the existing SSL context.
 */

#ifndef INCLUDED_paste_listener_h
#define INCLUDED_paste_listener_h

#include <stddef.h>

/** Maximum length of paste_id (msgid + "-" + secret) */
#define PASTE_ID_MAX 80

/** Maximum length of filename hint */
#define PASTE_FILENAME_MAX 64

/**
 * Initialize the paste HTTP listener.
 * Creates a TLS listener on the configured port.
 * @return 0 on success, -1 on error.
 */
int paste_listener_init(void);

/**
 * Shutdown the paste listener.
 * Closes all connections and the listening socket.
 */
void paste_listener_shutdown(void);

/**
 * Check if the paste listener is active.
 * @return 1 if active, 0 if not.
 */
int paste_listener_active(void);

/**
 * Generate a paste URL from a paste_id.
 * @param[in] paste_id The paste identifier.
 * @return Static buffer containing the full URL (do not free).
 */
const char *paste_url(const char *paste_id);

/**
 * Generate a random secret suffix for paste URLs.
 * Uses cryptographic random for security.
 * @param[out] out Output buffer (should be at least 12 bytes).
 * @param[in] len Size of output buffer.
 */
void paste_generate_secret(char *out, size_t len);

/**
 * Parse a filename hint from the first line of content.
 * Convention: first line is "filename.ext:" followed by newline.
 * If found, populates filename and adjusts content pointer.
 * @param[in] content Original content.
 * @param[in] len Length of content.
 * @param[out] filename Buffer for filename (empty if no hint found).
 * @param[in] filename_size Size of filename buffer.
 * @param[out] out_content Adjusted content pointer (after hint line).
 * @param[out] out_len Adjusted content length.
 */
void paste_parse_filename_hint(const char *content, size_t len,
                               char *filename, size_t filename_size,
                               const char **out_content, size_t *out_len);

/**
 * Map a file extension to a highlight.js language class.
 * @param[in] filename Filename with extension.
 * @return Language class name (e.g., "python", "cpp") or "plaintext".
 */
const char *paste_ext_to_lang(const char *filename);

#endif /* INCLUDED_paste_listener_h */
