---
name: nefarious-codebase
description: General Nefarious IRCd C codebase reference — Client vs Connection accessor patterns, ircd_strncpy strlcpy semantics and the truncation audit rule, the libkc/curl_multi event adapter, ircd.conf block-ordering and syntax gotchas, and the autotools build/test workflow. Use when editing IRCd C code, chasing accessor or buffer-truncation bugs, or touching config parsing.
---

# Nefarious Codebase Skill

General reference for working in the Nefarious IRCd C codebase: client/connection accessor patterns, the libkc/curl_multi event adapter, config-file parsing rules, and build/test workflow. For the bouncer subsystem see the `bouncer-architecture` skill; for P10 see the `p10-protocol` skill.

## Client / Connection Accessor Patterns

Some state lives on the `Client` struct, some on its `Connection`. Getting the indirection wrong compiles but reads garbage.

- `cli_sock_ip(cli)` → `con_sock_ip(cli_connect(cli))` — on the Connection struct
- `cli_ip(cli)` → `cli->cli_ip` — on the Client struct directly
- `cli_listener(cli)` → `con_listener(cli_connect(cli))` — on the Connection struct
- Confs are SLink lists on the Connection; must be detached properly (ref-counted ConfItems). `det_confs_butmask(client, 0)` detaches all confs (declared in `s_conf.h`).
- `release_listener()` decrements the listener ref count (declared in `listener.h`).
- `HasFlag(cli, FLAG_KILLED)` — there is **no** `IsKilled` macro. `IsDead(cli)` checks `FLAG_DEADSOCKET`.

### String copies — `ircd_strncpy` semantics

`ircd_strncpy(dest, src, n)` has **BSD strlcpy semantics**: `n` is the FULL buffer size, it copies at most `n-1` chars, and always null-terminates. So `ircd_strncpy(buf, src, 5)` copies only 4 chars. Use `sizeof(buf)` or `LEN + 1` (for a `buf[LEN+1]` declaration), never a bare `LEN`.

Audit rule: a bare `LEN` constant where the buffer is `LEN+1`, or a non-NUL-terminated source whose byte-length is passed as `n`, truncates by one char. Scan with a **paren-balanced parse** of each call — single-line grep misses calls whose size arg wraps to the next line. (A real-world straggler at `m_account.c` hid exactly this way — its size arg wrapped to the next line.)

## libkc / curl_multi Event Adapter

`ircd_kc_adapter.c` bridges libkc's curl_multi socket API with Nefarious's `ircd_events.h`.

- **FD recycling**: curl closes the DNS socket and opens the TCP socket with the same fd. Use `socket_reattach()` (ircd_events.c) to re-register with epoll — it preserves `gh_ref`/`gh_flags` and is safe during callbacks.
- **`socket_del` during callbacks is UNSAFE**: Nefarious's `event_add` == `event_execute` (synchronous, non-threaded). Calling `socket_del` mid-dispatch tears the socket down while `engine_loop` still holds a `gen_ref`, corrupting the synchronous ET_DESTROY chain. (`socket_del` sets `GEN_DESTROY`; `GEN_ACTIVE` is cleared in `event_execute` (ircd_events.c) on the ET_DESTROY event, and the `gh_flags & GEN_ACTIVE` assertion lives there too.)
- **Simple removal**: defer to a 0-second timer (`TT_RELATIVE, 0`). `timer_run()` executes after `engine_loop`'s event dispatch, once all `gen_ref`s are released.
- **Never `memset` a Socket struct that has pending gen_refs** — it zeroes `gh_ref` and corrupts the synchronous ET_DESTROY event chain.

## The ircd/kc boundary

`ircd/kc/*.c` + `include/kc/*.h` are vendored libkc (formerly `evilnet/libkc`,
merged 2026-07) and stay **verbatim** — no `#ifdef USE_LIBKC` inside them.
They reach the ircd **only** through `kc_event_ops` / `kc_log_ops`;
`ircd_kc_adapter.c` is the sole translation layer. Including an ircd header
from `kc/` is a build error, enforced by `make check-kc-boundary` (first
prerequisite of `ircd/Makefile`'s `build:`, so a plain `make` runs it).

The guard is an **allow-list**, not a deny-list — `<client.h>` and `<stdlib.h>`
are structurally identical, so only an explicit permit-set can work. kc code
may include, angle-form only: `<kc/…>`, `<curl/…>`, `<openssl/…>`,
`<jansson.h>`, `<sys/…> <arpa/…> <netinet/…> <net/…>`, and the C-standard /
top-level POSIX headers in `KC_ALLOWED_STD_HDRS` (`ircd/Makefile.in`).
Everything else fails — every quoted include, and every angle include naming
an ircd header. It covers **both** directories (sources and headers). A new
C-library header goes into `KC_ALLOWED_STD_HDRS`; an ircd header never does.

Because the files carry no `#ifdef`, configure gates them at the *source-list* level:
`configure.in` substitutes `@KC_SRC@` into `IRCD_SRC` and `@KC_CMOCKA_TESTPROGS@` into the
test `CMOCKA_TESTPROGS`, both empty when libkc is not built.  Since 2026-09-03 the default is
**auto**: libkc builds whenever libcurl and libjansson are found (`--enable-keycloak` =
required, `--disable-keycloak` = out).  The old OFF default let a plain `./configure` ship an
ircd that advertised `draft/webpush` with no transport and no log line; the ircd now turns the
cap off at boot with a CONFIG error when the transport is missing, and `STATS webpush` shows a
Delivery line.  Adding a `kc/*.c` file or a kc cmocka suite means editing `configure.in`, not
the Makefiles.

If kc code needs something from the ircd, add it to the adapter interface in
`include/kc/kc_event.h` — do not reach across.

## Persistent store keys fold names

Channel, nick and account names are case-insensitive under the casemapping, but RocksDB compares bytes. **Every key builder folds the name components it embeds** with `db_casefold_bytes()` (`include/db_casefold.h`): `history.c` `build_key` / reply index / msgid-index tail / targets index / quota keys / seek prefixes, `metadata.c` `build_lmdb_key` (target **and** key name) and `build_readmarker_key`, the presence CF's channel half. Msgids, timestamps and session ids are case-sensitive data and stay as written.

- **Never hand-build a key or a seek prefix** with `memcpy` / `ircd_snprintf("%s%c")`; call the builder (`build_key(buf, size, target, NULL, NULL)` yields the `target\0` prefix). A verbatim prefix silently scans an empty range.
- Names read back from keys are folded. Show clients a live object's spelling (TARGETS uses `FindChannel(...)->chname`); compare stored names with `ircd_strcmp`, never `strcmp`.
- `ToLower(c)` indexes its table from `CHAR_MIN`: pass a plain `char`. `ToLower((unsigned char)c)` reads past the table for bytes above 127.
- Existing stores are rewritten once at open by `db_casefold_migrate()` (marker `schema/casefold` in the env's default CF; idempotent without it, so an interrupted run resumes next start). A new name-keyed CF must be added to the `cfs[]` list in `history_init` / `metadata_lmdb_init` with its component mask, plus a case in `ircd/test/db_casefold_cmocka.c` (in-memory fake store, no RocksDB needed).
- Left unfolded on purpose: `bouncer_sessions` (opaque ids), webpush (canonical accounts only), multiline content (msgid keys).

## Config File Parsing

### Block ordering (CRITICAL)

- `make_conf()` **prepends** to `GlobalConfList` (s_conf.c).
- `attach_iline()` returns the **first** match while walking the list.
- Therefore the **last** Client block in the file is checked **first** at runtime.
- **Catch-all blocks must come FIRST in the config file** (so they end up last in the list, checked last).
- Port-specific / more-specific blocks must come **after** the catch-all (so they're checked first).

### Syntax gotchas

- `include "file";` requires the trailing semicolon — `include "file"` without `;` causes cascading parse errors.
- A new parser token needs BOTH `TOKEN(FOO)` in the lexer AND `%token FOO` in the parser — missing either silently breaks parsing via error recovery.

## Build / Test Workflow

- Build with autotools: `./configure --enable-debug --with-maxcon=4096 && make`. `make install` installs to `$HOME/bin`, `$HOME/lib` by default; `--prefix=PATH` to relocate.
- `./configure --help` lists options; common ones: `--enable-debug`, `--with-maxcon=N`, `--with-zstd` (S2S compression).
- C unit tests live in `ircd/test/` (CMocka): build with `make cmocka` and run with `make test-cmocka` (or `make test-all`) from `ircd/test/`. Note `ircd/test/run-tests.sh` is a *separate* functional harness — it boots a real ircd and runs `.cmd` scripts via `test-driver.pl`; it does NOT run the CMocka unit tests.
- Config-check without starting the daemon: `ircd -k` runs the conf parser and exits (note: feature-notify callbacks fire during init before `make_server(&me)`, so a notify that dereferences `cli_serv(&me)` will SIGSEGV under `-k` — guard with `if (!cli_serv(&me)) return;`).
- For stalls/hangs ("why isn't X firing"), attach `gdb`/`strace` to the running PID before theorizing.
