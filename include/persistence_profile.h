/*
 * IRC - Internet Relay Chat, include/persistence_profile.h
 * Copyright (C) 2026 Nefarious Development Team
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
 */
/** @file
 * @brief draft/persistence configuration-profile data layer.
 *
 * Profiles are named bundles of bouncer preferences (hold, auto-replay,
 * channel list, …) scoped to one account.  Storage uses the existing
 * account-metadata LMDB tree under the server-managed `bouncer/profile/`
 * prefix:
 *
 *   bouncer/profile/<name>/parent  -> parent profile name
 *                                     (absent on the implicit `default`;
 *                                      defaults to "default" for any
 *                                      custom profile that didn't CREATE
 *                                      … FROM)
 *   bouncer/profile/<name>/<key>   -> any preference value
 *
 * Effective-value lookup walks the inheritance chain:
 *   active profile -> parent -> ... -> default -> account-global -> FEAT_*
 *
 * The `default` profile is implicit — always present, can't be deleted,
 * can't be renamed.  Custom profiles must be CREATE'd before they have
 * any keys set on them.
 *
 * Phase 4 / milestone M1 — wire surface is `PERSISTENCE PROFILE
 * LIST|CREATE|DELETE|RENAME|GET|SET` (see m_persistence.c).  M1 covers
 * scalar preferences and inheritance; channel-list storage joins in M3.
 */
#ifndef INCLUDED_persistence_profile_h
#define INCLUDED_persistence_profile_h

struct Client;

/** Maximum profile-name length on the wire and in storage. */
#define PERSISTENCE_PROFILE_NAME_MAX 32

/** The reserved name of the implicit default profile. */
#define PERSISTENCE_PROFILE_DEFAULT "default"

/** Callback for persistence_profile_list().
 * @param[in] name Profile name.
 * @param[in] parent Parent profile name (NULL or empty for default).
 * @param[in] cookie Caller-provided opaque pointer.
 */
typedef void (*persistence_profile_list_cb)(const char *name,
                                            const char *parent,
                                            void *cookie);

/** Validate a profile name for the wire / storage.
 * Allowed chars: [a-zA-Z0-9_-], length 1..PERSISTENCE_PROFILE_NAME_MAX.
 * @param[in] name Candidate profile name.
 * @return Non-zero if valid.
 */
extern int persistence_profile_name_valid(const char *name);

/** Test whether a profile exists for an account.
 * The `default` profile always exists (returns 1) even if no keys are
 * set on it.
 * @param[in] account Account name.
 * @param[in] name Profile name.
 * @return Non-zero if the profile exists.
 */
extern int persistence_profile_exists(const char *account, const char *name);

/** Resolve the effective value of a key for a profile, walking the
 * inheritance chain (this profile -> parent -> ... -> default).  Does
 * NOT fall through to the account-global key or to FEAT_* — that's
 * the caller's responsibility once this returns "not set".
 * @param[in] account Account name.
 * @param[in] profile Profile name (may be "default").
 * @param[in] key Key name (without the `bouncer/profile/<name>/` prefix).
 * @param[out] value Buffer for resolved value.
 * @param[in] value_len Buffer size.
 * @return 0 on success, 1 if no profile in the chain has the key,
 *         -1 on error.
 */
extern int persistence_profile_get_effective(const char *account,
                                              const char *profile,
                                              const char *key,
                                              char *value,
                                              size_t value_len);

/** Read a key set directly on a profile (no inheritance walk).
 * @return 0 on success, 1 if key not set on this profile, -1 on error.
 */
extern int persistence_profile_get_own(const char *account,
                                        const char *profile,
                                        const char *key,
                                        char *value,
                                        size_t value_len);

/** Set a key on a profile.  Refuses to set `parent` to a value that
 * would create an inheritance cycle.
 * @param[in] value Value to set; NULL deletes the key.
 * @return 0 on success, -1 on error (e.g. cycle, invalid name).
 */
extern int persistence_profile_set(const char *account,
                                    const char *profile,
                                    const char *key,
                                    const char *value);

/** Create a profile.  Refuses if `name` already exists.  If `parent`
 * is NULL or empty, the new profile inherits from `default`.
 * The `default` profile is implicit and cannot be created.
 * @return 0 on success, -1 on error.
 */
extern int persistence_profile_create(const char *account,
                                       const char *name,
                                       const char *parent);

/** Delete a profile.  Refuses to delete `default`, or any profile that
 * is the parent of another existing profile.  Removes all
 * `bouncer/profile/<name>/*` keys.
 * @return 0 on success, -1 on error.
 */
extern int persistence_profile_delete(const char *account, const char *name);

/** Rename a profile.  Updates the names in storage AND fixes up any
 * other profile that had `parent = <old>` to point at `<new>`.  Refuses
 * to rename `default` or to overwrite an existing profile.
 * @return 0 on success, -1 on error.
 */
extern int persistence_profile_rename(const char *account,
                                       const char *old_name,
                                       const char *new_name);

/** Enumerate profiles for an account.  Always emits at least
 * `default`; emits custom profiles in arbitrary order.
 * @return 0 on success, -1 on error.
 */
extern int persistence_profile_list(const char *account,
                                     persistence_profile_list_cb cb,
                                     void *cookie);

#endif /* INCLUDED_persistence_profile_h */
