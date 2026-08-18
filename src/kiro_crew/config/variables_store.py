"""Storage for user-defined ``{{name}}`` variables, in their own file.

WHY THIS IS NOT IN ``config.json``
==================================

It was, and that placement was the root cause of most of this feature's review
history. ``KiroCrewConfig.save()`` serializes the MERGED config and replaces the
whole file, and ``to_dict()`` builds an explicit dict, so the file is a lossy
whole-document rewrite of exactly the keys the dataclass models. For a map whose
only legitimate writer is a dedicated endpoint, that produced a genuine trilemma —
every possible behaviour for the variables slot during an unrelated ``save()`` is
wrong in a different way:

* serialize the merged value  -> overwrites a base value the overlay shadowed, and
  the shadowed value is not in the merged view at all, so it is unrecoverable;
* preserve it while holding the config lock -> ``save()`` is a sync method called
  from 13 async call sites, so a contended POSIX flock stalls the event loop;
* preserve it with an unlocked read -> the read-then-write window silently drops a
  variables write that already returned 200 to its caller.

Moving the data out deletes the trilemma rather than choosing among its three
positions. ``save()`` no longer serializes variables at all, so there is nothing to
preserve, no lock to interact with, and no window. It also removes the overlay
subtraction problem, the overlay-owned-key refusal, and the deleted-workspace
resurrection window — all of which existed only because this map lived inside a
document with a second overlay layer and a whole-file writer.

The cost, stated plainly: variables are no longer part of ``config.json``, so they
are not covered by whatever backs that file up, and a hand-edit goes here instead.
There is no migration path because no released version stored them anywhere.

SHAPE
=====

One flat document, one writer, three scopes::

    {
      "global":     {"NAME": "value"},
      "workspaces": {"ops": {"NAME": "value"}},
      "crews":      {"reviewer": {"NAME": "value"}}
    }

Session scope is deliberately absent: it is per-turn state, never persisted.

READ is tolerant, WRITE is strict. An unreadable or malformed store resolves to no
variables rather than raising, because a broken store must not take the gateway down
over an optional feature. A WRITE refuses a malformed container instead of replacing
it, because the operator's hand-written value is the only copy there is.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from pathlib import Path
from typing import Any

from kiro_crew import platform_compat

logger = logging.getLogger(__name__)

SCOPE_GLOBAL = "global"
SCOPE_WORKSPACE = "workspace"
SCOPE_CREW = "crew"

# The scope's key in the stored document. Global is a flat map; the other two are
# maps of name -> map, so they need a container key.
_CONTAINER = {SCOPE_WORKSPACE: "workspaces", SCOPE_CREW: "crews"}

_STORE_DIR = "variables"
_STORE_NAME = "variables.json"

# mtime-keyed read cache. KiroCrewConfig.load() applies the store on every call and
# load() runs on the event loop, so an uncached read meant a file read plus a JSON
# parse per load -- for a large store, a measurable stall. Keyed on the same signature
# shape config.json's own cache uses (mtime_ns + size + mode), so any edit,
# truncation or replacement busts it, and a missing file has a distinct sentinel so
# create and delete bust it too.
#
# The residual is one stat() per config load on the loop. That is the same class of
# cost load() already pays to read config.json itself, so this adds no new kind of
# blocking work -- but it is not zero, and a caller that needs a guaranteed-fresh read
# without a stat does not exist today.
_cache: tuple[tuple, dict] | None = None

# Bumped by every invalidation. A reader captures this BEFORE it reads and refuses to
# publish if it changed, which closes a race the fingerprint alone cannot: a reader
# that started before a write can finish after it, and would otherwise install its
# pre-write document under a signature that now matches the post-write file — so every
# later reader would be served stale values indefinitely, not just once.
_generation = 0


def _fingerprint(path: Path) -> tuple:
    """Cheap signature of the store file; changes whenever it is edited."""
    try:
        st = path.stat()
        return (str(path), st.st_mtime_ns, st.st_size, st.st_mode)
    except OSError:
        return (str(path), None)


def invalidate_cache() -> None:
    """Drop the read cache and advance the generation.

    Called by ``patch_store`` after a write rather than relying on the fingerprint
    alone: an atomic replace can land inside the same mtime granularity as the read
    that preceded it, and a stale hit would then serve the pre-write document.

    The generation bump is the second half of that, and it covers the harder case —
    a reader already IN FLIGHT when the write lands. Clearing ``_cache`` does nothing
    about a reader that is about to assign to it.
    """
    global _cache, _generation
    _cache = None
    _generation += 1


class UntrustedStoreLocation(Exception):
    """The store directory or file is a link, so its bytes are not ours to trust.

    Separate from :class:`MalformedStore` because the remedy is different and belongs
    to the operator, not to the writer: nothing about the document is wrong, and no
    retry or repair of its contents helps. The link itself has to be removed, by
    someone outside the agent.
    """


class MalformedStore(Exception):
    """A container the write would have to replace holds a non-mapping.

    Refused rather than coerced: replacing it would discard whatever the operator
    hand-wrote, and there is no second copy to restore from. Carries the dotted path
    so the caller can tell the operator what to repair.
    """

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.path = path


def store_location_is_trusted() -> bool:
    """Is the store reachable without following a link out of the fenced directory?

    The fence in ``security.py`` stops the agent CREATING this link, but it cannot
    un-plant one that predates the fence: on any install that ran before ``variables``
    was fenced, ``variables/`` may already be a symlink into agent-writable space, and
    every read then loads attacker-chosen values straight into an operator's prompt.
    A path-name fence protects a name, not the inode it currently resolves to.

    So the location is verified rather than assumed, on both the read and the write
    path. Checked with ``lstat`` semantics at each level -- resolving first would
    follow exactly the link being looked for -- and the resolved directory must still
    be the one derived from ``config_path()``.

    Answers, never raises: this is called from ``read_store``, whose contract is that a
    variables file can never take down a turn. An untrusted location yields no
    variables, which surfaces as unresolved ``{{tokens}}`` -- this feature's visible
    failure mode everywhere else -- rather than as silently substituted attacker text.
    """
    from kiro_crew.config.loader import config_path

    try:
        base = config_path().parent
        store_dir = base / _STORE_DIR
        # `os.path.lexists`, NOT `Path.exists()`. `exists()` FOLLOWS the link, so a
        # DANGLING one -- planted at a target that does not exist yet -- reported
        # "nothing here", took this early return as trusted, and the writer then
        # created the attacker's target through it. The same trap as resolving first,
        # one predicate over: never ask a link-following question about a path whose
        # being-a-link is the thing under test.
        if not os.path.lexists(store_dir):
            return True  # nothing planted at all; the writer creates it fenced
        if platform_compat.is_link_or_junction(str(store_dir)):
            logger.error(
                "the variables store directory %s is a link; refusing to read through "
                "it. A link here predates the sensitive-path fence and points at "
                "storage the agent can write.",
                store_dir,
            )
            return False
        leaf = store_dir / _STORE_NAME
        # A HARD link is invisible to every check above: there is no link at the path
        # level, `lstat` reports an ordinary regular file, and only the link COUNT
        # differs. It matters most on the write path, which is a read-modify-write:
        # `update_config_locked` reads the shared inode, merges the operator's patch
        # onto whatever the attacker put there, and writes the union -- so the
        # attacker's keys become trusted substitutions carrying the operator's
        # authority. (The atomic replace then severs the link, which is why the leak
        # does not run the other way and why this is easy to miss.)
        #
        # Checked HERE rather than only in the reader because this is the predicate the
        # writer consults; hardening `read_store` alone left the write path reading
        # through a path nobody had validated.
        try:
            if os.lstat(leaf).st_nlink > 1:
                logger.error(
                    "the variables store file %s is hardlinked (st_nlink=%d); refusing "
                    "to read or write through it. Another name for the same bytes means "
                    "the agent can supply what the operator's next write merges onto.",
                    leaf,
                    os.lstat(leaf).st_nlink,
                )
                return False
        except OSError:
            pass  # absent is fine; the writer creates it fenced
        # Unconditional, for the same reason: gating on `leaf.exists()` hid a dangling
        # leaf link exactly as it hid a dangling directory link.
        if platform_compat.is_link_or_junction(str(leaf)):
            logger.error("the variables store file %s is a link; refusing to read it", leaf)
            return False
        if store_dir.resolve() != (base.resolve() / _STORE_DIR):
            logger.error("the variables store directory %s resolves outside the fence", store_dir)
            return False
    except OSError:
        logger.debug("could not verify the variables store location", exc_info=True)
        return False
    return True


def store_path() -> Path:
    """Location of the store, in its OWN directory under the config root.

    A directory rather than a bare file beside ``config.json``, because the fence in
    ``security.py`` protects a path by name and this file is not written alone:
    ``update_config_locked`` creates a predictable ``<path>.lock`` sidecar, and
    ``write_config_atomically`` stages a temp inode in the same directory before
    renaming. A leaf entry covers the target and leaves both of those unfenced, so an
    agent watching the directory could write the staging inode or the lock. Fencing
    the whole directory covers the target, the lock and the temp files together —
    the same reason the ``.vault`` entry is a directory entry.

    Derived from ``config_path()`` rather than hardcoded so a relocated or
    test-redirected config root carries the store with it. Imported lazily because
    this module is a leaf and ``loader`` imports it.
    """
    from kiro_crew.config.loader import config_path

    return config_path().parent / _STORE_DIR / _STORE_NAME


def read_store() -> dict[str, Any]:
    """Read the raw store document. Never raises.

    Every failure resolves to an empty document, which resolves to no variables. A
    malformed store must not break a gateway boot over an optional feature; the
    write path is where a malformed value is reported, because that is where it can
    be acted on and where silence would destroy data.
    Cached on the file's signature (see ``_fingerprint``): this runs on every config
    load, and those run on the event loop, so an uncached read meant a file read plus
    a JSON parse per load. Returns a deep copy so a caller cannot mutate the cached
    document — ``_apply_variables_store`` hands these maps to config objects, and an
    alias would let one session's edit leak into every later reader.
    """
    global _cache
    # Before the fingerprint, so a planted link is refused rather than cached.
    if not store_location_is_trusted():
        return {}
    path = store_path()
    fingerprint = _fingerprint(path)
    if _cache is not None and _cache[0] == fingerprint:
        return copy.deepcopy(_cache[1])
    # Captured BEFORE the read. If a write invalidates while this read is in flight,
    # the document in hand is pre-write and must not be published — otherwise it lands
    # under a signature matching the post-write file and every later reader is served
    # stale values. Dropping the publish costs one re-read; publishing costs
    # correctness until the next write.
    generation = _generation
    doc = _read_uncached(path)
    if generation == _generation:
        _cache = (fingerprint, doc)
    return copy.deepcopy(doc)


def _read_uncached(path: Path) -> dict[str, Any]:
    """The read itself, split out so the cache wrapper stays legible.

    Read through ``safe_read_file_bytes_nolink`` for the same two reasons the dotenv
    reader is: a **hard link** planted here shares its inode with a file the agent can
    write and is invisible to every path-level check (``lstat`` sees an ordinary
    regular file; only ``st_nlink > 1`` differs), and opening by name after stating by
    name leaves a check-to-use window. The helper opens ``O_NOFOLLOW`` and ``fstat``s
    the descriptor, so the inode validated is the inode read.

    Both readers of this fenced directory now go through it. Hardening one and not the
    other is how the weaker path becomes the one that gets used.
    """
    from kiro_crew.hooks import FileTooLargeError, safe_read_file_bytes_nolink

    try:
        data = safe_read_file_bytes_nolink(str(path))
    except (FileTooLargeError, OSError):
        logger.warning(
            "variables store at %s could not be read safely; resolving no variables.",
            path.name,
        )
        return {}
    if data is None:
        # Absent is the ordinary case -- no variables configured yet -- and must stay
        # silent or every fresh install warns on every config load. Anything else means
        # the bytes ARE there and we refused them, which the operator has to hear: their
        # variables just stopped resolving and nothing else would tell them why.
        #
        # `lexists`, not `exists`: a dangling link is present-and-refused, not absent.
        if os.path.lexists(path):
            logger.warning(
                "variables store at %s is unreadable (hardlinked, non-regular, or "
                "permission-denied); resolving no variables. Repair or remove that "
                "file to restore them.",
                path.name,
            )
        return {}

    try:
        raw = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning(
            "variables store at %s is unreadable (%s); resolving no variables. "
            "Repair or remove that file to restore them.",
            path.name,
            exc.__class__.__name__,
        )
        return {}
    if not isinstance(raw, dict):
        logger.warning(
            "variables store at %s is not a JSON object; resolving no variables.",
            path.name,
        )
        return {}
    return raw


def _clean_pairs(raw: object, where: str) -> dict[str, str]:
    """Coerce one scope's map to validated str->str pairs.

    Delegates to the loader's ``coerce_variables`` so validation lives in exactly one
    place — the same name grammar and value-length cap the write path enforces, and
    the same drop-one-pair-not-the-scope tolerance. Imported lazily: the loader
    imports this module, so a module-level import here would close a cycle.
    """
    from kiro_crew.config.loader import coerce_variables

    return coerce_variables(raw, where)


def global_values(doc: dict[str, Any] | None = None) -> dict[str, str]:
    """Global-scope pairs."""
    doc = read_store() if doc is None else doc
    return _clean_pairs(doc.get(SCOPE_GLOBAL), SCOPE_GLOBAL)


def scoped_values(scope: str, doc: dict[str, Any] | None = None) -> dict[str, dict[str, str]]:
    """All named maps for ``workspace`` or ``crew`` scope."""
    container = _CONTAINER[scope]
    doc = read_store() if doc is None else doc
    raw = doc.get(container)
    if not isinstance(raw, dict):
        if raw is not None:
            logger.warning("variables store: %s is not an object; ignoring it", container)
        return {}
    return {
        name: _clean_pairs(pairs, f"{container}.{name}")
        for name, pairs in raw.items()
        if isinstance(name, str)
    }


def _mutate(
    doc: dict[str, Any],
    *,
    scope: str,
    name: str,
    values: dict[str, str],
    removals: list[str],
) -> dict[str, Any]:
    """Apply a per-KEY patch to the document read under the lock.

    Named keys only: a key nobody mentioned is never read and never rewritten, so
    two concurrent writers touching different keys cannot lose each other's edits,
    and there is no whole-scope echo to go stale.

    A container that is ABSENT is created — that is the legitimate first write. A
    container that is PRESENT but not a mapping is refused, because replacing it
    would destroy the only copy of what the operator wrote.

    "Absent" means the key is MISSING, tested by membership. ``.get()`` returning None
    conflates a missing key with an explicit ``null``, and a hand-edited
    ``{"global": null}`` is present operator data — treating it as absent overwrote
    it, which is exactly what the malformed refusal exists to prevent. All three
    container levels use membership, for the same reason.
    """
    if scope == SCOPE_GLOBAL:
        if SCOPE_GLOBAL not in doc:
            target: dict = {}
            doc[SCOPE_GLOBAL] = target
        elif isinstance(doc[SCOPE_GLOBAL], dict):
            target = doc[SCOPE_GLOBAL]
        else:
            raise MalformedStore(SCOPE_GLOBAL)
    else:
        container = _CONTAINER[scope]
        if container not in doc:
            holder: dict = {}
            doc[container] = holder
        elif isinstance(doc[container], dict):
            holder = doc[container]
        else:
            raise MalformedStore(container)
        if name not in holder:
            target = {}
            holder[name] = target
        elif isinstance(holder[name], dict):
            target = holder[name]
        else:
            raise MalformedStore(f"{container}.{name}")

    for key, value in values.items():
        target[key] = value
    for key in removals:
        target.pop(key, None)
    return doc


def patch_store(
    *,
    scope: str,
    name: str = "",
    values: dict[str, str] | None = None,
    removals: list[str] | None = None,
) -> dict[str, Any]:
    """Apply a per-key patch under the store's own lock. Blocking; call off-loop.

    Routed through ``update_config_locked`` so the read and the write are one
    transaction against the store's advisory lock. That helper is reused rather than
    re-implemented so this file inherits its atomic replace, its mode preservation,
    and its symlink handling.

    This is the ONLY writer. ``KiroCrewConfig.save()`` does not touch this file,
    which is the entire point of the file existing.
    """
    if scope not in (SCOPE_GLOBAL, SCOPE_WORKSPACE, SCOPE_CREW):
        raise ValueError(f"unknown variables scope: {scope!r}")
    if scope != SCOPE_GLOBAL and not name:
        raise ValueError(f"{scope} scope requires a name")

    from kiro_crew.config.loader import update_config_locked

    vals = dict(values or {})
    dels = list(removals or [])

    def _apply(current: dict) -> dict:
        return _mutate(current, scope=scope, name=name, values=vals, removals=dels)

    # The directory is created here, not at import: it must exist before
    # update_config_locked places its lock sidecar, and creating it on a read path
    # would make a plain resolution write to disk. 0o700 so the fenced directory is
    # not world-listable either.
    if not store_location_is_trusted():
        raise UntrustedStoreLocation(
            "the variables store is not at a location we can trust: its directory or "
            "file is a link, or the file has another name pointing at the same bytes. "
            "It will not be written through. The specific cause is logged."
        )
    path = store_path()
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        logger.debug("could not create the variables store directory", exc_info=True)

    # on_corrupt="fail": a corrupt store must NOT be reset to {} by a write, which
    # would delete every variable at every scope to service one patch. read_store()
    # is the tolerant path; this one refuses and the caller reports it.
    #
    # stamp_meta=False: this is not a config document and must not grow config's
    # bookkeeping keys — the shape here is exactly the three scope containers.
    result = update_config_locked(store_path(), mutate=_apply, stamp_meta=False, on_corrupt="fail")
    # Before anything else: a reader arriving after this write must not take a cache
    # hit on the pre-write document.
    invalidate_cache()
    try:
        os.chmod(store_path(), 0o600)
    except OSError:
        # Mode is defence in depth, not the security boundary — values are declared
        # non-secret. A filesystem that refuses chmod must not fail the write.
        logger.debug("could not tighten mode on the variables store", exc_info=True)
    return result if isinstance(result, dict) else {}
