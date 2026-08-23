"""Every reader of kiro-cli's Windows identity store must name the same places.

Five separate places in the tree resolve that store, each with its own hardcoded
per-platform list and no shared helper. They drifted: the trusted live-store
list, the sensitive-path fence and the logout fingerprint all named
``AppData/Roaming`` only, while sign-in staging named ``AppData/Local`` only --
so on any given host at least one of them was looking at nothing.

The installed CLI is observed using EITHER AppData root, so the fix is that every
reader covers both. These tests pin that agreement, and in particular the
ordering constraint that makes it safe: a path may be TRUSTED only if it is also
FENCED. A trusted path outside the fence is one an agent file tool could author,
which would let it forge the identity rows these readers believe.
"""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path, PurePosixPath

import pytest

from kiro_crew import kiro_prerequisite as kp
from kiro_crew.dashboard.handlers import kiro_usage_api as usage_api
from kiro_crew.kiro_cli import kiro_cli_state_dbs
from kiro_crew.security import _SENSITIVE_HOME_DIRS

# The two roots the installed CLI is observed using, for each product whose store
# holds a live SSO bearer token.
_EXPECTED_WINDOWS_STORE_DIRS = frozenset(
    {
        "AppData/Local/kiro-cli",
        "AppData/Local/amazon-q",
        "AppData/Roaming/kiro-cli",
        "AppData/Roaming/amazon-q",
    }
)


def _home_relative(path: Path) -> str:
    """Return ``path`` relative to the real home, as a forward-slash string.

    The store tuples are built from ``Path.home()`` at import time, so on a POSIX
    CI host the Windows entries are POSIX-shaped strings under that home. Only
    the home-relative remainder is comparable to ``_SENSITIVE_HOME_DIRS``, which
    is itself expressed home-relative with forward slashes.
    """

    return path.relative_to(Path.home()).as_posix()


def _windows_entries(paths: tuple[Path, ...]) -> set[str]:
    """Home-relative DIRECTORIES of the Windows entries in a store tuple."""

    relatives = (_home_relative(path) for path in paths)
    return {
        str(PurePosixPath(relative).parent)
        for relative in relatives
        if relative.startswith("AppData/")
    }


def _is_fenced(relative_dir: str) -> bool:
    """Whether a home-relative directory is inside a fenced store directory."""

    candidate = PurePosixPath(relative_dir)
    return any(
        candidate == PurePosixPath(fenced) or PurePosixPath(fenced) in candidate.parents
        for fenced in _SENSITIVE_HOME_DIRS
    )


class TestWindowsIdentityStorePathsAgree:
    def test_fence_covers_both_appdata_roots(self) -> None:
        """The fence is the floor: it must name every location anyone trusts."""

        assert _EXPECTED_WINDOWS_STORE_DIRS <= set(_SENSITIVE_HOME_DIRS)

    def test_trusted_live_store_list_covers_both_roots(self) -> None:
        assert _windows_entries(usage_api._CLI_SQLITE_DBS) == {
            "AppData/Local/kiro-cli",
            "AppData/Roaming/kiro-cli",
        }

    def test_other_product_store_list_covers_both_roots(self) -> None:
        """amazon-q had no Windows entry at all while the fence already named it."""

        assert _windows_entries(usage_api._OTHER_SQLITE_DBS) == {
            "AppData/Local/amazon-q",
            "AppData/Roaming/amazon-q",
        }

    def test_every_trusted_windows_store_is_fenced(self) -> None:
        """The ordering constraint, stated as an assertion.

        Membership in the trusted tuples sets ``from_cli_store=True``, a claim
        that rests entirely on agent file tools being unable to write the path.
        Adding a location to a trusted tuple without fencing it first creates a
        forgeable trusted path, so this test fails on that mistake rather than
        letting it ship.
        """

        trusted = _windows_entries(usage_api._CLI_SQLITE_DBS) | _windows_entries(
            usage_api._OTHER_SQLITE_DBS
        )
        assert trusted, "no Windows entries found -- the tuples changed shape"
        unfenced = sorted(entry for entry in trusted if not _is_fenced(entry))
        assert not unfenced, f"trusted but NOT fenced: {unfenced}"

    def test_signin_staging_covers_both_roots(self, tmp_path: Path) -> None:
        """Staging looked only at Local, so a Roaming host staged nothing."""

        mappings = kp._auth_store_mappings("win32", tmp_path, {})
        staged = {
            mapping.source.relative_to(tmp_path).as_posix()
            for mapping in mappings
            if mapping.source.is_relative_to(tmp_path / "AppData")
        }
        assert staged == set(_EXPECTED_WINDOWS_STORE_DIRS)

    def test_staging_groups_alternate_locations_of_one_store(self, tmp_path: Path) -> None:
        """The two roots of one product are ALTERNATES, not two required stores.

        They share a group so a stale or partial store in the root this host does
        not use cannot abort staging from the root it does.
        """

        mappings = kp._auth_store_mappings("win32", tmp_path, {})
        for app_name in ("kiro-cli", "amazon-q"):
            roots = [m for m in mappings if m.group == app_name]
            assert len(roots) == 2
            assert len({m.staged_relative for m in roots}) == 2

    def test_staging_stages_each_root_under_its_own_relative_path(self, tmp_path: Path) -> None:
        """Distinct staged paths, so one root cannot overwrite the other's store."""

        mappings = kp._auth_store_mappings("win32", tmp_path, {})
        staged_relatives = [m.staged_relative for m in mappings]
        assert len(staged_relatives) == len(set(staged_relatives))

    def test_logout_fingerprint_reads_a_fenced_path(self, tmp_path: Path) -> None:
        """Whichever root it selects, the result must be inside the fence."""

        path = kp.kiro_identity_store_path("win32", tmp_path, {})
        assert _is_fenced(str(PurePosixPath(path.relative_to(tmp_path).as_posix()).parent))

    def test_logout_fingerprint_prefers_the_root_that_exists(self, tmp_path: Path) -> None:
        """Naming one fixed root read a path that does not exist on half the hosts."""

        roaming = tmp_path / "AppData" / "Roaming" / "kiro-cli"
        roaming.mkdir(parents=True)
        (roaming / kp._AUTH_SQLITE_DB).write_bytes(b"")

        assert kp.kiro_identity_store_path("win32", tmp_path, {}) == (roaming / kp._AUTH_SQLITE_DB)

        local = tmp_path / "AppData" / "Local" / "kiro-cli"
        local.mkdir(parents=True)
        (local / kp._AUTH_SQLITE_DB).write_bytes(b"")

        assert kp.kiro_identity_store_path("win32", tmp_path, {}) == (local / kp._AUTH_SQLITE_DB)

    def test_relocation_guard_watches_both_variables(self, tmp_path: Path) -> None:
        """Both roots are anchors, so either variable moving is a relocation."""

        assert not kp.identity_store_is_relocated("win32", tmp_path, {})
        assert kp.identity_store_is_relocated(
            "win32", tmp_path, {"LOCALAPPDATA": str(tmp_path / "elsewhere")}
        )
        assert kp.identity_store_is_relocated(
            "win32", tmp_path, {"APPDATA": str(tmp_path / "elsewhere")}
        )
        # Set to exactly the defaults is not a relocation.
        assert not kp.identity_store_is_relocated(
            "win32",
            tmp_path,
            {
                "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
                "APPDATA": str(tmp_path / "AppData" / "Roaming"),
            },
        )

    def test_state_db_reader_already_covered_both_roots(self, tmp_path: Path) -> None:
        """The one reader that was already right -- pinned so it stays that way."""

        dbs = kiro_cli_state_dbs("win32", tmp_path, {})
        relatives = {db.relative_to(tmp_path).parent.as_posix() for db in dbs}
        assert relatives == {"AppData/Local/kiro-cli", "AppData/Roaming/kiro-cli"}


class TestAStaleAlternateRootNeverBecomesAuthoritative:
    """A migrated host can keep a store in the root it abandoned.

    Nothing in a path proves which root the running CLI writes to, so picking the
    first existing one would let a stale database carry trusted provenance and own
    the fingerprint: the former account's usage would be shown, and a logout in
    the active store would retire nothing. When both roots hold a store the
    correct answer is "cannot tell", which routes to the untrusted fallback and to
    an absent fingerprint.
    """

    def test_both_roots_present_reports_unidentifiable(self, tmp_path: Path) -> None:
        for root in ("Local", "Roaming"):
            store = tmp_path / "AppData" / root / "kiro-cli"
            store.mkdir(parents=True)
            (store / kp._AUTH_SQLITE_DB).write_bytes(b"")

        assert kp.identity_store_is_relocated("win32", tmp_path, {})

    def test_one_root_present_stays_identifiable(self, tmp_path: Path) -> None:
        store = tmp_path / "AppData" / "Roaming" / "kiro-cli"
        store.mkdir(parents=True)
        (store / kp._AUTH_SQLITE_DB).write_bytes(b"")

        assert not kp.identity_store_is_relocated("win32", tmp_path, {})

    def test_a_single_root_is_read_rather_than_gated_out(self, tmp_path: Path, monkeypatch) -> None:
        """The gate must not swallow the case this PR exists to fix.

        Asserts WHICH path the resolver reads, which is the finding's actual
        concern -- a digest value would only prove the fixture had rows in it.
        """

        store = tmp_path / "AppData" / "Local" / "kiro-cli"
        store.mkdir(parents=True)
        (store / kp._AUTH_SQLITE_DB).write_bytes(b"")

        seen: list[Path] = []
        monkeypatch.setattr(kp, "identity_fingerprint", lambda path: seen.append(path) or "d")

        assert kp.resolve_identity_fingerprint("win32", tmp_path, {}) == "d"
        assert seen == [store / kp._AUTH_SQLITE_DB]

    def test_ambiguity_reads_nothing_at_all(self, tmp_path: Path, monkeypatch) -> None:
        """Not merely 'returns absent' -- the store must never be opened."""

        for root in ("Local", "Roaming"):
            store = tmp_path / "AppData" / root / "kiro-cli"
            store.mkdir(parents=True)
            (store / kp._AUTH_SQLITE_DB).write_bytes(b"")

        seen: list[Path] = []
        monkeypatch.setattr(kp, "identity_fingerprint", lambda path: seen.append(path) or "d")

        assert kp.resolve_identity_fingerprint("win32", tmp_path, {}) == ""
        assert seen == []

    def test_both_roots_carry_no_trust_claim(self, tmp_path: Path) -> None:
        """Neither store may be offered as the CLI's own live credential."""

        dbs = tuple(
            tmp_path / "AppData" / root / "kiro-cli" / "data.sqlite3"
            for root in ("Local", "Roaming")
        )
        for db in dbs:
            db.parent.mkdir(parents=True)
            db.write_bytes(b"")

        assert usage_api._trustable_stores(dbs) == ()

    def test_one_root_keeps_its_trust_claim(self, tmp_path: Path) -> None:
        db = tmp_path / "AppData" / "Local" / "kiro-cli" / "data.sqlite3"
        db.parent.mkdir(parents=True)
        db.write_bytes(b"")
        absent = tmp_path / "AppData" / "Roaming" / "kiro-cli" / "data.sqlite3"

        assert usage_api._trustable_stores((db, absent)) == (db,)

    def test_posix_stores_are_never_filtered(self, tmp_path: Path) -> None:
        """The rule is about the two AppData roots, not about store count."""

        posix = tmp_path / ".local" / "share" / "kiro-cli" / "data.sqlite3"
        posix.parent.mkdir(parents=True)
        posix.write_bytes(b"")
        mac = tmp_path / "Library" / "Application Support" / "kiro-cli" / "data.sqlite3"
        mac.parent.mkdir(parents=True)
        mac.write_bytes(b"")

        assert usage_api._trustable_stores((posix, mac)) == (posix, mac)


def _write_identity_store(path: Path) -> None:
    """Write a store holding every identity table, so projection succeeds."""

    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    with contextlib.closing(connection):
        for table in kp._AUTH_IDENTITY_TABLES:
            connection.execute(f'CREATE TABLE "{table}" (key TEXT PRIMARY KEY, value TEXT)')
        connection.commit()


def _write_unusable_store(path: Path) -> None:
    """Write a store with NO identity table, the shape that fails projection."""

    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    with contextlib.closing(connection):
        connection.execute("CREATE TABLE unrelated (k TEXT)")
        connection.commit()


class TestStagingToleratesTheUnusedAppDataRoot:
    """Widening staging to both roots must not turn a stale store into a failure.

    Staging aborts rather than omit a matched store, because a staged home with
    no identity looks signed-out. That rule is right per LOCATION and wrong
    across alternates: once both roots are staged, a leftover database in the
    root a host does not use would abort staging from the root it does, breaking
    sign-in on exactly the hosts this change is meant to fix.
    """

    def _stage(self, home: Path) -> None:
        kp._prepare_auth_workspace("win32", home, {}, {})

    def test_a_usable_store_in_one_root_survives_a_dead_store_in_the_other(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(kp, "_ensure_auth_staging_parent", lambda home: tmp_path / "stage")
        (tmp_path / "stage").mkdir()
        _write_identity_store(tmp_path / "AppData" / "Local" / "kiro-cli" / kp._AUTH_SQLITE_DB)
        _write_unusable_store(tmp_path / "AppData" / "Roaming" / "kiro-cli" / kp._AUTH_SQLITE_DB)

        self._stage(tmp_path)

    def test_no_usable_store_in_any_root_still_aborts(self, tmp_path: Path, monkeypatch) -> None:
        """The signed-out-looking case must stay loud."""

        monkeypatch.setattr(kp, "_ensure_auth_staging_parent", lambda home: tmp_path / "stage")
        (tmp_path / "stage").mkdir()
        _write_unusable_store(tmp_path / "AppData" / "Local" / "kiro-cli" / kp._AUTH_SQLITE_DB)

        with pytest.raises(OSError):
            self._stage(tmp_path)
