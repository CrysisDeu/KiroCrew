"""Update pins: where new code may come from, and the minimum version.

Covers the two enterprise pins (``governance.UpdatePins``) and the shared seam
the three update paths call (``platform.update_governance``).
"""

from __future__ import annotations

import os
import pathlib

import pytest

from kiro_crew.platform import update_governance
from kiro_crew.platform.context import PlatformCompositionError
from kiro_crew.platform.governance import (
    UpdatePins,
    active_update_pins,
    parse_policy,
    parse_profile,
)
from kiro_crew.subprocess_utf8 import UTF8_TEXT


def _policy(**updates: str) -> dict:
    body: dict = {"version": 1, "boot": {}}
    if updates:
        body["updates"] = updates
    return body


class TestSourcePin:
    def test_unpinned_permits_anything(self):
        pins = UpdatePins()
        assert pins.permits_source("https://github.com/anyone/anything")
        assert pins.permits_source("")

    def test_glob_matches(self):
        pins = UpdatePins(source="https://github.com/acme/*")
        assert pins.permits_source("https://github.com/acme/kirocrew")
        assert not pins.permits_source("https://github.com/acme-evil/kirocrew")

    def test_unresolvable_source_is_denied_when_pinned(self):
        """An admin's pin must not be satisfied by "we could not tell"."""
        pins = UpdatePins(source="https://git.corp.example/*")
        assert not pins.permits_source("")
        assert not pins.permits_source("   ")

    def test_scp_and_path_remotes_are_matchable(self):
        """`updates.source` is a glob, so non-URL remote shapes work too."""
        assert UpdatePins(source="git@corp:*").permits_source("git@corp:team/repo")
        assert UpdatePins(source="/srv/repos/*").permits_source("/srv/repos/approved")

    @pytest.mark.parametrize(
        "url",
        [
            "/srv/repos/approved/../evil/repo.git",  # git resolves this outside
            "/srv/repos/approved/./ok.git",
            "/srv/repos/approved/..\\evil/repo.git",  # `\` separates on Windows
        ],
    )
    def test_traversal_cannot_escape_the_pin(self, url):
        """`*` spans separators, so a glob alone does not confine the path."""
        assert not UpdatePins(source="/srv/repos/approved/*").permits_source(url)

    def test_a_dot_inside_a_name_is_not_a_traversal(self):
        pins = UpdatePins(source="https://github.com/acme/*")
        assert pins.permits_source("https://github.com/acme/my.repo.git")
        assert pins.permits_source("https://github.com/acme/.hidden")

    def test_matching_is_case_sensitive_on_every_platform(self):
        """`fnmatch` normcases (lowercases on Windows); `fnmatchcase` does not.

        `…/APPROVED` must not satisfy an `…/approved` pin — git and every
        case-sensitive forge treat those as different repositories, and a ceiling
        must not change verdict with the OS. Fails on Windows if it regresses.
        """
        assert not UpdatePins(source="https://git.corp/approved").permits_source(
            "https://git.corp/APPROVED"
        )


class TestMinVersion:
    def test_unpinned_always_met(self):
        assert UpdatePins().meets_min_version("0.0.1")
        assert UpdatePins().meets_min_version("")

    @pytest.mark.parametrize(
        "current,floor,expected",
        [
            ("1.2.3", "1.2.3", True),
            ("1.2.4", "1.2.3", True),
            ("1.2.2", "1.2.3", False),
            ("2.0.0", "1.9.9", True),
            # Shorter tuples zero-extend: 1.2 == 1.2.0.
            ("1.2", "1.2.0", True),
            ("1.2", "1.2.1", False),
            ("1.10.0", "1.9.0", True),  # numeric, not lexical
        ],
    )
    def test_ordering(self, current, floor, expected):
        assert UpdatePins(min_version=floor).meets_min_version(current) is expected

    def test_prerelease_suffix_is_stripped_off_the_whole_string(self):
        """This project's CI stamps a dot INSIDE the pre-release.

        A per-component strip would leave `nightly.20260728t184500` as its own
        component and read every nightly build as version 0 — permanently
        non-compliant, which at boot means a forced-update loop.
        """
        pins = UpdatePins(min_version="0.2.0")
        assert pins.meets_min_version("0.2.0-nightly.20260728t184500")
        assert pins.meets_min_version("0.3.0-insider.2")
        assert pins.meets_min_version("0.2.0+build.7")
        assert not pins.meets_min_version("0.1.9-nightly.20260728t184500")

    def test_unparseable_floor_imposes_none(self):
        """A typo must not brick a fleet."""
        assert UpdatePins(min_version="not-a-version").meets_min_version("0.0.1")

    def test_unparseable_current_is_below_the_floor(self):
        """Take the update rather than sit on a build we cannot identify."""
        assert not UpdatePins(min_version="1.0.0").meets_min_version("dev")


class TestPolicyParsing:
    def test_absent_updates_is_unpinned(self):
        ceiling = parse_policy(_policy())
        assert ceiling.updates == UpdatePins()

    def test_pins_are_parsed(self):
        ceiling = parse_policy(_policy(source="https://git.corp/*", min_version="1.2.3"))
        assert ceiling.updates.source == "https://git.corp/*"
        assert ceiling.updates.min_version == "1.2.3"

    def test_unknown_key_fails_closed(self):
        with pytest.raises(PlatformCompositionError, match="unknown key"):
            parse_policy(_policy(sources="typo"))

    def test_non_object_fails_closed(self):
        with pytest.raises(PlatformCompositionError, match="must be an object"):
            parse_policy({"version": 1, "boot": {}, "updates": "https://git.corp"})

    def test_profile_may_not_set_updates(self):
        """Policy-only: a profile redirecting the source would be escalation."""
        with pytest.raises(PlatformCompositionError, match="policy-only"):
            parse_profile({"name": "app-x", "updates": {"source": "https://evil/*"}})

    def test_profile_without_updates_still_parses(self):
        assert parse_profile({"name": "app-x"}).name == "app-x"

    @pytest.mark.parametrize("bad", [False, 0, [], {}])
    def test_falsy_non_string_pin_is_rejected_not_coerced(self, bad):
        """`"source": false` must not silently mean "unpinned"."""
        with pytest.raises(PlatformCompositionError, match="must be a string"):
            parse_policy(_policy(source=bad))

    def test_null_is_a_valid_no_pin(self):
        ceiling = parse_policy({"version": 1, "boot": {}, "updates": {"source": None}})
        assert ceiling.updates.source == ""


class TestSeam:
    """The shared gate the API, CLI and boot paths call."""

    def test_ungoverned_host_is_unpinned(self, monkeypatch):
        monkeypatch.setattr(
            "kiro_crew.platform.governance.active_update_pins", lambda: UpdatePins()
        )
        assert update_governance.update_blocked_reason("https://anywhere") == ""
        assert update_governance.update_required("0.0.1") is False
        assert update_governance.min_version() == ""

    def test_source_mismatch_is_blocked_with_a_reason(self, monkeypatch):
        monkeypatch.setattr(
            "kiro_crew.platform.governance.active_update_pins",
            lambda: UpdatePins(source="https://git.corp/*"),
        )
        reason = update_governance.update_blocked_reason("https://github.com/evil/x")
        # Names neither the remote nor the pin: both can embed a token.
        assert "does not match" in reason
        assert "github.com" not in reason and "git.corp" not in reason

    def test_unresolvable_source_reports_so(self, monkeypatch):
        monkeypatch.setattr(
            "kiro_crew.platform.governance.active_update_pins",
            lambda: UpdatePins(source="https://git.corp/*"),
        )
        assert "does not match" in update_governance.update_blocked_reason("")

    def test_below_floor_requires_an_update(self, monkeypatch):
        monkeypatch.setattr(
            "kiro_crew.platform.governance.active_update_pins",
            lambda: UpdatePins(min_version="2.0.0"),
        )
        assert update_governance.update_required("1.9.9") is True
        assert update_governance.update_required("2.0.0") is False

    def test_governance_error_does_not_block(self, monkeypatch):
        """A glitch must not strand a host on a build that may need a patch."""

        def _boom():
            raise RuntimeError("context unavailable")

        monkeypatch.setattr("kiro_crew.platform.context.current_context", _boom)
        assert active_update_pins() == UpdatePins()
        assert update_governance.update_blocked_reason("https://anywhere") == ""
        assert update_governance.update_required("0.0.1") is False


class TestRemoteResolution:
    def test_reads_the_tracked_remote_not_origin(self, monkeypatch):
        """`git pull` follows branch.<name>.remote, so that is what we check."""
        calls: list[list[str]] = []

        class _R:
            returncode = 0

            def __init__(self, out: str) -> None:
                self.stdout = out

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if "config" in argv:
                return _R("upstream\n")
            if "ls-remote" in argv:
                return _R("https://git.corp/team/repo\n")
            return _R("")

        monkeypatch.setattr("subprocess.run", fake_run)
        url = update_governance.resolve_remote_url("/proj", branch="main")
        assert url == "https://git.corp/team/repo"
        assert ["git", "ls-remote", "--get-url", "--", "upstream"] in calls

    def test_unknown_remote_echo_is_not_a_url(self, monkeypatch):
        """`--get-url` echoes its argument back for an unknown remote."""

        class _R:
            returncode = 0
            stdout = "origin\n"

        monkeypatch.setattr("subprocess.run", lambda argv, **kw: _R())
        assert update_governance.resolve_remote_url("/proj", branch="main") == ""

    def test_detached_head_is_unresolvable(self, monkeypatch):
        monkeypatch.setattr("subprocess.run", lambda *a, **k: pytest.fail("must not run git"))
        assert update_governance.resolve_remote_url("/proj", branch="HEAD") == ""

    def test_fixed_remote_ignores_the_tracked_remote(self, monkeypatch):
        """CLI/boot fetch a hardcoded `origin`, so they must validate `origin`.

        Otherwise a branch tracking an approved upstream green-lights an `origin`
        fetch from elsewhere — approving one source and installing another.
        """
        calls: list[list[str]] = []

        class _R:
            returncode = 0
            stdout = "https://git.corp/origin-repo\n"

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return _R()

        monkeypatch.setattr("subprocess.run", fake_run)
        assert (
            update_governance.resolve_remote_url("/proj", remote="origin")
            == "https://git.corp/origin-repo"
        )
        # Neither the branch nor its tracked remote is consulted.
        assert calls == [["git", "ls-remote", "--get-url", "--", "origin"]]

    def test_resolves_the_branch_itself_when_not_given(self, monkeypatch):
        """The API path passes no branch; the seam resolves it (one impl)."""
        calls: list[list[str]] = []

        class _R:
            returncode = 0

            def __init__(self, out: str) -> None:
                self.stdout = out

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if "rev-parse" in argv:
                return _R("main\n")
            if "config" in argv:
                return _R("origin\n")
            return _R("https://git.corp/team/repo\n")

        monkeypatch.setattr("subprocess.run", fake_run)
        assert update_governance.resolve_remote_url("/proj") == "https://git.corp/team/repo"
        assert ["git", "rev-parse", "--abbrev-ref", "HEAD"] in calls

    def test_missing_git_is_unresolvable_not_an_error(self, monkeypatch):
        def _no_git(*a, **k):
            raise FileNotFoundError("git")

        monkeypatch.setattr("subprocess.run", _no_git)
        assert update_governance.resolve_remote_url("/proj", branch="main") == ""


class TestPrimaryBranchResolution:
    """The gate on the unattended boot-time ``git reset --hard`` + reinstall.

    Two failure modes are asserted here, because the gate can be wrong in
    opposite directions and only one of them is loud:

    * Too narrow -> a whole install cohort silently never updates. A hardcoded
      ``mainline`` did that to every ``main`` checkout of this repo.
    * Too wide, or steerable -> unreviewed code is installed and executed, or a
      mandatory version floor is vetoed.
    """

    def test_main_is_primary(self):
        """The regression: this repo's primary line is `main`, not `mainline`."""
        assert update_governance.is_primary_branch("main")

    def test_mainline_is_primary(self):
        """Internal and mirror clones whose primary line carries that name."""
        assert update_governance.is_primary_branch("mainline")

    def test_feature_branch_is_not_primary(self):
        assert not update_governance.is_primary_branch("fix/some-thing")
        assert not update_governance.is_primary_branch("beta-braveheart")

    def test_detached_head_is_never_primary(self):
        """There is no branch to fast-forward, so there is nothing to apply.

        The old code fabricated `branch = "mainline"` here, which on an internal
        clone would have let a boot-time `git reset --hard` move a deliberately
        detached checkout.
        """
        assert not update_governance.is_primary_branch("HEAD")
        assert not update_governance.is_primary_branch("")

    def test_lookalike_names_are_not_primary(self):
        """Membership is exact — no prefix, suffix, or case leniency.

        A remote is free to carry a branch called `main-2`, and pushing one must
        not be enough to get it installed on boot.
        """
        for name in ("main-2", "mainline2", "Main", "MAIN", "origin/main", " main"):
            assert not update_governance.is_primary_branch(name), name

    def test_decision_reads_no_git_state_at_all(self, monkeypatch):
        """The security property, asserted directly: no local ref participates.

        `refs/remotes/<remote>/HEAD` is one `git remote set-head` away from being
        repointed by anything with write access to the checkout. Consulting it
        breaks in BOTH directions — obeying it aims the boot-time
        `git reset --hard` + `pip install` + `execv` at an arbitrary branch of the
        still-approved origin (the source pin cannot catch it, the remote URL is
        unchanged), while letting it merely narrow turns the same one-command
        repoint into a veto. So the gate runs no git at all, and this fails if a
        future change reintroduces one.
        """
        monkeypatch.setattr("subprocess.run", lambda *a, **k: pytest.fail("must not run git"))
        assert update_governance.is_primary_branch("main")
        assert not update_governance.is_primary_branch("attacker-branch")

    def test_a_repointed_pointer_cannot_veto_a_mandatory_update(self):
        """A `main` checkout stays primary however `origin/HEAD` is aimed.

        `_auto_apply_update` is what an enterprise `min_version` floor calls on a
        checkout, so a vetoable gate would let a local repoint strand a host
        below the administrator's minimum version — the ceiling bypass the
        module docstring says a pin must not permit.
        """
        assert update_governance.is_primary_branch("main")
        assert update_governance.is_primary_branch("mainline")

    def test_unrelated_primary_fork_gets_no_unattended_update(self):
        """The accepted cost, asserted rather than left implicit.

        A fork whose primary line is named something else only gets the badge.
        `kirocrew update` and the dashboard apply path still serve it, and both
        have a human in the loop — the difference that makes wider trust
        acceptable there and not on an unauthenticated boot path.
        """
        assert not update_governance.is_primary_branch("develop")
        assert not update_governance.is_primary_branch("trunk")

    def test_allowlist_is_frozen(self):
        """A mutable set here would be writable by any import-time code."""
        assert isinstance(update_governance.PRIMARY_BRANCHES, frozenset)

    def test_this_repo_s_real_primary_branch_is_allowlisted(self):
        """No mock: the real checkout's default branch must be in the allowlist.

        This is the only test that can catch the original bug CLASS — a name that
        is simply wrong for this repo. Every assertion above would still pass if
        the allowlist held one wrong literal, because they choose their own
        inputs; this one reads the repo. Skips where the metadata is absent
        (`--single-branch` CI clones, exported tarballs).
        """
        import pathlib as _pathlib
        import subprocess as _subprocess

        root = _pathlib.Path(update_governance.__file__).resolve().parents[3]
        if not (root / ".git").exists():
            pytest.skip("not a git checkout")
        probe = _subprocess.run(
            ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
            cwd=root,
            capture_output=True,
            timeout=10,
            **UTF8_TEXT,
        )
        if probe.returncode != 0 or not probe.stdout.strip():
            pytest.skip("clone published no origin/HEAD pointer")
        default = probe.stdout.strip().removeprefix("origin/")
        assert update_governance.is_primary_branch(default), (
            f"this repo's default branch {default!r} is not in PRIMARY_BRANCHES — "
            "auto-update would silently never run for any checkout of it"
        )


def _fixture_git_env(repo: str) -> dict:
    """Env for a fixture git call: no inherited templates, hooks, or identity.

    A developer (or CI image) with ``GIT_TEMPLATE_DIR`` set, or a global
    ``core.hooksPath``, would otherwise have those hooks COPIED into every
    fixture repo and executed by the ``git commit`` below — host-side side
    effects from running the test suite. ``init.templateDir`` and the exec
    vectors are pinned through the same mechanism the production path uses, and
    the committer identity is supplied so the call cannot depend on, or fall
    back to, the developer's global config.
    """
    env = {
        **os.environ,
        **update_governance.git_neutralizer_env(),
        "GIT_TEMPLATE_DIR": "",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    count = int(env["GIT_CONFIG_COUNT"])
    env[f"GIT_CONFIG_KEY_{count}"] = "init.templateDir"
    env[f"GIT_CONFIG_VALUE_{count}"] = ""
    env["GIT_CONFIG_COUNT"] = str(count + 1)
    return env


def _init_repo(path) -> str:
    """A real one-commit git repo at *path*, or a skip when git is unusable."""
    import subprocess

    path.mkdir(parents=True, exist_ok=True)
    repo = str(path)
    env = _fixture_git_env(repo)
    for argv in (
        ["git", "init", "-q", "--template=", "."],
        ["git", "commit", "-q", "--no-verify", "--allow-empty", "-m", "x"],
    ):
        done = subprocess.run(argv, cwd=repo, env=env, capture_output=True, **UTF8_TEXT)
        if done.returncode != 0:
            pytest.skip(f"git unusable: {(done.stderr or '').strip()[:120]}")
    return repo


def _git_config(repo: str, *args: str) -> None:
    import subprocess

    done = subprocess.run(
        ["git", "config", *args],
        cwd=repo,
        env=_fixture_git_env(repo),
        capture_output=True,
        **UTF8_TEXT,
    )
    assert done.returncode == 0, done.stderr


class TestGitExecNeutralizers:
    """The update path runs git on a tree the agent can write.

    `git status` and `git diff` do not just READ config — they exec the program a
    repo names in `core.fsmonitor`, and a reset runs hooks. These assert the
    fixed-key vectors are pinned back, against real git rather than a mock,
    because the whole question is what git actually does with the config.
    """

    @staticmethod
    def _pinned() -> dict:
        env = update_governance.git_neutralizer_env()
        return {
            env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
            for i in range(int(env["GIT_CONFIG_COUNT"]))
        }

    def test_env_pins_the_named_exec_vectors(self):
        pinned = self._pinned()
        assert pinned["core.fsmonitor"] == "false"
        assert pinned["core.hooksPath"] == os.devnull
        assert pinned["credential.helper"] == ""
        assert pinned["protocol.ext.allow"] == "never"
        assert pinned["diff.external"] == ""

    def test_every_exec_capable_fixed_key_is_pinned(self):
        """The list's criterion is "git may exec this value, key name is fixed".

        Asserted as a set rather than one key at a time because the first version
        of the list was an enumeration with no criterion, and was missing
        `core.gitProxy` for exactly that reason.
        """
        pinned = self._pinned()
        for key in (
            "core.fsmonitor",
            "core.hooksPath",
            "core.sshCommand",
            "core.gitProxy",
            "core.askPass",
            "core.alternateRefsCommand",
            "core.pager",
            "core.editor",
            "sequence.editor",
            "credential.helper",
            "diff.external",
            "gpg.program",
            "uploadpack.packObjectsHook",
            "protocol.ext.allow",
        ):
            assert key in pinned, f"{key} is exec-capable but not pinned"

    def test_no_pinned_value_is_a_repo_supplied_program(self):
        """A pin must not itself name something the repo could control."""
        for key, value in update_governance._GIT_EXEC_NEUTRALIZERS:
            assert not value.startswith("!"), (key, value)
            assert "$" not in value, (key, value)

    def test_count_matches_the_entries(self):
        """A stale GIT_CONFIG_COUNT silently drops the tail of the list."""
        env = update_governance.git_neutralizer_env()
        count = int(env["GIT_CONFIG_COUNT"])
        assert count == len(update_governance._GIT_EXEC_NEUTRALIZERS)
        assert f"GIT_CONFIG_KEY_{count}" not in env
        for i in range(count):
            assert f"GIT_CONFIG_KEY_{i}" in env
            assert f"GIT_CONFIG_VALUE_{i}" in env

    def test_fsmonitor_program_does_not_run(self, tmp_path):
        """The finding, reproduced: `git status` execs a repo-named program.

        Asserted in both directions — without the neutralizer the program runs,
        with it it does not — so the test fails if the pin ever stops working
        rather than passing vacuously on a git that never ran the hook at all.
        """
        import subprocess

        repo = _init_repo(tmp_path / "repo")
        marker = tmp_path / "FSMONITOR_RAN"
        hook = tmp_path / "fsmon.sh"
        hook.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 1\n')
        hook.chmod(0o755)
        _git_config(repo, "--local", "core.fsmonitor", str(hook))

        def _status(env):
            if marker.exists():
                marker.unlink()
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=repo,
                env=env,
                capture_output=True,
                **UTF8_TEXT,
            )
            return marker.exists()

        if not _status(dict(os.environ)):
            pytest.skip("this git does not spawn core.fsmonitor")
        assert not _status(
            {**os.environ, **update_governance.git_neutralizer_env()}
        ), "core.fsmonitor still executed with the neutralizer applied"


class TestWorktreeRedirectRefusal:
    """`core.worktree` is not an exec vector -- it is a data-loss vector.

    Repo config can point the work tree at another directory, and the unattended
    `git reset --hard` then overwrites matching files THERE. Nothing is executed,
    so no exec-key pin covers it, and it cannot be pinned away either: git
    ignores `core.worktree` from `-c`/`GIT_CONFIG_*`, and the `GIT_WORK_TREE`
    that does override it is refused without a matching `GIT_DIR`. So it is
    refused.
    """

    def test_ordinary_checkout_is_allowed(self, tmp_path):
        repo = _init_repo(tmp_path / "plain")
        assert update_governance.repo_exec_config_reason(repo) == ""

    def test_redirected_worktree_is_refused(self, tmp_path):
        """Against real git, with the redirect proven to take effect first."""
        import subprocess

        repo = _init_repo(tmp_path / "wt")
        decoy = tmp_path / "decoy"
        decoy.mkdir()
        _git_config(repo, "--local", "core.worktree", str(decoy))
        proof = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repo,
            capture_output=True,
            **UTF8_TEXT,
        )
        if str(decoy) not in (proof.stdout or ""):
            pytest.skip("this git does not honour core.worktree here")
        assert "redirected" in update_governance.repo_exec_config_reason(repo)

    def test_a_symlinked_checkout_is_not_a_redirect(self, tmp_path):
        """`realpath` both sides, or every symlinked install reads as redirected.

        This repo is itself reached through a symlinked path, so a naive string
        compare would refuse the update on the developer's own checkout.
        """
        repo = _init_repo(tmp_path / "real")
        link = tmp_path / "link"
        try:
            link.symlink_to(repo)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
        assert update_governance.repo_exec_config_reason(str(link)) == ""

    def test_unresolvable_work_tree_is_refused(self, monkeypatch):
        """Cannot prove where a write would land, so do not write."""
        monkeypatch.setattr(
            "kiro_crew.platform.update_governance._git_probe",
            lambda proj, *a: "" if a[:1] == ("config",) else None,
        )
        assert update_governance.repo_exec_config_reason("/proj") != ""


class TestRepoExecConfigRefusal:
    """Drivers named BY THE REPOSITORY have no fixed key, so they are refused.

    Real repos, not mocks: two of these cases exist only because git resolves
    config in a way a mock would not reproduce.
    """

    def test_clean_repo_is_allowed(self, tmp_path):
        repo = _init_repo(tmp_path / "clean")
        assert update_governance.repo_exec_config_reason(repo) == ""

    def test_local_filter_driver_is_refused(self, tmp_path):
        repo = _init_repo(tmp_path / "local")
        _git_config(repo, "--local", "filter.evil.smudge", "sh -c ':'")
        assert "filter.evil.smudge" in update_governance.repo_exec_config_reason(repo)

    def test_worktree_scoped_driver_is_refused(self, tmp_path):
        """A `--local` listing does NOT report worktree-scoped keys.

        So probing only `--local` let a repo with `extensions.worktreeConfig`
        hide a driver that still resolved when the command ran.
        """
        repo = _init_repo(tmp_path / "wt")
        _git_config(repo, "--local", "extensions.worktreeConfig", "true")
        _git_config(repo, "--worktree", "filter.evil.process", "sh -c ':'")
        assert "filter.evil.process" in update_governance.repo_exec_config_reason(repo)

    def test_included_driver_is_refused(self, tmp_path):
        """For a SPECIFIC scope query git defaults include-following OFF.

        Without `--includes` a driver reached through `include.path` is invisible
        to the probe yet still resolves when git runs. The include path is
        relative to the config file's own directory, i.e. `.git/`.
        """
        import subprocess

        repo = _init_repo(tmp_path / "inc")
        (pathlib.Path(repo) / ".git" / "hostile.cfg").write_text(
            "[filter \"evil\"]\n\tclean = sh -c ':'\n"
        )
        _git_config(repo, "--local", "include.path", "hostile.cfg")
        # Precondition: git itself must resolve it, or the case proves nothing.
        resolved = subprocess.run(
            ["git", "-C", repo, "config", "--includes", "--get", "filter.evil.clean"],
            capture_output=True,
            **UTF8_TEXT,
        )
        if resolved.returncode != 0:
            pytest.skip("this git does not follow include.path here")
        assert "filter.evil.clean" in update_governance.repo_exec_config_reason(repo)

    def test_textconv_driver_is_refused(self, tmp_path):
        """`git diff` runs a textconv driver, and its name is repo-chosen too."""
        repo = _init_repo(tmp_path / "tc")
        _git_config(repo, "--local", "diff.evil.textconv", "sh -c ':'")
        assert "diff.evil.textconv" in update_governance.repo_exec_config_reason(repo)

    def test_external_diff_command_is_refused(self, tmp_path):
        """`diff.<driver>.command` REPLACES the diff with an external program.

        `textconv` only converts a blob to text; `command` runs instead of the
        diff itself. Both are repo-named and both are reached by the `git diff`
        the update path runs, so refusing only `textconv` left this open.
        """
        repo = _init_repo(tmp_path / "extdiff")
        _git_config(repo, "--local", "diff.evil.command", "sh -c ':'")
        assert "diff.evil.command" in update_governance.repo_exec_config_reason(repo)

    def test_namespaced_credential_helper_is_refused(self, tmp_path):
        """`credential.<url>.helper` is per-URL, so pinning the bare key misses it.

        The pinned `credential.helper` does not reach a per-URL form, and the URL
        is repo-chosen, so there is no key name to override — refuse instead.
        """
        repo = _init_repo(tmp_path / "cred")
        _git_config(repo, "--local", "credential.https://example.invalid.helper", "!sh -c ':'")
        assert "credential" in update_governance.repo_exec_config_reason(repo)

    def test_unreadable_config_refuses(self, monkeypatch):
        """Cannot prove a repo driver-free, so do not proceed."""
        monkeypatch.setattr("kiro_crew.platform.update_governance._git_probe", lambda *a, **k: None)
        assert update_governance.repo_exec_config_reason("/proj") != ""

    def test_driver_regex_agrees_with_the_worktree_gate(self):
        """The two copies of this rule must not drift apart.

        `worktree._FILTER_KEY_RE` guards the same class for `worktree add`; this
        module carries its own because `platform/` must not import a dashboard
        handler. Parity is asserted rather than assumed.
        """
        from kiro_crew.dashboard.handlers.worktree import _FILTER_KEY_RE

        for key in (
            "filter.evil.process",
            "filter.evil.smudge",
            "filter.evil.clean",
            "filter.a.b.smudge",
        ):
            assert _FILTER_KEY_RE.match(key), key
            assert update_governance._REPO_EXEC_DRIVER_RE.match(key), key
        for key in ("filter.evil.required", "core.fsmonitor", "diff.external"):
            assert not _FILTER_KEY_RE.match(key), key
            assert not update_governance._REPO_EXEC_DRIVER_RE.match(key), key


class TestTracksUpstream:
    """The apply resets to `origin/<branch>`; the check measures `@{u}`.

    When those are not the same ref the check measures one thing and a `--hard`
    reset applies another, so the gap is lost commits. BOTH halves of the
    upstream are checked, and each has its own case here because either alone
    leaves the gap open.
    """

    def test_branch_tracking_the_same_ref_is_accepted(self, tmp_path):
        repo = _init_repo(tmp_path / "o")
        _git_config(repo, "--local", "branch.main.remote", "origin")
        _git_config(repo, "--local", "branch.main.merge", "refs/heads/main")
        assert update_governance.tracks_upstream(repo, "main")

    def test_branch_tracking_another_remote_is_refused(self, tmp_path):
        """The fork case: `main` tracks `upstream`, `origin` is a stale fork."""
        repo = _init_repo(tmp_path / "u")
        _git_config(repo, "--local", "branch.main.remote", "upstream")
        _git_config(repo, "--local", "branch.main.merge", "refs/heads/main")
        assert not update_governance.tracks_upstream(repo, "main")

    def test_branch_tracking_another_branch_is_refused(self, tmp_path):
        """Right remote, wrong branch: `@{u}` is `origin/other`, reset is `origin/main`."""
        repo = _init_repo(tmp_path / "b")
        _git_config(repo, "--local", "branch.main.remote", "origin")
        _git_config(repo, "--local", "branch.main.merge", "refs/heads/other")
        assert not update_governance.tracks_upstream(repo, "main")

    def test_untracked_branch_is_refused(self, tmp_path):
        """No upstream at all means the check had nothing to compare either."""
        repo = _init_repo(tmp_path / "n")
        assert not update_governance.tracks_upstream(repo, "main")

    def test_remote_without_merge_is_refused(self, tmp_path):
        """A half-configured upstream is not an upstream."""
        repo = _init_repo(tmp_path / "h")
        _git_config(repo, "--local", "branch.main.remote", "origin")
        assert not update_governance.tracks_upstream(repo, "main")

    def test_detached_head_is_refused(self, tmp_path):
        repo = _init_repo(tmp_path / "d")
        assert not update_governance.tracks_upstream(repo, "HEAD")
        assert not update_governance.tracks_upstream(repo, "")


class TestFixtureGitHygiene:
    """The fixtures must not run anything the developer's environment supplies.

    `git init` COPIES a template directory's hooks into the new repo and the
    following `git commit` runs them, so an inherited `GIT_TEMPLATE_DIR` turned
    running this suite into host-side execution.
    """

    def test_fixture_env_disables_templates_and_hooks(self, tmp_path):
        repo = _init_repo(tmp_path / "hyg")
        env = _fixture_git_env(repo)
        keys = {
            env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
            for i in range(int(env["GIT_CONFIG_COUNT"]))
        }
        assert env["GIT_TEMPLATE_DIR"] == ""
        assert keys["init.templateDir"] == ""
        assert keys["core.hooksPath"] == os.devnull

    def test_a_template_hook_does_not_run(self, tmp_path):
        """The finding, reproduced end to end against real git."""
        import subprocess

        marker = tmp_path / "TEMPLATE_HOOK_RAN"
        template = tmp_path / "tpl" / "hooks"
        template.mkdir(parents=True)
        hook = template / "post-commit"
        hook.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
        hook.chmod(0o755)

        # Control: with the template inherited, the hook DOES run -- otherwise
        # this test would pass vacuously on a git that never ran it.
        loose = tmp_path / "loose"
        loose.mkdir()
        subprocess.run(
            ["git", "init", "-q", f"--template={template.parent}", "."],
            cwd=loose,
            capture_output=True,
            **UTF8_TEXT,
        )
        subprocess.run(
            ["git", "commit", "-q", "--allow-empty", "-m", "x"],
            cwd=loose,
            env={
                **os.environ,
                "GIT_AUTHOR_NAME": "t",
                "GIT_AUTHOR_EMAIL": "t@example.invalid",
                "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.invalid",
            },
            capture_output=True,
            **UTF8_TEXT,
        )
        if not marker.exists():
            pytest.skip("this git did not run the template post-commit hook")
        marker.unlink()

        # The fixture helper, with GIT_TEMPLATE_DIR pointing at the same hooks.
        os.environ["GIT_TEMPLATE_DIR"] = str(template.parent)
        try:
            _init_repo(tmp_path / "guarded")
        finally:
            os.environ.pop("GIT_TEMPLATE_DIR", None)
        assert not marker.exists(), "fixture ran an inherited template hook"
