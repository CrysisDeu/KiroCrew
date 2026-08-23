"""The update seam: where new code may come from, and the minimum version.

Two enterprise pins, read from the trust-root ``security_policy.json`` (see
``governance.UpdatePins``), applied at the three places KiroCrew replaces its own
code: ``POST /api/update``, ``kirocrew update``, and the unattended gateway-boot
auto-apply. This module exists so those three share one implementation and
cannot drift.

Deliberately NOT a governance archetype: a remote URL and a version number are
values the core consumes, not "is X permitted?" decisions, so they need no
``SCOPE_CATALOG`` row, no matcher, and no evaluator change.

**A pin blocks; an unresolvable pin does not.** If governance cannot be read at
all the update proceeds — refusing one would strand a host on a build that may
need a patch, and the pins are a routing constraint, not a security boundary
against a local operator who could edit the checkout directly.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess

from kiro_crew.subprocess_utf8 import UTF8_TEXT

logger = logging.getLogger(__name__)

_GIT_TIMEOUT_SECS = 10


#: The ONLY branch names an unattended update may reset a checkout to.
#:
#: A literal in reviewed code, and deliberately the WHOLE decision: see
#: :func:`is_primary_branch` for why no local git ref is allowed to participate.
#: This repo's primary branch is ``main``; the other two cover internal and
#: mirror clones. Mirrors ``security._PROTECTED_BRANCHES`` by intent — the branch
#: an unattended update may reset to is exactly the branch a push must never
#: target — but is kept separate so update routing does not read a
#: security-module private.
PRIMARY_BRANCHES = frozenset(
    {
        "main",
        "mainline",
        "master",  # wokeignore:rule=master  # legacy primary in older clones
    }
)


def is_primary_branch(branch: str) -> bool:
    """Whether *branch* is a primary line an unattended update may reset to.

    Membership in :data:`PRIMARY_BRANCHES` is the entire test. That is a design
    constraint, not an omission: this gate gates the most privileged path in the
    product — a boot-time ``git reset --hard`` + ``pip install`` + ``execv`` with
    no auth and no click — and it is also the path the enterprise ``min_version``
    floor drives (``_auto_apply_update`` is what a mandatory update calls on a
    checkout). So the decision must not read any state a local process can write.

    ``refs/remotes/<remote>/HEAD`` is exactly such state: one
    ``git remote set-head`` repoints it. Consulting it fails in BOTH directions,
    and there is no ordering that fixes both —

    * Obeying it as authoritative lets a repoint aim the install at an arbitrary
      branch of the still-approved origin, so unreviewed code gets installed and
      executed. The source pin cannot catch that: the remote URL is unchanged.
    * Letting it merely narrow (accept only when it agrees) turns the same
      one-command repoint into a veto — point a ``main`` checkout's pointer at
      ``mainline`` and the host silently stops updating, including for a
      mandatory floor, stranding it below the administrator's minimum version.

    A fork whose primary line is named something else entirely therefore gets no
    unattended update, only the badge. ``kirocrew update`` and the dashboard
    apply path still serve it, and both have a human in the loop — the
    difference that makes wider trust acceptable there and not here.

    A wrong literal here fails SILENTLY — the gate returns and the host simply
    never updates — which is what a hardcoded ``!= "mainline"`` did to every
    ``main`` checkout of this repo for three months. The allowlist is the fix for
    that: it names every primary line this project's clones actually use, so no
    single name has to be guessed right.

    A detached HEAD is never primary: there is no branch to fast-forward.
    """
    return branch in PRIMARY_BRANCHES


def _git(proj: str, *args: str) -> str:
    """Run a read-only git command in *proj*, returning stripped stdout or ``""``."""
    out = _git_probe(proj, *args)
    return out.strip() if out is not None else ""


def _git_probe(proj: str, *args: str) -> str | None:
    """As :func:`_git`, but ``None`` when git could not answer at all.

    Every git invocation in this module carries
    :func:`git_neutralizer_env`, so a repo-planted ``core.fsmonitor`` (or any
    other fixed-key exec vector) cannot run just because the update seam looked
    at the checkout.
    """
    try:
        done = subprocess.run(
            ["git", *args],
            cwd=proj,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECS,
            env={**os.environ, **git_neutralizer_env()},
            **UTF8_TEXT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def resolve_remote_url(proj: str, *, remote: str = "", branch: str = "") -> str:
    """The URL of the remote an update would fetch from in *proj* (``""`` if unknown).

    Pass *remote* for a FIXED remote name: the CLI and gateway paths run
    ``git fetch origin <branch>``, so they must validate ``origin`` rather than
    whatever the branch tracks. With no *remote*, ``branch.<name>.remote`` is
    resolved instead — that is the API path's bare ``git pull``, which follows the
    tracked remote. Validating a different remote than the one fetched would
    approve one source and install another.

    ``ls-remote --get-url`` (not ``remote get-url``) additionally applies
    ``url.<base>.insteadOf`` rewriting, so the value checked is the URL git
    resolves rather than the one merely written down.

    Returns ``""`` on any failure, which a source pin then treats as "not
    permitted" and an unpinned host ignores.
    """

    if not remote:
        if not branch:
            branch = _git(proj, "rev-parse", "--abbrev-ref", "HEAD")
        if not branch or branch == "HEAD":  # detached HEAD tracks nothing
            return ""
        remote = _git(proj, "config", "--get", f"branch.{branch}.remote") or "origin"
    url = _git(proj, "ls-remote", "--get-url", "--", remote)
    # `--get-url` echoes its argument back for an unknown remote; that is a bare
    # name, not a URL, and must not be checked as one.
    return "" if url == remote else url


#: Repo-scoped config keys whose VALUE git may execute as a program, and whose
#: KEY NAME is fixed so ``-c``/``GIT_CONFIG_*`` can pin it back to a safe value.
#:
#: The membership criterion is exactly that — "git may exec this value, and the
#: key is a literal" — and it is written down because the first version of this
#: list was an enumeration without one and was therefore missing members
#: (``core.gitProxy``). Adding a key here is correct whenever git might exec it;
#: the cost of an unnecessary pin is nil, because none of these are values the
#: update path wants from the repository in the first place.
#:
#: Keys whose NAME is repo-chosen (``filter.<name>.smudge``,
#: ``diff.<driver>.textconv``, ``credential.<url>.helper``) cannot be pinned at
#: all — there is no name to override — so those are refused instead, by
#: :func:`repo_exec_config_reason`.
#:
#: Mirrors the neutralizer lists the app-side git callers already carry
#: (``apps/builtins/md_notebook/git_ops.py``, ``papyrus/backend/gitops.py``,
#: ``dev_fleet/server.py``). This copy exists because ``platform/`` must not
#: import from ``apps/``, and the update seam needs it at the same chokepoint.
_GIT_EXEC_NEUTRALIZERS: tuple[tuple[str, str], ...] = (
    # `git status` and `git diff` consult core.fsmonitor and SPAWN it.
    ("core.fsmonitor", "false"),
    # Any command may run hooks; a reset checks files out.
    ("core.hooksPath", os.devnull),
    ("credential.helper", ""),
    ("core.sshCommand", "ssh"),
    # A fixed-key exec vector on the `git diff` call below.
    ("diff.external", ""),
    # The transport command for a `git://` remote. Reachable because a repo that
    # can write .git/config can also point remote.origin.url at `git://`, and an
    # unpinned host has no `updates.source` pin to refuse that URL.
    ("core.gitProxy", ""),
    # Prompt helpers git execs when a transport wants credentials.
    ("core.askPass", ""),
    # Executed while enumerating an alternate object store's refs.
    ("core.alternateRefsCommand", ""),
    # Server-side hook honoured for a local/file transport fetch.
    ("uploadpack.packObjectsHook", ""),
    # Paged output execs the pager. `--porcelain`/`--quiet` and a non-tty stdout
    # make this unreachable today, which is exactly why it is pinned rather than
    # reasoned about at each call site.
    ("core.pager", "cat"),
    ("core.editor", "true"),
    ("sequence.editor", "true"),
    # Reached through signature verification, which is also forced off below.
    ("gpg.program", "true"),
    # Signature VERIFICATION is the trigger here: a fetched commit carrying a
    # gpgsig header would invoke gpg.program. The update never verifies
    # signatures, so the only reason git would exec it is an attacker's.
    ("merge.verifySignatures", "false"),
    ("pull.verifySignatures", "false"),
    # Local/file transports exec the config-named pack programs directly, and
    # GIT_ALLOW_PROTOCOL does not gate them (they are not a protocol). Every
    # update fetch uses the literal remote `origin`, so pinning these restores
    # git's own defaults over anything in .git/config.
    ("remote.origin.uploadpack", "git-upload-pack"),
    ("remote.origin.receivepack", "git-receive-pack"),
    # `ext::` remote URLs run an arbitrary command as the transport.
    ("protocol.ext.allow", "never"),
)

#: Repo-scoped keys naming an arbitrary-named driver program. Refused, not
#: neutralized. Mirrors ``dashboard/handlers/worktree._FILTER_KEY_RE``, widened
#: with the ``textconv`` cousin that ``git diff`` reaches;
#: ``test_governance_updates`` asserts the two stay in agreement.
_REPO_EXEC_DRIVER_RE = re.compile(
    r"^(?:filter\.(?P<f>.+)\.(?:process|smudge|clean)"
    # `textconv` converts a blob to text; `command` REPLACES the whole diff with
    # an external program. Both are repo-named and both are reached by the
    # `git diff` this path runs, so refusing only one left the other open.
    r"|diff\.(?P<d>.+)\.(?:textconv|command)"
    # `credential.<url>.helper` is per-URL and so repo-named: pinning the bare
    # `credential.helper` does not reach it.
    r"|credential\.(?P<c>.+)\.helper)$",
    re.IGNORECASE,
)

#: Returned when a config scope could not be read at all. An unreadable scope
#: cannot be PROVEN driver-free, so it refuses rather than assuming the best.
_EXEC_CONFIG_UNREADABLE = "unreadable git config"


def git_neutralizer_env() -> dict[str, str]:
    """Environment pinning every fixed-key git exec vector to a safe value.

    ``GIT_CONFIG_COUNT``/``KEY``/``VALUE`` carry the same precedence as ``git
    -c``, so these beat the repository's own ``.git/config``. Returned as
    environment rather than per-call flags so one chokepoint covers every
    invocation in a sequence and a later-added command cannot forget it.

    This covers only keys git may EXEC. A redirected work tree is a different
    hazard — data loss with nothing executed — and cannot be closed here:
    ``core.worktree`` supplied through ``-c``/``GIT_CONFIG_*`` is deliberately
    ignored by git (verified: a repo-set value still won), and the
    ``GIT_WORK_TREE`` that does override it is refused without a matching
    ``GIT_DIR``. It is therefore REFUSED instead, by
    :func:`repo_exec_config_reason`.

    Callers MUST merge this over ``os.environ`` rather than passing it alone: a
    bare env would drop ``PATH``/``HOME`` and git would not run.
    """
    env: dict[str, str] = {"GIT_CONFIG_COUNT": str(len(_GIT_EXEC_NEUTRALIZERS))}
    for index, (key, value) in enumerate(_GIT_EXEC_NEUTRALIZERS):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    return env


def _same_dir(a: str, b: str) -> bool:
    """Whether two paths name the same directory, symlinks and case resolved.

    ``os.path.realpath`` on both sides so a symlinked checkout (this repo is
    reached through one) does not read as a redirect, and ``normcase`` so a
    Windows drive-letter or case difference does not either.
    """
    if not a or not b:
        return False
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def repo_exec_config_reason(proj: str) -> str:
    """Why *proj* must not be driven unattended, or ``""`` when it is clean.

    :data:`_GIT_EXEC_NEUTRALIZERS` closes the keys whose NAME is fixed. A
    content filter or a textconv driver is named by the repository
    (``filter.evil.smudge``), so there is no key to pin — the operation is
    refused instead, exactly as ``worktree._checkout_filter`` refuses a
    worktree add.

    Two scopes are probed, and both details are load-bearing (see that
    function's docstring, where each was verified empirically):

    * ``--worktree`` as well as ``--local``, because a ``--local`` listing does
      NOT report worktree-scoped keys, so a repo with
      ``extensions.worktreeConfig=true`` hides a driver from a ``--local`` probe.
    * ``--includes`` on both, because for a SPECIFIC scope query git defaults
      include-following off, so a driver reached via ``include.path`` is
      invisible to the probe yet still resolves when the command runs.

    Global and system config are deliberately not probed: that is the user's own
    machine configuration, not something the repository supplies.
    """
    scopes = ["--local"]
    if _git(
        proj, "config", "--local", "--includes", "--get", "extensions.worktreeConfig"
    ).lower() in (
        "true",
        "yes",
        "on",
        "1",
    ):
        scopes.append("--worktree")
    for scope in scopes:
        listing = _git_probe(proj, "config", scope, "--includes", "--name-only", "--list")
        if listing is None:
            return _EXEC_CONFIG_UNREADABLE
        for line in listing.splitlines():
            key = line.strip()
            if _REPO_EXEC_DRIVER_RE.match(key):
                return f"repository declares {key[:120]}"

    # A redirected work tree executes nothing, so no exec-key pin touches it —
    # but `git reset --hard` would overwrite matching files in the OTHER
    # directory. Ask git where the tree actually resolves rather than parsing
    # `core.worktree`: that catches a relative value, a worktree-scoped one, and
    # one reached through `include.path` with a single probe. A legitimate linked
    # worktree resolves to the directory being operated on, so it is unaffected.
    toplevel = _git_probe(proj, "rev-parse", "--show-toplevel")
    if toplevel is None:
        return "cannot resolve the work tree"
    if not _same_dir(toplevel.strip(), proj):
        return f"work tree is redirected to {toplevel.strip()[:120]}"
    return ""


def tracks_upstream(proj: str, branch: str, *, remote: str = "origin") -> bool:
    """Whether *branch* in *proj* tracks exactly ``<remote>/<branch>``.

    The unattended update FETCHES and RESETS to ``<remote>/<branch>``, and the
    source pin validates that same fixed remote. But the availability check that
    decides an update exists compares ``HEAD`` against ``@{u}`` — whatever the
    branch actually tracks. When those two are not the same ref, the check
    measures one thing and the reset applies another, and the reset is a
    ``--hard`` one, so the gap is lost commits rather than a stale answer.

    BOTH halves of the upstream are therefore checked, because either alone
    leaves the gap open:

    * the remote — a fork checkout whose ``main`` tracks ``upstream/main`` while
      ``origin`` is the user's own stale fork;
    * the branch — ``branch.main.remote=origin`` with
      ``branch.main.merge=refs/heads/other``, which still points ``@{u}`` at
      ``origin/other`` while the reset targets ``origin/main``.

    A checkout that tracks anything else still gets the badge, and can update
    through ``kirocrew update`` or the dashboard, both of which have a human
    deciding.
    """
    if not branch or branch == "HEAD":
        return False
    if _git(proj, "config", "--get", f"branch.{branch}.remote") != remote:
        return False
    return _git(proj, "config", "--get", f"branch.{branch}.merge") == f"refs/heads/{branch}"


def update_blocked_reason(remote_url: str) -> str:
    """Why this update is not allowed, or ``""`` when it is.

    The one gate the three update paths call. The returned string is
    operator-facing (it reaches an API 403 body and the CLI's stderr), so it names
    neither the remote nor the pin: a git remote can embed a token
    (``https://x-access-token:<pat>@host/…``, ``?access_token=…``) and so can the
    pin. The operator can read both from `git remote -v` and the policy file; the
    log/response needs only to say which check failed.
    """
    from kiro_crew.platform.governance import active_update_pins

    if not active_update_pins().permits_source(remote_url):
        return (
            "this checkout's git remote does not match the update source pinned "
            "by the security policy"
        )
    return ""


def update_required(current_version: str) -> bool:
    """Is this build below the fleet's pinned minimum version?

    ``True`` makes an update MANDATORY — it overrides the user's
    ``auto_update=False``, because user config sits under the enterprise ceiling
    and an operator opting out must not be able to hold a fleet on a build the
    policy forbids. It never refuses to boot: bricking a fleet on a policy typo
    would remove the very surface an admin needs to fix it.
    """
    from kiro_crew.platform.governance import active_update_pins

    return not active_update_pins().meets_min_version(current_version)


def min_version() -> str:
    """The pinned minimum version, or ``""`` when unpinned (for display)."""
    from kiro_crew.platform.governance import active_update_pins

    return active_update_pins().min_version


__all__ = [
    "PRIMARY_BRANCHES",
    "git_neutralizer_env",
    "is_primary_branch",
    "min_version",
    "repo_exec_config_reason",
    "resolve_remote_url",
    "tracks_upstream",
    "update_blocked_reason",
    "update_required",
]
