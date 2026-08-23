"""The data home cannot be relocated by the agent.

Every fenced leaf is identified by its PATH, so the fence assumes the directory
holding it stays where it is. It did not: ``rm -rf ~/.kiro/crew`` was refused, but
``mv`` and ``ln -s`` were not, so

    mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil ~/.kiro/crew

left every fence naming a file that is no longer there, and the next write to
``security_policy.json``, ``profiles/``, ``admission_policy.json`` or
``computer_use.json`` followed the link. That is the keystone the whole ceiling
rests on, so this is a bypass of the ceiling rather than of one feature.
"""

from __future__ import annotations

import os

import pytest

from kiro_crew import security

HOME = os.path.expanduser("~")


def _blocked(command: str) -> bool:
    return security.is_sensitive_bash_command(command) is not None


class TestTheContainerCannotBeRelocated:
    """Refused verb-independently: the refusal is on NAMING the container, because an
    enumerated write-verb allowlist is bypassable -- the reason the leaf fence gives
    for its own verb-independence."""

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/crew /tmp/stash",
            "ln -s /tmp/evil ~/.kiro/crew",
            "cp -r ~/.kiro /tmp/x",
            "rsync -a ~/.kiro/crew /tmp/x",
            "mv ~/.kiro/crew/ /tmp/x",
            # A verb nobody enumerated, which is the point of not enumerating.
            "install -d ~/.kiro/crew",
        ],
    )
    def test_a_relocating_verb_is_refused(self, command: str) -> None:
        assert _blocked(command), f"{command!r} can relocate the fenced container"

    @pytest.mark.parametrize(
        "command",
        [
            'mv "$HOME/.kiro/crew" /tmp/x',
            "mv $HOME/.kiro/crew /tmp/x",
            "mv ~/.kiro/../.kiro/crew /tmp/x",
            "mv ~/.KIRO/CREW /tmp/x",
            "cd ~/.kiro && mv crew /tmp/x",
            "cd ~/.kiro/crew && mv . /tmp/x",
            "cd ~ && mv .kiro/crew /tmp/x",
            "D=~/.kiro/crew; mv $D /tmp/x",
            "python3 -c \"import os; os.rename(os.path.expanduser('~/.kiro/crew'),'/tmp/x')\"",
        ],
    )
    def test_the_obfuscated_forms_are_refused(self, command: str) -> None:
        """Quoting, `$HOME`, traversal, casefold, `cd`-relative, variables, and an
        interpreter payload -- the evasion families the leaf gate already covers."""
        assert _blocked(command), f"{command!r} relocates the container undetected"

    def test_a_spent_cd_does_not_excuse_a_later_mention(self) -> None:
        """The navigation carve-out must not become a prefix that launders the rest of
        the line."""
        assert _blocked("cd ~/.kiro/crew && mv ~/.kiro/crew /tmp/x")


class TestOrdinaryAgentWorkIsUnaffected:
    """The gate is exact, not prefix -- the reason the container cannot simply be added
    to ``_SENSITIVE_HOME_DIRS``, whose matcher IS prefix-based."""

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.kiro/crew/sessions/a.json",
            "ls ~/.kiro/crew/skills",
            "tail -n 50 ~/.kiro/crew/logs/gateway.log",
            "grep -r todo ~/.kiro/crew/memory",
        ],
    )
    def test_content_under_the_container_stays_reachable(self, command: str) -> None:
        assert not _blocked(command), (
            f"{command!r} was refused; a prefix match here cuts the agent off from its "
            "own sessions, memory, skills and logs"
        )

    @pytest.mark.parametrize("command", ["cd ~/.kiro", "cd ~/.kiro/crew", 'cd "~/.kiro"'])
    def test_navigating_into_it_is_still_allowed(self, command: str) -> None:
        """Entering a directory cannot relocate it, and `_GENERAL_PURPOSE_PARENT_DIRS`
        already excludes `.kiro` from parent-tainting to avoid exactly this false
        positive."""
        assert not _blocked(command)

    def test_an_unrelated_path_is_untouched(self) -> None:
        assert not _blocked("mv /tmp/a /tmp/b")


class TestItIsNoWeakerThanTheLeafGateBesideIt:
    """The ratchet, and the invariant that matters most.

    The container gate reuses the leaf gate's machinery precisely so the two cannot
    drift, but they are separate code paths and the first cut of this fix was wired
    into only ONE of the three passes -- so it missed `cd`-relative, variable, and
    interpreter forms that the leaf gate had caught for a long time. Asserting parity
    form-by-form is what caught that; asserting the attack alone did not.
    """

    # (leaf command, container command) exercising the SAME evasion family.
    FORMS = [
        (
            "cd ~/.kiro && cat crew/security_policy.json",
            "cd ~/.kiro && mv crew /tmp/x",
        ),
        (
            "cd ~/.kiro/crew && cat ./security_policy.json",
            "cd ~/.kiro/crew && mv . /tmp/x",
        ),
        (
            "cd ~ && cat .kiro/crew/security_policy.json",
            "cd ~ && mv .kiro/crew /tmp/x",
        ),
        (
            "D=~/.kiro/crew; cat $D/security_policy.json",
            "D=~/.kiro/crew; mv $D /tmp/x",
        ),
        (
            f"python3 -c \"print(open('{HOME}/.kiro/crew/security_policy.json').read())\"",
            f"python3 -c \"import os; os.rename('{HOME}/.kiro/crew','/tmp/x')\"",
        ),
    ]

    @pytest.mark.parametrize("leaf,container", FORMS)
    def test_every_form_the_leaf_gate_catches_the_container_gate_catches(
        self, leaf: str, container: str
    ) -> None:
        assert _blocked(leaf), (
            f"the leaf gate stopped catching {leaf!r}; this test's premise is gone and "
            "the parity assertion below would pass vacuously"
        )
        assert _blocked(container), (
            f"the leaf gate catches {leaf!r} but the container gate misses the same "
            f"evasion in {container!r} -- the container gate is the weaker of the two"
        )


class TestTheContainerSetCoversEveryDataHome:
    def test_the_legacy_home_is_covered_too(self) -> None:
        """`~/.kirocrew` is fully deprecated and never migrated to, but an installation
        that still has one must not have it swapped out from under the files inside --
        the same reason it stays in the leaf fence."""
        assert _blocked("mv ~/.kirocrew /tmp/x")

    def test_the_predicate_is_exact_rather_than_prefix(self) -> None:
        assert security.is_unreplaceable_container("~/.kiro/crew")
        assert not security.is_unreplaceable_container("~/.kiro/crew/sessions")
        assert not security.is_unreplaceable_container("~/.kiro/crewuxx")


class TestShellExpansionCannotSpellAroundEitherGate:
    """Bash expands the operand before the command runs; the matcher did not.

    `~/.kiro/cr{e..e}w` reached the gate as a literal matching no protected path and
    reached bash as `~/.kiro/crew`. This was NOT specific to the container gate -- the
    leaf gate had the identical hole, so `cat ~/.kiro/cr{e..e}w/security_policy.json`
    read the governance trust root on `main`. Expansion therefore lands in the shared
    candidate generator, where both gates inherit it.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.kiro/cr{e..e}w/security_policy.json",
            "cat ~/.kiro/crew/security_polic{y..y}.json",
            "cat ~/.kiro/cre[w]/security_policy.json",
            "cat ~/.kiro/*/security_policy.json",
        ],
    )
    def test_the_leaf_gate_resists_it_too(self, command: str) -> None:
        """The finding arrived on the container gate; the fix had to cover both."""
        assert _blocked(command), f"{command!r} reads the trust root through expansion"

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/cr{e..e}w /tmp/x",
            "mv ~/.kiro/cre[w] /tmp/x",
            "mv ~/.kiro/* /tmp/x",
            "mv ~/.kiro/{crew,other} /tmp/x",
        ],
    )
    def test_the_container_gate_resists_it(self, command: str) -> None:
        assert _blocked(command), f"{command!r} relocates the container through expansion"

    @pytest.mark.parametrize(
        "command",
        [
            "ls *",
            "ls ~/*",
            "rm -f build/*.o",
            "cp {a,b}.txt /tmp/",
            "ls ~/.kiro/crew/sessions/*.json",
            "cat ~/.kiro/crew/logs/*.log",
            "grep -r x ~/.kiro/crew/skills/*",
        ],
    )
    def test_ordinary_globbing_is_untouched(self, command: str) -> None:
        """The expensive half of this fix.

        A first cut used `fnmatch` over the whole path and denied `ls *`, because
        `fnmatch`'s `*` crosses `/` and matched every absolute target. Matching is
        component-wise instead, with bash's dotfile rule -- which is why `ls ~/*` is
        allowed (bash without `dotglob` does not match `.kiro`) while `ls ~/.kiro/*`,
        which names it, is not.
        """
        assert not _blocked(command), f"{command!r} is ordinary shell usage"

    def test_a_pattern_naming_the_container_explicitly_is_still_refused(self) -> None:
        assert _blocked("ls ~/.kiro/*")

    def test_expansion_is_bounded(self) -> None:
        """A gate is not the place to discover that `{a..z}{a..z}{a..z}` is 17,576
        strings. Past the cap the token is left unexpanded and the metacharacter arm
        still refuses anything that could name a protected path."""
        from kiro_crew.security import _MAX_BRACE_EXPANSIONS, _expand_braces

        assert len(_expand_braces("~/{a..z}{a..z}{a..z}")) <= _MAX_BRACE_EXPANSIONS


class TestTheFencedPathsAreHiddenFromSubprocesses:
    """The command gate reads command TEXT; a subprocess is one opaque token to it.

    `security.is_sensitive_bash_command` refuses `echo x > ~/.kiro/crew/
    security_policy.json`, and says nothing about `./script.sh` containing that exact
    line — an approved `make install` or `npm run build` writes whatever it likes. So
    the path fence alone never constrained a subprocess, and the sandbox's hide lists
    are the layer that does not depend on the write being spelled out in a command.

    Asserted as a COUPLING rather than as a literal list, because the two halves live
    in different modules with no shared symbol: `security.py` names the fenced leaves,
    `sandbox.py` names what is hidden, and a leaf added to one and not the other is
    protected only against the spelling nobody uses.
    """

    # The keystone leaves this branch's base already fences by NAME. Both halves of
    # the coupling are assertable for these.
    MUST_BE_HIDDEN = [
        ".kiro/crew/profiles",
        ".kiro/crew/security_policy.json",
        ".kiro/crew/admission_policy.json",
        ".kiro/crew/computer_use.json",
    ]

    # Hidden here, but fenced by NAME only once the crew-variables work lands, so the
    # command-gate half of the coupling cannot be asserted on this base yet. Listed
    # separately rather than dropped: the hide list is the half that stops a
    # subprocess, and it is correct to ship it whether or not the name fence exists.
    HIDDEN_AHEAD_OF_ITS_NAME_FENCE = [
        ".kiro/crew/variables",
        # Persisted authorship records. Same reasoning: the flag is derived carefully
        # in process and forgeable on disk, so the file has to be out of reach. Name
        # fence lands with the crew-variables work; the hide list is independent.
        ".kiro/crew/cron.json",
        ".kiro/crew/autonudge.json",
    ]

    def _all_hidden(self) -> set[str]:
        from kiro_crew import sandbox

        hidden: set[str] = set()
        for name in ("_STRICT_DIRS", "_STANDARD_DIRS", "_CC_DIRS", "_CC_FILES"):
            hidden.update(getattr(sandbox, name, []))
        return hidden

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_each_fenced_path_is_hidden_from_the_agent(self, path: str) -> None:
        assert path in self._all_hidden(), (
            f"{path} is refused by the command gate but VISIBLE to a subprocess. An "
            "approved script can write it without the gate ever seeing a path."
        )

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_the_legacy_home_is_covered_too(self, path: str) -> None:
        """A not-yet-migrated box still holds the real bytes."""
        legacy = path.replace(".kiro/crew/", ".kirocrew/")
        assert legacy in self._all_hidden()

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_the_command_gate_still_refuses_the_spelled_out_write(self, path: str) -> None:
        """The other half of the coupling. If this stops refusing, the hide list is
        carrying a burden it was never meant to carry alone.

        A directory entry is probed through a file INSIDE it: `echo x > <dir>` is not a
        write anyone can perform, so asserting on the bare directory would be asserting
        on a shape that never occurs.
        """
        target = f"~/{path}" if path.endswith(".json") else f"~/{path}/planted"
        assert security.is_sensitive_bash_command(f"echo x > {target}") is not None

    @pytest.mark.parametrize("path", HIDDEN_AHEAD_OF_ITS_NAME_FENCE)
    def test_the_store_is_hidden_even_before_its_name_fence_exists(self, path: str) -> None:
        assert path in self._all_hidden()
        assert path.replace(".kiro/crew/", ".kirocrew/") in self._all_hidden()

    def test_hiding_is_in_every_mode_not_only_strict(self) -> None:
        """A protection that only applies in strict mode is absent on the default."""
        from kiro_crew import sandbox

        for name in ("_STRICT_DIRS", "_STANDARD_DIRS", "_CC_DIRS"):
            entries = getattr(sandbox, name)
            assert ".kiro/crew/variables" in entries, f"{name} does not hide the store"


class TestTheMatcherDoesNotDivergeFromBash:
    """Four ways the hand-rolled expander disagreed with the shell it models.

    Each is the same failure mode: bash produced a protected path and the gate produced
    something else, so the operand looked harmless. This layer is best-effort by
    construction -- a matcher is not a bash parser, which the module says of itself --
    and the floor beneath it is the sandbox hide list. That is why these are worth
    fixing but not worth trusting alone.
    """

    def test_a_descending_range_expands_like_bash(self) -> None:
        """`{w..e}` counts DOWN in bash. Walking only upward gave an empty span, so the
        operand produced no candidates at all while bash produced `crew`."""
        from kiro_crew.security import _expand_braces

        assert "crew" in _expand_braces("cr{w..e}w")
        assert "crew" in _expand_braces("cr{e..e}w")
        assert _blocked("mv ~/.kiro/cr{w..e}w /tmp/stash")

    def test_a_descending_numeric_range_too(self) -> None:
        from kiro_crew.security import _expand_braces

        assert _expand_braces("{3..1}") == ["3", "2", "1"]

    def test_an_oversized_brace_fails_closed(self) -> None:
        """Truncating dropped the TAIL, so a 65-item list with `crew` last expanded to
        `crew` in bash and to everything-but-`crew` here. Too-many-to-check must answer
        like names-the-container, not like names-nothing."""
        big = ",".join([f"x{i}" for i in range(64)] + ["crew"])
        assert _blocked(f"mv ~/.kiro/{{{big}}} /tmp/stash")

    def test_a_shadowed_navigation_verb_loses_the_carve_out(self) -> None:
        """`cd` can be a function. The carve-out spares an ordinary `cd`, and an
        ordinary `cd` does not appear in a command that also defines one."""
        assert _blocked('cd(){ mv "$1" /tmp/stash; }; cd ~/.kiro/crew')
        assert _blocked('function cd { mv "$1" /tmp/x; }; cd ~/.kiro/crew')
        assert _blocked("alias cd='mv'; cd ~/.kiro/crew /tmp/x")

    def test_an_ordinary_cd_keeps_the_carve_out(self) -> None:
        """Not an everything-is-refused pass: the carve-out still exists."""
        assert not _blocked("cd ~/.kiro")
        assert not _blocked("cd ~/.kiro/crew")

    def test_glob_matching_splits_on_either_separator(self) -> None:
        """`_home_dir_targets` yields NATIVE paths, so a Windows target is
        backslash-separated. Splitting on "/" alone gave one component, the length
        check never matched, and the glob arm silently passed everything -- green on
        macOS and absent on Windows."""
        from kiro_crew.security import _glob_could_name

        assert _glob_could_name("/x/y/*", {"/x/y/z"})
        assert _glob_could_name("/x/y/*", {r"\x\y\z"}), "a native Windows target must match"


class TestACustomDataHomeIsProtectedToo:
    """`KIROCREW_HOME` relocates the data home wholesale.

    An interpreter payload never tokenizes, so for a custom home the RAW scan is the
    only layer that can see it -- and anchoring solely on `~` left it invisible. With
    the variable set, that directory IS the container rather than a parent of one.
    """

    def test_the_configured_home_is_refused(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/custom/home")
        assert _blocked("mv /custom/home /tmp/stash")
        assert _blocked("python3 -c \"import os; os.rename('/custom/home','/tmp/x')\"")

    def test_the_pattern_is_rebuilt_when_the_home_changes(self, monkeypatch) -> None:
        """The cache is keyed on the variable. A plain module-level cache would pin
        whatever it was at first call, and tests pin it per test -- so one built under
        a previous test's home would be reused, failing in the permissive direction."""
        monkeypatch.setenv("KIROCREW_HOME", "/first/home")
        assert _blocked("mv /first/home /tmp/x")
        monkeypatch.setenv("KIROCREW_HOME", "/second/home")
        assert _blocked("mv /second/home /tmp/x"), "the cached pattern went stale"

    def test_content_under_a_custom_home_is_still_reachable(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/custom/home")
        assert not _blocked("cat /custom/home/sessions/a.json")
