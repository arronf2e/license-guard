"""Attestation lifecycle: policy versions, access, and stored verdicts."""

import pytest

from tests.conftest import APACHE, CUSTOM_COPYLEFT, CUSTOM_OK, GPL3, MIT, load_module, warp


def _custom_answer():
    import json

    return json.dumps({
        "permissions": [
            {"id": "private_use", "quote": "You may use the software and modify it."},
            {"id": "modify", "quote": "You may use the software and modify it."},
            {"id": "distribute", "quote": "You may distribute copies and sell"},
            {"id": "commercial", "quote": "sell commercial builds"},
            {"id": "proprietary_embed", "quote": "proprietary applications without restriction"},
        ],
        "obligations": [{"id": "notice", "quote": "Keep the copyright notice in every copy."}],
    })


def test_mit_is_compatible_and_the_claim_is_not_trusted(guard):
    aid = guard.attest("left-pad", "proprietary-embed", 1, "GPL-3.0-only", "text", MIT)
    got = guard.get_attestation(aid)
    assert got["verdict"] == "compatible"
    assert got["identity"] == "MIT"
    assert got["claim_matches_identity"] is False
    assert "proprietary_embed" in got["permissions"]
    assert got["source_ref"] == "inline"
    assert got["evidence"]


def test_gpl_is_incompatible_and_conflict_abstains(guard):
    gpl = guard.attest("copyleft-tool", "proprietary-embed", 1, "GPL-3.0-only", "text", GPL3)
    clash = guard.attest("dual", "proprietary-embed", 1, "MIT", "text", MIT + "\n" + GPL3)
    assert guard.get_attestation(gpl)["verdict"] == "incompatible"
    assert guard.get_attestation(clash)["verdict"] == "inconclusive"
    assert guard.get_attestation(clash)["identity"] == "conflict"


def test_old_policy_version_stays_in_force(guard, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    guard.register_policy(
        "proprietary-embed",
        ["private_use"],
        [],
        ["notice", "attribution", "state_changes", "disclose_source", "same_license", "network_source", "trademark_restricted"],
        "*",
        False,
        "Version two only asks for private use",
    )
    assert guard.latest_policy_version("proprietary-embed") == 2
    assert guard.get_policy("proprietary-embed", 1)["require"] == [
        "private_use", "modify", "distribute", "commercial", "proprietary_embed"
    ]
    aid = guard.attest("left-pad", "proprietary-embed", 1, "MIT", "text", MIT)
    assert guard.get_attestation(aid)["policy_version"] == 1
    assert guard.get_attestation(aid)["verdict"] == "compatible"


def test_custom_grant_and_custom_copyleft(guard, direct_vm):
    direct_vm.mock_llm(r".*LICENSE_CLAUSE_EXTRACT.*", _custom_answer())
    ok = guard.attest("northwind", "custom-embed", 1, "", "text", CUSTOM_OK)
    assert guard.get_attestation(ok)["verdict"] == "compatible"
    assert guard.get_attestation(ok)["identity"] == "custom"

    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*LICENSE_CLAUSE_EXTRACT.*", """
        {"permissions":[{"id":"proprietary_embed","quote":"proprietary applications without restriction"}],
         "obligations":[{"id":"same_license","quote":"released under the same license"}]}
    """)
    bad = guard.attest("northwind-copy", "custom-embed", 1, "", "text", CUSTOM_COPYLEFT)
    got = guard.get_attestation(bad)
    assert got["verdict"] == "incompatible"
    assert "same_license" in got["obligations"]


def test_wildcard_policy_does_not_accept_an_unrecognized_text(guard, direct_vm):
    direct_vm.mock_llm(r".*LICENSE_CLAUSE_EXTRACT.*", _custom_answer())
    aid = guard.attest("northwind", "proprietary-embed", 1, "MIT", "text", CUSTOM_OK)
    got = guard.get_attestation(aid)
    assert got["identity"] == "custom"
    assert got["verdict"] == "inconclusive"


def test_url_fetch_and_truncation(guard, direct_vm):
    mod = load_module()
    direct_vm.mock_web(r".*example\.com/LICENSE.*", {"status": 200, "body": APACHE})
    aid = guard.attest(
        "httpd", "proprietary-embed", 1, "Apache-2.0", "url", "https://example.com/LICENSE"
    )
    got = guard.get_attestation(aid)
    assert got["verdict"] == "compatible"
    assert got["identity"] == "Apache-2.0"
    assert got["source_ref"] == "https://example.com/LICENSE"

    direct_vm.clear_mocks()
    direct_vm.mock_web(
        r".*example\.com/BIG.*",
        {"status": 200, "body": MIT + ("x" * mod.TEXT_CAP)},
    )
    aid = guard.attest("big", "proprietary-embed", 1, "MIT", "url", "https://example.com/BIG")
    assert guard.get_attestation(aid)["verdict"] == "inconclusive"
    assert "truncated" in guard.get_attestation(aid)["reasons"]


def test_down_url_does_not_write(guard, direct_vm):
    direct_vm.mock_web(r".*example\.com/MISSING.*", {"status": 503, "body": ""})
    with direct_vm.expect_revert("license text unavailable"):
        guard.attest("missing", "proprietary-embed", 1, "MIT", "url", "https://example.com/MISSING")
    assert guard.subject_attestations("missing") == []


def _hex(account) -> str:
    return account.as_hex if hasattr(account, "as_hex") else str(account)


def test_access_and_supersede(guard, direct_vm, direct_alice, direct_bob, direct_charlie):
    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("not a registrar"):
            guard.register_policy("bob-policy", ["private_use"], [], ["notice"], "MIT", False, "")
    who = _hex(direct_bob)
    direct_vm.sender = direct_alice
    guard.grant_registrar(who, True)
    assert guard.is_registrar(who) is True
    direct_vm.sender = direct_bob
    assert guard.register_policy("bob-policy", ["private_use"], [], ["notice"], "MIT", False, "bob") == 1
    direct_vm.sender = direct_alice
    guard.grant_registrar(_hex(direct_charlie), True)
    with direct_vm.prank(direct_charlie):
        with direct_vm.expect_revert("not the policy curator"):
            guard.register_policy("bob-policy", ["private_use"], [], ["notice"], "MIT", False, "nope")

    direct_vm.sender = direct_bob
    aid = guard.attest("left-pad", "proprietary-embed", 1, "MIT", "text", MIT)
    with direct_vm.prank(direct_charlie):
        with direct_vm.expect_revert("not the requester"):
            guard.supersede(aid)
    guard.supersede(aid)
    assert guard.get_attestation(aid)["superseded"] is True
    with direct_vm.expect_revert("no active attestation"):
        guard.latest_attestation("left-pad", "proprietary-embed")

    direct_vm.sender = direct_alice
    guard.set_registry_frozen(True)
    with direct_vm.expect_revert("registry is frozen"):
        guard.register_policy("after-freeze", ["private_use"], [], ["notice"], "MIT", False, "")
    guard.set_attestations_paused(True)
    with direct_vm.expect_revert("attestations are paused"):
        guard.attest("left-pad", "proprietary-embed", 1, "MIT", "text", MIT)


def test_subject_cap(guard):
    mod = load_module()
    for _ in range(mod.MAX_PER_SUBJECT):
        guard.attest("capped", "proprietary-embed", 1, "MIT", "text", MIT)
    with pytest.raises(Exception, match="subject attestation cap reached"):
        guard.attest("capped", "proprietary-embed", 1, "MIT", "text", MIT)


def test_inline_over_cap_is_rejected(guard):
    mod = load_module()
    with pytest.raises(Exception, match="exceeds"):
        guard.attest("huge", "proprietary-embed", 1, "MIT", "text", "M" * (mod.TEXT_CAP + 1))


def test_clock_is_stored(guard, direct_vm):
    warp(direct_vm, "2026-11-16T03:00:00Z")
    aid = guard.attest("left-pad", "proprietary-embed", 1, "MIT", "text", MIT)
    assert guard.get_attestation(aid)["ts"] > 0
