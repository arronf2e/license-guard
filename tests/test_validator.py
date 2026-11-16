"""Validator half of license consensus."""

import json

from tests.conftest import APACHE, CUSTOM_COPYLEFT, CUSTOM_OK, GPL3, MIT

URL = "https://example.com/LICENSE"


def _ok_answer():
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


def _attest_url(guard, vm, body):
    vm.mock_web(r".*example\.com/LICENSE.*", {"status": 200, "body": body})
    return guard.attest("pkg", "proprietary-embed", 1, "MIT", "url", URL)


def test_validator_agrees_on_the_same_license(guard, direct_vm):
    _attest_url(guard, direct_vm, MIT)
    assert direct_vm.run_validator() is True


def test_validator_rejects_a_license_that_changed(guard, direct_vm):
    _attest_url(guard, direct_vm, MIT)
    direct_vm.clear_mocks()
    direct_vm.mock_web(r".*example\.com/LICENSE.*", {"status": 200, "body": GPL3})
    assert direct_vm.run_validator() is False


def test_validator_rejects_a_forged_identity(guard, direct_vm):
    _attest_url(guard, direct_vm, GPL3)
    forged = {
        "identity": "MIT",
        "verdict": "compatible",
        "truncated": False,
        "evidence": [],
        "obls": ["notice"],
        "perms": ["proprietary_embed"],
    }
    assert direct_vm.run_validator(leader_result=forged) is False


def test_validator_rejects_a_phrase_that_is_not_in_the_text(guard, direct_vm):
    _attest_url(guard, direct_vm, MIT)
    forged = {
        "identity": "MIT",
        "verdict": "compatible",
        "truncated": False,
        "tag": "",
        "obls": ["notice"],
        "perms": ["private_use", "modify", "distribute", "commercial", "proprietary_embed"],
        "evidence": ["fp:MIT|this phrase is not in the mit text at all"],
    }
    assert direct_vm.run_validator(leader_result=forged) is False


def test_validator_disputes_a_false_outage(guard, direct_vm):
    _attest_url(guard, direct_vm, APACHE)
    assert direct_vm.run_validator(leader_error=Exception("license text unavailable")) is False


def test_validator_confirms_a_real_outage(guard, direct_vm):
    _attest_url(guard, direct_vm, APACHE)
    direct_vm.clear_mocks()
    direct_vm.mock_web(r".*example\.com/LICENSE.*", {"status": 503, "body": ""})
    assert direct_vm.run_validator(leader_error=Exception("license text unavailable")) is True


def test_validator_rejects_a_missed_copyleft_clause(guard, direct_vm):
    direct_vm.mock_llm(r".*LICENSE_CLAUSE_EXTRACT.*", _ok_answer())
    guard.attest("northwind", "custom-embed", 1, "", "text", CUSTOM_COPYLEFT)
    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*LICENSE_CLAUSE_EXTRACT.*", json.dumps({
        "permissions": [
            {"id": "proprietary_embed", "quote": "proprietary applications without restriction"},
        ],
        "obligations": [{"id": "same_license", "quote": "released under the same license"}],
    }))
    assert direct_vm.run_validator() is False


def test_validator_agrees_when_the_custom_reading_matches(guard, direct_vm):
    direct_vm.mock_llm(r".*LICENSE_CLAUSE_EXTRACT.*", _ok_answer())
    guard.attest("northwind", "custom-embed", 1, "", "text", CUSTOM_OK)
    assert direct_vm.run_validator() is True
