# license-guard

LicenseGuard is a GenLayer intelligent contract that attests whether a supplied license text satisfies a versioned compatibility policy.

The policy is ordinary data: required permissions, forbidden obligations, obligations the policy is willing to accept, and an SPDX target. Recognized licenses never take their permissions from a model. A fixed phrase profile identifies MIT, Apache-2.0, the BSD and ISC forms, Unlicense, MPL-2.0, and the GPL family, and that profile is what the gate evaluates. A model is used only when the text matches none of those profiles. Every clause the model reports has to be a verbatim quote that also contains an anchor for that clause. The stored verdict is recomputed from the grounded reading after consensus, so a leader cannot submit a verdict the gates do not produce.

This is an attestation about the text that was submitted. It is not legal advice, and it does not establish that the text is the license of a named package.

Deployed on GenLayer Studio (studionet):
[`0x9bda6728b13f2cDce3562bBCCF9330c962571ba2`](https://explorer-studio.genlayer.com/address/0x9bda6728b13f2cDce3562bBCCF9330c962571ba2).
The deploying account is `0xEf047a1fEbD27E18CA8EF7Ab2C1f3f91B0d733a3`. Transaction hashes are in `deploy/address.json`.

## Consensus

`attest` runs in `gl.vm.run_nondet_unsafe`.

The leader loads the text (the transaction argument, or `gl.nondet.web.get` for an https URL) and builds a reading:

1. Normalize quotes, case, and whitespace.
2. If the normalized text is at least 280 characters, test the phrase profiles. Zero hits means `custom`. Two or more hits means `conflict`.
3. An SPDX tag in the text is recorded and is not trusted. `MIT OR Apache-2.0` is stored as `expression`.
4. For a unique profile, permissions and obligations come from the table in the contract. The model is not called.
5. For a long enough custom text, `gl.nondet.exec_prompt` extracts clauses. A clause is kept only when its quote is in the text, is 12–200 characters, is not an instruction aimed at the model, and contains an anchor that is not negated earlier in the quote. `same_license` additionally needs copyleft language, not the bare words "this license".
6. `evaluate` applies the policy. Possible verdicts are `compatible`, `incompatible`, and `inconclusive`.

A validator loads the text again and accepts the leader only when all of the following hold:

- The identity, the truncation flag, and the verdict match the validator's own reading.
- The obligation sets match. A missed copyleft clause is not inside a tolerance band.
- The required permissions match.
- Every fingerprint phrase or clause quote the leader listed is present in the text the validator read.
- If the leader reports that the URL is unavailable, the validator agrees only when its own fetch also fails.

After the validators accept, the contract runs `evaluate` again on the agreed payload and reverts if the stored verdict would not match. For a recognized identity, the table profile overwrites any permissions the payload listed.

`truncated` never yields `compatible`. A recognized license can still be `incompatible` when a forbidden obligation is already in the portion that was read.

## State

```text
owner                  deploying account
registry_frozen        bool
attestations_paused    bool
registrars             TreeMap[Address, u8]     owner is always a registrar
curators               TreeMap[str, Address]    first publisher of a policy id
heads                  TreeMap[str, u32]        latest version
policies               TreeMap["id:version", Policy]
policy_ids             DynArray[str]            cap 64
attestations           TreeMap[str, Attestation]
by_subject             TreeMap[str, DynArray[str]]   cap 8 ids per subject
next_id                u64
```

Policy versions are immutable. Publishing again writes version N+1 and leaves version N readable. Only the curator or the owner can publish a later version.

An attestation stores the revision tag, a 160-character excerpt, the identity, the verdict, the reasons, permission and obligation masks, and the evidence lines. It does not store the full license. `supersede` flips a flag; it does not edit the verdict. `latest_attestation` skips superseded rows.

The revision tag is FNV-1a 64 of the normalized text. It is a correlation id for this submission, not a cryptographic commitment.

## Access

| action | who |
|---|---|
| `grant_registrar`, `set_registry_frozen`, `set_attestations_paused` | owner |
| `register_policy` | owner or a registrar, and only the curator or the owner may publish version 2+ |
| `attest` | anyone, unless attestations are paused |
| `supersede` | the requester or the owner |

Freezing the registry stops new policy versions. It does not stop attestations against versions that already exist.

## Usage

Contract runtime header:

```text
py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6
```

That is the runner hash in the official GenLayer intelligent-contract docs at the time this contract was written. Client packages are pinned separately below.

Constructor: none.

```text
LicenseGuard()
```

The deploying account is `owner`.

```bash
genlayer deploy --contract contracts/license_guard.py
```

```javascript
await client.deployContract({
  code,          // contents of contracts/license_guard.py
  args: [],
});
```

`node deploy/deploy.mjs` prints this plan and does not broadcast. Broadcasting requires `GENLAYER_DEPLOY=1` and an operator-supplied `PRIVATE_KEY`. The script does not generate a key.

### Demo writes

Replace `ADDRESS` with the studionet address in `deploy/address.json`.

```bash
genlayer write ADDRESS register_policy --args \
  proprietary-embed \
  '["private_use","modify","distribute","commercial","proprietary_embed"]' \
  '["disclose_source","same_license","network_source"]' \
  '["notice","attribution","state_changes","trademark_restricted"]' \
  "*" false \
  "Closed-source distribution, standard texts only"

genlayer write ADDRESS register_policy --args \
  custom-embed \
  '["private_use","modify","distribute","commercial","proprietary_embed"]' \
  '["disclose_source","same_license","network_source"]' \
  '["notice","attribution","state_changes","trademark_restricted"]' \
  custom false \
  "Same gates for an unrecognized text"

genlayer write ADDRESS attest --args \
  left-pad proprietary-embed 1 MIT text "$(cat /path/to/LICENSE)"

genlayer write ADDRESS attest --args \
  httpd proprietary-embed 1 Apache-2.0 url https://example.com/LICENSE
```

`proprietary-embed` accepts any single recognized license whose table profile contains those permissions and does not contain those obligations. MIT and Apache-2.0 pass. GPL-3.0-only and AGPL-3.0-only fail. A text that hits two profiles is `inconclusive`. An unrecognized text is `inconclusive` on this policy; use `custom-embed` when the text is bespoke.

### Demo reads

```bash
genlayer call ADDRESS get_attestation --args 1
genlayer call ADDRESS latest_attestation --args left-pad proprietary-embed
genlayer call ADDRESS get_policy --args proprietary-embed 1
genlayer call ADDRESS config
```

```javascript
await client.readContract({ address, functionName: "get_attestation", args: [1] });
await client.readContract({
  address,
  functionName: "latest_attestation",
  args: ["left-pad", "proprietary-embed"],
});
await client.writeContract({
  address,
  functionName: "attest",
  args: ["left-pad", "proprietary-embed", 1, "MIT", "text", licenseText],
});
```

`source_kind` is `text` or `url`. Inline text longer than 36,000 characters is rejected. A URL body longer than that is truncated and cannot come back `compatible`.

## Recognized profiles

The gate uses these identities. `proprietary_embed` is intentionally false for MPL, LGPL, GPL, and AGPL. LGPL linking is not treated as a proprietary embed. GPL-2.0 has no patent bit; GPL-3.0, AGPL-3.0, Apache-2.0, MPL-2.0, and LGPL-3.0 do. AGPL-3.0 adds `network_source`.

| identity | proprietary_embed | patent | copyleft obligations |
|---|---|---|---|
| MIT, BSD-2-Clause, BSD-3-Clause, ISC, Unlicense | yes | no | notice, except Unlicense |
| Apache-2.0 | yes | yes | notice, state_changes, trademark_restricted |
| MPL-2.0, LGPL-3.0-only | no | yes | notice, disclose_source, same_license |
| GPL-2.0-only | no | no | notice, state_changes, disclose_source, same_license |
| GPL-3.0-only | no | yes | notice, state_changes, disclose_source, same_license |
| AGPL-3.0-only | no | yes | those, plus network_source |

Phrase lists live in `fingerprint` in `contracts/license_guard.py`. A full GPL-3 mentions the Affero GPL in section 13, so the AGPL profile also requires the remote-network heading and is tested before GPL-3.

## Development

Python 3.12 or newer.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

genvm-lint check contracts/license_guard.py
pytest -q
```

Pinned packages:

| package | version |
|---|---|
| contract runtime | `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` |
| genlayer-test | 0.29.2 |
| genlayer-py | 0.16.3 |
| genvm-linter | 0.11.0 |
| pytest | 8.3.5 |
| genlayer-js (deploy helper only) | 1.1.8 |

`genlayer-test` 0.29.2 requires `genlayer-py>=0.13,<0.17`. 0.16.3 is the last release inside that range. Prereleases `genlayer-test` 0.30.0rc2 and `genvm-linter` 0.11.1rc2 were not used. `genlayer-py` here is the client and test package. The contract itself runs on the `py-genlayer` runner named in its first line.

Direct-mode tests mock `gl.nondet.web.get` and `gl.nondet.exec_prompt`. They do not start GenLayer Studio and they do not run a multi-validator network.

`genlayer-test` 0.29.2 fetches a release asset named `genvm-universal.tar.xz`. Tag `v0.3.0-rc7`, which is the bundle that contains this contract's runner hash, publishes that archive as `genvm-runners-all.tar.xz` instead. `tests/runtime_cache.py` copies the file already downloaded by `genvm-lint`, or downloads the runners archive, into the cache directory gltest reads. `pytest` does that before the first deploy. `genvm-lint check` also reports that runner `1zr6nqk597d97kg0dyxg0shhrykx5v02zjgnyrajapy4wlqvfvwh` is newer than the hash above. The hash above is the one in the current docs example and the one these direct-mode tests load.

- `tests/test_policy.py` covers phrase identity, conflict, truncation, tags, anchors, and negation.
- `tests/test_attest.py` covers the policy registry, attestations, URL fetch, the subject cap, and access control.
- `tests/test_validator.py` covers agreement, a changed page, a forged identity, a phrase that is not in the text, a false outage, and a validator that finds a copyleft quote the leader omitted.

## Limitations

- The phrase table is a slice of SPDX, not the SPDX license list. Anything else is `custom` or, if two profiles hit, `conflict`.
- A text that quotes the required sentences and is long enough is identified as that license. The contract does not prove the text is complete or that it belongs to `subject`.
- Dual-licensed files are `inconclusive`. Submit one license text, or publish a policy aimed at the single text you mean.
- Custom `compatible` depends on the model quoting the obligations that are actually present. Validators reject a leader when their own extraction disagrees. They do not invent a clause that every node missed.
- Anchor checks reject ungrounded and off-topic quotes. They are not a parser for nested legal exceptions.
- URL fetches trust HTTPS at the GenVM boundary. The contract rejects credentials, non-443 ports, and IP literals. It does not authenticate the host as the upstream project.
- The stored excerpt and FNV revision are not enough to reconstruct the license, and the revision is not collision-resistant.
- Direct-mode tests mock web and model calls and do not start a multi-validator network. The studionet transactions listed in `deploy/address.json` are live Studio consensus, not those mocks.

## License

MIT
