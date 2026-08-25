<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

**English** · [Français](CONTRIBUTING.fr.md)

# Contributing to Vanargand

The project is at the design stage. The most valuable contribution right now is
**a correct argument that something here does not work** — a mechanism that
breaks under an adversary the threat model does not cover, an invariant that
fails, a claim that is stronger than its justification.

## Before you open a pull request

Read [`README.md`](README.md), and in particular the *Open problems* table. If
your finding is already listed there as open, it is known; an issue is still
welcome if you have a remedy.

## Sign-off (DCO)

This project uses the **Developer Certificate of Origin 1.1** — see
[`DCO`](DCO). There is no Contributor License Agreement.

Every commit must carry a `Signed-off-by` line matching the author:

```
Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` adds it automatically. To fix a missing sign-off on the last
commit:

```
git commit --amend -s --no-edit
```

By signing off, you certify the statements in `DCO` and agree your contribution
is made under this project's licenses.

## Licensing of contributions

| You contribute to | Your contribution is licensed under |
|---|---|
| Code | `MIT OR Apache-2.0` |
| Documents, specifications | `CC-BY-4.0` |
| Test vectors | `CC0-1.0` |

This follows Apache-2.0 §5: contributions intentionally submitted for inclusion
are made under the same terms unless you state otherwise explicitly.

**Note on relicensing.** Because there is no CLA, the project cannot be
relicensed once external contributions are merged without the agreement of
every contributor. This is intentional.

## Code standards

These are not yet enforced by CI because there is no code. They are recorded
now because retrofitting them is expensive.

### Determinism is mandatory in state-transition code

Every state transition must be provable and reproducible. Any divergence
between two honest nodes is a consensus failure.

- **No `HashMap` / `HashSet` in state code.** Their iteration order is
  randomised by default in Rust and will cause honest nodes to diverge. Use
  `BTreeMap` / `BTreeSet`, or `IndexMap` where insertion order is the
  intended semantics.
- **No floating point** (`f32`, `f64`) anywhere state-affecting. Enforce by
  lint.
- **No wall-clock time.** The only clock is block height.
- **No dependence on allocation addresses, thread scheduling, or iterator
  order over unordered collections.**
- Every state transition must be replayable: given the same blocks in any
  arrival order, the same state root.

### Canonical encoding is frozen

Serialisation, address derivation, tree hashing convention, and the transaction
envelope cannot change after genesis. Changes to these require a new
specification version and are reviewed as breaking.

### Cryptography

All cryptographic primitives are accessed through the abstraction in
`vanargand-crypto`. Do not call a primitive directly from elsewhere. Every protocol
object carries a version byte.

## Commit messages

```
component: short imperative summary

Body explaining why, not what. Reference the specification section or
threat-model identifier where relevant (for example: "addresses C9").

Signed-off-by: Jane Doe <jane@example.com>
```

## Verify the DCO text

The copy of the DCO in this repository should match the canonical text at
<https://developercertificate.org/>. If it does not, the canonical version
governs — please open an issue.
