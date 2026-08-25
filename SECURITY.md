<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

**English** · [Français](SECURITY.fr.md)

# Security Policy

## Scope

There is no implementation yet. At this stage, a security report means a **flaw
in the design**: a mechanism that fails against an adversary the threat model
does not cover, an invariant that does not hold, or a claim whose justification
is weaker than stated.

## Reporting

For findings that are **already listed as open** in the threat model, open a
public issue. They are known; discussion in the open is more useful than
private disclosure.

For findings that are **not** listed, please report privately first:

- Email: geri.freki99@gmail.com
- PGP: 6AD8 68F6 1B0C 4BC9 71CB F125 3779 5BC1 3B64 3F77

Please include: the mechanism affected, the assumptions you rely on, and the
sequence of events that produces the failure.

Expect an acknowledgement within 7 days.

## Disclosure

Since nothing is deployed and no funds are at risk, there is no embargo period
to protect. The default is to publish the finding and the remedy together, with
credit, once the remedy is understood. If you prefer not to be credited, say so.

If a finding turns out to affect a **third-party deployed system** rather than
Vanargand, it will not be published here; it will be reported to that project's
maintainers first.

## Out of scope

- Anything already documented as open in the threat model, reported as if new
- Attacks that assume more than the stated fault threshold without saying so
- Findings against the economic model that do not state their parameter
  assumptions

## No bug bounty

There is no bounty programme and no funding. A bounty is planned for the
pre-launch phase and does not exist today. Reports are accepted on that basis.
