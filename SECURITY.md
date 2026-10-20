# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security defect.** A public issue names the
defect, the code that carries it and the shape of the attack, and that is
enough to weaponise before a patch exists.

Use one of these channels, in this order:

1. **GitHub Security Advisory** — the "Report a vulnerability" button on this
   repository. This is the intended intake: it is private between you and the
   maintainers until a fix ships.
2. **Email** — `security@jounit.org`.

Include: the affected crate and file, the version or commit, a description of
the impact, and a reproduction (a failing test is ideal — the repository's
`fuzz/` and `tests/vectors/` harnesses accept them directly).

### Encryption

`security@jounit.org` is currently served **without a published PGP key**. Until
a key is published here, encrypting the report is not possible, and the
maintainers acknowledge this as an open gap in the disclosure channel rather
than a settled part of it. Until a key exists:

- treat the GitHub Security Advisory channel as the confidential one;
- do not send a live exploit against a public network;
- ask for a key to be published if your report needs one.

## Disclosure window

| Severity | Meaning | Fix target | Disclosure |
|---|---|---|---|
| **Critical** | Chain-halting: an invalid block is accepted, or a consensus rule can be broken | Immediate, out of cycle | Coordinated, after a patch is published on the affected branch |
| **High** | Key compromise, forging of an authorization or a certificate, or theft of funds | 7 days | Coordinated, after the fix ships |
| **Medium** | A bounded denial of service, a resource limit that can be exhausted, or a bookkeeping defect that cannot move value | 30 days | Public on the fix date |
| **Low** | A hardening gap, an information leak with no key material, or a missing limit | Next release | Public on the fix date |

**Responsible disclosure window: 90 days.** If a fix is taking longer, tell us
before the window closes and we will agree a date with you. We will not pursue
an action against a reporter who stays inside the agreed window.

A report is a bug report, not an attack. Demonstrating the defect on a
`mini` or `testnet` network is fine; demonstrating it against a live network
with real value is not.

## What counts as a vulnerability

- Any path by which a node accepts a block or transaction that the
  specification forbids, or by which two nodes with the same valid history
  disagree on the resulting state.
- Any path by which value moves without the authority the protocol requires —
  including the node-local books (receipts, payments, credit, escrow,
  delegation), which must never be able to create spendable balance.
- Any path by which a private key, a wallet file, a validator key or a bearer
  token is disclosed, or by which an encrypted wallet file can be decrypted
  without the passphrase.
- Any path by which a policy, a credit line, a delegation chain or an escrow
  authorisation can be forged, replayed, or bypassed.
- Any unbounded resource consumption reachable from the network boundary (API,
  peer-to-peer frame, block or transaction decoding, storage recovery).
- Any failure to fail closed: a refusal that is silently converted into a
  permissive path, or a missing-state case that produces an empty set where a
  populated one was meant.

## What is out of scope

- A miner with more hash power than the honest majority: that is the
  documented security model of a proof-of-work chain, not a bug.
- A validator committee that exceeds two thirds of itself: that is the
  documented assumption behind quorum finality.
- An unchallenged but incorrect task result being paid. That is the documented
  optimistic settlement rule; the protocol distinguishes a quorum-backed
  certificate from an unchallenged one, and the weakness is structural and
  documented.
- Compile-time, dependency or linter findings with no reachable impact.
- Missing tests without an identified defect.

## Supported versions

The protocol is **pre-launch**. Security fixes land on `main` and on the
release branch of the current protocol version. There is no long-term-support
branch: the chain has not launched, so there is no deployed history to keep
compatible.

Any fix that changes a consensus rule, a serialization format or a fee
schedule is a **protocol version bump**: it changes the genesis hash, the
network magic and the state format, and it is announced as such in the release
notes before it ships.

## Scope of this policy

This policy covers the code in this repository: the protocol implementation, the
node, the worker SDK, the MCP surface, the fuzzing harnesses and the
simulation suite.

It does **not** cover a network operated by a third party, an exchange, a
custodian or a wallet provider, nor any service that reaches this code over
the network. Those are their own operators' responsibility. If a defect in
this repository is what makes a third-party service unsafe, report it here
anyway.
