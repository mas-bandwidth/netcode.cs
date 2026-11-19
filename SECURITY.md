# Security Policy

netcode.cs implements an encrypted, connection-oriented protocol over UDP. It parses
untrusted data straight off the wire — packets, connect tokens, and the challenge exchange
— and it holds the keys, so we take memory-safety and protocol bugs seriously.

## Reporting a vulnerability

**Please do not report security issues in public GitHub issues or pull requests.**

Report privately through either channel:

- **GitHub private vulnerability reporting** (preferred): on this repository, go to the
  **Security** tab → **Report a vulnerability**. This opens a private advisory visible only
  to the maintainers.
- **Email**: glenn@mas-bandwidth.com.

Please include enough detail to reproduce: the affected version or commit, a description of
the flaw, and — where possible — a proof-of-concept input or a small patch.

We will acknowledge your report, keep you updated on our assessment, and coordinate
disclosure timing with you. We prefer coordinated disclosure and will credit reporters who
wish to be named.

## Scope

In scope — bugs in this repository: packet parsing, connect token handling, the challenge
exchange, replay protection (`src/Netcode.cs`, `src/Client.cs`, `src/Server.cs`), and the
managed XChaCha20-Poly1305, ChaCha20-Poly1305, and HChaCha20 constructions (`src/Crypto.cs`).

Especially of interest: unhandled exceptions or resource-exhaustion bugs reachable from a
received packet or connect token (hostile wire bytes must never throw), and protocol or
cryptographic flaws that let a peer bypass authentication, encryption, or replay protection.

The library is compiled with `<AllowUnsafeBlocks>false</AllowUnsafeBlocks>`, so unmanaged
memory corruption is off the table by construction; logic, state-machine, and cryptographic
flaws are the primary classes in scope.

The protocol itself is specified in `STANDARD.md`. **A flaw in the *specification* — as
opposed to this implementation of it — is in scope and is more valuable to us**, because it
affects every implementation of netcode rather than one. Report those the same way.

## Known issue: AEAD nonce reuse on unfinished handshakes and multi-server connect tokens (fixed in v1.2.0)

**Advisory: [GHSA-8mrq-q9c6-h23v](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-8mrq-q9c6-h23v)** (published 2026-11-19).

**Affected: v1.1.0 and earlier (`NETCODE 1.02`). Fixed in v1.2.0 (`NETCODE 1.03`).**

In `NETCODE 1.02`, packets encrypted directly under the 32-byte `ClientToServerKey` and
`ServerToClientKey` carried inside a connect token, which allowed two AEAD nonce-reuse
paths within a single connect token's lifetime:

1. **Retried unfinished handshakes.** If a client received a connection challenge and sent
   one or more connection response packets that were lost (or aborted the handshake before a
   client slot was assigned), the server's connect token history entry remained _pending_. If
   the caller reconnected with the same unexpired connect token, the client reset its packet
   sequence to zero and encrypted new connection response packets under the same
   `ClientToServerKey` at already-used nonces.
2. **Multi-server connect tokens.** When a connect token listed multiple dedicated servers,
   two freshly started servers shared the connect token's `ServerToClientKey` and both
   began their global packet sequence at `2^63` (e.g. a full first server sending a
   connection denied packet at `2^63` and the next server sending a connection challenge
   packet at `2^63`).

Fixed in **v1.2.0** (corresponding to C reference **1.5.0**) by upgrading the wire protocol
to **`NETCODE 1.03`**:

- Per-connection packet keys are derived via `HChaCha20(tokenKey, clientSalt || serverNonce)`
  from a fresh 8-byte client salt per attempt (`connection request`, now 1086 bytes) and a
  fresh 8-byte server nonce per server mapping or full-server denial (`connection denied` and
  `connection challenge` headers, bound into 30-byte AEAD associated data). Connect token root
  keys never encrypt packets directly.
- Pending connect token history entries bind the 8-byte client salt and expire as admissible
  after `timeout_seconds` from creation; valid `connection disconnect` packets on a half-open
  mapping consume the history entry and remove the mapping.

Thank you to [@magicaldave](https://github.com/magicaldave) ([DreamWeave-MP/dream-net](https://github.com/DreamWeave-MP/dream-net)) for discovering and privately reporting the unfinished-handshake connect-token reuse issue.

### If you are using an affected version

Upgrade to **v1.2.0** or later (`netcode` C **1.5.0** or later; `netcode.go` and `netcode.rs`
**1.2.0** or later; **yojimbo 1.16.0** or later). Because `NETCODE 1.03` changes the wire
protocol version string and handshake packet headers, clients, servers, and token-issuing
backends must be upgraded together.

## Known issue: connect token reuse after disconnect (fixed in v1.1.0)

**Advisory: [GHSA-v29p-3vj4-vg4f](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-v29p-3vj4-vg4f)** (published 2026-09-04).

**Affected: v1.0.0. Fixed in v1.1.0.**

A connect token that had already established a session could establish another one once that
client disconnected, and the second session encrypted under the same keys from a packet
sequence that started over, repeating AEAD nonces.

Fixed in **v1.1.0** (corresponding to C reference **1.4.5**), which spends a connect token
on the connection it admits and refuses connect tokens that could have been issued before
the server started (`ServerConfig.MaxConnectTokenLifetime`).

## Historical note: netcode.cs was NOT affected by the C 1.3.5 server-restart nonce reuse issue

`netcode.cs` **v1.0.0** was ported after `netcode` 1.4.0 and re-seeded `_globalSequence` to
`2^63` on every `Start()` from its initial release, so it was never affected by
[GHSA-3x95-24j9-7448](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-3x95-24j9-7448).

## Supported versions

Security fixes land on the latest release. We do not backport to older release lines.
