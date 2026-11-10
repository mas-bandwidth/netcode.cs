# netcode.cs — status

_Last updated: 2026-11-10, at commit ec95e86 on `main`._

## Where the port stands

**Released: v1.1.0** (`src/Netcode.csproj`, release commit 2026-09-13). A
byte-exact C# port of [mas-bandwidth/netcode](https://github.com/mas-bandwidth/netcode)
(protocol "NETCODE 1.02"; interop is pinned to netcode 1.4.9), idiomatic over the
same non-blocking update-loop model. Changes since the release are in the git log.

### What is built

- **Library** (`src/`, 4 files): protocol core (`Netcode.cs`), client and server
  state machines (`Client.cs`, `Server.cs`, ported line-for-line from
  `netcode.c`), and the crypto (`Crypto.cs`). Targets `net8.0` + `net10.0`,
  warnings-as-errors, nullable enabled, no unsafe, zero third-party deps.
- **Crypto — fully managed, single production path.** XChaCha20-Poly1305
  (private connect token) + ChaCha20-Poly1305 IETF (challenge tokens, packets),
  hand-written ChaCha20/Poly1305/HChaCha20, no P/Invoke, no platform crypto.
  Rationale and the alternatives (BCL `ChaCha20Poly1305`, libsodium P/Invoke)
  are in `notes/port-map.md`.
- **Tests** (`tests/`): a console runner with 68 named tests in two tiers. The
  default run is the unit tier (59 tests): the C suite's tests ported
  test-for-test, plus seeded hostile fuzz over every parse path, two
  zero-allocation assertions, a managed-vs-BCL crypto differential and an
  FP-contraction canary. It opens no OS sockets, never sleeps, and uses an
  injected clock. `--functional` runs the functional tier (9 tests: client and
  server create, the three real UDP socket connects, the two port-in-use
  creates, packet tagging, and the socket zero-allocation check).
  `-- soak <n>` runs the bounded soak. The full list, and which C tests have no
  C# test of the same name, is in `notes/port-map.md`.
  - `dotnet run -c Release --project tests/Tests.csproj -f net10.0` (unit tier)
    passed on a Linux x64 bench (.NET SDK 10.0.401) at ec95e86.
- **Interop gate** (`compat/` + `scripts/interop.sh`): builds the REAL
  `netcode.c` + its vendored libsodium (with `-ffp-contract=off`) and runs four
  legs:
  1. golden byte identity: token and packet goldens byte-identical, both directions
  2. cross-verify: each side decrypts+parses the other's goldens
  3. live session: C server ← C# client, token minted by C#
  4. live session: C# server ← C client, token minted by C
- **CI** (`.github/workflows/ci.yml`), on pushes to `main` and `sprint/*` and on
  every pull request:
  - `test` on ubuntu-latest, macos-latest and windows-latest: build both TFMs, the unit tests
    and the functional tier on net10.0 and on the real .NET 8 runtime, `soak 2000`, and a build of the
    compat harness;
  - `C wire compatibility`: the interop gate against netcode pinned at
    `ced9b4b8…` (v1.4.9);
  - `STANDARD.md matches upstream`: the vendored spec is diffed against
    mas-bandwidth/netcode `main`.
- **License**: AGPL-3.0 (`LICENSE`), with the "move to MBSL when ready" note in
  the README.

## Gaps / what's next

- **Planned work** is recorded in `docs/roadmap.sexp` (`ROADMAP.md` is
  generated from it).
- **Post-release hardening** items from the 2026-08-07 review, and what the code
  does about each now, are in `notes/post-release-hardening.md`.
- **netstandard2.1 (Unity) target** is not attempted. `UInt128`/`InlineArray`/`u8`
  literals would need shims.
- **Windows packet tagging** (Qwave) is deliberately not ported; documented.

## Layout for someone reading cold

- `notes/port-map.md` — protocol objects → C# shapes, the crypto construction
  inventory + decision + alternatives, state machines, invariants, test inventory.
- `notes/red-team-brief.md` — attack surface, wire claims, how to run, known gaps
  (written 2026-08-07, before v1.0.0).
- `notes/post-release-hardening.md` — follow-ups from the 2026-08-07 review.
- `README.md` — the public front door + the deliberate-decisions list.
- `STANDARD.md` — the protocol standard, vendored verbatim from the C repo.
- `docs/roadmap.sexp` / `ROADMAP.md` — planned work.
