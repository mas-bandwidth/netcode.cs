# netcode.cs — status

_Last updated: 2026-08-07, end of the blue-team build session._

## Where the port stands

**Blue-team build complete and green.** A byte-exact C# port of
[mas-bandwidth/netcode](https://github.com/mas-bandwidth/netcode) (protocol
"NETCODE 1.02"), idiomatic over the same non-blocking update-loop model. Every
gate below was run and passed on this machine (Apple Silicon, .NET SDK 10.0.302,
Apple clang 21) before this commit.

### What is built and verified

- **Library** (`src/`, 4 files): protocol core (`Netcode.cs`), client and server
  state machines (`Client.cs`, `Server.cs`, ported line-for-line from
  `netcode.c`), and the crypto (`Crypto.cs`). Targets `net8.0` + `net10.0`,
  warnings-as-errors, nullable enabled, no unsafe, zero third-party deps.
- **Crypto decision — fully managed, single production path.** XChaCha20-Poly1305
  (private connect token) + ChaCha20-Poly1305 IETF (challenge tokens, packets),
  hand-written ChaCha20/Poly1305/HChaCha20, no P/Invoke, no platform crypto.
  Rationale and the alternatives (BCL `ChaCha20Poly1305`, libsodium P/Invoke)
  are in `notes/port-map.md`.
- **Tests** (`tests/`): test-for-test port of the C suite (46 tests) + seeded
  hostile fuzz over every parse path + a zero-allocation assertion + a
  managed-vs-BCL crypto differential + a bounded soak.
  - `dotnet run --project tests/Tests.csproj -f net10.0` → **all pass**
  - net8.0 leg (via `DOTNET_ROLL_FORWARD=LatestMajor`) → **all pass**
  - `-- soak 5000` → **passed** (508 connects, ~65k payloads each way)
- **Interop gate** (`compat/` + `scripts/interop.sh`): builds the REAL
  `netcode.c` + its vendored libsodium and runs four legs — all **passed**:
  1. 10/10 token & packet goldens byte-identical, both directions
  2. cross-verify: each side decrypts+parses the other's goldens
  3. live session: C server ← C# client, token minted by C#
  4. live session: C# server ← C client, token minted by C
  Command run: `scripts/interop.sh ~/rowan-working/netcode` → `INTEROP GATE PASSED`
- **CI** (`.github/workflows/ci.yml`): mirrors serialize.cs (two TFMs,
  warnings-as-errors, both test legs, soak) + a `c-interop` job pinned to
  netcode ref `12d25754…` + a STANDARD.md drift check. **Not yet observed
  running on GitHub** (see below).
- **License**: AGPL-3.0 (`LICENSE`), with the "move to MBSL when ready" note in
  the README.

## Honest gaps / what's next

- **CI has not been observed green on GitHub yet.** It is written and mirrors the
  family pattern, but this session only ran the gates locally. First push should
  be watched. The `c-interop` job clones `mas-bandwidth/netcode` at the pinned
  ref; if that ref is not reachable/públic the pin must be updated.
- **Red team owns the next pass.** `notes/red-team-brief.md` is written cold (no
  design rationale) and lists the attack surface with the crypto first, plus a
  "known gaps" section pointing at: XChaCha has no BCL differential oracle
  (pinned only by one KAT + the interop gate); address parsing is not
  cross-checked byte-for-byte against the C parser; interop live sessions are
  single-client/single-payload/clean-disconnect; the socket layer is only
  exercised on Linux/macOS.
- **netstandard2.1 (Unity) target** is not attempted (serialize.cs lists it as an
  open deliverable too). `UInt128`/`InlineArray`/`u8` literals would need shims.
- **Windows packet tagging** (Qwave) is deliberately not ported; documented.

## Layout for someone reading cold

- `notes/port-map.md` — protocol objects → C# shapes, the crypto construction
  inventory + decision + alternatives, state machines, invariants, test inventory.
- `notes/red-team-brief.md` — attack surface, wire claims, how to run, known gaps.
- `README.md` — the public front door + the deliberate-decisions list.
- `STANDARD.md` — the protocol standard, vendored verbatim from the C repo.
