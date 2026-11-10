; netcode.cs roadmap: the data ROADMAP.md is generated from (nova-roadmap, a nova-tools release binary;
; make roadmap renders, make roadmap-check fails on drift). Read as data, never evaluated.
; A cell is done only when its task is :done with :evidence, a test or a commit;
; :tested-revision is the main commit whose CI passed with that evidence.
(:schema 1
 :root "goal"
 :page (:title "netcode.cs roadmap"
        :roadmaps ("connection" "security" "network" "dotnet" "compat" "testing"))
 :nodes
 ((:id "goal" :type :work-set :children ("connection" "security" "network" "dotnet" "compat" "testing"))
  (:id "connection" :type :roadmap :title "Connection"
   :text "Connect tokens, client slots, the handshake, keep-alive, disconnects and timeouts between a client and a server."
   :rows (("connect-tokens" "connect tokens issued by a web backend")
          ("handshake" "request, challenge and response handshake")
          ("slots" "client slots; a full server denies at once")
          ("many-clients" "many clients on one server")
          ("server-list" "fall through to the next server in the token")
          ("keep-alive" "keep-alive")
          ("disconnect-client" "clean disconnect from the client")
          ("disconnect-server" "clean disconnect from the server, with a reason")
          ("timeouts" "request, response and connection timeouts")
          ("bad-tokens" "expired and invalid connect tokens refused")
          ("reconnect" "reconnect with a new token")
          ("no-timeout" "timeouts can be disabled for debugging")
          ("loopback" "loopback clients inside the server process")
          ("missing-callbacks" "override and loopback modes refuse to start without their callbacks (netcode#191)")
          ("disconnect-callback" "the disconnect callback cannot re-enter a slot being cleared")
          ("socketless-address" "the client skips a server address it has no socket for"))
   :columns (("done" "done"))
   :cells (("connect-tokens" "done" "connection/connect-tokens")
           ("handshake" "done" "connection/handshake")
           ("slots" "done" "connection/slots")
           ("many-clients" "done" "connection/many-clients")
           ("server-list" "done" "connection/server-list")
           ("keep-alive" "done" "connection/keep-alive")
           ("disconnect-client" "done" "connection/disconnect-client")
           ("disconnect-server" "done" "connection/disconnect-server")
           ("timeouts" "done" "connection/timeouts")
           ("bad-tokens" "done" "connection/bad-tokens")
           ("reconnect" "done" "connection/reconnect")
           ("no-timeout" "done" "connection/no-timeout")
           ("loopback" "done" "connection/loopback")
           ("missing-callbacks" "done" "connection/missing-callbacks")
           ("disconnect-callback" "done" "connection/disconnect-callback")
           ("socketless-address" "done" "connection/socketless-address")))
  (:id "connection/connect-tokens" :type :task :title "connect tokens issued by a web backend" :state :done :evidence ("tests/Tests.cs: TestConnectToken" "tests/Tests.cs: TestConnectTokenPublic" "tests/Tests.cs: TestGenerateConnectTokenOutOfRange") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/handshake" :type :task :title "request, challenge and response handshake" :state :done :evidence ("tests/ClientServer.cs: TestClientServerConnect" "tests/Tests.cs: TestChallengeToken") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/slots" :type :task :title "client slots; a full server denies at once" :state :done :evidence ("tests/ClientServer.cs: TestClientErrorConnectionDenied") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/many-clients" :type :task :title "many clients on one server" :state :done :evidence ("tests/ClientServer.cs: TestClientServerMultipleClients") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/server-list" :type :task :title "fall through to the next server in the token" :state :done :evidence ("tests/ClientServer.cs: TestClientServerMultipleServers") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/keep-alive" :type :task :title "keep-alive" :state :done :evidence ("tests/ClientServer.cs: TestClientServerKeepAlive") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/disconnect-client" :type :task :title "clean disconnect from the client" :state :done :evidence ("tests/ClientServer.cs: TestClientSideDisconnect") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/disconnect-server" :type :task :title "clean disconnect from the server, with a reason" :state :done :evidence ("tests/ClientServer.cs: TestServerSideDisconnect" "tests/ClientServer.cs: TestServerClientDisconnectReason") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/timeouts" :type :task :title "request, response and connection timeouts" :state :done :evidence ("tests/ClientServer.cs: TestClientErrorConnectionRequestTimeout" "tests/ClientServer.cs: TestClientErrorConnectionResponseTimeout" "tests/ClientServer.cs: TestClientErrorConnectionTimedOut") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/bad-tokens" :type :task :title "expired and invalid connect tokens refused" :state :done :evidence ("tests/ClientServer.cs: TestClientErrorConnectTokenExpired" "tests/ClientServer.cs: TestClientErrorInvalidConnectToken") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/reconnect" :type :task :title "reconnect with a new token" :state :done :evidence ("tests/ClientServer.cs: TestClientReconnect") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/no-timeout" :type :task :title "timeouts can be disabled for debugging" :state :done :evidence ("tests/ClientServer.cs: TestDisableTimeout") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/loopback" :type :task :title "loopback clients inside the server process" :state :done :evidence ("tests/ClientServer.cs: TestLoopback") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "connection/missing-callbacks" :type :task :title "override and loopback modes refuse to start without their callbacks (netcode#191)" :state :done :evidence ("tests/ClientServer.cs: TestClientCreateMissingOverrideCallback" "tests/ClientServer.cs: TestServerCreateMissingOverrideCallback" "tests/ClientServer.cs: TestClientLoopbackRequiresCallback" "tests/ClientServer.cs: TestServerLoopbackRequiresCallback" "commit 1d19477 (Refuse override and loopback configs missing callbacks (netcode#191))") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8"
   :github-issue "7"
   :github-pr "8")
  (:id "connection/disconnect-callback" :type :task :title "the disconnect callback cannot re-enter a slot being cleared" :state :todo
   :note "On main, Server.DisconnectClientInternal calls the callback before the slot is cleared; a re-entrant disconnect throws or recurses. Landed on sprint/netcode-cs-port (commit 9befda5), not yet merged to main; done when it is on main with its test green."
   :sprint-card "cs-netcode-disconnect-callback-cannot-reenter-a-clearing-slot"
   :sprint-branch "sprint/netcode-cs-port"
   :landed-commit "9befda5")
  (:id "connection/socketless-address" :type :task :title "the client skips a server address it has no socket for" :state :todo
   :note "On main, Connect and ConnectToNextServer never skip an address whose family has no socket, and never set InvalidConnectToken. Landed on sprint/netcode-cs-port (commit e4fa521), not yet merged to main; done when it is on main with its test green."
   :sprint-card "cs-netcode-client-refuses-a-server-address-it-has-no-socket-for"
   :sprint-branch "sprint/netcode-cs-port"
   :landed-commit "e4fa521")
  (:id "security" :type :roadmap :title "Security"
   :text "Encrypted, signed packets and the protections against forged, replayed and malformed traffic."
   :rows (("aead" "encrypted and signed packets (ChaCha20-Poly1305)")
          ("private-token" "encrypted connect token private data (XChaCha20-Poly1305)")
          ("managed-crypto" "fully managed crypto, checked against the .NET built-in AEAD")
          ("replay" "replay protection")
          ("token-reuse" "a used connect token is refused (GHSA-v29p-3vj4-vg4f)")
          ("token-history" "a full token history refuses rather than forgets")
          ("token-predates" "a token created before the server started is refused")
          ("restart-nonce" "no nonce reuse across a server restart")
          ("malformed" "malformed packets, tokens and addresses ignored, never thrown, fuzzed")
          ("amplification" "amplification protection")
          ("own-challenge" "each connection response is bound to its own challenge")
          ("replay-top" "replay protection at the top of the sequence space")
          ("mapping-lifetime" "pre-connect mappings expire even for tokens without a timeout")
          ("shared-token-nonces" "servers sharing a connect token use distinct global packet nonces")
          ("zeroize-keys" "key material zeroized on disconnect and stop"))
   :columns (("done" "done"))
   :cells (("aead" "done" "security/aead")
           ("private-token" "done" "security/private-token")
           ("managed-crypto" "done" "security/managed-crypto")
           ("replay" "done" "security/replay")
           ("token-reuse" "done" "security/token-reuse")
           ("token-history" "done" "security/token-history")
           ("token-predates" "done" "security/token-predates")
           ("restart-nonce" "done" "security/restart-nonce")
           ("malformed" "done" "security/malformed")
           ("amplification" "done" "security/amplification")
           ("own-challenge" "done" "security/own-challenge")
           ("replay-top" "done" "security/replay-top")
           ("mapping-lifetime" "done" "security/mapping-lifetime")
           ("shared-token-nonces" "done" "security/shared-token-nonces")
           ("zeroize-keys" "done" "security/zeroize-keys")))
  (:id "security/aead" :type :task :title "encrypted and signed packets (ChaCha20-Poly1305)" :state :done :evidence ("tests/Tests.cs: TestConnectionPayloadPacket" "tests/Tests.cs: TestEncryptionManager" "tests/Tests.cs: TestCryptoAeadVectors") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "security/private-token" :type :task :title "encrypted connect token private data (XChaCha20-Poly1305)" :state :done :evidence ("tests/Tests.cs: TestConnectToken" "tests/Tests.cs: TestCryptoAeadVectors") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "security/managed-crypto" :type :task :title "fully managed crypto, checked against the .NET built-in AEAD" :state :done :evidence ("tests/Hostile.cs: TestCryptoDifferentialBcl" "tests/Tests.cs: TestCryptoAeadVectors") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "security/replay" :type :task :title "replay protection" :state :done :evidence ("tests/Tests.cs: TestReplayProtection") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "security/token-reuse" :type :task :title "a used connect token is refused (GHSA-v29p-3vj4-vg4f)" :state :done :evidence ("tests/ClientServer.cs: TestClientReconnectUsedConnectToken" "commit 2e0978c (Fix connect token reuse and restart handling)") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8"
   :github-issue "6"
   :github-pr "9")
  (:id "security/token-history" :type :task :title "a full token history refuses rather than forgets" :state :done :evidence ("tests/ClientServer.cs: TestConnectTokenHistory") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8"
   :github-issue "6")
  (:id "security/token-predates" :type :task :title "a token created before the server started is refused" :state :done :evidence ("tests/ClientServer.cs: TestClientErrorConnectTokenPredatesServerStart") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8"
   :github-issue "6")
  (:id "security/restart-nonce" :type :task :title "no nonce reuse across a server restart" :state :done :evidence ("tests/ClientServer.cs: TestServerRestartGlobalSequence") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "security/malformed" :type :task :title "malformed packets, tokens and addresses ignored, never thrown, fuzzed" :state :done :evidence ("tests/Hostile.cs: TestFuzzReadPacketRaw" "tests/Hostile.cs: TestFuzzPacketRoundTripCorruption" "tests/Hostile.cs: TestFuzzConnectToken" "tests/Hostile.cs: TestFuzzParseAddress") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "security/amplification" :type :task :title "amplification protection" :state :unknown
   :note "The connection request is larger than the challenge it draws (netcode 1.02), but no test here asserts that sizing; a test that a short request is dropped and that the challenge is smaller than the request makes this done.")
  (:id "security/own-challenge" :type :task :title "each connection response is bound to its own challenge" :state :todo
   :note "A response encrypted under token B could carry token A's challenge; the fix binds the challenge token AEAD to the mapping's connect token MAC. Landed on sprint/netcode-cs-port (commit 018b5f9), not yet merged to main; done when it is on main with its test green."
   :sprint-card "cs-netcode-connection-response-takes-only-its-own-mappings-challenge"
   :sprint-branch "sprint/netcode-cs-port"
   :landed-commit "018b5f9")
  (:id "security/replay-top" :type :task :title "replay protection at the top of the sequence space" :state :todo
   :note "AlreadyReceived should return true first when sequence == ulong.MaxValue. Landed on sprint/netcode-cs-port (commit 398e8c8), not yet merged to main; done when it is on main with its test green."
   :sprint-card "cs-netcode-replay-top-sequence-and-restart-floor-edges"
   :sprint-branch "sprint/netcode-cs-port"
   :landed-commit "398e8c8")
  (:id "security/mapping-lifetime" :type :task :title "pre-connect mappings expire even for tokens without a timeout" :state :todo
   :note "A pre-connect mapping lives timeoutSeconds, or PreconnectMappingSeconds (10) when the token timeout is not positive; over-long tokens are refused. Landed on sprint/netcode-cs-port (commit ae6a97a), not yet merged to main; done when it is on main with its test green."
   :sprint-card "cs-netcode-token-lifetimes-are-bounded"
   :sprint-branch "sprint/netcode-cs-port"
   :landed-commit "ae6a97a")
  (:id "security/shared-token-nonces" :type :task :title "servers sharing a connect token use distinct global packet nonces" :state :todo
   :note "Two servers in one token must not encrypt global packets under the same key and nonce. Landed on sprint/netcode-cs-port (commit 1c9e726), not yet merged to main; done when it is on main with its test green."
   :sprint-card "cs-netcode-global-packet-nonces-differ-between-servers-sharing-a-token"
   :sprint-branch "sprint/netcode-cs-port"
   :landed-commit "1c9e726")
  (:id "security/zeroize-keys" :type :task :title "key material zeroized on disconnect and stop" :state :todo
   :note "Post-release hardening item 1 (notes/post-release-hardening.md): EncryptionManager send/receive keys, the challenge key and the connect token private data linger on the GC heap.")
  (:id "network" :type :roadmap :title "Networking"
   :text "Sockets, address families, platforms and the tools for testing under bad networks."
   :rows (("ipv4" "IPv4")
          ("ipv6" "IPv6")
          ("dual-stack" "dual-stack server (IPv4 and IPv6 at once)")
          ("addresses" "address parsing and formatting")
          ("tagging" "packet tagging (DSCP) on unix and macOS")
          ("simulator" "network simulator: latency, jitter, loss, duplicates")
          ("receive-drain" "receive drains skip empty datagrams and stop at a cap")
          ("linux-macos" "Linux and macOS")
          ("windows" "Windows")
          ("socket-review" "socket layer reviewed line by line against the C"))
   :columns (("done" "done"))
   :cells (("ipv4" "done" "network/ipv4")
           ("ipv6" "done" "network/ipv6")
           ("dual-stack" "done" "network/dual-stack")
           ("addresses" "done" "network/addresses")
           ("tagging" "done" "network/tagging")
           ("simulator" "done" "network/simulator")
           ("receive-drain" "done" "network/receive-drain")
           ("linux-macos" "done" "network/linux-macos")
           ("windows" "done" "network/windows")
           ("socket-review" "done" "network/socket-review")))
  (:id "network/ipv4" :type :task :title "IPv4" :state :done :evidence ("tests/ClientServer.cs: TestClientServerIpv4SocketConnect") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "network/ipv6" :type :task :title "IPv6" :state :done :evidence ("tests/ClientServer.cs: TestClientServerIpv6SocketConnect") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "network/dual-stack" :type :task :title "dual-stack server (IPv4 and IPv6 at once)" :state :done :evidence ("tests/ClientServer.cs: TestClientServerDualSocketConnect") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "network/addresses" :type :task :title "address parsing and formatting" :state :done :evidence ("tests/Tests.cs: TestAddress" "tests/Hostile.cs: TestFuzzParseAddress") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "network/tagging" :type :task :title "packet tagging (DSCP) on unix and macOS" :state :unknown
   :note "EnablePacketTagging exists on ClientConfig and ServerConfig, but no test connects with it on; a client/server test with tagging enabled makes this done. Windows (Qwave) tagging is deliberately not ported.")
  (:id "network/simulator" :type :task :title "network simulator: latency, jitter, loss, duplicates" :state :done :evidence ("tests/Tests.cs: TestNetworkSimulatorDeterminism") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "network/receive-drain" :type :task :title "receive drains skip empty datagrams and stop at a cap" :state :todo
   :note "Match the C receive loop: an empty datagram does not end the drain, and each drain is capped. Landed on sprint/netcode-cs-port (commit 44a3110), not yet merged to main; done when it is on main with its test green."
   :sprint-card "cs-netcode-receive-drain-skips-empty-datagrams-and-stops-at-a-cap"
   :sprint-branch "sprint/netcode-cs-port"
   :landed-commit "44a3110")
  (:id "network/linux-macos" :type :task :title "Linux and macOS" :state :done :evidence (".github/workflows/ci.yml: test job, matrix ubuntu-latest, macos-latest, green on c1fcf5a") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "network/windows" :type :task :title "Windows" :state :todo
   :note "No Windows leg in CI; the socket layer is exercised only on Linux and macOS (STATUS.md). A windows-latest leg in the test job makes this done.")
  (:id "network/socket-review" :type :task :title "socket layer reviewed line by line against the C" :state :todo
   :note "Post-release hardening item 2 (notes/post-release-hardening.md): NetcodeSocket, the simulator and the loopback paths were not line-diffed against netcode.c.")
  (:id "dotnet" :type :roadmap :title ".NET"
   :text "The runtimes the library targets and the properties it keeps on them."
   :rows (("net10" ".NET 10")
          ("net8" ".NET 8 (LTS)")
          ("zero-alloc" "zero allocation on the steady-state packet paths")
          ("fp-contract" "no fused multiply-add in the network arithmetic")
          ("unity" "Unity (netstandard2.1)" :later t))
   :columns (("done" "done"))
   :cells (("net10" "done" "dotnet/net10")
           ("net8" "done" "dotnet/net8")
           ("zero-alloc" "done" "dotnet/zero-alloc")
           ("fp-contract" "done" "dotnet/fp-contract")
           ("unity" "done" "dotnet/unity")))
  (:id "dotnet/net10" :type :task :title ".NET 10" :state :done :evidence (".github/workflows/ci.yml: test job, Tests (net10.0)") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "dotnet/net8" :type :task :title ".NET 8 (LTS)" :state :done :evidence (".github/workflows/ci.yml: test job, Tests (net8.0, the LTS leg)" "commit 1941d8a (Re-arm SocketAddress.Size before every ReceiveFrom: the net8.0 leg is whole again (#1))") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "dotnet/zero-alloc" :type :task :title "zero allocation on the steady-state packet paths" :state :done :evidence ("tests/Hostile.cs: TestZeroAllocationSteadyState") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "dotnet/fp-contract" :type :task :title "no fused multiply-add in the network arithmetic" :state :done :evidence ("tests/Tests.cs: FloatMultiplyAddRoundsTwice" "commit dba7ce9 (interop: build C with -ffp-contract=off, add FP canary and README note)") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "dotnet/unity" :type :task :title "Unity (netstandard2.1)" :state :todo
   :note "Not attempted: UInt128, InlineArray and u8 literals would need shims (STATUS.md).")
  (:id "compat" :type :roadmap :title "Compatibility"
   :text "Wire compatibility with the C reference implementation and the netcode 1.02 standard."
   :rows (("standard" "netcode 1.02 standard, kept in sync with upstream")
          ("golden-vectors" "every token and packet type byte-identical to C, both directions")
          ("c-interop" "live sessions with the C client and server, both directions")
          ("packets" "every packet type reads and writes as the C suite expects")
          ("version" "tracks the C reference release (1.4.8)"))
   :columns (("done" "done"))
   :cells (("standard" "done" "compat/standard")
           ("golden-vectors" "done" "compat/golden-vectors")
           ("c-interop" "done" "compat/c-interop")
           ("packets" "done" "compat/packets")
           ("version" "done" "compat/version")))
  (:id "compat/standard" :type :task :title "netcode 1.02 standard, kept in sync with upstream" :state :done :evidence (".github/workflows/ci.yml: spec-sync job (STANDARD.md matches upstream)") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "compat/golden-vectors" :type :task :title "every token and packet type byte-identical to C, both directions" :state :done :evidence (".github/workflows/ci.yml: c-interop job, scripts/interop.sh leg 1 (golden byte identity) and leg 2 (cross verify)") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "compat/c-interop" :type :task :title "live sessions with the C client and server, both directions" :state :done :evidence (".github/workflows/ci.yml: c-interop job, scripts/interop.sh legs 3 and 4 (live sessions)") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "compat/packets" :type :task :title "every packet type reads and writes as the C suite expects" :state :done :evidence ("tests/Tests.cs: TestConnectionRequestPacket" "tests/Tests.cs: TestEmptyPacket" "tests/Tests.cs: TestChallengeResponsePacket" "tests/Tests.cs: TestConnectionKeepAlivePacket" "tests/Tests.cs: TestConnectionPayloadPacket") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "compat/version" :type :task :title "tracks the C reference release (1.4.8)" :state :done :evidence ("commit 194f150 (release: netcode.cs 1.1.0)" "commit fc235d2 (Pin C interop to the reviewed security release API)") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "testing" :type :roadmap :title "Testing"
   :text "How the implementation is checked on every change."
   :rows (("c-suite" "test-for-test port of the C test suite")
          ("soak" "soak test"))
   :columns (("done" "done"))
   :cells (("c-suite" "done" "testing/c-suite")
           ("soak" "done" "testing/soak")))
  (:id "testing/c-suite" :type :task :title "test-for-test port of the C test suite" :state :done :evidence ("tests/Tests.cs: TestQueue" "tests/Tests.cs: TestSequence" "tests/ClientServer.cs: TestClientCreate" "tests/ClientServer.cs: TestServerCreate") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")
  (:id "testing/soak" :type :task :title "soak test" :state :done :evidence (".github/workflows/ci.yml: test job, Soak (bounded), soak 2000") :tested-revision "c1fcf5a17adc91b02bb70a88b49519bd3de154a8")))
