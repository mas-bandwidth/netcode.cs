/*
    Tests.cs

    Console test runner for the C# netcode port. Zero third-party dependencies,
    including test frameworks (family value): each test prints its name, a failed
    check prints and exits nonzero — the exact shape of check / RUN_TEST in the C
    reference implementation.

    The suite is a test-for-test port of the C suite in netcode.c (minus
    test_endian, irrelevant with explicit little endian primitives, and the
    assert-hook machinery, which does not exist in C#), plus hostile fuzz tests
    over every parse path, a zero-allocation assertion on the steady-state packet
    paths, and a differential test of the managed crypto against the BCL's
    ChaCha20Poly1305 where the platform supports it (Hostile.cs).
*/

using System;
using System.Runtime.CompilerServices;

namespace Netcode.Tests;

internal static class Check
{
    public static void That(bool condition, [CallerFilePath] string file = "", [CallerLineNumber] int line = 0, [CallerArgumentExpression(nameof(condition))] string expr = "")
    {
        if (!condition)
        {
            Console.WriteLine($"check failed: ( {expr} ), {file}:{line}");
            Environment.Exit(1);
        }
    }
}

internal static class TestConstants
{
    public const ulong TestProtocolId = 0x1122334455667788UL;
    public const ulong TestClientId = 0x1UL;
    public const int TestServerPort = 40000;
    public const int TestConnectTokenExpiry = 30;
    public const int TestTimeoutSeconds = 15;

    // TEST KEY ONLY — same fixed key as the C reference test suite. Obviously
    // non-production: it is published in two public repositories.
    public static readonly byte[] PrivateKey =
    {
        0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
        0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
        0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
        0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
    };
}

// deterministic xorshift64* rng for seeded "random" test data (never the CSPRNG:
// hostile tests must reproduce exactly from the printed seed)
internal sealed class TestRng
{
    private ulong _state;

    public TestRng(ulong seed) => _state = seed != 0 ? seed : 1;

    public ulong NextUInt64()
    {
        ulong x = _state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        _state = x;
        return unchecked(x * 0x2545F4914F6CDD1DUL);
    }

    public int Next(int maxExclusive) => (int)(NextUInt64() % (ulong)maxExclusive);

    public void Fill(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)NextUInt64();
    }
}

internal static class Program
{
    private static string? _filter;

    private static void RunTest(string name, Action test)
    {
        if (_filter != null && !name.Contains(_filter, StringComparison.OrdinalIgnoreCase))
            return;
        Console.WriteLine(name);
        test();
    }

    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "soak")
        {
            int iterations = args.Length > 1 ? int.Parse(args[1]) : 1000;
            return Soak.Run(iterations);
        }

        if (args.Length > 0)
            _filter = args[0];

        Console.WriteLine("[netcode.cs tests]\n");

        RunTest("test_crypto_aead_vectors", CoreTests.TestCryptoAeadVectors);
        RunTest("test_crypto_differential_bcl", Hostile.TestCryptoDifferentialBcl);
        RunTest("test_queue", CoreTests.TestQueue);
        RunTest("test_sequence", CoreTests.TestSequence);
        RunTest("test_address", CoreTests.TestAddress);
        RunTest("test_connect_token", CoreTests.TestConnectToken);
        RunTest("test_generate_connect_token_out_of_range", CoreTests.TestGenerateConnectTokenOutOfRange);
        RunTest("test_challenge_token", CoreTests.TestChallengeToken);
        RunTest("test_connection_request_packet", CoreTests.TestConnectionRequestPacket);
        RunTest("test_connection_denied_packet", () => CoreTests.TestEmptyPacket(PacketType.ConnectionDenied));
        RunTest("test_connection_challenge_packet", () => CoreTests.TestChallengeResponsePacket(PacketType.ConnectionChallenge));
        RunTest("test_connection_response_packet", () => CoreTests.TestChallengeResponsePacket(PacketType.ConnectionResponse));
        RunTest("test_connection_keep_alive_packet", CoreTests.TestConnectionKeepAlivePacket);
        RunTest("test_connection_payload_packet", CoreTests.TestConnectionPayloadPacket);
        RunTest("test_connection_disconnect_packet", () => CoreTests.TestEmptyPacket(PacketType.ConnectionDisconnect));
        RunTest("test_connect_token_public", CoreTests.TestConnectTokenPublic);
        RunTest("test_encryption_manager", CoreTests.TestEncryptionManager);
        RunTest("test_replay_protection", CoreTests.TestReplayProtection);
        RunTest("test_network_simulator_determinism", CoreTests.TestNetworkSimulatorDeterminism);
        RunTest("test_client_create", ClientServerTests.TestClientCreate);
        RunTest("test_server_create", ClientServerTests.TestServerCreate);
        RunTest("test_server_restart_global_sequence", ClientServerTests.TestServerRestartGlobalSequence);
        RunTest("test_connect_token_history", ClientServerTests.TestConnectTokenHistory);
        RunTest("test_client_reconnect_used_connect_token", ClientServerTests.TestClientReconnectUsedConnectToken);
        RunTest("test_client_error_connect_token_predates_server_start", ClientServerTests.TestClientErrorConnectTokenPredatesServerStart);
        RunTest("test_client_server_connect", ClientServerTests.TestClientServerConnect);
        RunTest("test_client_server_ipv4_socket_connect", ClientServerTests.TestClientServerIpv4SocketConnect);
        RunTest("test_client_server_ipv6_socket_connect", ClientServerTests.TestClientServerIpv6SocketConnect);
        RunTest("test_client_server_dual_socket_connect", ClientServerTests.TestClientServerDualSocketConnect);
        RunTest("test_client_server_keep_alive", ClientServerTests.TestClientServerKeepAlive);
        RunTest("test_client_server_multiple_clients", ClientServerTests.TestClientServerMultipleClients);
        RunTest("test_client_server_multiple_servers", ClientServerTests.TestClientServerMultipleServers);
        RunTest("test_client_error_connect_token_expired", ClientServerTests.TestClientErrorConnectTokenExpired);
        RunTest("test_client_error_invalid_connect_token", ClientServerTests.TestClientErrorInvalidConnectToken);
        RunTest("test_client_error_connection_timed_out", ClientServerTests.TestClientErrorConnectionTimedOut);
        RunTest("test_client_error_connection_response_timeout", ClientServerTests.TestClientErrorConnectionResponseTimeout);
        RunTest("test_client_error_connection_request_timeout", ClientServerTests.TestClientErrorConnectionRequestTimeout);
        RunTest("test_client_error_connection_denied", ClientServerTests.TestClientErrorConnectionDenied);
        RunTest("test_client_side_disconnect", ClientServerTests.TestClientSideDisconnect);
        RunTest("test_server_side_disconnect", ClientServerTests.TestServerSideDisconnect);
        RunTest("test_server_client_disconnect_reason", ClientServerTests.TestServerClientDisconnectReason);
        RunTest("test_client_reconnect", ClientServerTests.TestClientReconnect);
        RunTest("test_disable_timeout", ClientServerTests.TestDisableTimeout);
        RunTest("test_loopback", ClientServerTests.TestLoopback);
        RunTest("test_client_create_missing_override_callback", ClientServerTests.TestClientCreateMissingOverrideCallback);
        RunTest("test_server_create_missing_override_callback", ClientServerTests.TestServerCreateMissingOverrideCallback);
        RunTest("test_client_loopback_requires_callback", ClientServerTests.TestClientLoopbackRequiresCallback);
        RunTest("test_server_loopback_requires_callback", ClientServerTests.TestServerLoopbackRequiresCallback);
        RunTest("test_fuzz_read_packet_raw", Hostile.TestFuzzReadPacketRaw);
        RunTest("test_fuzz_packet_round_trip_corruption", Hostile.TestFuzzPacketRoundTripCorruption);
        RunTest("test_fuzz_connect_token", Hostile.TestFuzzConnectToken);
        RunTest("test_fuzz_parse_address", Hostile.TestFuzzParseAddress);
        RunTest("test_zero_allocation_steady_state", Hostile.TestZeroAllocationSteadyState);

        Console.WriteLine("\nAll tests passed.");
        return 0;
    }
}

internal static class CoreTests
{
    public static void TestCryptoAeadVectors()
    {
        // Known-answer test pinned to the same golden bytes as netcode.c's
        // test_crypto_aead_vectors (generated from libsodium reference output).
        // A golden failure here means the managed crypto no longer agrees with
        // libsodium, which would break wire compatibility with every other
        // netcode implementation.

        byte[] katKey =
        {
            0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
            0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
            0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
        };
        byte[] katAd = { 0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb };
        byte[] katMsg =
        {
            0x79,0x6f,0x6a,0x69,0x6d,0x62,0x6f,0x20,0x76,0x65,0x6e,0x64,0x6f,0x72,0x65,0x64,0x20,0x6c,0x69,0x62,
            0x73,0x6f,0x64,0x69,0x75,0x6d,0x20,0x41,0x45,0x41,0x44,0x20,0x6b,0x6e,0x6f,0x77,0x6e,0x2d,0x61,0x6e,
            0x73,0x77,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,0x76,0x65,0x63,0x74,0x6f,0x72,0x21,0x21,
        };
        byte[] katNpubIetf = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab };
        byte[] katCtIetf =
        {
            0xd5,0xae,0xb1,0x85,0x15,0x8b,0x07,0xb3,0x01,0x15,0xf0,0x59,
            0xb4,0x4e,0x9d,0x45,0x91,0x58,0xab,0xff,0xaf,0xbd,0x81,0x4f,
            0xbf,0x52,0xc2,0x4c,0xa1,0x5e,0x60,0x5f,0x58,0x63,0x31,0x96,
            0xda,0x90,0x07,0x63,0xb9,0x0c,0x21,0x46,0xf2,0xe4,0x65,0x96,
            0x7a,0x81,0x7f,0xa2,0x5d,0xd1,0x79,0xf6,0x9b,0x18,0x5d,0xe0,
            0xb6,0x57,0x93,0xbe,0x8c,0xb5,0xa9,0x75,0x98,0xa4,0x6f,0xd5,
            0xbe,0x9d,
        };
        byte[] katNpubXChaCha =
        {
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
            0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        };
        byte[] katCtXChaCha =
        {
            0x2b,0x24,0x83,0x2a,0x6c,0x9e,0x21,0x02,0x2a,0x14,0x32,0x56,
            0x4b,0x27,0x37,0x92,0x24,0x40,0xa9,0x92,0xd3,0x53,0xa7,0xa5,
            0x64,0xd3,0x8e,0x0c,0x75,0x79,0x75,0x3f,0xca,0x82,0xfa,0x85,
            0xf0,0xa6,0xac,0x08,0x9a,0x25,0xf1,0x8f,0x42,0x20,0x70,0x8e,
            0x38,0x25,0xd1,0x08,0x45,0x81,0x75,0x18,0xe4,0xd1,0x88,0xbd,
            0x92,0xfa,0x84,0xdc,0xd6,0xa3,0x9a,0x67,0x52,0x91,0x62,0xf4,
            0x86,0x7b,
        };

        // ChaCha20-Poly1305 (IETF) — the construction netcode uses on the wire

        byte[] buffer = new byte[128];
        katMsg.CopyTo(buffer, 0);
        Aead.EncryptIetf(buffer, katMsg.Length, katAd, katNpubIetf, katKey);
        Check.That(buffer.AsSpan(0, katCtIetf.Length).SequenceEqual(katCtIetf));

        Check.That(Aead.DecryptIetf(buffer, katCtIetf.Length, katAd, katNpubIetf, katKey));
        Check.That(buffer.AsSpan(0, katMsg.Length).SequenceEqual(katMsg));

        // a tampered ciphertext must be rejected, and the buffer must be untouched
        // (plaintext must not be produced before authentication has completed)

        katMsg.CopyTo(buffer, 0);
        Aead.EncryptIetf(buffer, katMsg.Length, katAd, katNpubIetf, katKey);
        buffer[0] ^= 0x01;
        byte[] tampered = (byte[])buffer.Clone();
        Check.That(!Aead.DecryptIetf(buffer, katCtIetf.Length, katAd, katNpubIetf, katKey));
        Check.That(buffer.AsSpan().SequenceEqual(tampered));

        // XChaCha20-Poly1305

        Array.Clear(buffer);
        katMsg.CopyTo(buffer, 0);
        Aead.EncryptX(buffer, katMsg.Length, katAd, katNpubXChaCha, katKey);
        Check.That(buffer.AsSpan(0, katCtXChaCha.Length).SequenceEqual(katCtXChaCha));

        Check.That(Aead.DecryptX(buffer, katCtXChaCha.Length, katAd, katNpubXChaCha, katKey));
        Check.That(buffer.AsSpan(0, katMsg.Length).SequenceEqual(katMsg));

        katMsg.CopyTo(buffer, 0);
        Aead.EncryptX(buffer, katMsg.Length, katAd, katNpubXChaCha, katKey);
        buffer[0] ^= 0x01;
        Check.That(!Aead.DecryptX(buffer, katCtXChaCha.Length, katAd, katNpubXChaCha, katKey));

        // a tampered tag (not just ciphertext) must also be rejected

        katMsg.CopyTo(buffer, 0);
        Aead.EncryptIetf(buffer, katMsg.Length, katAd, katNpubIetf, katKey);
        buffer[katCtIetf.Length - 1] ^= 0x80;
        Check.That(!Aead.DecryptIetf(buffer, katCtIetf.Length, katAd, katNpubIetf, katKey));
    }

    public static void TestQueue()
    {
        var queue = new PacketQueue();

        Check.That(queue.Count == 0);

        // attempting to pop a packet off an empty queue should fail

        Span<byte> popped = stackalloc byte[Protocol.MaxPacketSize];
        Check.That(queue.Pop(popped, out _) == -1);

        // add some packets to the queue and make sure they pop off in the correct order

        var rng = new TestRng(0x1234);
        const int NumPackets = 100;
        byte[] payload = new byte[Protocol.MaxPacketSize];

        for (int i = 0; i < NumPackets; i++)
        {
            payload.AsSpan().Fill((byte)i);
            Check.That(queue.Push(payload.AsSpan(0, 1 + i * 3 % Protocol.MaxPacketSize), (ulong)i));
        }

        Check.That(queue.Count == NumPackets);

        for (int i = 0; i < NumPackets; i++)
        {
            int length = queue.Pop(popped, out ulong sequence);
            Check.That(sequence == (ulong)i);
            Check.That(length == 1 + i * 3 % Protocol.MaxPacketSize);
            for (int j = 0; j < length; j++)
                Check.That(popped[j] == (byte)i);
        }

        // after all entries are popped off, the queue is empty again

        Check.That(queue.Count == 0);
        Check.That(queue.Pop(popped, out _) == -1);

        // test that the packet queue can be filled to max capacity

        for (int i = 0; i < 256; i++)
        {
            payload.AsSpan().Fill((byte)i);
            Check.That(queue.Push(payload.AsSpan(0, 256), (ulong)i));
        }

        Check.That(queue.Count == 256);

        // when the queue is full, attempting to push a packet should fail

        Check.That(!queue.Push(payload.AsSpan(0, 100), 0));

        // make sure all packets pop off in the correct order

        for (int i = 0; i < 256; i++)
        {
            int length = queue.Pop(popped, out ulong sequence);
            Check.That(sequence == (ulong)i);
            Check.That(length == 256);
            for (int j = 0; j < length; j++)
                Check.That(popped[j] == (byte)i);
        }

        // add some packets again, clear, and the queue must be empty

        for (int i = 0; i < 256; i++)
            Check.That(queue.Push(payload.AsSpan(0, 64), (ulong)i));

        queue.Clear();

        Check.That(queue.Count == 0);
        Check.That(queue.Pop(popped, out _) == -1);

        _ = rng;
    }

    public static void TestSequence()
    {
        Check.That(PacketIO.SequenceNumberBytesRequired(0) == 1);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x11) == 1);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x1122) == 2);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x112233) == 3);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x11223344) == 4);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x1122334455) == 5);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x112233445566) == 6);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x11223344556677) == 7);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x1122334455667788) == 8);
    }

    public static void TestAddress()
    {
        Check.That(!Address.TryParse("", out _));
        Check.That(!Address.TryParse("[", out _));
        Check.That(!Address.TryParse("[]", out _));
        Check.That(!Address.TryParse("[]:", out _));
        Check.That(!Address.TryParse(":", out _));
        Check.That(!Address.TryParse("1", out _));
        Check.That(!Address.TryParse("12", out _));
        Check.That(!Address.TryParse("123", out _));
        Check.That(!Address.TryParse("1234", out _));
        Check.That(!Address.TryParse("1234.0.12313.0000", out _));
        Check.That(!Address.TryParse("1234.0.12313.0000.0.0.0.0.0", out _));
        Check.That(!Address.TryParse("1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", out _));
        Check.That(!Address.TryParse(".", out _));
        Check.That(!Address.TryParse("..", out _));
        Check.That(!Address.TryParse("...", out _));
        Check.That(!Address.TryParse("....", out _));
        Check.That(!Address.TryParse(".....", out _));

        // ports must be all digits in [0,65535]. out of range and non-numeric ports must not silently truncate

        {
            Check.That(Address.TryParse("127.0.0.1:65535", out Address address));
            Check.That(address.Type == AddressType.IPv4);
            Check.That(address.Port == 65535);
            Check.That(Address.TryParse("[::1]:65535", out address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 65535);
            Check.That(!Address.TryParse("127.0.0.1:65536", out _));
            Check.That(!Address.TryParse("127.0.0.1:99999", out _));
            Check.That(!Address.TryParse("127.0.0.1:", out _));
            Check.That(!Address.TryParse("127.0.0.1:40k", out _));
            Check.That(!Address.TryParse("[::1]:65536", out _));
            Check.That(!Address.TryParse("[::1]:", out _));
            Check.That(!Address.TryParse("[::1]:40k", out _));
        }

        {
            Check.That(Address.TryParse("107.77.207.77", out Address address));
            Check.That(address.Type == AddressType.IPv4);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv4(0) == 107 && address.GetIPv4(1) == 77 && address.GetIPv4(2) == 207 && address.GetIPv4(3) == 77);
        }

        {
            Check.That(Address.TryParse("127.0.0.1", out Address address));
            Check.That(address.Type == AddressType.IPv4);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv4(0) == 127 && address.GetIPv4(1) == 0 && address.GetIPv4(2) == 0 && address.GetIPv4(3) == 1);
        }

        {
            Check.That(Address.TryParse("107.77.207.77:40000", out Address address));
            Check.That(address.Type == AddressType.IPv4);
            Check.That(address.Port == 40000);
            Check.That(address.GetIPv4(0) == 107 && address.GetIPv4(1) == 77 && address.GetIPv4(2) == 207 && address.GetIPv4(3) == 77);
        }

        {
            Check.That(Address.TryParse("fe80::202:b3ff:fe1e:8329", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv6(0) == 0xfe80);
            Check.That(address.GetIPv6(1) == 0x0000);
            Check.That(address.GetIPv6(2) == 0x0000);
            Check.That(address.GetIPv6(3) == 0x0000);
            Check.That(address.GetIPv6(4) == 0x0202);
            Check.That(address.GetIPv6(5) == 0xb3ff);
            Check.That(address.GetIPv6(6) == 0xfe1e);
            Check.That(address.GetIPv6(7) == 0x8329);
        }

        {
            Check.That(Address.TryParse("::", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            for (int i = 0; i < 8; i++)
                Check.That(address.GetIPv6(i) == 0);
        }

        {
            Check.That(Address.TryParse("::1", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            for (int i = 0; i < 7; i++)
                Check.That(address.GetIPv6(i) == 0);
            Check.That(address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("::0", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            for (int i = 0; i < 8; i++)
                Check.That(address.GetIPv6(i) == 0);
        }

        {
            Check.That(Address.TryParse("[::1]", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("[::0]", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv6(7) == 0);
        }

        {
            Check.That(Address.TryParse("[fe80::1]", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv6(0) == 0xfe80 && address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("[fe80::202:b3ff:fe1e:8329]:40000", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 40000);
            Check.That(address.GetIPv6(0) == 0xfe80);
            Check.That(address.GetIPv6(4) == 0x0202);
            Check.That(address.GetIPv6(5) == 0xb3ff);
            Check.That(address.GetIPv6(6) == 0xfe1e);
            Check.That(address.GetIPv6(7) == 0x8329);
        }

        {
            Check.That(Address.TryParse("[::]:40000", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 40000);
            for (int i = 0; i < 8; i++)
                Check.That(address.GetIPv6(i) == 0);
        }

        {
            Check.That(Address.TryParse("[::1]:5", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 5);
            Check.That(address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("[fe80::1]:5", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 5);
            Check.That(address.GetIPv6(0) == 0xfe80 && address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("[::1]:40000", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 40000);
            Check.That(address.GetIPv6(7) == 1);
        }

        // to-string round trips (C# addition: the C library formats the same way)

        Check.That(Address.Parse("107.77.207.77:40000").ToString() == "107.77.207.77:40000");
        Check.That(Address.Parse("127.0.0.1").ToString() == "127.0.0.1");
        Check.That(Address.Parse("[fe80::202:b3ff:fe1e:8329]:40000").ToString() == "[fe80::202:b3ff:fe1e:8329]:40000");
        Check.That(Address.Parse("::1").ToString() == "::1");
        Check.That(default(Address).ToString() == "NONE");
    }

    private static Address TestServerAddress()
    {
        Address address = default;
        address.SetIPv4(127, 0, 0, 1);
        address.Port = TestConstants.TestServerPort;
        return address;
    }

    public static void TestConnectToken()
    {
        // generate a connect token

        Address serverAddress = TestServerAddress();

        byte[] userData = new byte[Protocol.UserDataBytes];
        new TestRng(0xAA55).Fill(userData);

        var inputToken = new ConnectTokenPrivate();
        Span<Address> addresses = stackalloc Address[1] { serverAddress };
        inputToken.Generate(TestConstants.TestClientId, TestConstants.TestTimeoutSeconds, addresses, userData);

        Check.That(inputToken.ClientId == TestConstants.TestClientId);
        Check.That(inputToken.NumServerAddresses == 1);
        Check.That(inputToken.UserData.AsSpan().SequenceEqual(userData));
        Check.That(inputToken.ServerAddresses[0].Equals(serverAddress));

        // write it to a buffer

        byte[] buffer = new byte[Defines.ConnectTokenPrivateBytes];
        inputToken.Write(buffer);

        // encrypt the buffer

        ulong expireTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30;
        byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
        Rng.GenerateNonce(nonce);
        byte[] key = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(key);

        Check.That(ConnectTokenPrivate.Encrypt(buffer, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, key));

        // decrypt the buffer

        Check.That(ConnectTokenPrivate.Decrypt(buffer, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, key));

        // read the connect token back in and verify everything matches

        var outputToken = new ConnectTokenPrivate();
        Check.That(outputToken.Read(buffer));

        Check.That(outputToken.ClientId == inputToken.ClientId);
        Check.That(outputToken.TimeoutSeconds == inputToken.TimeoutSeconds);
        Check.That(outputToken.NumServerAddresses == inputToken.NumServerAddresses);
        Check.That(outputToken.ServerAddresses[0].Equals(inputToken.ServerAddresses[0]));
        Check.That(outputToken.ClientToServerKey.AsSpan().SequenceEqual(inputToken.ClientToServerKey));
        Check.That(outputToken.ServerToClientKey.AsSpan().SequenceEqual(inputToken.ServerToClientKey));
        Check.That(outputToken.UserData.AsSpan().SequenceEqual(inputToken.UserData));
    }

    public static void TestGenerateConnectTokenOutOfRange()
    {
        // netcode_generate_connect_token guards num_server_addresses with a runtime
        // check (upstream fix; the parse arrays are sized MaxServersPerConnect).
        // In C# the equivalent guard must reject empty and oversized address lists.

        byte[] connectToken = new byte[Protocol.ConnectTokenBytes];
        byte[] userData = new byte[Protocol.UserDataBytes];

        string[] none = Array.Empty<string>();
        Check.That(!ConnectTokenGenerator.Generate(none, none, 30, 5, 1000UL, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken));

        string[] tooMany = new string[Protocol.MaxServersPerConnect + 1];
        Array.Fill(tooMany, "127.0.0.1:40000");
        Check.That(!ConnectTokenGenerator.Generate(tooMany, tooMany, 30, 5, 1000UL, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken));

        // and an in-range call still succeeds, so the guard cannot pass by rejecting everything

        string[] one = { "127.0.0.1:40000" };
        Check.That(ConnectTokenGenerator.Generate(one, one, 30, 5, 1000UL, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken));
    }

    public static void TestChallengeToken()
    {
        // generate a challenge token

        var inputToken = new ChallengeToken();
        inputToken.ClientId = TestConstants.TestClientId;
        new TestRng(0x77).Fill(inputToken.UserData);

        // write it to a buffer

        byte[] buffer = new byte[Defines.ChallengeTokenBytes];
        inputToken.Write(buffer);

        // encrypt the buffer

        ulong sequence = 1000;
        byte[] key = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(key);

        ChallengeToken.Encrypt(buffer, sequence, key);

        // decrypt the buffer

        Check.That(ChallengeToken.Decrypt(buffer, sequence, key));

        // read the challenge token back in and verify everything matches

        var outputToken = new ChallengeToken();
        Check.That(outputToken.Read(buffer));

        Check.That(outputToken.ClientId == inputToken.ClientId);
        Check.That(outputToken.UserData.AsSpan().SequenceEqual(inputToken.UserData));
    }

    private static readonly bool[] AllAllowed = CreateAllAllowed();

    private static bool[] CreateAllAllowed()
    {
        var allowed = new bool[PacketType.NumPackets];
        Array.Fill(allowed, true);
        return allowed;
    }

    public static void TestConnectionRequestPacket()
    {
        // generate a private connect token and write it (non-encrypted copy kept for verification)

        Address serverAddress = TestServerAddress();

        byte[] userData = new byte[Protocol.UserDataBytes];
        new TestRng(0x99).Fill(userData);

        var inputToken = new ConnectTokenPrivate();
        Span<Address> addresses = stackalloc Address[1] { serverAddress };
        inputToken.Generate(TestConstants.TestClientId, TestConstants.TestTimeoutSeconds, addresses, userData);

        byte[] connectTokenData = new byte[Defines.ConnectTokenPrivateBytes];
        inputToken.Write(connectTokenData);

        byte[] encryptedConnectTokenData = (byte[])connectTokenData.Clone();

        ulong expireTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30;
        byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
        Rng.GenerateNonce(nonce);
        byte[] key = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(key);

        Check.That(ConnectTokenPrivate.Encrypt(encryptedConnectTokenData, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, key));

        // write a connection request packet wrapping the encrypted connect token

        byte[] buffer = new byte[2048];
        int bytesWritten = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, encryptedConnectTokenData);

        Check.That(bytesWritten == PacketIO.ConnectionRequestPacketBytes);

        // read the packet back in (the connect token data is decrypted as part of the read)

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, new byte[Protocol.KeyBytes],
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: true, key,
            AllAllowed, null);

        Check.That(result.Type == PacketType.ConnectionRequest);
        Check.That(result.DataLength == Defines.ConnectTokenPrivateBytes);
        Check.That(buffer.AsSpan(result.DataOffset, Defines.ConnectTokenPrivateBytes - Protocol.MacBytes)
            .SequenceEqual(connectTokenData.AsSpan(0, Defines.ConnectTokenPrivateBytes - Protocol.MacBytes)));

        var outputToken = new ConnectTokenPrivate();
        Check.That(outputToken.Read(buffer.AsSpan(result.DataOffset, result.DataLength)));
        Check.That(outputToken.ClientId == TestConstants.TestClientId);
    }

    public static void TestEmptyPacket(int packetType)
    {
        // denied and disconnect packets: no data, encrypted

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int bytesWritten = PacketIO.WriteEncryptedPacket(buffer, packetType, ReadOnlySpan<byte>.Empty, 1000, packetKey, TestConstants.TestProtocolId);
        Check.That(bytesWritten > 0);

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);

        Check.That(result.Type == packetType);
        Check.That(result.Sequence == 1000);
        Check.That(result.DataLength == 0);
    }

    public static void TestChallengeResponsePacket(int packetType)
    {
        // challenge and response packets: challenge token sequence + 300 bytes of token data

        byte[] packetData = new byte[8 + Defines.ChallengeTokenBytes];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(packetData.AsSpan(0, 8), 0);
        new TestRng(0x1EE7).Fill(packetData.AsSpan(8));

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int bytesWritten = PacketIO.WriteEncryptedPacket(buffer, packetType, packetData, 1000, packetKey, TestConstants.TestProtocolId);
        Check.That(bytesWritten > 0);

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);

        Check.That(result.Type == packetType);
        Check.That(result.Sequence == 1000);
        Check.That(result.DataLength == 8 + Defines.ChallengeTokenBytes);
        Check.That(buffer.AsSpan(result.DataOffset, result.DataLength).SequenceEqual(packetData));
    }

    public static void TestConnectionKeepAlivePacket()
    {
        byte[] packetData = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(packetData.AsSpan(0, 4), 10); // client index
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(packetData.AsSpan(4, 4), 16); // max clients

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int bytesWritten = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionKeepAlive, packetData, 1000, packetKey, TestConstants.TestProtocolId);
        Check.That(bytesWritten > 0);

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);

        Check.That(result.Type == PacketType.ConnectionKeepAlive);
        Check.That(result.DataLength == 8);
        Check.That(buffer.AsSpan(result.DataOffset, 8).SequenceEqual(packetData));
    }

    public static void TestConnectionPayloadPacket()
    {
        byte[] payload = new byte[Defines.MaxPayloadBytes];
        new TestRng(0xF00D).Fill(payload);

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int bytesWritten = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionPayload, payload, 1000, packetKey, TestConstants.TestProtocolId);
        Check.That(bytesWritten > 0);

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);

        Check.That(result.Type == PacketType.ConnectionPayload);
        Check.That(result.DataLength == Defines.MaxPayloadBytes);
        Check.That(buffer.AsSpan(result.DataOffset, result.DataLength).SequenceEqual(payload));
    }

    public static void TestConnectTokenPublic()
    {
        // generate a private connect token, encrypt it, wrap a public connect token around it

        Address serverAddress = TestServerAddress();

        byte[] userData = new byte[Protocol.UserDataBytes];
        new TestRng(0xABCD).Fill(userData);

        var connectTokenPrivate = new ConnectTokenPrivate();
        Span<Address> addresses = stackalloc Address[1] { serverAddress };
        connectTokenPrivate.Generate(TestConstants.TestClientId, TestConstants.TestTimeoutSeconds, addresses, userData);

        byte[] connectTokenPrivateData = new byte[Defines.ConnectTokenPrivateBytes];
        connectTokenPrivate.Write(connectTokenPrivateData);

        ulong createTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        ulong expireTimestamp = createTimestamp + 30;
        byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
        Rng.GenerateNonce(nonce);
        byte[] key = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(key);
        Check.That(ConnectTokenPrivate.Encrypt(connectTokenPrivateData, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, key));

        var inputConnectToken = new ConnectTokenData();
        Defines.VersionInfo.CopyTo(inputConnectToken.VersionInfo);
        inputConnectToken.ProtocolId = TestConstants.TestProtocolId;
        inputConnectToken.CreateTimestamp = createTimestamp;
        inputConnectToken.ExpireTimestamp = expireTimestamp;
        nonce.CopyTo(inputConnectToken.Nonce, 0);
        connectTokenPrivateData.CopyTo(inputConnectToken.PrivateData, 0);
        inputConnectToken.NumServerAddresses = 1;
        inputConnectToken.ServerAddresses[0] = serverAddress;
        connectTokenPrivate.ClientToServerKey.CopyTo(inputConnectToken.ClientToServerKey, 0);
        connectTokenPrivate.ServerToClientKey.CopyTo(inputConnectToken.ServerToClientKey, 0);
        inputConnectToken.TimeoutSeconds = TestConstants.TestTimeoutSeconds;

        // write the connect token to a buffer, read it back in, verify it matches

        byte[] buffer = new byte[Protocol.ConnectTokenBytes];
        inputConnectToken.Write(buffer);

        var outputConnectToken = new ConnectTokenData();
        Check.That(outputConnectToken.Read(buffer));

        Check.That(outputConnectToken.VersionInfo.AsSpan().SequenceEqual(inputConnectToken.VersionInfo));
        Check.That(outputConnectToken.ProtocolId == inputConnectToken.ProtocolId);
        Check.That(outputConnectToken.CreateTimestamp == inputConnectToken.CreateTimestamp);
        Check.That(outputConnectToken.ExpireTimestamp == inputConnectToken.ExpireTimestamp);
        Check.That(outputConnectToken.Nonce.AsSpan().SequenceEqual(inputConnectToken.Nonce));
        Check.That(outputConnectToken.PrivateData.AsSpan().SequenceEqual(inputConnectToken.PrivateData));
        Check.That(outputConnectToken.NumServerAddresses == inputConnectToken.NumServerAddresses);
        Check.That(outputConnectToken.ServerAddresses[0].Equals(inputConnectToken.ServerAddresses[0]));
        Check.That(outputConnectToken.ClientToServerKey.AsSpan().SequenceEqual(inputConnectToken.ClientToServerKey));
        Check.That(outputConnectToken.ServerToClientKey.AsSpan().SequenceEqual(inputConnectToken.ServerToClientKey));
        Check.That(outputConnectToken.TimeoutSeconds == inputConnectToken.TimeoutSeconds);
    }

    public static void TestEncryptionManager()
    {
        var encryptionManager = new EncryptionManager();

        double time = 100.0;

        // generate some test encryption mappings

        const int NumEncryptionMappings = 5;

        var addresses = new Address[NumEncryptionMappings];
        var sendKeys = new byte[NumEncryptionMappings][];
        var receiveKeys = new byte[NumEncryptionMappings][];

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            addresses[i] = default;
            addresses[i].SetIPv6(0, 0, 0, 0, 0, 0, 0, 1);
            addresses[i].Port = (ushort)(20000 + i);
            sendKeys[i] = new byte[Protocol.KeyBytes];
            receiveKeys[i] = new byte[Protocol.KeyBytes];
            Rng.GenerateKey(sendKeys[i]);
            Rng.GenerateKey(receiveKeys[i]);
        }

        // add the encryption mappings and look them up by address

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionIndex == -1);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).Length == 0);
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).Length == 0);

            Check.That(encryptionManager.AddEncryptionMapping(in addresses[i], sendKeys[i], receiveKeys[i], time, -1.0, TestConstants.TestTimeoutSeconds));

            encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).SequenceEqual(sendKeys[i]));
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).SequenceEqual(receiveKeys[i]));
        }

        // removing an encryption mapping that doesn't exist should fail

        {
            Address address = default;
            address.SetIPv6(0, 0, 0, 0, 0, 0, 0, 1);
            address.Port = 50000;
            Check.That(!encryptionManager.RemoveEncryptionMapping(in address, time));
        }

        // remove the first and last encryption mappings

        Check.That(encryptionManager.RemoveEncryptionMapping(in addresses[0], time));
        Check.That(encryptionManager.RemoveEncryptionMapping(in addresses[NumEncryptionMappings - 1], time));

        // make sure the removed mappings can no longer be looked up

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);

            if (i != 0 && i != NumEncryptionMappings - 1)
            {
                Check.That(encryptionManager.GetSendKey(encryptionIndex).SequenceEqual(sendKeys[i]));
                Check.That(encryptionManager.GetReceiveKey(encryptionIndex).SequenceEqual(receiveKeys[i]));
            }
            else
            {
                Check.That(encryptionManager.GetSendKey(encryptionIndex).Length == 0);
                Check.That(encryptionManager.GetReceiveKey(encryptionIndex).Length == 0);
            }
        }

        // add the mappings back in; all should be findable again

        Check.That(encryptionManager.AddEncryptionMapping(in addresses[0], sendKeys[0], receiveKeys[0], time, -1.0, TestConstants.TestTimeoutSeconds));
        Check.That(encryptionManager.AddEncryptionMapping(in addresses[NumEncryptionMappings - 1], sendKeys[NumEncryptionMappings - 1], receiveKeys[NumEncryptionMappings - 1], time, -1.0, TestConstants.TestTimeoutSeconds));

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).SequenceEqual(sendKeys[i]));
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).SequenceEqual(receiveKeys[i]));
        }

        // check that encryption mappings time out properly

        time += TestConstants.TestTimeoutSeconds * 2;

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).Length == 0);
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).Length == 0);
        }

        // add the same encryption mappings after timeout

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionIndex == -1);

            Check.That(encryptionManager.AddEncryptionMapping(in addresses[i], sendKeys[i], receiveKeys[i], time, -1.0, TestConstants.TestTimeoutSeconds));

            encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).SequenceEqual(sendKeys[i]));
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).SequenceEqual(receiveKeys[i]));
        }

        // reset the encryption manager and verify all mappings are removed

        encryptionManager.Reset();

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionIndex == -1);
        }

        // test the expire time for encryption mappings works as expected

        Check.That(encryptionManager.AddEncryptionMapping(in addresses[0], sendKeys[0], receiveKeys[0], time, time + 1.0, TestConstants.TestTimeoutSeconds));

        int index = encryptionManager.FindEncryptionMapping(in addresses[0], time);
        Check.That(index != -1);

        Check.That(encryptionManager.FindEncryptionMapping(in addresses[0], time + 1.1) == -1);

        encryptionManager.SetExpireTime(index, -1.0);

        Check.That(encryptionManager.FindEncryptionMapping(in addresses[0], time) == index);
    }

    public static void TestReplayProtection()
    {
        var replayProtection = new ReplayProtection();

        for (int i = 0; i < 2; i++)
        {
            replayProtection.Reset();

            Check.That(replayProtection.MostRecentSequence == 0);

            // the first time we receive packets, they should not be already received

            const ulong MaxSequence = Defines.ReplayProtectionBufferSize * 4;

            for (ulong sequence = 0; sequence < MaxSequence; sequence++)
            {
                Check.That(!replayProtection.AlreadyReceived(sequence));
                replayProtection.AdvanceSequence(sequence);
            }

            // old packets outside the buffer should be considered already received

            Check.That(replayProtection.AlreadyReceived(0));

            // packets received a second time should be flagged already received

            for (ulong sequence = MaxSequence - 10; sequence < MaxSequence; sequence++)
                Check.That(replayProtection.AlreadyReceived(sequence));

            // jumping ahead to a much higher sequence should be considered not already received

            Check.That(!replayProtection.AlreadyReceived(MaxSequence + Defines.ReplayProtectionBufferSize));

            // old packets should be considered already received

            for (ulong sequence = 0; sequence < MaxSequence; sequence++)
                Check.That(replayProtection.AlreadyReceived(sequence));
        }

        // sequence numbers near UINT64_MAX must not be falsely rejected as replays
        // ("sequence + buffer size" overflowed in the C library once; found by fuzzing)

        replayProtection.Reset();

        Check.That(!replayProtection.AlreadyReceived(ulong.MaxValue - Defines.ReplayProtectionBufferSize));
        replayProtection.AdvanceSequence(ulong.MaxValue - Defines.ReplayProtectionBufferSize);

        Check.That(!replayProtection.AlreadyReceived(ulong.MaxValue - 1));
        replayProtection.AdvanceSequence(ulong.MaxValue - 1);

        // and a replayed packet up there is still caught

        Check.That(replayProtection.AlreadyReceived(ulong.MaxValue - 1));

        // while packets that fell out of the window are rejected as before

        Check.That(replayProtection.AlreadyReceived(ulong.MaxValue - 1 - Defines.ReplayProtectionBufferSize));
    }

    public static void TestNetworkSimulatorDeterminism()
    {
        // two simulators given identical inputs must drop, delay and duplicate identically

        const int NumPackets = 100;

        var simulatorA = new NetworkSimulator { LatencyMilliseconds = 100.0f, JitterMilliseconds = 50.0f, PacketLossPercent = 25.0f, DuplicatePacketPercent = 25.0f };
        var simulatorB = new NetworkSimulator { LatencyMilliseconds = 100.0f, JitterMilliseconds = 50.0f, PacketLossPercent = 25.0f, DuplicatePacketPercent = 25.0f };

        Address from = Address.Parse("127.0.0.1:40000");
        Address to = Address.Parse("127.0.0.1:50000");

        byte[] packetData = new byte[256];
        for (int i = 0; i < NumPackets; i++)
        {
            for (int j = 0; j < packetData.Length; j++)
                packetData[j] = (byte)(i + j);
            simulatorA.SendPacket(in from, in to, packetData);
            simulatorB.SendPacket(in from, in to, packetData);
        }

        int totalReceived = 0;

        var receivedA = new System.Collections.Generic.List<byte[]>();
        var receivedB = new System.Collections.Generic.List<byte[]>();

        for (double time = 0.0; time < 2.0; time += 0.01)
        {
            simulatorA.Update(time);
            simulatorB.Update(time);

            receivedA.Clear();
            receivedB.Clear();

            simulatorA.ReceivePackets(in to, 256, (in Address _, ReadOnlySpan<byte> data) => receivedA.Add(data.ToArray()));
            simulatorB.ReceivePackets(in to, 256, (in Address _, ReadOnlySpan<byte> data) => receivedB.Add(data.ToArray()));

            Check.That(receivedA.Count == receivedB.Count);

            for (int i = 0; i < receivedA.Count; i++)
                Check.That(receivedA[i].AsSpan().SequenceEqual(receivedB[i]));

            totalReceived += receivedA.Count;
        }

        Check.That(totalReceived > 0);
    }
}
