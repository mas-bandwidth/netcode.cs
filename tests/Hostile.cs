/*
    Hostile.cs — seeded hostile-input tests over every parse path, the
    zero-allocation assertion for the steady-state packet paths, and the
    differential test of the managed crypto against the BCL's ChaCha20Poly1305.

    All "random" data comes from a deterministic seeded generator so any failure
    reproduces exactly. These tests port the intent of the C repo's libFuzzer
    harnesses (fuzz_read_packet, fuzz_connect_token, fuzz_parse_address) as
    bounded deterministic sweeps.
*/

using System;
using System.IO;
using System.Security.Cryptography;

namespace Netcode.Tests;

internal static class Hostile
{
    private static readonly bool[] AllAllowed = CreateAllAllowed();

    private static bool[] CreateAllAllowed()
    {
        var allowed = new bool[PacketType.NumPackets];
        Array.Fill(allowed, true);
        return allowed;
    }

    public static void TestCryptoDifferentialBcl()
    {
        // the managed AEAD must agree byte-for-byte with the platform's
        // ChaCha20Poly1305 (an independent implementation) wherever it exists

        if (!ChaCha20Poly1305.IsSupported)
        {
            Console.WriteLine("  (skipped: platform ChaCha20Poly1305 not supported here — KATs and the interop gate still pin the construction)");
            return;
        }

        var rng = new TestRng(0xD1FF);

        byte[] key = new byte[Aead.KeyBytes];
        byte[] nonce = new byte[Aead.NonceBytesIetf];

        for (int iteration = 0; iteration < 500; iteration++)
        {
            rng.Fill(key);
            rng.Fill(nonce);

            int messageLength = rng.Next(400);
            int adLength = rng.Next(64);

            byte[] message = new byte[messageLength];
            byte[] ad = new byte[adLength];
            rng.Fill(message);
            rng.Fill(ad);

            // managed encrypt
            byte[] managedBuffer = new byte[messageLength + Aead.MacBytes];
            message.CopyTo(managedBuffer, 0);
            Aead.EncryptIetf(managedBuffer, messageLength, ad, nonce, key);

            // platform encrypt
            byte[] platformCiphertext = new byte[messageLength];
            byte[] platformTag = new byte[Aead.MacBytes];
            using (var bcl = new ChaCha20Poly1305(key))
                bcl.Encrypt(nonce, message, platformCiphertext, platformTag, ad);

            Check.That(managedBuffer.AsSpan(0, messageLength).SequenceEqual(platformCiphertext));
            Check.That(managedBuffer.AsSpan(messageLength, Aead.MacBytes).SequenceEqual(platformTag));

            // managed decrypts platform output
            Check.That(Aead.DecryptIetf(managedBuffer, managedBuffer.Length, ad, nonce, key));
            Check.That(managedBuffer.AsSpan(0, messageLength).SequenceEqual(message));
        }
    }

    public static void TestFuzzReadPacketRaw()
    {
        // raw hostile bytes into ReadPacket: every parse/reject path ahead of AEAD
        // authentication. must never throw, and (a fuzzer cannot forge a MAC) must
        // never accept.

        var rng = new TestRng(0xF0221);

        byte[] packetKey = new byte[Protocol.KeyBytes];
        byte[] privateKey = new byte[Protocol.KeyBytes];
        packetKey.AsSpan().Fill(0xAA);
        privateKey.AsSpan().Fill(0xBB);

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        var replayProtection = new ReplayProtection();

        for (int iteration = 0; iteration < 20000; iteration++)
        {
            int length = rng.Next(Defines.MaxPacketBytes + 1);
            rng.Fill(buffer.AsSpan(0, length));

            // half the time, shape the header so parsing goes deeper before rejection
            int shape = rng.Next(4);
            if (length > 0 && shape == 1)
            {
                buffer[0] = (byte)((1 + rng.Next(8)) << 4 | rng.Next(PacketType.NumPackets));
            }
            else if (length > 0 && shape == 2)
            {
                buffer[0] = 0; // connection request
                if (length >= 14)
                    Defines.VersionInfo.CopyTo(buffer.AsSpan(1, Defines.VersionInfoBytes));
            }

            ReadPacketResult result = PacketIO.ReadPacket(
                buffer.AsSpan(0, length),
                hasReadPacketKey: true, packetKey,
                TestConstants.TestProtocolId,
                currentTimestamp: 0,
                hasPrivateKey: true, privateKey,
                AllAllowed,
                rng.Next(2) == 0 ? replayProtection : null);

            Check.That(result.Type == -1);
        }
    }

    public static void TestFuzzPacketRoundTripCorruption()
    {
        // build valid packets with real keys, then read them back: uncorrupted
        // packets must round-trip exactly; any single corrupted byte must be
        // rejected (the corruption lands in authenticated data, the sequence used
        // as the nonce, or pre-auth validated fields).

        var rng = new TestRng(0x2A2A);

        byte[] packetKey = new byte[Protocol.KeyBytes];
        byte[] privateKey = new byte[Protocol.KeyBytes];
        rng.Fill(packetKey);
        rng.Fill(privateKey);

        byte[] packetData = new byte[Defines.MaxPayloadBytes];
        byte[] buffer = new byte[2048];

        for (int iteration = 0; iteration < 2000; iteration++)
        {
            int packetType = rng.Next(PacketType.NumPackets);
            ulong sequence = rng.NextUInt64() >> rng.Next(64);
            bool corrupt = rng.Next(2) == 1;
            byte corruptXor = (byte)(1 + rng.Next(255)); // never the identity

            int bytesWritten;
            int expectedDataLength;

            if (packetType == PacketType.ConnectionRequest)
            {
                // a fully valid request: the private token encrypts with the real private key

                ulong expireTimestamp = rng.NextUInt64() | (1UL << 62) | 1; // cannot be zeroed by one byte flip
                byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
                rng.Fill(nonce);

                byte[] tokenData = new byte[Defines.ConnectTokenPrivateBytes];
                rng.Fill(tokenData.AsSpan(0, Defines.ConnectTokenPrivateBytes - Protocol.MacBytes));

                Check.That(ConnectTokenPrivate.Encrypt(tokenData, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, privateKey));

                bytesWritten = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, tokenData);
                expectedDataLength = Defines.ConnectTokenPrivateBytes;
                sequence = 0;
            }
            else
            {
                int dataLength = packetType switch
                {
                    PacketType.ConnectionChallenge or PacketType.ConnectionResponse => 8 + Defines.ChallengeTokenBytes,
                    PacketType.ConnectionKeepAlive => 8,
                    PacketType.ConnectionPayload => 1 + rng.Next(Defines.MaxPayloadBytes),
                    _ => 0,
                };

                rng.Fill(packetData.AsSpan(0, dataLength));

                bytesWritten = PacketIO.WriteEncryptedPacket(buffer, packetType, packetData.AsSpan(0, dataLength), sequence, packetKey, TestConstants.TestProtocolId);
                expectedDataLength = dataLength;
            }

            Check.That(bytesWritten > 0);

            byte[] original = buffer.AsSpan(0, bytesWritten).ToArray();

            if (corrupt)
                buffer[rng.Next(bytesWritten)] ^= corruptXor;

            ReadPacketResult result = PacketIO.ReadPacket(
                buffer.AsSpan(0, bytesWritten),
                hasReadPacketKey: true, packetKey,
                TestConstants.TestProtocolId,
                currentTimestamp: 0,
                hasPrivateKey: true, privateKey,
                AllAllowed, null);

            if (!corrupt)
            {
                Check.That(result.Type == packetType);
                Check.That(result.Sequence == sequence);
                Check.That(result.DataLength == expectedDataLength);
            }
            else
            {
                Check.That(result.Type == -1);
            }

            original.CopyTo(buffer, 0); // restore for clarity (buffer reused next round)
        }
    }

    public static void TestFuzzConnectToken()
    {
        var rng = new TestRng(0x70CE);

        // hostile public connect tokens: must never throw, and mostly reject.
        // when read succeeds (version bytes + field ranges can line up only if we
        // plant them), the parsed fields must be within their documented ranges.

        byte[] publicBuffer = new byte[Protocol.ConnectTokenBytes];
        var publicToken = new ConnectTokenData();

        for (int iteration = 0; iteration < 5000; iteration++)
        {
            rng.Fill(publicBuffer);
            if (rng.Next(2) == 0)
                Defines.VersionInfo.CopyTo(publicBuffer.AsSpan(0, Defines.VersionInfoBytes));

            if (publicToken.Read(publicBuffer))
            {
                Check.That(publicToken.NumServerAddresses >= 1 && publicToken.NumServerAddresses <= Protocol.MaxServersPerConnect);
                Check.That(publicToken.CreateTimestamp <= publicToken.ExpireTimestamp);
            }

            // wrong length must always be rejected
            Check.That(!publicToken.Read(publicBuffer.AsSpan(0, Protocol.ConnectTokenBytes - 1)));
        }

        // hostile private connect tokens

        byte[] privateBuffer = new byte[Defines.ConnectTokenPrivateBytes];
        var privateToken = new ConnectTokenPrivate();

        for (int iteration = 0; iteration < 5000; iteration++)
        {
            rng.Fill(privateBuffer);

            if (privateToken.Read(privateBuffer))
            {
                Check.That(privateToken.NumServerAddresses >= 1 && privateToken.NumServerAddresses <= Protocol.MaxServersPerConnect);
                for (int i = 0; i < privateToken.NumServerAddresses; i++)
                    Check.That(privateToken.ServerAddresses[i].Type == AddressType.IPv4 || privateToken.ServerAddresses[i].Type == AddressType.IPv6);
            }
        }

        // write/read round trip over the private token with random address mixes

        for (int iteration = 0; iteration < 1000; iteration++)
        {
            int numAddresses = 1 + rng.Next(Protocol.MaxServersPerConnect);
            var addresses = new Address[numAddresses];
            for (int i = 0; i < numAddresses; i++)
            {
                if (rng.Next(2) == 0)
                {
                    addresses[i].SetIPv4((byte)rng.Next(256), (byte)rng.Next(256), (byte)rng.Next(256), (byte)rng.Next(256));
                }
                else
                {
                    addresses[i].SetIPv6((ushort)rng.NextUInt64(), (ushort)rng.NextUInt64(), (ushort)rng.NextUInt64(), (ushort)rng.NextUInt64(),
                                         (ushort)rng.NextUInt64(), (ushort)rng.NextUInt64(), (ushort)rng.NextUInt64(), (ushort)rng.NextUInt64());
                }
                addresses[i].Port = (ushort)rng.NextUInt64();
            }

            byte[] userData = new byte[Protocol.UserDataBytes];
            rng.Fill(userData);

            var input = new ConnectTokenPrivate();
            input.Generate(rng.NextUInt64(), (int)(uint)rng.NextUInt64(), addresses, userData);
            input.Write(privateBuffer);

            var output = new ConnectTokenPrivate();
            Check.That(output.Read(privateBuffer));
            Check.That(output.ClientId == input.ClientId);
            Check.That(output.TimeoutSeconds == input.TimeoutSeconds);
            Check.That(output.NumServerAddresses == input.NumServerAddresses);
            for (int i = 0; i < numAddresses; i++)
                Check.That(output.ServerAddresses[i].Equals(input.ServerAddresses[i]));
            Check.That(output.UserData.AsSpan().SequenceEqual(input.UserData));
        }
    }

    public static void TestFuzzParseAddress()
    {
        // the C repo's fuzz corpus seeds, when present (reused across implementations)

        string corpusDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "netcode", "fuzz", "corpus", "fuzz_parse_address");
        string? envCorpus = Environment.GetEnvironmentVariable("NETCODE_FUZZ_CORPUS");
        if (envCorpus != null)
            corpusDir = envCorpus;

        int corpusFiles = 0;
        if (Directory.Exists(corpusDir))
        {
            foreach (string file in Directory.GetFiles(corpusDir))
            {
                string text = File.ReadAllText(file);
                ExerciseParse(text);
                corpusFiles++;
            }
        }
        Console.WriteLine($"  (corpus files exercised: {corpusFiles})");

        // seeded random strings over the parser's alphabet

        var rng = new TestRng(0xADD2);
        const string alphabet = "0123456789abcdefABCDEF.::[]%kx- ";
        var builder = new System.Text.StringBuilder();

        for (int iteration = 0; iteration < 20000; iteration++)
        {
            builder.Clear();
            int length = rng.Next(300);
            for (int i = 0; i < length; i++)
                builder.Append(alphabet[rng.Next(alphabet.Length)]);
            ExerciseParse(builder.ToString());
        }
    }

    private static void ExerciseParse(string input)
    {
        // must never throw; a successful parse must round-trip through ToString

        if (Address.TryParse(input, out Address address))
        {
            Check.That(address.Type == AddressType.IPv4 || address.Type == AddressType.IPv6);
            string formatted = address.ToString();
            Check.That(Address.TryParse(formatted, out Address reparsed));
            Check.That(reparsed.Equals(address));
        }
    }

    // ------------------------------------------------------------------
    // zero allocation
    // ------------------------------------------------------------------

    /// <summary>In-memory packet pipe with preallocated slots: a send/receive override
    /// transport that allocates nothing per packet.</summary>
    private sealed class MemoryPipe
    {
        private const int Capacity = 256;

        private readonly byte[][] _buffers;
        private readonly int[] _lengths;
        private readonly Address[] _from;
        private int _count;
        private int _start;

        public MemoryPipe()
        {
            _buffers = new byte[Capacity][];
            for (int i = 0; i < Capacity; i++)
                _buffers[i] = new byte[Defines.MaxPacketBytes];
            _lengths = new int[Capacity];
            _from = new Address[Capacity];
        }

        public Address Sender; // stamped as the from-address of every packet pushed

        public void Send(in Address to, ReadOnlySpan<byte> packetData)
        {
            if (_count == Capacity)
                return; // drop, like a full socket buffer
            int index = (_start + _count) % Capacity;
            packetData.CopyTo(_buffers[index]);
            _lengths[index] = packetData.Length;
            _from[index] = Sender;
            _count++;
        }

        public int Receive(ref Address from, Span<byte> packetData)
        {
            if (_count == 0)
                return 0;
            int index = _start;
            _buffers[index].AsSpan(0, _lengths[index]).CopyTo(packetData);
            from = _from[index];
            int length = _lengths[index];
            _start = (_start + 1) % Capacity;
            _count--;
            return length;
        }
    }

    public static void TestZeroAllocationSteadyState()
    {
        // a connected client/server pair exchanging payloads every frame must not
        // allocate at all once warm. transport is an in-memory pipe (so the
        // measurement covers netcode's paths, not the OS socket layer).

        var clientToServer = new MemoryPipe();
        var serverToClient = new MemoryPipe();

        Address clientAddress = Address.Parse("127.0.0.1:50000");
        Address serverAddress = Address.Parse("127.0.0.1:40000");
        clientToServer.Sender = clientAddress;
        serverToClient.Sender = serverAddress;

        var clientConfig = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => clientToServer.Send(in to, data),
            ReceivePacketOverride = (ref Address from, Span<byte> data) => serverToClient.Receive(ref from, data),
        };

        var serverConfig = new ServerConfig
        {
            ProtocolId = TestConstants.TestProtocolId,
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => serverToClient.Send(in to, data),
            ReceivePacketOverride = (ref Address from, Span<byte> data) => clientToServer.Receive(ref from, data),
        };
        TestConstants.PrivateKey.CopyTo(serverConfig.PrivateKey, 0);

        using var client = new Client("127.0.0.1:50000", clientConfig, 0.0);
        using var server = new Server("127.0.0.1:40000", serverConfig, 0.0);

        server.Start(1);

        byte[] connectToken = new byte[Protocol.ConnectTokenBytes];
        byte[] userData = new byte[Protocol.UserDataBytes];
        string[] address = { "127.0.0.1:40000" };
        Check.That(ConnectTokenGenerator.Generate(address, address, 60, 15, 0x1234, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken));

        client.Connect(connectToken);

        double time = 0.0;
        double deltaTime = 1.0 / 60.0;

        while (client.State != ClientState.Connected)
        {
            Check.That(client.State > ClientState.Disconnected);
            client.Update(time);
            server.Update(time);
            time += deltaTime;
        }

        byte[] payload = new byte[Protocol.MaxPacketSize];
        byte[] received = new byte[Protocol.MaxPacketSize];

        void Frame()
        {
            client.Update(time);
            server.Update(time);
            client.SendPacket(payload);
            server.SendPacket(0, payload);
            while (client.ReceivePacket(received, out _) >= 0) { }
            while (server.ReceivePacket(0, received, out _) >= 0) { }
            time += deltaTime;
        }

        // warm up: fills queue pools, promotes jitted code
        for (int i = 0; i < 2000; i++)
            Frame();

        long before = GC.GetAllocatedBytesForCurrentThread();

        for (int i = 0; i < 2000; i++)
            Frame();

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Check.That(client.State == ClientState.Connected);
        Check.That(server.ClientConnected(0));

        if (allocated != 0)
            Console.WriteLine($"  steady state allocated {allocated} bytes over 2000 frames");
        Check.That(allocated == 0);
    }
}
