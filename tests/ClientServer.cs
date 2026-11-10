/*
    ClientServer.cs — client/server integration tests, ported test-for-test from
    netcode.c: deterministic network-simulator tests (unit tier: no sockets,
    injected time), all error states, disconnect flows, reconnect, disable
    timeout and loopback; real UDP socket creates and connects (functional
    tier, --functional). Also the soak runner.
*/

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Netcode.Tests;

internal static class ClientServerTests
{
    private delegate void ProcessAtTime(in Address from, Span<byte> packet, ulong timestamp);

    internal static byte[] GenerateConnectToken(string serverAddress, ulong clientId, int expiry = TestConstants.TestConnectTokenExpiry + 1, int timeout = TestConstants.TestTimeoutSeconds)
    {
        return GenerateConnectToken(new[] { serverAddress }, clientId, expiry, timeout);
    }

    private static byte[] GenerateConnectToken(string[] serverAddresses, ulong clientId, int expiry = TestConstants.TestConnectTokenExpiry + 1, int timeout = TestConstants.TestTimeoutSeconds)
    {
        byte[] connectToken = new byte[Protocol.ConnectTokenBytes];
        byte[] userData = new byte[Protocol.UserDataBytes];
        Rng.Fill(userData);
        Check.That(ConnectTokenGenerator.Generate(serverAddresses, serverAddresses, expiry, timeout, clientId, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken));
        return connectToken;
    }

    private static NetworkSimulator CreateSimulator()
    {
        return new NetworkSimulator
        {
            LatencyMilliseconds = 250,
            JitterMilliseconds = 250,
            PacketLossPercent = 5,
            DuplicatePacketPercent = 10,
        };
    }

    internal static ServerConfig CreateServerConfig(NetworkSimulator? simulator)
    {
        var config = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, Simulator = simulator };
        TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
        return config;
    }

    private static void ConnectLoop(NetworkSimulator simulator, Client client, Server server, ref double time, double deltaTime)
    {
        while (true)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;
            if (client.State == ClientState.Connected)
                break;

            time += deltaTime;
        }
    }

    public static void TestClientServerAddressFamilies()
    {
        static byte[] Token(params string[] addresses)
        {
            var parsed = new Address[addresses.Length];
            for (int i = 0; i < addresses.Length; i++)
                Check.That(Address.TryParse(addresses[i], out parsed[i]));
            byte[] token = new byte[Protocol.ConnectTokenBytes];
            Check.That(ConnectTokenGenerator.GenerateInternal(parsed, parsed, 1000, 2000,
                TestConstants.TestTimeoutSeconds, 1, TestConstants.TestProtocolId,
                TestConstants.PrivateKey, new byte[Protocol.UserDataBytes], new byte[Defines.ConnectTokenNonceBytes], token));
            return token;
        }

        foreach (bool ipv6 in new[] { false, true })
        {
            string matching = ipv6 ? "[::1]:50000" : "127.0.0.1:50000";
            string mismatched = ipv6 ? "127.0.0.1:50001" : "[::1]:50001";
            var config = new ClientConfig
            {
                OverrideSendAndReceive = true,
                SendPacketOverride = (in Address to, ReadOnlySpan<byte> payload) => { },
                ReceivePacketOverride = (ref Address from, Span<byte> payload) => 0,
            };
            using var client = new Client(matching, config, 1000.0);
            var socketField = typeof(Client).GetField(ipv6 ? "_socketIpv6" : "_socketIpv4",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
            var configField = typeof(Client).GetField("_config",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
            var clientConfig = (ClientConfig)configField.GetValue(client)!;
            // Only socket presence is read by address selection. A sentinel exercises
            // that path without opening a socket or sending/receiving any packets.
            socketField.SetValue(client, System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(NetcodeSocket)));
            clientConfig.OverrideSendAndReceive = false;
            try
            {
                client.Connect(Token(mismatched));
                Check.That(client.State == ClientState.InvalidConnectToken);

                client.Connect(Token(mismatched, matching, mismatched, matching, mismatched));
                Check.That(client.State == ClientState.SendingConnectionRequest);
                Check.That(client.ServerAddress.ToString() == matching);
                var next = typeof(Client).GetMethod("ConnectToNextServer",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
                Check.That((bool)next.Invoke(client, null)!);
                Check.That(client.ServerAddress.ToString() == matching);
                Check.That(!(bool)next.Invoke(client, null)!);
            }
            finally
            {
                // The sentinel has no underlying socket and must never be disposed.
                socketField.SetValue(client, null);
                clientConfig.OverrideSendAndReceive = true;
            }
        }
    }

    public static void TestServerRestartGlobalSequence()
    {
        // global packets (challenge, denied) share per-token server to client keys with
        // per-client packets, so the global sequence must stay in the top half of the
        // sequence space or a stopped and restarted server reuses AEAD nonces.

        using var server = new Server("127.0.0.1:40000", CreateServerConfig(new NetworkSimulator()), 1000.0);

        Check.That(server.GlobalSequence == 1UL << 63);

        server.Start(1);

        Check.That(server.GlobalSequence == 1UL << 63);

        server.GlobalSequence += 1000; // as if the server had sent some global packets

        server.Stop();

        server.Start(1);

        Check.That(server.GlobalSequence == 1UL << 63);
    }

    public static void TestConnectTokenHistory()
    {
        var history = new ConnectTokenHistory();
        Check.That(Address.TryParse("[::1]:50000", out Address addressA));
        Check.That(Address.TryParse("[::1]:50001", out Address addressB));

        ulong currentTimestamp = 1000;
        ulong expireTimestamp = currentTimestamp + 30;
        byte[] mac = new byte[Protocol.MacBytes];
        mac[0] = 1;

        int index = history.FindOrAdd(in addressA, mac, expireTimestamp, currentTimestamp, 100.0);
        Check.That(index >= 0);

        Check.That(history.FindOrAdd(in addressA, mac, expireTimestamp, currentTimestamp, 200.0) == index);
        Check.That(history.FindOrAdd(in addressB, mac, expireTimestamp, currentTimestamp, 200.0) == ConnectTokenHistory.Refused);

        history.Consume(index);
        Check.That(history.FindOrAdd(in addressA, mac, expireTimestamp, currentTimestamp, 300.0) == ConnectTokenHistory.Refused);
        Check.That(history.FindOrAdd(in addressB, mac, expireTimestamp, currentTimestamp, 300.0) == ConnectTokenHistory.Refused);

        for (int i = 1; i < ConnectTokenHistory.MaxEntries; i++)
        {
            mac = new byte[Protocol.MacBytes];
            mac[0] = unchecked((byte)(i + 1));
            mac[1] = unchecked((byte)((i + 1) >> 8));
            Check.That(history.FindOrAdd(in addressA, mac, expireTimestamp, currentTimestamp, 400.0) >= 0);
        }

        mac = new byte[Protocol.MacBytes];
        mac[0] = 0xFF;
        mac[1] = 0xFF;
        Check.That(history.FindOrAdd(in addressA, mac, expireTimestamp, currentTimestamp, 500.0) == ConnectTokenHistory.Full);

        mac[0] = 1;
        mac[1] = 0;
        Check.That(history.FindOrAdd(in addressA, mac, expireTimestamp, currentTimestamp, 500.0) == ConnectTokenHistory.Refused);

        mac[0] = 0xFF;
        mac[1] = 0xFF;
        Check.That(history.FindOrAdd(in addressA, mac, expireTimestamp, expireTimestamp, 600.0) >= 0);
    }

    public static void TestClientReconnectUsedConnectToken()
    {
        NetworkSimulator simulator = CreateSimulator();
        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);
        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        server.Start(1);

        byte[] connectToken = GenerateConnectToken("[::1]:40000", 0x1234);
        client.Connect(connectToken);
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.Connected);

        server.DisconnectClient(0);
        while (client.State > ClientState.Disconnected)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);
            time += deltaTime;
        }

        simulator.Reset();
        client.Connect(connectToken);
        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.ConnectionRequestTimedOut);
        Check.That(server.NumConnectedClients == 0);
    }

    public static void TestClientErrorConnectTokenPredatesServerStart()
    {
        NetworkSimulator simulator = CreateSimulator();
        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;
        var serverConfig = CreateServerConfig(simulator);
        serverConfig.MaxConnectTokenLifetime = 30;
        using var server = new Server("[::1]:40000", serverConfig, time);
        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        server.Start(1);

        client.Connect(GenerateConnectToken("[::1]:40000", 0x1234, expiry: 20));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.ConnectionRequestTimedOut);
        Check.That(server.NumConnectedClients == 0);

        simulator.Reset();
        client.Connect(GenerateConnectToken("[::1]:40000", 0x5678, expiry: 31));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.Connected);
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestClientErrorConnectTokenAtServerStart()
    {
        NetworkSimulator simulator = CreateSimulator();
        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;
        var serverConfig = CreateServerConfig(simulator);
        serverConfig.MaxConnectTokenLifetime = 30;
        using var server = new Server("[::1]:40000", serverConfig, time);
        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        server.Start(1);

        // a token that expires in the same second the server started does not open a session
        client.Connect(GenerateConnectToken("[::1]:40000", 0x1234, expiry: 30));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.ConnectionRequestTimedOut);
        Check.That(server.NumConnectedClients == 0);

        // one second past the start floor does
        simulator.Reset();
        client.Connect(GenerateConnectToken("[::1]:40000", 0x5678, expiry: 31));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.Connected);
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestClientServerConnect()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        ulong clientId = new TestRng(0xC11E17).NextUInt64();
        client.Connect(GenerateConnectToken("[::1]:40000", clientId));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);
        Check.That(client.ClientIndex == 0);
        Check.That(server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 1);
        Check.That(server.ClientId(0) == clientId);

        int serverNumPacketsReceived = 0;
        int clientNumPacketsReceived = 0;

        byte[] packetData = new byte[Protocol.MaxPacketSize];
        for (int i = 0; i < packetData.Length; i++)
            packetData[i] = unchecked((byte)i);

        byte[] received = new byte[Protocol.MaxPacketSize];

        while (true)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            client.SendPacket(packetData);
            server.SendPacket(0, packetData);

            while (true)
            {
                int bytes = client.ReceivePacket(received, out _);
                if (bytes < 0)
                    break;
                Check.That(bytes == Protocol.MaxPacketSize);
                Check.That(received.AsSpan(0, bytes).SequenceEqual(packetData));
                clientNumPacketsReceived++;
            }

            while (true)
            {
                int bytes = server.ReceivePacket(0, received, out _);
                if (bytes < 0)
                    break;
                Check.That(bytes == Protocol.MaxPacketSize);
                Check.That(received.AsSpan(0, bytes).SequenceEqual(packetData));
                serverNumPacketsReceived++;
            }

            if (clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10)
            {
                if (server.ClientConnected(0))
                    server.DisconnectClient(0);
            }

            if (client.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10);
    }

    public static void TestKeepAliveClientIndexOutOfRange()
    {
        Console.WriteLine("test_keep_alive_client_index_out_of_range");

        TestConnectedKeepAliveClientIndexOutOfRange();

        const string serverAddress = "127.0.0.1:40000";
        using var client = OpenRespondingClient(serverAddress, out Address from, out byte[] serverToClientKey);

        // Each of these is stored on the unfixed path: uint.MaxValue casts to -1,
        // 5000 is past any server, 0 is not a slot count, and MaxClients is the ceiling.
        (uint clientIndex, uint maxClients)[] rejected =
        {
            (uint.MaxValue, 32),
            (5000, 32),
            (1, 0),
            (0, (uint)Protocol.MaxClients + 1),
        };

        ulong sequence = 2;
        foreach (var rejectedPacket in rejected)
        {
            DeliverKeepAlive(client, in from, serverToClientKey, sequence, rejectedPacket.clientIndex, rejectedPacket.maxClients);
            sequence++;
            Console.WriteLine($"rejected keep-alive wire clientIndex={rejectedPacket.clientIndex} maxClients={rejectedPacket.maxClients} stored clientIndex={client.ClientIndex} maxClients={client.MaxClients} state={client.State}");
            Check.That(client.State == ClientState.SendingConnectionResponse);
            Check.That(client.ClientIndex == 0);
            Check.That(client.MaxClients == 0);
        }

        DeliverKeepAlive(client, in from, serverToClientKey, sequence, 3, 32);
        Check.That(client.State == ClientState.Connected);
        Check.That(client.ClientIndex == 3);
        Check.That(client.MaxClients == 32);
    }

    private static void TestConnectedKeepAliveClientIndexOutOfRange()
    {
        const string serverAddress = "127.0.0.1:40000";
        using var client = OpenRespondingClient(serverAddress, out Address from, out byte[] serverToClientKey);

        DeliverKeepAlive(client, in from, serverToClientKey, 2, 3, 32);
        Check.That(client.State == ClientState.Connected);
        Check.That(client.ClientIndex == 3);
        Check.That(client.MaxClients == 32);

        client.Update(TestConstants.TestTimeoutSeconds - 1.0);

        // a keep-alive that names a slot outside the server's client range must not
        // hold an established connection open, nor change the stored index

        DeliverKeepAlive(client, in from, serverToClientKey, 3, uint.MaxValue, 32);
        DeliverKeepAlive(client, in from, serverToClientKey, 4, 5000, 32);
        DeliverKeepAlive(client, in from, serverToClientKey, 5, 1, 0);
        DeliverKeepAlive(client, in from, serverToClientKey, 6, 0, (uint)Protocol.MaxClients + 1);

        Check.That(client.State == ClientState.Connected);
        Check.That(client.ClientIndex == 3);
        Check.That(client.MaxClients == 32);

        client.Update(TestConstants.TestTimeoutSeconds + 1.0);
        Check.That(client.State == ClientState.ConnectionTimedOut);
    }

    private static Client OpenRespondingClient(string serverAddress, out Address from, out byte[] serverToClientKey)
    {
        byte[] tokenBytes = GenerateConnectToken(serverAddress, 0x11);
        var token = new ConnectTokenData();
        Check.That(token.Read(tokenBytes));
        serverToClientKey = token.ServerToClientKey;
        Check.That(Address.TryParse(serverAddress, out from));

        var config = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> payload) => { },
            ReceivePacketOverride = (ref Address receiveFrom, Span<byte> payload) => 0,
        };
        var client = new Client("127.0.0.1:0", config, 0.0);
        client.Connect(tokenBytes);
        Check.That(client.State == ClientState.SendingConnectionRequest);

        byte[] challenge = new byte[8 + Defines.ChallengeTokenBytes];
        Deliver(client, in from, serverToClientKey, PacketType.ConnectionChallenge, challenge, 1);
        Check.That(client.State == ClientState.SendingConnectionResponse);
        Check.That(client.ClientIndex == 0);
        Check.That(client.MaxClients == 0);
        return client;
    }

    private static void Deliver(Client client, in Address from, byte[] key, int packetType, ReadOnlySpan<byte> packetData, ulong sequence)
    {
        byte[] buffer = new byte[Defines.MaxPacketBytes];
        int written = PacketIO.WriteEncryptedPacket(buffer, packetType, packetData, sequence, key, TestConstants.TestProtocolId);
        Check.That(written > 0);
        client.ProcessPacket(in from, buffer.AsSpan(0, written));
    }

    private static void DeliverKeepAlive(Client client, in Address from, byte[] key, ulong sequence, uint clientIndex, uint maxClients)
    {
        byte[] data = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), clientIndex);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4, 4), maxClients);
        Deliver(client, in from, key, PacketType.ConnectionKeepAlive, data, sequence);
    }

    public static void TestClientServerKeepAlive()
    {
        TestKeepAliveClientIndexOutOfRange();

        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        client.Connect(GenerateConnectToken("[::1]:40000", 0x1234));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);

        // pump the connection without sending any payloads; keep-alives alone must hold it open
        // for far longer than the timeout

        int numIterations = (int)(TestConstants.TestTimeoutSeconds * 3 / deltaTime);

        for (int i = 0; i < numIterations; i++)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(client.State == ClientState.Connected);
        Check.That(server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestClientServerMultipleClients()
    {
        int[] maxClients = { 2, 32, 5 };

        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        for (int i = 0; i < maxClients.Length; i++)
        {
            server.Start(maxClients[i]);

            var clients = new Client[maxClients[i]];
            for (int j = 0; j < maxClients[i]; j++)
            {
                clients[j] = new Client($"[::]:{50000 + j}", new ClientConfig { Simulator = simulator }, time);
                clients[j].Connect(GenerateConnectToken("[::1]:40000", (ulong)(j + 1000 * (i + 1))));
            }

            // make sure all clients can connect

            while (true)
            {
                simulator.Update(time);

                foreach (Client c in clients)
                    c.Update(time);

                server.Update(time);

                int numConnectedClients = 0;
                bool anyFailed = false;
                foreach (Client c in clients)
                {
                    if (c.State <= ClientState.Disconnected)
                    {
                        anyFailed = true;
                        break;
                    }
                    if (c.State == ClientState.Connected)
                        numConnectedClients++;
                }

                Check.That(!anyFailed);

                if (numConnectedClients == maxClients[i])
                    break;

                time += deltaTime;
            }

            Check.That(server.NumConnectedClients == maxClients[i]);

            for (int j = 0; j < maxClients[i]; j++)
            {
                Check.That(clients[j].State == ClientState.Connected);
                Check.That(server.ClientConnected(j));
            }

            // make sure all clients can exchange packets with the server

            var serverNumPacketsReceived = new int[maxClients[i]];
            var clientNumPacketsReceived = new int[maxClients[i]];

            byte[] packetData = new byte[Protocol.MaxPacketSize];
            for (int j = 0; j < packetData.Length; j++)
                packetData[j] = unchecked((byte)j);

            byte[] received = new byte[Protocol.MaxPacketSize];

            while (true)
            {
                simulator.Update(time);

                foreach (Client c in clients)
                    c.Update(time);

                server.Update(time);

                for (int j = 0; j < maxClients[i]; j++)
                    clients[j].SendPacket(packetData);

                for (int j = 0; j < maxClients[i]; j++)
                    server.SendPacket(j, packetData);

                for (int j = 0; j < maxClients[i]; j++)
                {
                    while (true)
                    {
                        int bytes = clients[j].ReceivePacket(received, out _);
                        if (bytes < 0)
                            break;
                        Check.That(bytes == Protocol.MaxPacketSize);
                        Check.That(received.AsSpan(0, bytes).SequenceEqual(packetData));
                        clientNumPacketsReceived[j]++;
                    }
                }

                for (int j = 0; j < maxClients[i]; j++)
                {
                    while (true)
                    {
                        int bytes = server.ReceivePacket(j, received, out _);
                        if (bytes < 0)
                            break;
                        Check.That(bytes == Protocol.MaxPacketSize);
                        Check.That(received.AsSpan(0, bytes).SequenceEqual(packetData));
                        serverNumPacketsReceived[j]++;
                    }
                }

                int numClientsReady = 0;
                for (int j = 0; j < maxClients[i]; j++)
                {
                    if (clientNumPacketsReceived[j] >= 1 && serverNumPacketsReceived[j] >= 1)
                        numClientsReady++;
                }

                if (numClientsReady == maxClients[i])
                    break;

                foreach (Client c in clients)
                    Check.That(c.State > ClientState.Disconnected);

                time += deltaTime;
            }

            simulator.Reset();

            foreach (Client c in clients)
                c.Dispose();

            server.Stop();
        }
    }

    public static void TestClientServerMultipleServers()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        // the first two addresses point at servers that do not exist; the client works
        // through them and connects to the third

        string[] serverAddresses = { "10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000" };

        client.Connect(GenerateConnectToken(serverAddresses, 0x8877, expiry: 60));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);
        Check.That(client.ClientIndex == 0);
        Check.That(server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestClientErrorConnectTokenExpired()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);

        // a token that expires immediately: the client transitions to ConnectTokenExpired

        client.Connect(GenerateConnectToken("[::1]:40000", 0x1, expiry: 0));

        client.Update(time);

        Check.That(client.State == ClientState.ConnectTokenExpired);

        TestClientErrorConnectTokenExpiredMultipleServers();
    }

    public static void TestClientErrorConnectTokenExpiredMultipleServers()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);

        string[] serverAddresses = { "10.10.10.10:1000", "100.100.100.100:50000" };

        client.Connect(GenerateConnectToken(serverAddresses, 0x8878, expiry: 20));

        while (true)
        {
            simulator.Update(time);
            client.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(client.State == ClientState.ConnectTokenExpired);
        Check.That(time < 1025.0);
    }

    public static void TestClientErrorInvalidConnectToken()
    {
        NetworkSimulator simulator = CreateSimulator();

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, 1000.0);

        byte[] garbage = new byte[Protocol.ConnectTokenBytes];
        new TestRng(0xBAD).Fill(garbage);

        client.Connect(garbage);

        Check.That(client.State == ClientState.InvalidConnectToken);
    }

    public static void TestClientErrorConnectionTimedOut()
    {
        // connect a client to a server, then stop updating the server. the client
        // must transition to ConnectionTimedOut.

        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        client.Connect(GenerateConnectToken("[::1]:40000", 0x2));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);

        // stop updating the server; the client must time out

        while (true)
        {
            simulator.Update(time);
            client.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(client.State == ClientState.ConnectionTimedOut);
    }

    public static void TestClientErrorConnectionResponseTimeout()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        // the server ignores connection response packets, so the client hangs in
        // SendingConnectionResponse until it times out

        server.Flags = Server.FlagIgnoreConnectionResponsePackets;

        client.Connect(GenerateConnectToken("[::1]:40000", 0x3));

        while (true)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(client.State == ClientState.ConnectionResponseTimedOut);
    }

    public static void TestClientErrorConnectionRequestTimeout()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        // the server ignores connection request packets, so the client hangs in
        // SendingConnectionRequest until it times out

        server.Flags = Server.FlagIgnoreConnectionRequestPackets;

        client.Connect(GenerateConnectToken("[::1]:40000", 0x4));

        while (true)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(client.State == ClientState.ConnectionRequestTimedOut);
    }

    public static void TestClientErrorConnectionDenied()
    {
        // connect a client to a 1-slot server, then try to connect a second client:
        // the second client must be denied

        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        client.Connect(GenerateConnectToken("[::1]:40000", 0x5));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);

        using var client2 = new Client("[::]:50001", new ClientConfig { Simulator = simulator }, time);

        client2.Connect(GenerateConnectToken("[::1]:40000", 0x6));

        while (true)
        {
            simulator.Update(time);
            client.Update(time);
            client2.Update(time);
            server.Update(time);

            if (client2.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(client.State == ClientState.Connected);
        Check.That(client2.State == ClientState.ConnectionDenied);
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestClientSideDisconnect()
    {
        // the client disconnects; the server must see the slot free quickly (via
        // disconnect packets), not by waiting for the timeout

        NetworkSimulator simulator = new NetworkSimulator(); // clean network for the disconnect packets

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        client.Connect(GenerateConnectToken("[::1]:40000", 0x7));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);
        Check.That(server.ClientConnected(0));

        client.Disconnect();

        for (int i = 0; i < 10; i++)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            if (!server.ClientConnected(0))
                break;

            time += deltaTime;
        }

        Check.That(!server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 0);
    }

    public static void TestServerSideDisconnect()
    {
        // the server disconnects; the client must see it quickly (via disconnect
        // packets), not by waiting for the timeout

        NetworkSimulator simulator = new NetworkSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        int disconnectCallbackCount = 0;
        Server? serverRef = null;
        Address departingAddress = default;
        byte[] departingUserData = new byte[Protocol.UserDataBytes];
        var serverConfig = CreateServerConfig(simulator);
        serverConfig.OnClientConnectDisconnect = (clientIndex, connected) =>
        {
            if (!connected)
            {
                disconnectCallbackCount++;

                // the departing client stays readable through the callback, already disconnected
                Check.That(!serverRef!.ClientConnected(clientIndex));
                Check.That(serverRef.ClientId(clientIndex) == 0x8);
                Check.That(serverRef.ClientAddress(clientIndex).Equals(departingAddress));
                Check.That(serverRef.ClientUserData(clientIndex).SequenceEqual(departingUserData));

                if (disconnectCallbackCount == 1)
                    serverRef.DisconnectClient(clientIndex);
            }
        };

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", serverConfig, time);
        serverRef = server;

        server.Start(1);

        client.Connect(GenerateConnectToken("[::1]:40000", 0x8));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);

        departingAddress = server.ClientAddress(0);
        Check.That(departingAddress.Type == AddressType.IPv6);
        server.ClientUserData(0).CopyTo(departingUserData);

        server.DisconnectClient(0);
        Check.That(disconnectCallbackCount == 1);
        Check.That(server.ClientId(0) == 0);
        Check.That(server.ClientAddress(0).Type == AddressType.None);

        for (int i = 0; i < 10; i++)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(client.State == ClientState.Disconnected);
        Check.That(server.NumConnectedClients == 0);
    }

    public static void TestServerClientDisconnectReason()
    {
        // the disconnect reason is recorded before the callback fires and queryable inside it

        NetworkSimulator simulator = new NetworkSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        DisconnectReason reasonInCallback = DisconnectReason.None;
        int callbackCount = 0;

        var serverConfig = CreateServerConfig(simulator);
        Server? serverRef = null;
        serverConfig.OnClientConnectDisconnect = (clientIndex, connected) =>
        {
            if (!connected)
            {
                reasonInCallback = serverRef!.ClientDisconnectReason(clientIndex);
                callbackCount++;
            }
        };

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", serverConfig, time);
        serverRef = server;

        server.Start(1);

        // server-side disconnect

        client.Connect(GenerateConnectToken("[::1]:40000", 0x9));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.Connected);
        Check.That(server.ClientDisconnectReason(0) == DisconnectReason.None);

        server.DisconnectClient(0);
        Check.That(callbackCount == 1);
        Check.That(reasonInCallback == DisconnectReason.ServerDisconnect);
        Check.That(server.ClientDisconnectReason(0) == DisconnectReason.ServerDisconnect);

        // client-side disconnect: the server sees the disconnect packet

        client.Disconnect();
        client.Connect(GenerateConnectToken("[::1]:40000", 0xA));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.Connected);

        client.Disconnect();

        for (int i = 0; i < 10; i++)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);
            if (!server.ClientConnected(0))
                break;
            time += deltaTime;
        }

        Check.That(callbackCount == 2);
        Check.That(reasonInCallback == DisconnectReason.ClientDisconnect);

        // timeout: stop updating the client

        client.Connect(GenerateConnectToken("[::1]:40000", 0xB));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.Connected);

        while (server.ClientConnected(0))
        {
            simulator.Update(time);
            server.Update(time);
            time += deltaTime;
        }

        Check.That(callbackCount == 3);
        Check.That(reasonInCallback == DisconnectReason.TimedOut);
    }

    public static void TestClientReconnect()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        ulong clientId = 0xCAFE;

        client.Connect(GenerateConnectToken("[::1]:40000", clientId));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);
        Check.That(server.NumConnectedClients == 1);

        // disconnect client on the server-side and wait until the client sees it

        simulator.Reset();

        server.DisconnectClient(0);

        while (true)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;

            time += deltaTime;
        }

        Check.That(client.State == ClientState.Disconnected);
        Check.That(!server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 0);

        // now reconnect the client (fresh token) and verify they connect

        simulator.Reset();

        client.Connect(GenerateConnectToken("[::1]:40000", clientId));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);
        Check.That(client.ClientIndex == 0);
        Check.That(server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestPendingEncryptionMappingExpiry()
    {
        const System.Reflection.BindingFlags Fields = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;

        var config = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, OverrideSendAndReceive = true };
        TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
        config.SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => { };
        config.ReceivePacketOverride = (ref Address from, Span<byte> data) => 0;
        using var server = new Server("127.0.0.1:40000", config, 0.0);
        server.Start(4);
        typeof(Server).GetField("_minConnectTokenExpireTimestamp", Fields)!.SetValue(server, 0UL);
        var process = typeof(Server).GetMethod("ReadAndProcessPacket", Fields)!.CreateDelegate<ProcessAtTime>(server);
        var encryptionManager = (EncryptionManager)typeof(Server).GetField("_encryptionManager", Fields)!.GetValue(server)!;
        Address serverAddress = Address.Parse("127.0.0.1:40000");
        Address firstAddress = Address.Parse("127.0.0.1:50000");
        Address secondAddress = Address.Parse("127.0.0.1:50001");
        Address thirdAddress = Address.Parse("127.0.0.1:50002");
        Address fourthAddress = Address.Parse("127.0.0.1:50003");
        Address fifthAddress = Address.Parse("127.0.0.1:50004");
        Address sixthAddress = Address.Parse("127.0.0.1:50005");

        void Request(in Address from, ulong clientId, ulong expireTimestamp, double time, int timeout = -1)
        {
            byte[] tokenBytes = new byte[Protocol.ConnectTokenBytes];
            byte[] userData = new byte[Protocol.UserDataBytes];
            Span<Address> addresses = stackalloc Address[1] { serverAddress };
            Span<byte> nonce = stackalloc byte[Defines.ConnectTokenNonceBytes];
            new TestRng(clientId).Fill(nonce);
            Check.That(ConnectTokenGenerator.GenerateInternal(addresses, addresses, 1000, expireTimestamp, timeout,
                clientId, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, nonce, tokenBytes));
            var token = new ConnectTokenData();
            Check.That(token.Read(tokenBytes));
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteConnectionRequestPacket(wire, token.VersionInfo, token.ProtocolId,
                token.ExpireTimestamp, token.Nonce, token.PrivateData);
            server.Update(time);
            process(in from, wire.AsSpan(0, bytes), 1001);
        }

        // the token has four seconds left, so an unfinished request's mapping must not outlive it
        Request(in firstAddress, 0x1001, 1005, 0.0);
        Check.That(encryptionManager.NumEncryptionMappings == 1);

        server.Update(6.0);
        Check.That(encryptionManager.EntryExpired(0, server.Time));

        // the expired mapping's slot is available to another pending request
        Request(in secondAddress, 0x1002, 1030, 6.0);
        Check.That(encryptionManager.NumEncryptionMappings == 1);
        Check.That(encryptionManager.Address[0].Equals(secondAddress));

        // a positive timeout is also limited by a shorter token lifetime
        Request(in thirdAddress, 0x1003, 1005, 6.0, timeout: 30);
        Check.That(encryptionManager.NumEncryptionMappings == 2);
        Check.That(encryptionManager.ExpireTime[1] <= server.Time + 4.0);

        server.Update(11.0);
        Check.That(encryptionManager.EntryExpired(1, server.Time));

        // the expired mapping's slot is available to another pending request
        Request(in fourthAddress, 0x1004, 1030, 11.0);
        Check.That(encryptionManager.NumEncryptionMappings == 2);
        Check.That(encryptionManager.Address[1].Equals(fourthAddress));

        // a negative timeout is bounded by the pre-connect lifetime even when the
        // token has much longer to live
        server.Update(22.0);
        Check.That(encryptionManager.EntryExpired(1, server.Time));

        Request(in fifthAddress, 0x1005, 1030, 22.0);
        Check.That(encryptionManager.NumEncryptionMappings == 2);

        // the pending mapping is finite and its slot is reclaimed once it expires,
        // even though the token has much longer to live
        int fifthIndex = encryptionManager.FindEncryptionMapping(in fifthAddress, server.Time);
        Check.That(fifthIndex != -1);
        Check.That(encryptionManager.ExpireTime[fifthIndex] > server.Time);

        server.Update(33.0);
        Check.That(encryptionManager.EntryExpired(fifthIndex, server.Time));

        Request(in sixthAddress, 0x1006, 1030, 33.0);
        Check.That(encryptionManager.NumEncryptionMappings == 2);
        Check.That(encryptionManager.FindEncryptionMapping(in sixthAddress, server.Time) != -1);
    }

    public static void TestDisableTimeout()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        server.Start(1);

        // timeout of -1 disables timeouts entirely (dev only)

        client.Connect(GenerateConnectToken("[::1]:40000", 0xD15AB1E, timeout: -1));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);

        int serverNumPacketsReceived = 0;
        int clientNumPacketsReceived = 0;

        byte[] packetData = new byte[Protocol.MaxPacketSize];
        for (int i = 0; i < packetData.Length; i++)
            packetData[i] = unchecked((byte)i);

        byte[] received = new byte[Protocol.MaxPacketSize];

        while (true)
        {
            simulator.Update(time);
            client.Update(time);
            server.Update(time);

            client.SendPacket(packetData);
            server.SendPacket(0, packetData);

            while (client.ReceivePacket(received, out _) >= 0)
                clientNumPacketsReceived++;

            while (server.ReceivePacket(0, received, out _) >= 0)
                serverNumPacketsReceived++;

            if (clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10)
            {
                if (server.ClientConnected(0))
                    server.DisconnectClient(0);
            }

            if (client.State <= ClientState.Disconnected)
                break;

            time += 1000.0; // normally this would time out the client
        }

        Check.That(clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10);
    }

    public static void TestLoopback()
    {
        TestLoopbackStateChanges();
        TestClientStateChangeNotification();

        NetworkSimulator simulator = CreateSimulator();

        double time = 1000.0;
        double deltaTime = 1.0 / 10.0;

        int numLoopbackPacketsSentToClient = 0;
        int numLoopbackPacketsSentToServer = 0;

        byte[] packetData = new byte[Protocol.MaxPacketSize];
        for (int i = 0; i < packetData.Length; i++)
            packetData[i] = unchecked((byte)i);

        Client? loopbackClientRef = null;
        Server? serverRef = null;

        // client slot 0 is the loopback client (the local player on a listen server);
        // slot 1 is a regular remote client connecting over the (simulated) network

        var clientConfig = new ClientConfig
        {
            Simulator = simulator,
            SendLoopbackPacket = (clientIndex, payload, sequence) =>
            {
                Check.That(clientIndex == 0);
                Check.That(payload.SequenceEqual(packetData));
                numLoopbackPacketsSentToServer++;
                serverRef!.ProcessLoopbackPacket(clientIndex, payload, sequence);
            },
        };

        var serverConfig = CreateServerConfig(simulator);
        serverConfig.SendLoopbackPacket = (clientIndex, payload, sequence) =>
        {
            Check.That(clientIndex == 0);
            Check.That(payload.SequenceEqual(packetData));
            numLoopbackPacketsSentToClient++;
            loopbackClientRef!.ProcessLoopbackPacket(payload, sequence);
        };

        using var loopbackClient = new Client("[::]:50000", clientConfig, time);
        using var server = new Server("[::1]:40000", serverConfig, time);
        loopbackClientRef = loopbackClient;
        serverRef = server;

        server.Start(2);

        // connect the loopback client to slot 0

        loopbackClient.ConnectLoopback(0, 2);

        byte[] userData = new byte[Protocol.UserDataBytes];
        new TestRng(0x10CA1).Fill(userData);
        server.ConnectLoopbackClient(0, 0x11111111, userData);

        Check.That(loopbackClient.IsLoopback);
        Check.That(loopbackClient.State == ClientState.Connected);
        Check.That(loopbackClient.ClientIndex == 0);
        Check.That(server.ClientLoopback(0));
        Check.That(server.ClientConnected(0));
        Check.That(server.ClientId(0) == 0x11111111);
        Check.That(server.NumConnectedClients == 1);
        Check.That(server.ClientUserData(0).SequenceEqual(userData));

        // connect a regular client to slot 1

        using var regularClient = new Client("[::]:50001", new ClientConfig { Simulator = simulator }, time);

        regularClient.Connect(GenerateConnectToken("[::1]:40000", 0x22222222));

        ConnectLoop(simulator, regularClient, server, ref time, deltaTime);

        Check.That(regularClient.State == ClientState.Connected);
        Check.That(regularClient.ClientIndex == 1);
        Check.That(server.ClientConnected(0) && server.ClientConnected(1));
        Check.That(!server.ClientLoopback(1));
        Check.That(server.NumConnectedClients == 2);

        // exchange loopback payloads both ways

        byte[] received = new byte[Protocol.MaxPacketSize];

        for (int i = 0; i < 10; i++)
        {
            loopbackClient.SendPacket(packetData);
            server.SendPacket(0, packetData);
        }

        Check.That(numLoopbackPacketsSentToServer == 10);
        Check.That(numLoopbackPacketsSentToClient == 10);

        int clientReceived = 0;
        while (loopbackClient.ReceivePacket(received, out _) >= 0)
            clientReceived++;
        Check.That(clientReceived == 10);

        int serverReceived = 0;
        while (server.ReceivePacket(0, received, out _) >= 0)
            serverReceived++;
        Check.That(serverReceived == 10);

        // disconnect the loopback client; slot 0 frees, slot 1 remains

        server.DisconnectLoopbackClient(0);
        loopbackClient.DisconnectLoopback();

        Check.That(!server.ClientConnected(0));
        Check.That(server.ClientConnected(1));
        Check.That(server.NumConnectedClients == 1);
        Check.That(loopbackClient.State == ClientState.Disconnected);
    }

    public static void TestLoopbackDisconnectReentry()
    {
        // a disconnect callback that disconnects its own loopback slot again, or stops the
        // server, sees the departing client once, already disconnected and still readable

        int callbackCount = 0;
        bool stopInCallback = false;
        Server? serverRef = null;

        var config = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, OverrideSendAndReceive = true };
        TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
        config.SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => { };
        config.ReceivePacketOverride = (ref Address from, Span<byte> data) => 0;
        config.SendLoopbackPacket = (clientIndex, payload, sequence) => { };
        config.OnClientConnectDisconnect = (clientIndex, connected) =>
        {
            if (connected)
                return;

            callbackCount++;

            // bounded so a regression fails the checks below instead of overflowing the stack
            if (callbackCount > 4)
                return;

            if (stopInCallback)
            {
                serverRef!.Stop();
                return;
            }

            Check.That(!serverRef!.ClientConnected(clientIndex));
            Check.That(serverRef.ClientId(clientIndex) == 0x5151);
            serverRef.DisconnectLoopbackClient(clientIndex);
        };

        using var server = new Server("127.0.0.1:40000", config, 1000.0);
        serverRef = server;

        server.Start(2);
        server.ConnectLoopbackClient(1, 0x5151, ReadOnlySpan<byte>.Empty);
        Check.That(server.NumConnectedClients == 1);

        server.DisconnectLoopbackClient(1);
        Check.That(callbackCount == 1);
        Check.That(!server.ClientConnected(1));
        Check.That(server.ClientId(1) == 0);
        Check.That(server.NumConnectedClients == 0);

        server.ConnectLoopbackClient(1, 0x5151, ReadOnlySpan<byte>.Empty);
        Check.That(server.NumConnectedClients == 1);

        callbackCount = 0;
        stopInCallback = true;
        server.DisconnectLoopbackClient(1);
        Check.That(callbackCount == 1);
        Check.That(!server.Running);
        Check.That(server.NumConnectedClients == 0);
    }

    private static void TestLoopbackStateChanges()
    {
        int changes = 0;
        Client? clientRef = null;
        var config = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> payload) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> payload) => 0,
            SendLoopbackPacket = (clientIndex, payload, sequence) => { },
            OnStateChange = (previous, next) =>
            {
                if (changes == 0)
                {
                    Check.That(previous == ClientState.Disconnected);
                    Check.That(next == ClientState.Connected);
                    Check.That(clientRef!.IsLoopback);
                    Check.That(clientRef.ClientIndex == 2);
                    Check.That(clientRef.MaxClients == 4);
                }
                else
                {
                    Check.That(changes == 1);
                    Check.That(previous == ClientState.Connected);
                    Check.That(next == ClientState.Disconnected);
                }
                changes++;
            },
        };
        using var client = new Client("127.0.0.1:40000", config, 1000.0);
        clientRef = client;

        client.ConnectLoopback(2, 4);
        Check.That(changes == 1);
        Check.That(client.State == ClientState.Connected);

        client.DisconnectLoopback();
        Check.That(changes == 2);
        Check.That(client.State == ClientState.Disconnected);
    }

    private static void TestClientStateChangeNotification()
    {
        Client? clientRef = null;
        bool observedNewState = false;
        int disconnectNotifications = 0;
        var callbackException = new InvalidOperationException("state notification");
        var config = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> payload) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> payload) => 0,
            SendLoopbackPacket = (clientIndex, payload, sequence) => { },
            OnStateChange = (previous, next) =>
            {
                if (next != ClientState.Disconnected)
                    return;
                Check.That(previous == ClientState.Connected);
                observedNewState = clientRef!.State == next;
                disconnectNotifications++;
                throw callbackException;
            },
        };
        using var client = new Client("127.0.0.1:40000", config, 1000.0);
        clientRef = client;
        client.ConnectLoopback(0, 1);

        try
        {
            client.Disconnect();
            Check.That(false);
        }
        catch (InvalidOperationException exception)
        {
            Check.That(ReferenceEquals(exception, callbackException));
        }

        Check.That(observedNewState);
        Check.That(client.State == ClientState.Disconnected);
        Check.That(disconnectNotifications == 1);
        client.Disconnect();
        Check.That(disconnectNotifications == 1);
    }

    public static void TestClientCreateMissingOverrideCallback()
    {
        // override_send_and_receive with either override callback missing is refused at
        // create time with the new code, rather than calling null on the first update.

        var config = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> payload) => { },
        };

        try
        {
            using var client = new Client("127.0.0.1:40000", config);
            Check.That(false);
        }
        catch (NetcodeException e)
        {
            Check.That(e.ErrorCode == (int)ClientCreateError.MissingOverrideCallback);
        }

        config.SendPacketOverride = null;
        config.ReceivePacketOverride = (ref Address from, Span<byte> payload) => 0;

        try
        {
            using var client = new Client("127.0.0.1:40000", config);
            Check.That(false);
        }
        catch (NetcodeException e)
        {
            Check.That(e.ErrorCode == (int)ClientCreateError.MissingOverrideCallback);
        }
    }

    public static void TestServerCreateMissingOverrideCallback()
    {
        // override_send_and_receive with either override callback missing is refused at
        // create time with the new code, rather than calling null on the first update.

        var config = CreateServerConfig(null);
        config.OverrideSendAndReceive = true;
        config.SendPacketOverride = (in Address to, ReadOnlySpan<byte> payload) => { };

        try
        {
            using var server = new Server("127.0.0.1:40000", config);
            Check.That(false);
        }
        catch (NetcodeException e)
        {
            Check.That(e.ErrorCode == (int)ServerCreateError.MissingOverrideCallback);
        }

        config.SendPacketOverride = null;
        config.ReceivePacketOverride = (ref Address from, Span<byte> payload) => 0;

        try
        {
            using var server = new Server("127.0.0.1:40000", config);
            Check.That(false);
        }
        catch (NetcodeException e)
        {
            Check.That(e.ErrorCode == (int)ServerCreateError.MissingOverrideCallback);
        }
    }

    public static void TestClientLoopbackRequiresCallback()
    {
        // entering loopback with SendLoopbackPacket unset must refuse to connect, in
        // every build, rather than calling null on the next send.

        using var client = new Client("127.0.0.1:40000", new ClientConfig { Simulator = new NetworkSimulator() }, 1000.0);

        client.ConnectLoopback(0, 1);

        byte[] payload = new byte[Protocol.MaxPacketSize];
        client.SendPacket(payload);

        Check.That(client.State == ClientState.Disconnected);
        Check.That(!client.IsLoopback);
    }

    public static void TestServerLoopbackRequiresCallback()
    {
        // attaching a loopback client with SendLoopbackPacket unset must refuse the slot,
        // in every build, rather than calling null on the next send.

        using var server = new Server("127.0.0.1:40000", CreateServerConfig(new NetworkSimulator()), 1000.0);
        server.Start(1);

        server.ConnectLoopbackClient(0, 0x11111111, ReadOnlySpan<byte>.Empty);

        byte[] payload = new byte[Protocol.MaxPacketSize];
        server.SendPacket(0, payload);

        Check.That(!server.ClientLoopback(0));
        Check.That(!server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 0);
    }

    // functional tests below: real loopback sockets. each binds an ephemeral port
    // first and reuses the port the OS gave it, so nothing depends on a fixed port
    // being free, and no packets are exchanged.

    public static void TestClientCreatePortInUse()
    {
        // functional. port of the "port already in use" blocks of test_client_create_error:
        // a second client bound to a port in use fails at socket creation, per family.

        {
            using var first = new Client("127.0.0.1:0");
            Check.That(first.Port != 0);
            try
            {
                using var second = new Client($"127.0.0.1:{first.Port}");
                Check.That(false);
            }
            catch (NetcodeException e)
            {
                Check.That(e.ErrorCode == (int)ClientCreateError.CreateSocketIpv4Failed);
            }
        }

        {
            using var first = new Client("[::1]:0");
            Check.That(first.Port != 0);
            try
            {
                using var second = new Client($"[::1]:{first.Port}");
                Check.That(false);
            }
            catch (NetcodeException e)
            {
                Check.That(e.ErrorCode == (int)ClientCreateError.CreateSocketIpv6Failed);
            }
        }
    }

    public static void TestServerCreatePortInUse()
    {
        // functional. port of the "port already in use" blocks of test_server_create_error:
        // a port in use is reported as a bind failure, distinct from other socket errors,
        // per family.

        {
            using var first = new Server("127.0.0.1:0", CreateServerConfig(null));
            Check.That(first.Port != 0);
            try
            {
                using var second = new Server($"127.0.0.1:{first.Port}", CreateServerConfig(null));
                Check.That(false);
            }
            catch (NetcodeException e)
            {
                Check.That(e.ErrorCode == (int)ServerCreateError.BindSocketIpv4Failed);
            }
        }

        {
            using var first = new Server("[::1]:0", CreateServerConfig(null));
            Check.That(first.Port != 0);
            try
            {
                using var second = new Server($"[::1]:{first.Port}", CreateServerConfig(null));
                Check.That(false);
            }
            catch (NetcodeException e)
            {
                Check.That(e.ErrorCode == (int)ServerCreateError.BindSocketIpv6Failed);
            }
        }
    }

    private static System.Net.Sockets.Socket UnderlyingSocket(object owner, string field)
    {
        const System.Reflection.BindingFlags Flags = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance;

        object? netcodeSocket = owner.GetType().GetField(field, Flags)?.GetValue(owner);
        Check.That(netcodeSocket is NetcodeSocket);

        object? socket = typeof(NetcodeSocket).GetField("_socket", Flags)?.GetValue(netcodeSocket);
        Check.That(socket is System.Net.Sockets.Socket);

        return (System.Net.Sockets.Socket)socket!;
    }

    private static int TrafficClass(System.Net.Sockets.Socket socket)
    {
        if (socket.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            // IPV6_TCLASS: 67 on linux, 36 on macOS/BSD
            int optname = OperatingSystem.IsLinux() ? 67 : 36;
            byte[] value = new byte[4];
            int bytes = socket.GetRawSocketOption(41 /* IPPROTO_IPV6 */, optname, value);
            Check.That(bytes == 4);
            return BitConverter.ToInt32(value, 0);
        }

        object? tos = socket.GetSocketOption(System.Net.Sockets.SocketOptionLevel.IP, System.Net.Sockets.SocketOptionName.TypeOfService);
        Check.That(tos is int);
        return (int)tos!;
    }

    public static void TestPacketTagging()
    {
        // functional. port of test_packet_tagging: create a server and a client with
        // packet tagging on and connect, over ipv4 and ipv6. beyond the C smoke test,
        // read the option back from each socket: DSCP EF (46) as IP_TOS / IPV6_TCLASS
        // when tagging is on, and not 46 when it is off. tagging is a documented no-op
        // on Windows, so the option is only checked elsewhere.

        string[] bindAddresses = { "127.0.0.1", "[::1]" };
        string[] socketFields = { "_socketIpv4", "_socketIpv6" };

        for (int i = 0; i < bindAddresses.Length; i++)
        {
            foreach (bool tagging in new[] { true, false })
            {
                var serverConfig = CreateServerConfig(null);
                serverConfig.EnablePacketTagging = tagging;

                using var server = new Server($"{bindAddresses[i]}:0", serverConfig);
                Check.That(server.Port != 0);

                using var client = new Client($"{bindAddresses[i]}:0", new ClientConfig { EnablePacketTagging = tagging });
                Check.That(client.Port != 0);

                byte[] connectToken = GenerateConnectToken($"{bindAddresses[i]}:{server.Port}", TestConstants.TestClientId);

                server.Start(1);
                client.Connect(connectToken);
                Check.That(client.State == ClientState.SendingConnectionRequest);

                if (OperatingSystem.IsWindows())
                    continue;

                int serverTrafficClass = TrafficClass(UnderlyingSocket(server, socketFields[i]));
                int clientTrafficClass = TrafficClass(UnderlyingSocket(client, socketFields[i]));

                if (tagging)
                {
                    Check.That(serverTrafficClass == 46);
                    Check.That(clientTrafficClass == 46);
                }
                else
                {
                    Check.That(serverTrafficClass != 46);
                    Check.That(clientTrafficClass != 46);
                }
            }
        }
    }
}

// The functional tier: real UDP sockets on fixed loopback ports, and real time.
// Run with --functional; the default run is the unit tier above.
internal static class FunctionalTests
{
    public static void TestClientCreate()
    {
        {
            using var client = new Client("127.0.0.1:40000");
            Check.That(client.Port == 40000);
            Check.That(client.State == ClientState.Disconnected);
        }
        {
            using var client = new Client("[::]:50000");
            Check.That(client.Port == 50000);
        }
        {
            using var client = new Client("127.0.0.1:40000", "[::]:50000", null, 0.0);
            Check.That(client.Port == 40000);
        }
        {
            using var client = new Client("[::]:50000", "127.0.0.1:40000", null, 0.0);
            Check.That(client.Port == 50000);
        }
        // bad address must throw with the right error code
        try
        {
            using var client = new Client("not an address");
            Check.That(false);
        }
        catch (NetcodeException e)
        {
            Check.That(e.ErrorCode == (int)ClientCreateError.ParseAddressFailed);
        }
    }

    public static void TestServerCreate()
    {
        {
            using var server = new Server("127.0.0.1:40000", ClientServerTests.CreateServerConfig(null));
            Check.That(server.Port == 40000);
            Check.That(!server.Running);
        }
        {
            using var server = new Server("[::1]:50000", ClientServerTests.CreateServerConfig(null));
            Check.That(server.Port == 50000);
        }
        {
            using var server = new Server("127.0.0.1:40000", "[::1]:50000", ClientServerTests.CreateServerConfig(null), 0.0);
            Check.That(server.Port == 40000);
        }
        {
            using var server = new Server("[::1]:50000", "127.0.0.1:40000", ClientServerTests.CreateServerConfig(null), 0.0);
            Check.That(server.Port == 50000);
        }
        // bad address must throw with the right error code
        try
        {
            using var server = new Server("not an address", ClientServerTests.CreateServerConfig(null));
            Check.That(false);
        }
        catch (NetcodeException e)
        {
            Check.That(e.ErrorCode == (int)ServerCreateError.ParseAddressFailed);
        }
    }

    private static void ClientServerSocketConnectTo(string clientAddress, string? clientAddress2, string serverAddress, string? serverAddress2, string connectAddress)
    {
        // real sockets run on real time: each update passes the wall clock, so a lost
        // packet is resent by the client and the connect succeeds or fails within the
        // token's timeout, however long the OS takes to deliver.

        var clock = System.Diagnostics.Stopwatch.StartNew();
        double time = 1000.0;

        using var client = new Client(clientAddress, clientAddress2, null, time);
        using var server = new Server(serverAddress, serverAddress2, ClientServerTests.CreateServerConfig(null), time);

        server.Start(1);

        ulong clientId = new TestRng((ulong)Environment.TickCount64 | 1).NextUInt64();
        client.Connect(ClientServerTests.GenerateConnectToken(connectAddress, clientId));

        while (true)
        {
            time = 1000.0 + clock.Elapsed.TotalSeconds;

            client.Update(time);
            server.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;
            if (client.State == ClientState.Connected)
                break;

            Thread.Sleep(1);
        }

        Check.That(client.State == ClientState.Connected);
        Check.That(server.NumConnectedClients == 1);
    }

    private static void ClientServerSocketConnect(string clientAddress, string? clientAddress2, string serverAddress, string? serverAddress2)
    {
        ClientServerSocketConnectTo(clientAddress, clientAddress2, serverAddress, serverAddress2, serverAddress);
    }

    // N empty UDP datagrams sit ahead of one payload in the real socket queue.
    // One server Update must deliver that payload. Time is injected; this does
    // not sleep and does not wait on the clock.
    public static void TestReceiveSkipsEmptyDatagrams()
    {
        double time = 1000.0;
        // Equality with the send interval still suppresses a send, so step past it.
        double step = (1.0 / Defines.PacketSendRate) + 1e-3;

        // The server's public address, port included, must be the address in the
        // connect token. Port 0 would stay 0 in that address after the bind.
        ushort port;
        using (var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            port = (ushort)((IPEndPoint)probe.LocalEndPoint!).Port;
        }

        string serverAddress = $"127.0.0.1:{port}";
        using var server = new Server(serverAddress, ClientServerTests.CreateServerConfig(null), time);
        server.Start(1);
        using var client = new Client("127.0.0.1:0", null, time);

        client.Connect(ClientServerTests.GenerateConnectToken(serverAddress, 0xE001));

        for (int i = 0; i < 32 && client.State > ClientState.Disconnected && client.State != ClientState.Connected; i++)
        {
            client.Update(time);
            server.Update(time);
            time += step;
        }

        Check.That(client.State == ClientState.Connected);
        Check.That(server.NumConnectedClients == 1);
        Check.That(server.ClientConnected(0));

        byte[] packetData = new byte[32];
        for (int i = 0; i < packetData.Length; i++)
            packetData[i] = unchecked((byte)(i ^ 0x5A));

        const int emptyDatagrams = 8;
        using (var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            var serverEndpoint = new IPEndPoint(IPAddress.Loopback, server.Port);
            for (int i = 0; i < emptyDatagrams; i++)
                sender.SendTo(Array.Empty<byte>(), serverEndpoint);
        }

        client.SendPacket(packetData);

        server.Update(time);

        byte[] received = new byte[Protocol.MaxPacketSize];
        int bytes = server.ReceivePacket(0, received, out _);
        Check.That(bytes == packetData.Length);
        Check.That(received.AsSpan(0, bytes).SequenceEqual(packetData));
    }

    public static void TestClientServerIpv4SocketConnect()
    {
        TestReceiveSkipsEmptyDatagrams();
        ClientServerSocketConnect("0.0.0.0:50000", null, "127.0.0.1:40000", null);
        ClientServerSocketConnect("0.0.0.0:50000", null, "127.0.0.1:40000", "[::1]:40000");
        ClientServerSocketConnect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", null);
        ClientServerSocketConnect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000");
    }

    public static void TestClientServerIpv6SocketConnect()
    {
        ClientServerSocketConnect("[::]:50000", null, "[::1]:40000", null);
        ClientServerSocketConnect("[::]:50000", null, "[::1]:40000", "127.0.0.1:40000");
        ClientServerSocketConnect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", null);
        ClientServerSocketConnect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000");
    }

    public static void TestClientServerDualSocketConnect()
    {
        // dual stack client connects to dual stack server over ipv4, then over ipv6

        ClientServerSocketConnect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000");
        ClientServerSocketConnect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000");

        // dual stack client connects to the second address of a dual stack server

        ClientServerSocketConnectTo("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000", "[::1]:40000");
        ClientServerSocketConnectTo("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000", "127.0.0.1:40000");
    }
}

internal static class Soak
{
    // A bounded version of the C library's soak.c: clients randomly connect,
    // exchange random payloads through a lossy simulated network, and randomly
    // disconnect, forever (here: for a fixed number of iterations).
    public static int Run(int iterations)
    {
        Console.WriteLine($"[netcode.cs soak] {iterations} iterations");

        const int MaxClients = 16;

        var rng = new TestRng(0x50AC);
        var simulator = new NetworkSimulator
        {
            LatencyMilliseconds = 100,
            JitterMilliseconds = 50,
            PacketLossPercent = 2,
            DuplicatePacketPercent = 5,
        };

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        var serverConfig = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, Simulator = simulator };
        TestConstants.PrivateKey.CopyTo(serverConfig.PrivateKey, 0);

        using var server = new Server("[::1]:40000", serverConfig, time);
        server.Start(MaxClients);

        var clients = new Client[MaxClients];
        for (int i = 0; i < MaxClients; i++)
            clients[i] = new Client($"[::]:{50000 + i}", new ClientConfig { Simulator = simulator }, time);

        byte[] payload = new byte[Protocol.MaxPacketSize];
        byte[] received = new byte[Protocol.MaxPacketSize];

        long totalClientPacketsReceived = 0;
        long totalServerPacketsReceived = 0;
        long totalConnects = 0;

        for (int iteration = 0; iteration < iterations; iteration++)
        {
            simulator.Update(time);

            for (int i = 0; i < MaxClients; i++)
            {
                Client client = clients[i];
                client.Update(time);

                if (client.State == ClientState.Connected)
                {
                    int payloadBytes = 1 + rng.Next(Protocol.MaxPacketSize);
                    rng.Fill(payload.AsSpan(0, payloadBytes));
                    client.SendPacket(payload.AsSpan(0, payloadBytes));

                    while (client.ReceivePacket(received, out _) >= 0)
                        totalClientPacketsReceived++;

                    if (rng.Next(200) == 0)
                        client.Disconnect();
                }
                else if (client.State <= ClientState.Disconnected)
                {
                    if (rng.Next(20) == 0)
                    {
                        byte[] connectToken = new byte[Protocol.ConnectTokenBytes];
                        byte[] userData = new byte[Protocol.UserDataBytes];
                        rng.Fill(userData);
                        string[] address = { "[::1]:40000" };
                        if (!ConnectTokenGenerator.Generate(address, address, 60, 5, rng.NextUInt64(), TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken))
                        {
                            Console.WriteLine("soak: failed to generate connect token");
                            return 1;
                        }
                        client.Connect(connectToken);
                        totalConnects++;
                    }
                }
            }

            server.Update(time);

            for (int i = 0; i < server.MaxClients; i++)
            {
                if (!server.ClientConnected(i))
                    continue;

                int payloadBytes = 1 + rng.Next(Protocol.MaxPacketSize);
                rng.Fill(payload.AsSpan(0, payloadBytes));
                server.SendPacket(i, payload.AsSpan(0, payloadBytes));

                while (server.ReceivePacket(i, received, out _) >= 0)
                    totalServerPacketsReceived++;

                if (rng.Next(500) == 0)
                    server.DisconnectClient(i);
            }

            time += deltaTime;

            if (iteration % 1000 == 0 && iteration > 0)
                Console.WriteLine($"  iteration {iteration}: {server.NumConnectedClients} connected, client rx {totalClientPacketsReceived}, server rx {totalServerPacketsReceived}");
        }

        foreach (Client client in clients)
            client.Dispose();

        Console.WriteLine($"soak complete: {totalConnects} connects, client rx {totalClientPacketsReceived}, server rx {totalServerPacketsReceived}");

        if (totalConnects == 0 || totalClientPacketsReceived == 0 || totalServerPacketsReceived == 0)
        {
            Console.WriteLine("soak FAILED: no traffic was exchanged");
            return 1;
        }

        Console.WriteLine("soak PASSED");
        return 0;
    }
}
