/*
    ClientServer.cs — client/server integration tests, ported test-for-test from
    netcode.c: deterministic network-simulator tests plus real UDP socket
    connects, all error states, disconnect flows, reconnect, disable timeout and
    loopback. Also the soak runner.
*/

using System;
using System.Net.Sockets;
using System.Threading;

namespace Netcode.Tests;

internal static class ClientServerTests
{
    private static byte[] GenerateConnectToken(string serverAddress, ulong clientId, int expiry = TestConstants.TestConnectTokenExpiry, int timeout = TestConstants.TestTimeoutSeconds)
    {
        return GenerateConnectToken(new[] { serverAddress }, clientId, expiry, timeout);
    }

    private static byte[] GenerateConnectToken(string[] serverAddresses, ulong clientId, int expiry = TestConstants.TestConnectTokenExpiry, int timeout = TestConstants.TestTimeoutSeconds)
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

    private static ServerConfig CreateServerConfig(NetworkSimulator? simulator)
    {
        var config = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, Simulator = simulator };
        TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
        return config;
    }

    private static void StartServerForTests(Server server, int maxClients)
    {
        server.Start(maxClients);
        // Session tests mint tokens in the server-start second. Place their test
        // floor one second earlier so a 30-second token can exercise the session;
        // the exact floor boundary has a separate packet-reader regression test.
        server.SetConnectTokenExpiryFloorForTest(
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds() + Protocol.DefaultMaxConnectTokenLifetime - 1);
    }

    private static Server OverrideServer(string address)
    {
        var config = new ServerConfig
        {
            ProtocolId = TestConstants.TestProtocolId,
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> data) => 0,
        };
        TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
        return new Server(address, config, 0.0);
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
            using var server = new Server("127.0.0.1:40000", CreateServerConfig(null));
            Check.That(server.Port == 40000);
            Check.That(!server.Running);
        }
        {
            using var server = new Server("[::1]:50000", CreateServerConfig(null));
            Check.That(server.Port == 50000);
        }
        {
            using var server = new Server("127.0.0.1:40000", "[::1]:50000", CreateServerConfig(null), 0.0);
            Check.That(server.Port == 40000);
        }
        {
            using var server = new Server("[::1]:50000", "127.0.0.1:40000", CreateServerConfig(null), 0.0);
            Check.That(server.Port == 50000);
        }
        // bad address must throw with the right error code
        try
        {
            using var server = new Server("not an address", CreateServerConfig(null));
            Check.That(false);
        }
        catch (NetcodeException e)
        {
            Check.That(e.ErrorCode == (int)ServerCreateError.ParseAddressFailed);
        }
    }

    public static void TestServerRestartGlobalSequence()
    {
        // global packets (challenge, denied) share per-token server to client keys with
        // per-client packets, so the global sequence must stay in the top half of the
        // sequence space. stop zeroes it; start re-seeds a random offset in that half.

        using var server = new Server("127.0.0.1:40000", CreateServerConfig(null));

        Check.That(server.GlobalSequence == 1UL << 63);

        StartServerForTests(server, 1);

        Check.That(server.GlobalSequence >= 1UL << 63);

        server.GlobalSequence += 1000; // as if the server had sent some global packets

        server.Stop();

        StartServerForTests(server, 1);

        Check.That(server.GlobalSequence >= 1UL << 63);
    }

    public static void TestGlobalSequenceDiffersBetweenServers()
    {
        // one connect token carries one server to client key for every server it lists.
        // two servers that both start at 2^63 encrypt their first challenge under the
        // same key and nonce. each start must draw a different sequence in the top half.

        using var server1 = OverrideServer("127.0.0.1:40000");
        using var server2 = OverrideServer("127.0.0.1:40001");
        server1.Start(1);
        StartServerForTests(server2, 1);

        Check.That(server1.GlobalSequence != server2.GlobalSequence);
        Check.That(server1.GlobalSequence >= 1UL << 63);
        Check.That(server2.GlobalSequence >= 1UL << 63);
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
        Check.That(history.State(index) == ConnectTokenEntryState.Pending);
        Check.That(history.EntryTime(index) == 100.0);

        Check.That(history.FindOrAdd(in addressA, mac, expireTimestamp, currentTimestamp, 200.0) == index);
        Check.That(history.EntryTime(index) == 100.0);
        Check.That(history.FindOrAdd(in addressB, mac, expireTimestamp, currentTimestamp, 200.0) == ConnectTokenHistory.Refused);

        history.Consume(index);
        Check.That(history.State(index) == ConnectTokenEntryState.Consumed);
        Check.That(history.FindOrAdd(in addressA, mac, expireTimestamp, currentTimestamp, 300.0) == ConnectTokenHistory.Refused);
        Check.That(history.FindOrAdd(in addressB, mac, expireTimestamp, currentTimestamp, 300.0) == ConnectTokenHistory.Refused);

        for (int i = 1; i < ConnectTokenHistory.MaxEntries; i++)
        {
            mac = new byte[Protocol.MacBytes];
            mac[0] = (byte)(i + 1);
            mac[1] = (byte)((i + 1) >> 8);
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
        double time = 0.0;
        double deltaTime = 1.0 / 10.0;
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);
        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        StartServerForTests(server, 1);

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

        Check.That(client.State == ClientState.InvalidConnectToken);
        Check.That(server.NumConnectedClients == 0);
    }

    public static void TestClientRefusesAReusedConnectToken()
    {
        // a client that connects, disconnects, then connects again with the same token
        // bytes would encrypt again from sequence zero under the same client to server
        // key. it must refuse the reused token before sending.

        var config = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> data) => 0,
        };
        using var client = new Client("127.0.0.1:50000", config, 0.0);
        byte[] connectToken = GenerateConnectToken("127.0.0.1:40000", TestConstants.TestClientId);

        client.Connect(connectToken);
        Check.That(client.State == ClientState.SendingConnectionRequest);

        client.Disconnect();
        Check.That(client.State == ClientState.Disconnected);

        client.Connect(connectToken);
        Check.That(client.State == ClientState.InvalidConnectToken);
    }

    public static void TestConnectionResponseUsesItsMappingChallenge()
    {
        // This functional server path reads the wall clock for token expiry. It uses
        // an override transport and performs no socket I/O or sleep.
        byte[] sent = Array.Empty<byte>();
        var config = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, OverrideSendAndReceive = true };
        TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
        config.SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => sent = data.ToArray();
        config.ReceivePacketOverride = (ref Address from, Span<byte> data) => 0;
        using var server = new Server("127.0.0.1:40000", config, 0.0);
        StartServerForTests(server, 4);
        Address x = Address.Parse("127.0.0.1:50000");
        Address y = Address.Parse("127.0.0.1:50001");

        ConnectTokenData Token(ulong id, byte marker)
        {
            byte[] bytes = new byte[Protocol.ConnectTokenBytes];
            byte[] userData = new byte[Protocol.UserDataBytes];
            Array.Fill(userData, marker);
            string[] addresses = { "127.0.0.1:40000" };
            Check.That(ConnectTokenGenerator.Generate(addresses, addresses, 30, 15, id,
                TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, bytes));
            var token = new ConnectTokenData();
            Check.That(token.Read(bytes));
            return token;
        }

        ConnectTokenData a = Token(0x1111, 0xA1);
        ConnectTokenData b = Token(0x2222, 0xB2);
        ConnectTokenData c = Token(0x3333, 0xC3);

        void Request(in Address from, ConnectTokenData token)
        {
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteConnectionRequestPacket(wire, token.VersionInfo, token.ProtocolId,
                token.ExpireTimestamp, token.Nonce, token.PrivateData);
            server.ProcessPacket(in from, wire.AsSpan(0, bytes));
        }

        byte[] Challenge(ConnectTokenData token)
        {
            byte[] wire = (byte[])sent.Clone();
            bool[] allowed = new bool[PacketType.NumPackets];
            allowed[PacketType.ConnectionChallenge] = true;
            ReadPacketResult packet = PacketIO.ReadPacket(wire, true, token.ServerToClientKey,
                TestConstants.TestProtocolId, 0, false, ReadOnlySpan<byte>.Empty, allowed, null);
            Check.That(packet.Type == PacketType.ConnectionChallenge);
            return wire.AsSpan(packet.DataOffset, packet.DataLength).ToArray();
        }

        void Response(in Address from, ConnectTokenData token, byte[] challenge, ulong sequence)
        {
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteEncryptedPacket(wire, PacketType.ConnectionResponse,
                challenge, sequence, token.ClientToServerKey, TestConstants.TestProtocolId);
            server.ProcessPacket(in from, wire.AsSpan(0, bytes));
        }

        Request(in x, a);
        byte[] challengeA = Challenge(a);
        Request(in y, b);
        byte[] challengeB = Challenge(b);
        Response(in y, b, challengeA, 1);
        Check.That(server.NumConnectedClients == 0);
        Response(in y, b, challengeB, 2);
        Check.That(server.NumConnectedClients == 1);
        Check.That(server.ClientId(0) == 0x2222);
        Check.That(server.ClientUserData(0)[0] == 0xB2);
        Request(in x, c);
        byte[] challengeCFirst = Challenge(c);
        Request(in x, c);
        byte[] challengeCSecond = Challenge(c);
        Check.That(!challengeCFirst.AsSpan().SequenceEqual(challengeCSecond));
        Response(in x, c, challengeA, 1);
        Check.That(server.NumConnectedClients == 1);
        Response(in x, c, challengeCFirst, 2);
        Check.That(server.NumConnectedClients == 2);
        Check.That(server.ClientId(1) == 0x3333);
        Check.That(server.ClientUserData(1)[0] == 0xC3);
    }

    public static void TestClientErrorConnectTokenPredatesServerStart()
    {
        NetworkSimulator simulator = CreateSimulator();
        double time = 0.0;
        double deltaTime = 1.0 / 10.0;
        var serverConfig = CreateServerConfig(simulator);
        serverConfig.MaxConnectTokenLifetime = 30;
        using var server = new Server("[::1]:40000", serverConfig, time);
        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        StartServerForTests(server, 1);

        client.Connect(GenerateConnectToken("[::1]:40000", 0x1234, expiry: 20));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.ConnectionRequestTimedOut);
        Check.That(server.NumConnectedClients == 0);

        simulator.Reset();
        client.Connect(GenerateConnectToken("[::1]:40000", 0x5678, expiry: 30));
        ConnectLoop(simulator, client, server, ref time, deltaTime);
        Check.That(client.State == ClientState.Connected);
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestClientServerConnect()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

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
            packetData[i] = (byte)i;

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

    private static void ClientServerSocketConnectTo(string clientAddress, string? clientAddress2, string serverAddress, string? serverAddress2, string connectAddress)
    {
        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client(clientAddress, clientAddress2, null, time);
        using var server = new Server(serverAddress, serverAddress2, CreateServerConfig(null), time);

        StartServerForTests(server, 1);

        ulong clientId = new TestRng((ulong)Environment.TickCount64 | 1).NextUInt64();
        client.Connect(GenerateConnectToken(connectAddress, clientId));

        while (true)
        {
            client.Update(time);
            server.Update(time);

            if (client.State <= ClientState.Disconnected)
                break;
            if (client.State == ClientState.Connected)
                break;

            // this test runs over real sockets while advancing virtual time, so it must
            // yield real time each iteration or the virtual timeouts can expire before
            // the OS delivers a single loopback packet
            Thread.Sleep(10);

            time += deltaTime;
        }

        Check.That(client.State == ClientState.Connected);
        Check.That(server.NumConnectedClients == 1);
    }

    private static void ClientServerSocketConnect(string clientAddress, string? clientAddress2, string serverAddress, string? serverAddress2)
    {
        ClientServerSocketConnectTo(clientAddress, clientAddress2, serverAddress, serverAddress2, serverAddress);
    }

    public static void TestClientServerIpv4SocketConnect()
    {
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

    public static void TestClientServerKeepAlive()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

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

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        for (int i = 0; i < maxClients.Length; i++)
        {
            StartServerForTests(server, maxClients[i]);

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
                packetData[j] = (byte)j;

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

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

        // the first two addresses point at servers that do not exist; the client works
        // through them and connects to the third

        string[] serverAddresses = { "10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000" };

        client.Connect(GenerateConnectToken(serverAddresses, 0x8877));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);
        Check.That(client.ClientIndex == 0);
        Check.That(server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestClientErrorConnectTokenExpired()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 0.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);

        // a token that expires immediately: the client transitions to ConnectTokenExpired

        client.Connect(GenerateConnectToken("[::1]:40000", 0x1, expiry: 0));

        client.Update(time);

        Check.That(client.State == ClientState.ConnectTokenExpired);
    }

    public static void TestClientErrorInvalidConnectToken()
    {
        NetworkSimulator simulator = CreateSimulator();

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, 0.0);

        byte[] garbage = new byte[Protocol.ConnectTokenBytes];
        new TestRng(0xBAD).Fill(garbage);

        client.Connect(garbage);

        Check.That(client.State == ClientState.InvalidConnectToken);
    }

    public static void TestClientCanReach()
    {
        // a client bound for one address family has no socket for the other; a
        // simulator or override client reaches every address

        Check.That(Client.CanReach(AddressType.IPv4, true, false, false));
        Check.That(!Client.CanReach(AddressType.IPv6, true, false, false));
        Check.That(Client.CanReach(AddressType.IPv6, false, true, false));
        Check.That(!Client.CanReach(AddressType.IPv4, false, true, false));
        Check.That(Client.CanReach(AddressType.IPv4, false, false, true));
        Check.That(Client.CanReach(AddressType.IPv6, false, false, true));
        Check.That(!Client.CanReach(AddressType.None, true, true, false));
    }

    public static void TestClientRefusesServerAddressWithoutSocket()
    {
        // an IPv4-only client given a token whose only server address is IPv6 must
        // refuse it; a token with a reachable IPv4 address must settle on it

        var config = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> data) => 0,
        };
        using var client = new Client("0.0.0.0:50000", config, 0.0);
        client.SocketAvailabilityOverride = type => Client.CanReach(type, true, false, false);

        byte[] Token(string[] addresses, ulong clientId)
        {
            Address[] parsed = Array.ConvertAll(addresses, Address.Parse);
            byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
            nonce[0] = (byte)clientId;
            byte[] token = new byte[Protocol.ConnectTokenBytes];
            Check.That(ConnectTokenGenerator.GenerateInternal(parsed, parsed, 1000, 1030, 15,
                clientId, TestConstants.TestProtocolId, TestConstants.PrivateKey,
                new byte[Protocol.UserDataBytes], nonce, token));
            return token;
        }

        byte[] token6 = Token(new[] { "[::1]:40000" }, 0x1);
        client.Connect(token6);
        Check.That(client.State == ClientState.InvalidConnectToken);

        byte[] tokenMixed = Token(new[] { "[::1]:40000", "127.0.0.1:40000" }, 0x2);
        client.Connect(tokenMixed);
        Check.That(client.State == ClientState.SendingConnectionRequest);
        Check.That(client.ServerAddressIndex == 1);
        Check.That(client.ServerAddress.Equals(Address.Parse("127.0.0.1:40000")));

        byte[] token4 = Token(new[] { "127.0.0.1:40000" }, 0x3);
        client.Connect(token4);
        Check.That(client.State == ClientState.SendingConnectionRequest);
        Check.That(client.ServerAddressIndex == 0);
        Check.That(client.ServerAddress.Equals(Address.Parse("127.0.0.1:40000")));

        byte[] token4Then6 = Token(new[] { "127.0.0.1:40000", "[::1]:40000" }, 0x4);
        client.Connect(token4Then6);
        Check.That(client.ConnectToNextServer());
        Check.That(client.State == ClientState.InvalidConnectToken);
    }

    public static void TestClientErrorConnectionTimedOut()
    {
        // connect a client to a server, then stop updating the server. the client
        // must transition to ConnectionTimedOut.

        NetworkSimulator simulator = CreateSimulator();

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

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

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

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

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

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

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

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

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

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

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

        client.Connect(GenerateConnectToken("[::1]:40000", 0x8));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);

        server.DisconnectClient(0);

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

    /// <summary>A scripted ReceivePacketOverride: values &gt; 0 are junk datagrams of that length, -1 means skip (an empty datagram or a receive error), 0 means would-block (nothing more).</summary>
    private sealed class DrainScript
    {
        private readonly int[] _script;
        private int _index;

        public int Calls;
        public int Processed;

        public DrainScript(params int[] script) => _script = script;

        public int Receive(ref Address from, Span<byte> packetData)
        {
            int result = _index < _script.Length ? _script[_index] : 0;
            _index++;
            Calls++;

            if (result > 0)
            {
                Processed++;
                for (int i = 0; i < result; i++)
                    packetData[i] = 0xFF; // junk: an invalid prefix byte that every reader refuses
                from = Address.Parse("203.0.113.7:12345");
            }

            return result;
        }

        public void Send(in Address to, ReadOnlySpan<byte> packetData)
        {
        }
    }

    public static void TestReceiveDrainSkipsEmptyAndStopsAtCap()
    {
        // a zero-length UDP datagram is legal and must not end the drain: only a
        // would-block does (the C fix, netcode_classify_receive_result). the loops
        // count every iteration and stop at the per-update caps.

        // classifier rows (the port of netcode_classify_receive_result):
        // (0,0) -> skip, (-1,would-block) -> drained, (-1,other error) -> skip, (5,0) -> 5

        Check.That(NetcodeSocket.ClassifyReceiveResult(0, SocketError.Success) == -1);
        Check.That(NetcodeSocket.ClassifyReceiveResult(-1, SocketError.WouldBlock) == 0);
        Check.That(NetcodeSocket.ClassifyReceiveResult(-1, SocketError.ConnectionRefused) == -1);
        Check.That(NetcodeSocket.ClassifyReceiveResult(5, SocketError.Success) == 5);

        // server: a queue [skip, junk, junk, would-block] is consumed whole in one update
        // and the skip never reaches the packet processor

        {
            var config = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, OverrideSendAndReceive = true };
            TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
            var script = new DrainScript(-1, 11, 11, 0);
            config.SendPacketOverride = script.Send;
            config.ReceivePacketOverride = script.Receive;

            using var server = new Server("127.0.0.1:40000", config, 0.0);
            StartServerForTests(server, 1);

            server.Update(1.0);

            Check.That(script.Calls == 4);
            Check.That(script.Processed == 2);
        }

        // server: a queue of ServerMaxReceivePackets + 10 junk datagrams consumes
        // exactly ServerMaxReceivePackets in one update

        {
            int cap = Defines.ServerMaxReceivePackets;
            var queue = new int[cap + 10];
            Array.Fill(queue, 11);
            queue[cap + 9] = 0;

            var config = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, OverrideSendAndReceive = true };
            TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
            var script = new DrainScript(queue);
            config.SendPacketOverride = script.Send;
            config.ReceivePacketOverride = script.Receive;

            using var server = new Server("127.0.0.1:40000", config, 0.0);
            StartServerForTests(server, 1);

            server.Update(1.0);

            Check.That(script.Calls == cap);
            Check.That(script.Processed == cap);
        }

        // client: a queue [skip, junk, would-block] is consumed whole in one update

        {
            var config = new ClientConfig { OverrideSendAndReceive = true };
            var script = new DrainScript(-1, 11, 0);
            config.SendPacketOverride = script.Send;
            config.ReceivePacketOverride = script.Receive;

            using var client = new Client("0.0.0.0:0", config, 0.0);

            client.Update(1.0);

            Check.That(script.Calls == 3);
            Check.That(script.Processed == 1);
        }

        // client: a queue of ClientMaxReceivePackets + 10 junk datagrams consumes
        // exactly ClientMaxReceivePackets in one update

        {
            int cap = Defines.ClientMaxReceivePackets;
            var queue = new int[cap + 10];
            Array.Fill(queue, 11);
            queue[cap + 9] = 0;

            var config = new ClientConfig { OverrideSendAndReceive = true };
            var script = new DrainScript(queue);
            config.SendPacketOverride = script.Send;
            config.ReceivePacketOverride = script.Receive;

            using var client = new Client("0.0.0.0:0", config, 0.0);

            client.Update(1.0);

            Check.That(script.Calls == cap);
            Check.That(script.Processed == cap);
        }
    }

    public static void TestServerClientDisconnectReason()
    {
        // the disconnect reason is recorded before the callback fires and queryable inside it

        NetworkSimulator simulator = new NetworkSimulator();

        double time = 0.0;
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

        StartServerForTests(server, 1);

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

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

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

    public static void TestDisableTimeout()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        using var client = new Client("[::]:50000", new ClientConfig { Simulator = simulator }, time);
        using var server = new Server("[::1]:40000", CreateServerConfig(simulator), time);

        StartServerForTests(server, 1);

        // timeout of -1 disables timeouts entirely (dev only)

        client.Connect(GenerateConnectToken("[::1]:40000", 0xD15AB1E, timeout: -1));

        ConnectLoop(simulator, client, server, ref time, deltaTime);

        Check.That(client.State == ClientState.Connected);

        int serverNumPacketsReceived = 0;
        int clientNumPacketsReceived = 0;

        byte[] packetData = new byte[Protocol.MaxPacketSize];
        for (int i = 0; i < packetData.Length; i++)
            packetData[i] = (byte)i;

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

    public static void TestPreconnectMappingLifetime()
    {
        // a pre-connect encryption mapping has its own bounded lifetime: a negative
        // timeout must not hold a slot forever, and a zero timeout must not expire the
        // mapping before the response can arrive.

        byte[] sent = Array.Empty<byte>();
        var config = new ServerConfig { ProtocolId = TestConstants.TestProtocolId, OverrideSendAndReceive = true };
        TestConstants.PrivateKey.CopyTo(config.PrivateKey, 0);
        config.SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => sent = data.ToArray();
        config.ReceivePacketOverride = (ref Address from, Span<byte> data) => 0;
        using var server = new Server("127.0.0.1:40000", config, 0.0);
        StartServerForTests(server, 4);
        server.SetConnectTokenExpiryFloorForTest(1000);
        Address x = Address.Parse("127.0.0.1:50000");

        ConnectTokenData Token(int timeout)
        {
            byte[] bytes = new byte[Protocol.ConnectTokenBytes];
            byte[] userData = new byte[Protocol.UserDataBytes];
            Span<Address> addresses = stackalloc Address[1] { Address.Parse("127.0.0.1:40000") };
            Span<byte> nonce = stackalloc byte[Defines.ConnectTokenNonceBytes];
            new TestRng(0x51).Fill(nonce);
            Check.That(ConnectTokenGenerator.GenerateInternal(addresses, addresses, 1000, 1030, timeout,
                0x1111, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, nonce, bytes));
            var token = new ConnectTokenData();
            Check.That(token.Read(bytes));
            return token;
        }

        void Request(in Address from, ConnectTokenData token, double logicalTime)
        {
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteConnectionRequestPacket(wire, token.VersionInfo, token.ProtocolId,
                token.ExpireTimestamp, token.Nonce, token.PrivateData);
            server.ProcessPacketAtTimestamp(in from, wire.AsSpan(0, bytes), 1001, logicalTime);
        }

        byte[] Challenge(ConnectTokenData token)
        {
            byte[] wire = (byte[])sent.Clone();
            bool[] allowed = new bool[PacketType.NumPackets];
            allowed[PacketType.ConnectionChallenge] = true;
            ReadPacketResult packet = PacketIO.ReadPacket(wire, true, token.ServerToClientKey,
                TestConstants.TestProtocolId, 1001, false, ReadOnlySpan<byte>.Empty, allowed, null);
            Check.That(packet.Type == PacketType.ConnectionChallenge);
            return wire.AsSpan(packet.DataOffset, packet.DataLength).ToArray();
        }

        void Response(in Address from, ConnectTokenData token, byte[] challenge, double logicalTime)
        {
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteEncryptedPacket(wire, PacketType.ConnectionResponse,
                challenge, 1, token.ClientToServerKey, TestConstants.TestProtocolId);
            server.ProcessPacketAtTimestamp(in from, wire.AsSpan(0, bytes), 1001, logicalTime);
        }

        // timeout -1: the mapping must expire after the preconnect lifetime, not never
        ConnectTokenData a = Token(-1);
        Request(in x, a, 0.0);
        Check.That(server.NumEncryptionMappings == 1);
        server.Update(11.0);
        Check.That(server.NumEncryptionMappings == 0);

        // timeout 0: the mapping must survive one update so the response connects
        ConnectTokenData b = Token(0);
        Request(in x, b, 0.0);
        Check.That(server.NumEncryptionMappings == 1);
        byte[] challengeB = Challenge(b);
        Response(in x, b, challengeB, 0.1);
        Check.That(server.NumConnectedClients == 1);
    }

    public static void TestLoopback()
    {
        NetworkSimulator simulator = CreateSimulator();

        double time = 0.0;
        double deltaTime = 1.0 / 10.0;

        int numLoopbackPacketsSentToClient = 0;
        int numLoopbackPacketsSentToServer = 0;

        byte[] packetData = new byte[Protocol.MaxPacketSize];
        for (int i = 0; i < packetData.Length; i++)
            packetData[i] = (byte)i;

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

        StartServerForTests(server, 2);

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

        using var client = new Client("127.0.0.1:40000");

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

        using var server = new Server("127.0.0.1:40000", CreateServerConfig(null));
        StartServerForTests(server, 1);

        server.ConnectLoopbackClient(0, 0x11111111, ReadOnlySpan<byte>.Empty);

        byte[] payload = new byte[Protocol.MaxPacketSize];
        server.SendPacket(0, payload);

        Check.That(!server.ClientLoopback(0));
        Check.That(!server.ClientConnected(0));
        Check.That(server.NumConnectedClients == 0);
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
                        if (!ConnectTokenGenerator.Generate(address, address, 30, 5, rng.NextUInt64(), TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken))
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
