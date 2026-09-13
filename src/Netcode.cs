/*
    Netcode.cs — protocol core.

    C# port of netcode (https://github.com/mas-bandwidth/netcode), the C reference
    implementation of the netcode protocol: secure client/server connections over
    UDP. Protocol "NETCODE 1.02"; the wire is byte-identical to the C library.

    This file holds the protocol objects: addresses, connect tokens, challenge
    tokens, packet read/write, replay protection, the encryption manager, packet
    queues and the deterministic network simulator. Client.cs and Server.cs hold
    the endpoint state machines; Crypto.cs holds the AEAD constructions.

    The API is idiomatic C# over the same update-loop model as the C library:
    games call Update(time) every frame; sockets are non-blocking; nothing here
    spawns threads or tasks. Like the C library, objects are single-threaded by
    design and perform no internal synchronization.

    Copyright © 2026 Más Bandwidth LLC. Licensed under AGPL-3.0 (see LICENSE).
*/

using System;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Netcode
{
    // ------------------------------------------------------------------
    // public constants
    // ------------------------------------------------------------------

    /// <summary>Protocol-level constants shared by clients, servers and the backend.</summary>
    public static class Protocol
    {
        /// <summary>Size of a connect token: 2048 bytes.</summary>
        public const int ConnectTokenBytes = 2048;
        /// <summary>Size of an encryption key: 32 bytes.</summary>
        public const int KeyBytes = 32;
        /// <summary>Size of an AEAD authentication tag: 16 bytes.</summary>
        public const int MacBytes = 16;
        /// <summary>Size of the per-client user data carried in connect tokens: 256 bytes.</summary>
        public const int UserDataBytes = 256;
        /// <summary>Maximum number of server addresses in a connect token.</summary>
        public const int MaxServersPerConnect = 32;
        /// <summary>Maximum number of client slots per server.</summary>
        public const int MaxClients = 256;
        /// <summary>Default maximum lifetime, in seconds, of connect tokens issued by the backend.</summary>
        public const int DefaultMaxConnectTokenLifetime = 30;
        /// <summary>Largest payload accepted by SendPacket / delivered by ReceivePacket.</summary>
        public const int MaxPacketSize = 1200;
        /// <summary>The protocol version string carried on the wire (13 bytes with null terminator).</summary>
        public const string VersionInfo = "NETCODE 1.02";
    }

    internal static class Defines
    {
        public const int ConnectTokenNonceBytes = 24;
        public const int ConnectTokenPrivateBytes = 1024;
        public const int ChallengeTokenBytes = 300;
        public const int VersionInfoBytes = 13; // "NETCODE 1.02" with null terminator
        public const int MaxPacketBytes = 1300;
        public const int MaxPayloadBytes = 1200;
        public const int MaxAddressStringLength = 256;
        public const int PacketQueueSize = 256;
        public const int ReplayProtectionBufferSize = 256;
        public const int ClientMaxReceivePackets = 64;
        public const int ServerMaxReceivePackets = 64 * Protocol.MaxClients;
        public const int SocketSndbufSize = 4 * 1024 * 1024;
        public const int SocketRcvbufSize = 4 * 1024 * 1024;
        public const double PacketSendRate = 10.0;
        public const int NumDisconnectPackets = 10;

        // "NETCODE 1.02" ASCII with null terminator — 13 bytes
        public static ReadOnlySpan<byte> VersionInfo => "NETCODE 1.02\0"u8;
    }

    // ------------------------------------------------------------------
    // logging (mirrors netcode_log_level / netcode_set_printf_function)
    // ------------------------------------------------------------------

    /// <summary>Log verbosity, matching NETCODE_LOG_LEVEL_*.</summary>
    public enum LogLevel
    {
        /// <summary>No logging.</summary>
        None = 0,
        /// <summary>Errors only.</summary>
        Error = 1,
        /// <summary>Errors and connection lifecycle messages.</summary>
        Info = 2,
        /// <summary>Everything, including per-packet messages.</summary>
        Debug = 3,
    }

    /// <summary>Library logging. Off by default; set <see cref="Level"/> to enable.</summary>
    public static class NetcodeLog
    {
        /// <summary>Current log level.</summary>
        public static LogLevel Level = LogLevel.None;
        /// <summary>Where log lines go. Defaults to Console.Write.</summary>
        public static Action<string> Writer = Console.Write;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool Enabled(LogLevel level) => level <= Level;

        internal static void Error(string message) { if (Enabled(LogLevel.Error)) Writer(message); }
        internal static void Info(string message) { if (Enabled(LogLevel.Info)) Writer(message); }
        internal static void Debug(string message) { if (Enabled(LogLevel.Debug)) Writer(message); }
    }

    // ------------------------------------------------------------------
    // byte-level IO (explicit little endian, like netcode_write_uint*)
    // ------------------------------------------------------------------

    internal ref struct ByteWriter
    {
        private readonly Span<byte> _buffer;
        private int _position;

        public ByteWriter(Span<byte> buffer)
        {
            _buffer = buffer;
            _position = 0;
        }

        public int Position => _position;

        public void U8(byte value) { _buffer[_position] = value; _position += 1; }
        public void U16(ushort value) { BinaryPrimitives.WriteUInt16LittleEndian(_buffer.Slice(_position, 2), value); _position += 2; }
        public void U32(uint value) { BinaryPrimitives.WriteUInt32LittleEndian(_buffer.Slice(_position, 4), value); _position += 4; }
        public void U64(ulong value) { BinaryPrimitives.WriteUInt64LittleEndian(_buffer.Slice(_position, 8), value); _position += 8; }
        public void Bytes(ReadOnlySpan<byte> data) { data.CopyTo(_buffer.Slice(_position)); _position += data.Length; }
        public void ZeroPadTo(int length) { _buffer.Slice(_position, length - _position).Clear(); _position = length; }
    }

    internal ref struct ByteReader
    {
        private readonly ReadOnlySpan<byte> _buffer;
        private int _position;

        public ByteReader(ReadOnlySpan<byte> buffer)
        {
            _buffer = buffer;
            _position = 0;
        }

        public int Position => _position;
        public int Remaining => _buffer.Length - _position;

        public byte U8() { byte v = _buffer[_position]; _position += 1; return v; }
        public ushort U16() { ushort v = BinaryPrimitives.ReadUInt16LittleEndian(_buffer.Slice(_position, 2)); _position += 2; return v; }
        public uint U32() { uint v = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_position, 4)); _position += 4; return v; }
        public ulong U64() { ulong v = BinaryPrimitives.ReadUInt64LittleEndian(_buffer.Slice(_position, 8)); _position += 8; return v; }
        public void Bytes(Span<byte> destination) { _buffer.Slice(_position, destination.Length).CopyTo(destination); _position += destination.Length; }
        public void Skip(int count) { _position += count; }
    }

    internal static class Rng
    {
        public static void Fill(Span<byte> data) => RandomNumberGenerator.Fill(data);

        public static void GenerateKey(Span<byte> key32) => Fill(key32);

        public static void GenerateNonce(Span<byte> nonce24) => Fill(nonce24);
    }

    // ------------------------------------------------------------------
    // Address (mirrors netcode_address_t + parse/to-string helpers)
    // ------------------------------------------------------------------

    /// <summary>Address family, matching NETCODE_ADDRESS_* wire values.</summary>
    public enum AddressType : byte
    {
        /// <summary>No address.</summary>
        None = 0,
        /// <summary>IPv4 (wire value 1).</summary>
        IPv4 = 1,
        /// <summary>IPv6 (wire value 2).</summary>
        IPv6 = 2,
    }

    [InlineArray(16)]
    internal struct AddressData
    {
        private byte _element0;
    }

    /// <summary>
    /// An IPv4 or IPv6 address with port. Value type, 19 bytes of state.
    /// Parsing accepts "a.b.c.d", "a.b.c.d:port", "addr6", "[addr6]" and
    /// "[addr6]:port" with the same rules as the C library's netcode_parse_address.
    /// </summary>
    public struct Address : IEquatable<Address>
    {
        internal AddressData Data;
        /// <summary>UDP port (0 means unspecified).</summary>
        public ushort Port;
        /// <summary>Address family.</summary>
        public AddressType Type;

        /// <summary>True when no address is set.</summary>
        public bool IsNone => Type == AddressType.None;

        /// <summary>IPv4 octets a.b.c.d (valid when Type is IPv4).</summary>
        public byte GetIPv4(int index)
        {
            if ((uint)index >= 4) throw new ArgumentOutOfRangeException(nameof(index));
            return Data[index];
        }

        /// <summary>Set an IPv4 address a.b.c.d (port unchanged).</summary>
        public void SetIPv4(byte a, byte b, byte c, byte d)
        {
            Type = AddressType.IPv4;
            Data[0] = a; Data[1] = b; Data[2] = c; Data[3] = d;
        }

        /// <summary>IPv6 group (host order), index 0..7 (valid when Type is IPv6).</summary>
        public ushort GetIPv6(int index)
        {
            if ((uint)index >= 8) throw new ArgumentOutOfRangeException(nameof(index));
            ReadOnlySpan<byte> bytes = Data;
            return BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(index * 2, 2));
        }

        /// <summary>Set an IPv6 address from its eight host-order groups (port unchanged).</summary>
        public void SetIPv6(ushort g0, ushort g1, ushort g2, ushort g3, ushort g4, ushort g5, ushort g6, ushort g7)
        {
            Type = AddressType.IPv6;
            Span<byte> bytes = Data;
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(0, 2), g0);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(2, 2), g1);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(4, 2), g2);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(6, 2), g3);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(8, 2), g4);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(10, 2), g5);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(12, 2), g6);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(14, 2), g7);
        }

        internal void SetIPv6Group(int index, ushort value)
        {
            Span<byte> bytes = Data;
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(index * 2, 2), value);
        }

        /// <summary>Parse an address string, throwing FormatException on failure.</summary>
        public static Address Parse(string addressString)
        {
            if (!TryParse(addressString, out Address address))
                throw new FormatException($"failed to parse address '{addressString}'");
            return address;
        }

        /// <summary>
        /// Parse an address string. Same observable behavior as netcode_parse_address:
        /// strict decimal port in [0,65535]; IPv6 first (bracketed or raw), IPv4
        /// dotted-quad second; input truncated to 255 characters.
        /// </summary>
        public static bool TryParse(string? addressString, out Address address)
        {
            address = default;

            if (addressString == null)
                return false;

            // the C library copies into a 256-byte buffer, truncating; match that
            ReadOnlySpan<char> s = addressString.AsSpan();
            if (s.Length > Defines.MaxAddressStringLength - 1)
                s = s.Slice(0, Defines.MaxAddressStringLength - 1);

            ushort port = 0;

            if (s.Length > 0 && s[0] == '[')
            {
                // probably "[addr6]:port"
                int baseIndex = s.Length - 1;
                for (int i = 0; i < 6; i++) // ":65535" is the longest possible port suffix
                {
                    int index = baseIndex - i;
                    if (index < 3)
                        break;
                    if (s[index] == ':' && s[index - 1] == ']')
                    {
                        if (!TryParsePort(s.Slice(index + 1), out port))
                            return false;
                        s = s.Slice(0, index - 1);
                        break;
                    }
                }

                // if a port is omitted, strip a trailing ']' so "[addr]" parses as the address.
                // NOTE: like the C library, a missing ']' is tolerated ("[::1" parses as ::1)
                if (s[s.Length - 1] == ']')
                    s = s.Slice(0, s.Length - 1);

                s = s.Slice(1);
            }

            if (TryParseIpv6(s, ref address))
            {
                address.Port = port;
                return true;
            }

            // otherwise it's probably IPv4: look for ":port" then strict dotted quad
            int stringLength = s.Length;
            int base4 = stringLength - 1;
            for (int i = 0; i < 6; i++)
            {
                int index = base4 - i;
                if (index < 0)
                    break;
                if (s[index] == ':')
                {
                    if (!TryParsePort(s.Slice(index + 1), out port))
                        return false;
                    s = s.Slice(0, index);
                    break;
                }
            }

            if (TryParseIpv4(s, ref address))
            {
                address.Port = port;
                return true;
            }

            return false;
        }

        private static bool TryParsePort(ReadOnlySpan<char> s, out ushort port)
        {
            // all digits, in [0,65535] — anything else is an error (matches netcode_parse_port)
            port = 0;
            if (s.Length == 0)
                return false;
            int value = 0;
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] < '0' || s[i] > '9')
                    return false;
                value = value * 10 + (s[i] - '0');
                if (value > 65535)
                    return false;
            }
            port = (ushort)value;
            return true;
        }

        private static bool TryParseIpv6(ReadOnlySpan<char> s, ref Address address)
        {
            if (s.Length == 0)
                return false;

            // inet_pton(AF_INET6) accepts no zone suffix; IPAddress.TryParse does — reject it
            if (s.IndexOf('%') >= 0)
                return false;

            if (!IPAddress.TryParse(s, out IPAddress? parsed) || parsed.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            Span<byte> bytes = stackalloc byte[16];
            if (!parsed.TryWriteBytes(bytes, out int written) || written != 16)
                return false;

            address.Type = AddressType.IPv6;
            for (int i = 0; i < 8; i++)
                address.SetIPv6Group(i, (ushort)((bytes[i * 2] << 8) | bytes[i * 2 + 1])); // ntohs
            return true;
        }

        private static bool TryParseIpv4(ReadOnlySpan<char> s, ref Address address)
        {
            // strict dotted quad, like inet_pton(AF_INET): four decimal parts 0..255
            Span<byte> octets = stackalloc byte[4];
            int part = 0;
            int value = 0;
            int digits = 0;

            for (int i = 0; i < s.Length; i++)
            {
                char ch = s[i];
                if (ch >= '0' && ch <= '9')
                {
                    value = value * 10 + (ch - '0');
                    digits++;
                    if (digits > 3 || value > 255)
                        return false;
                }
                else if (ch == '.')
                {
                    if (digits == 0 || part >= 3)
                        return false;
                    octets[part] = (byte)value;
                    part++;
                    value = 0;
                    digits = 0;
                }
                else
                {
                    return false;
                }
            }

            if (part != 3 || digits == 0)
                return false;
            octets[3] = (byte)value;

            address.SetIPv4(octets[0], octets[1], octets[2], octets[3]);
            return true;
        }

        /// <summary>Format like the C library: "a.b.c.d:port", "[addr6]:port", or "NONE".</summary>
        public override string ToString()
        {
            if (Type == AddressType.IPv6)
            {
                Span<byte> bytes = stackalloc byte[16];
                for (int i = 0; i < 8; i++)
                {
                    ushort g = GetIPv6(i);
                    bytes[i * 2] = (byte)(g >> 8);
                    bytes[i * 2 + 1] = (byte)g;
                }
                var ip = new IPAddress(bytes);
                return Port == 0 ? ip.ToString() : $"[{ip}]:{Port}";
            }
            else if (Type == AddressType.IPv4)
            {
                return Port != 0
                    ? $"{Data[0]}.{Data[1]}.{Data[2]}.{Data[3]}:{Port}"
                    : $"{Data[0]}.{Data[1]}.{Data[2]}.{Data[3]}";
            }
            else
            {
                return "NONE";
            }
        }

        /// <summary>Value equality. Note: like netcode_address_equal, two NONE addresses are NOT equal.</summary>
        public bool Equals(Address other)
        {
            if (Type != other.Type || Port != other.Port)
                return false;
            if (Type == AddressType.IPv4)
            {
                ReadOnlySpan<byte> a = Data;
                ReadOnlySpan<byte> b = other.Data;
                return a.Slice(0, 4).SequenceEqual(b.Slice(0, 4));
            }
            if (Type == AddressType.IPv6)
            {
                ReadOnlySpan<byte> a = Data;
                ReadOnlySpan<byte> b = other.Data;
                return a.SequenceEqual(b);
            }
            return false; // NONE != NONE, matching netcode_address_equal
        }

        /// <inheritdoc />
        public override bool Equals(object? obj) => obj is Address other && Equals(other);

        /// <inheritdoc />
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add((byte)Type);
            hash.Add(Port);
            ReadOnlySpan<byte> bytes = Data;
            hash.AddBytes(Type == AddressType.IPv4 ? bytes.Slice(0, 4) : bytes);
            return hash.ToHashCode();
        }
    }

    // ------------------------------------------------------------------
    // private connect token (netcode_connect_token_private_t)
    // ------------------------------------------------------------------

    internal sealed class ConnectTokenPrivate
    {
        public ulong ClientId;
        public int TimeoutSeconds;
        public int NumServerAddresses;
        public Address[] ServerAddresses = new Address[Protocol.MaxServersPerConnect];
        public byte[] ClientToServerKey = new byte[Protocol.KeyBytes];
        public byte[] ServerToClientKey = new byte[Protocol.KeyBytes];
        public byte[] UserData = new byte[Protocol.UserDataBytes];

        public void Generate(ulong clientId, int timeoutSeconds, ReadOnlySpan<Address> serverAddresses, ReadOnlySpan<byte> userData)
        {
            ClientId = clientId;
            TimeoutSeconds = timeoutSeconds;
            NumServerAddresses = serverAddresses.Length;
            for (int i = 0; i < serverAddresses.Length; i++)
                ServerAddresses[i] = serverAddresses[i];

            Rng.GenerateKey(ClientToServerKey);
            Rng.GenerateKey(ServerToClientKey);

            if (userData.Length > 0)
                userData.CopyTo(UserData);
            else
                Array.Clear(UserData);
        }

        public void Write(Span<byte> buffer)
        {
            var writer = new ByteWriter(buffer);
            writer.U64(ClientId);
            writer.U32((uint)TimeoutSeconds);
            writer.U32((uint)NumServerAddresses);
            for (int i = 0; i < NumServerAddresses; i++)
                WriteAddress(ref writer, in ServerAddresses[i]);
            writer.Bytes(ClientToServerKey);
            writer.Bytes(ServerToClientKey);
            writer.Bytes(UserData);
            writer.ZeroPadTo(Defines.ConnectTokenPrivateBytes);
        }

        public bool Read(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < Defines.ConnectTokenPrivateBytes)
                return false;

            var reader = new ByteReader(buffer);
            ClientId = reader.U64();
            TimeoutSeconds = (int)reader.U32();
            NumServerAddresses = (int)reader.U32();

            if (NumServerAddresses <= 0 || NumServerAddresses > Protocol.MaxServersPerConnect)
                return false;

            for (int i = 0; i < NumServerAddresses; i++)
            {
                if (!ReadAddress(ref reader, ref ServerAddresses[i]))
                    return false;
            }

            reader.Bytes(ClientToServerKey);
            reader.Bytes(ServerToClientKey);
            reader.Bytes(UserData);
            return true;
        }

        internal static void WriteAddress(ref ByteWriter writer, in Address address)
        {
            if (address.Type == AddressType.IPv4)
            {
                writer.U8((byte)AddressType.IPv4);
                for (int j = 0; j < 4; j++)
                    writer.U8(address.GetIPv4(j));
                writer.U16(address.Port);
            }
            else if (address.Type == AddressType.IPv6)
            {
                writer.U8((byte)AddressType.IPv6);
                for (int j = 0; j < 8; j++)
                    writer.U16(address.GetIPv6(j));
                writer.U16(address.Port);
            }
            else
            {
                throw new InvalidOperationException("cannot write address of type NONE");
            }
        }

        internal static bool ReadAddress(ref ByteReader reader, ref Address address)
        {
            byte type = reader.U8();
            if (type == (byte)AddressType.IPv4)
            {
                if (reader.Remaining < 6)
                    return false;
                byte a = reader.U8(), b = reader.U8(), c = reader.U8(), d = reader.U8();
                address.SetIPv4(a, b, c, d);
                address.Port = reader.U16();
                return true;
            }
            if (type == (byte)AddressType.IPv6)
            {
                if (reader.Remaining < 18)
                    return false;
                address.Type = AddressType.IPv6;
                for (int j = 0; j < 8; j++)
                    address.SetIPv6Group(j, reader.U16());
                address.Port = reader.U16();
                return true;
            }
            return false;
        }

        private static void BuildAdditionalData(Span<byte> additional, ReadOnlySpan<byte> versionInfo, ulong protocolId, ulong expireTimestamp)
        {
            var writer = new ByteWriter(additional);
            writer.Bytes(versionInfo);
            writer.U64(protocolId);
            writer.U64(expireTimestamp);
        }

        /// <summary>Encrypt the 1024-byte private token buffer in place (first 1008 bytes; last 16 hold the MAC).</summary>
        public static bool Encrypt(Span<byte> buffer, ReadOnlySpan<byte> versionInfo, ulong protocolId, ulong expireTimestamp, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> key)
        {
            Span<byte> additional = stackalloc byte[Defines.VersionInfoBytes + 8 + 8];
            BuildAdditionalData(additional, versionInfo, protocolId, expireTimestamp);
            Aead.EncryptX(buffer.Slice(0, Defines.ConnectTokenPrivateBytes), Defines.ConnectTokenPrivateBytes - Protocol.MacBytes, additional, nonce24, key);
            return true;
        }

        /// <summary>Decrypt the 1024-byte private token buffer in place. Returns false on authentication failure.</summary>
        public static bool Decrypt(Span<byte> buffer, ReadOnlySpan<byte> versionInfo, ulong protocolId, ulong expireTimestamp, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> key)
        {
            Span<byte> additional = stackalloc byte[Defines.VersionInfoBytes + 8 + 8];
            BuildAdditionalData(additional, versionInfo, protocolId, expireTimestamp);
            return Aead.DecryptX(buffer.Slice(0, Defines.ConnectTokenPrivateBytes), Defines.ConnectTokenPrivateBytes, additional, nonce24, key);
        }
    }

    // ------------------------------------------------------------------
    // challenge token (netcode_challenge_token_t)
    // ------------------------------------------------------------------

    internal sealed class ChallengeToken
    {
        public ulong ClientId;
        public byte[] UserData = new byte[Protocol.UserDataBytes];

        public void Write(Span<byte> buffer)
        {
            buffer.Slice(0, Defines.ChallengeTokenBytes).Clear();
            var writer = new ByteWriter(buffer);
            writer.U64(ClientId);
            writer.Bytes(UserData);
        }

        public bool Read(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < Defines.ChallengeTokenBytes)
                return false;
            var reader = new ByteReader(buffer);
            ClientId = reader.U64();
            reader.Bytes(UserData);
            return true;
        }

        private static void BuildNonce(Span<byte> nonce12, ulong sequence)
        {
            var writer = new ByteWriter(nonce12);
            writer.U32(0);
            writer.U64(sequence);
        }

        /// <summary>Encrypt the 300-byte challenge token buffer in place (first 284 bytes; last 16 hold the MAC).</summary>
        public static void Encrypt(Span<byte> buffer, ulong sequence, ReadOnlySpan<byte> key)
        {
            Span<byte> nonce = stackalloc byte[Aead.NonceBytesIetf];
            BuildNonce(nonce, sequence);
            Aead.EncryptIetf(buffer.Slice(0, Defines.ChallengeTokenBytes), Defines.ChallengeTokenBytes - Protocol.MacBytes, ReadOnlySpan<byte>.Empty, nonce, key);
        }

        /// <summary>Decrypt the 300-byte challenge token buffer in place. Returns false on authentication failure.</summary>
        public static bool Decrypt(Span<byte> buffer, ulong sequence, ReadOnlySpan<byte> key)
        {
            Span<byte> nonce = stackalloc byte[Aead.NonceBytesIetf];
            BuildNonce(nonce, sequence);
            return Aead.DecryptIetf(buffer.Slice(0, Defines.ChallengeTokenBytes), Defines.ChallengeTokenBytes, ReadOnlySpan<byte>.Empty, nonce, key);
        }
    }

    // ------------------------------------------------------------------
    // public connect token (netcode_connect_token_t)
    // ------------------------------------------------------------------

    internal sealed class ConnectTokenData
    {
        public byte[] VersionInfo = new byte[Defines.VersionInfoBytes];
        public ulong ProtocolId;
        public ulong CreateTimestamp;
        public ulong ExpireTimestamp;
        public byte[] Nonce = new byte[Defines.ConnectTokenNonceBytes];
        public byte[] PrivateData = new byte[Defines.ConnectTokenPrivateBytes];
        public int TimeoutSeconds;
        public int NumServerAddresses;
        public Address[] ServerAddresses = new Address[Protocol.MaxServersPerConnect];
        public byte[] ClientToServerKey = new byte[Protocol.KeyBytes];
        public byte[] ServerToClientKey = new byte[Protocol.KeyBytes];

        public void Write(Span<byte> buffer)
        {
            var writer = new ByteWriter(buffer);
            writer.Bytes(VersionInfo);
            writer.U64(ProtocolId);
            writer.U64(CreateTimestamp);
            writer.U64(ExpireTimestamp);
            writer.Bytes(Nonce);
            writer.Bytes(PrivateData);
            writer.U32((uint)TimeoutSeconds);
            writer.U32((uint)NumServerAddresses);
            for (int i = 0; i < NumServerAddresses; i++)
                ConnectTokenPrivate.WriteAddress(ref writer, in ServerAddresses[i]);
            writer.Bytes(ClientToServerKey);
            writer.Bytes(ServerToClientKey);
            writer.ZeroPadTo(Protocol.ConnectTokenBytes);
        }

        public bool Read(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length != Protocol.ConnectTokenBytes)
            {
                NetcodeLog.Error("error: read connect data has bad buffer length\n");
                return false;
            }

            var reader = new ByteReader(buffer);
            reader.Bytes(VersionInfo);
            if (!((ReadOnlySpan<byte>)VersionInfo).SequenceEqual(Defines.VersionInfo))
            {
                NetcodeLog.Error("error: read connect data has bad version info\n");
                return false;
            }

            ProtocolId = reader.U64();
            CreateTimestamp = reader.U64();
            ExpireTimestamp = reader.U64();

            if (CreateTimestamp > ExpireTimestamp)
                return false;

            reader.Bytes(Nonce);
            reader.Bytes(PrivateData);

            TimeoutSeconds = (int)reader.U32();
            NumServerAddresses = (int)reader.U32();

            if (NumServerAddresses <= 0 || NumServerAddresses > Protocol.MaxServersPerConnect)
            {
                NetcodeLog.Error("error: read connect data has bad number of server addresses\n");
                return false;
            }

            for (int i = 0; i < NumServerAddresses; i++)
            {
                if (!ConnectTokenPrivate.ReadAddress(ref reader, ref ServerAddresses[i]))
                {
                    NetcodeLog.Error("error: read connect data has bad address type\n");
                    return false;
                }
            }

            reader.Bytes(ClientToServerKey);
            reader.Bytes(ServerToClientKey);
            return true;
        }
    }

    /// <summary>
    /// Mints connect tokens. This runs on the backend, which shares the 32-byte
    /// private key with the dedicated servers. Mirrors netcode_generate_connect_token.
    /// </summary>
    public static class ConnectTokenGenerator
    {
        /// <summary>
        /// Generate a connect token into <paramref name="output"/> (2048 bytes).
        /// <paramref name="publicServerAddresses"/> go into the public portion the
        /// client connects to; <paramref name="internalServerAddresses"/> go into the
        /// encrypted private portion the server validates against. expireSeconds
        /// and timeoutSeconds negative values disable expiry/timeout (dev only).
        /// Returns false on invalid input.
        /// </summary>
        public static bool Generate(
            string[] publicServerAddresses,
            string[] internalServerAddresses,
            int expireSeconds,
            int timeoutSeconds,
            ulong clientId,
            ulong protocolId,
            ReadOnlySpan<byte> privateKey,
            ReadOnlySpan<byte> userData,
            Span<byte> output)
        {
            ArgumentNullException.ThrowIfNull(publicServerAddresses);
            ArgumentNullException.ThrowIfNull(internalServerAddresses);

            int numServerAddresses = publicServerAddresses.Length;

            if (numServerAddresses <= 0 || numServerAddresses > Protocol.MaxServersPerConnect)
            {
                NetcodeLog.Error($"error: number of server addresses must be in [1,{Protocol.MaxServersPerConnect}], got {numServerAddresses}\n");
                return false;
            }

            if (internalServerAddresses.Length != numServerAddresses)
            {
                NetcodeLog.Error("error: public and internal server address counts must match\n");
                return false;
            }

            if (privateKey.Length != Protocol.KeyBytes)
                throw new ArgumentException($"private key must be {Protocol.KeyBytes} bytes", nameof(privateKey));

            if (userData.Length != 0 && userData.Length != Protocol.UserDataBytes)
                throw new ArgumentException($"user data must be empty or {Protocol.UserDataBytes} bytes", nameof(userData));

            if (output.Length < Protocol.ConnectTokenBytes)
                throw new ArgumentException($"output must be at least {Protocol.ConnectTokenBytes} bytes", nameof(output));

            Span<Address> parsedPublic = stackalloc Address[Protocol.MaxServersPerConnect];
            for (int i = 0; i < numServerAddresses; i++)
            {
                if (!Address.TryParse(publicServerAddresses[i], out parsedPublic[i]))
                    return false;
            }

            Span<Address> parsedInternal = stackalloc Address[Protocol.MaxServersPerConnect];
            for (int i = 0; i < numServerAddresses; i++)
            {
                if (!Address.TryParse(internalServerAddresses[i], out parsedInternal[i]))
                    return false;
            }

            Span<byte> nonce = stackalloc byte[Defines.ConnectTokenNonceBytes];
            Rng.GenerateNonce(nonce);

            ulong createTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            ulong expireTimestamp = expireSeconds >= 0 ? createTimestamp + (ulong)expireSeconds : 0xFFFFFFFFFFFFFFFFUL;

            return GenerateInternal(parsedPublic.Slice(0, numServerAddresses), parsedInternal.Slice(0, numServerAddresses),
                createTimestamp, expireTimestamp, timeoutSeconds, clientId, protocolId, privateKey, userData, nonce, output);
        }

        // deterministic core, used by tests and the interop harness with fixed inputs
        internal static bool GenerateInternal(
            ReadOnlySpan<Address> publicAddresses,
            ReadOnlySpan<Address> internalAddresses,
            ulong createTimestamp,
            ulong expireTimestamp,
            int timeoutSeconds,
            ulong clientId,
            ulong protocolId,
            ReadOnlySpan<byte> privateKey,
            ReadOnlySpan<byte> userData,
            ReadOnlySpan<byte> nonce,
            Span<byte> output)
        {
            var connectTokenPrivate = new ConnectTokenPrivate();
            connectTokenPrivate.Generate(clientId, timeoutSeconds, internalAddresses, userData);

            Span<byte> privateData = stackalloc byte[Defines.ConnectTokenPrivateBytes];
            connectTokenPrivate.Write(privateData);

            if (!ConnectTokenPrivate.Encrypt(privateData, Defines.VersionInfo, protocolId, expireTimestamp, nonce, privateKey))
                return false;

            var connectToken = new ConnectTokenData();
            Defines.VersionInfo.CopyTo(connectToken.VersionInfo);
            connectToken.ProtocolId = protocolId;
            connectToken.CreateTimestamp = createTimestamp;
            connectToken.ExpireTimestamp = expireTimestamp;
            nonce.CopyTo(connectToken.Nonce);
            privateData.CopyTo(connectToken.PrivateData);
            connectToken.NumServerAddresses = publicAddresses.Length;
            for (int i = 0; i < publicAddresses.Length; i++)
                connectToken.ServerAddresses[i] = publicAddresses[i];
            connectTokenPrivate.ClientToServerKey.CopyTo(connectToken.ClientToServerKey, 0);
            connectTokenPrivate.ServerToClientKey.CopyTo(connectToken.ServerToClientKey, 0);
            connectToken.TimeoutSeconds = timeoutSeconds;

            connectToken.Write(output);
            return true;
        }
    }

    // ------------------------------------------------------------------
    // packets
    // ------------------------------------------------------------------

    internal static class PacketType
    {
        public const int ConnectionRequest = 0;
        public const int ConnectionDenied = 1;
        public const int ConnectionChallenge = 2;
        public const int ConnectionResponse = 3;
        public const int ConnectionKeepAlive = 4;
        public const int ConnectionPayload = 5;
        public const int ConnectionDisconnect = 6;
        public const int NumPackets = 7;
    }

    /// <summary>Result of PacketIO.ReadPacket: type, sequence and the location of the decrypted per-type data inside the caller's buffer.</summary>
    internal struct ReadPacketResult
    {
        public int Type;            // -1 when the packet was rejected
        public ulong Sequence;
        public ulong ConnectTokenExpireTimestamp;
        public int DataOffset;      // offset of decrypted per-packet-type data in the buffer
        public int DataLength;      // length of decrypted per-packet-type data
    }

    internal static class PacketIO
    {
        public const int ConnectionRequestPacketBytes =
            1 + Defines.VersionInfoBytes + 8 + 8 + Defines.ConnectTokenNonceBytes + Defines.ConnectTokenPrivateBytes; // 1078

        public static int SequenceNumberBytesRequired(ulong sequence)
        {
            int i;
            ulong mask = 0xFF00000000000000UL;
            for (i = 0; i < 7; i++)
            {
                if ((sequence & mask) != 0)
                    break;
                mask >>= 8;
            }
            return 8 - i;
        }

        public static int WriteConnectionRequestPacket(
            Span<byte> buffer,
            ReadOnlySpan<byte> versionInfo,
            ulong protocolId,
            ulong expireTimestamp,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> privateData)
        {
            var writer = new ByteWriter(buffer);
            writer.U8(PacketType.ConnectionRequest);
            writer.Bytes(versionInfo);
            writer.U64(protocolId);
            writer.U64(expireTimestamp);
            writer.Bytes(nonce);
            writer.Bytes(privateData);
            return writer.Position;
        }

        /// <summary>
        /// Write an encrypted packet (types 1..6): prefix byte, variable-length
        /// sequence, encrypted per-type data, MAC. <paramref name="packetData"/> is the
        /// plaintext per-type data. Returns the number of bytes written.
        /// </summary>
        public static int WriteEncryptedPacket(
            Span<byte> buffer,
            int packetType,
            ReadOnlySpan<byte> packetData,
            ulong sequence,
            ReadOnlySpan<byte> writePacketKey,
            ulong protocolId)
        {
            int sequenceBytes = SequenceNumberBytesRequired(sequence);
            byte prefixByte = (byte)(packetType | (sequenceBytes << 4));

            var writer = new ByteWriter(buffer);
            writer.U8(prefixByte);

            ulong sequenceTemp = sequence;
            for (int i = 0; i < sequenceBytes; i++)
            {
                writer.U8((byte)(sequenceTemp & 0xFF));
                sequenceTemp >>= 8;
            }

            int encryptedStart = writer.Position;
            writer.Bytes(packetData);
            int encryptedFinish = writer.Position;

            Span<byte> additional = stackalloc byte[Defines.VersionInfoBytes + 8 + 1];
            {
                var ad = new ByteWriter(additional);
                ad.Bytes(Defines.VersionInfo);
                ad.U64(protocolId);
                ad.U8(prefixByte);
            }

            Span<byte> nonce = stackalloc byte[Aead.NonceBytesIetf];
            {
                var n = new ByteWriter(nonce);
                n.U32(0);
                n.U64(sequence);
            }

            Aead.EncryptIetf(buffer.Slice(encryptedStart), encryptedFinish - encryptedStart, additional, nonce, writePacketKey);

            return encryptedFinish + Protocol.MacBytes;
        }

        /// <summary>
        /// Read a packet, following the exact validation order of netcode_read_packet
        /// (and the STANDARD.md "Reading Encrypted Packets" section). Decrypts in
        /// place. For connection request packets the private connect token is
        /// decrypted in place and DataOffset points at the 1024-byte token buffer.
        /// Result.Type is -1 when the packet is ignored.
        /// </summary>
        public static ReadPacketResult ReadPacket(
            Span<byte> buffer,
            bool hasReadPacketKey,
            ReadOnlySpan<byte> readPacketKey,
            ulong protocolId,
            ulong currentTimestamp,
            bool hasPrivateKey,
            ReadOnlySpan<byte> privateKey,
            ReadOnlySpan<bool> allowedPackets,
            ReplayProtection? replayProtection,
            ulong minConnectTokenExpireTimestamp = 0)
        {
            ReadPacketResult result = default;
            result.Type = -1;

            if (buffer.Length < 1)
            {
                NetcodeLog.Debug("ignored packet. buffer length is less than 1\n");
                return result;
            }

            byte prefixByte = buffer[0];

            if (prefixByte == PacketType.ConnectionRequest)
            {
                if (!allowedPackets[PacketType.ConnectionRequest])
                {
                    NetcodeLog.Debug("ignored connection request packet. packet type is not allowed\n");
                    return result;
                }

                if (buffer.Length != ConnectionRequestPacketBytes)
                {
                    NetcodeLog.Debug("ignored connection request packet. bad packet length\n");
                    return result;
                }

                if (!hasPrivateKey)
                {
                    NetcodeLog.Debug("ignored connection request packet. no private key\n");
                    return result;
                }

                ReadOnlySpan<byte> versionInfo = buffer.Slice(1, Defines.VersionInfoBytes);
                if (!versionInfo.SequenceEqual(Defines.VersionInfo))
                {
                    NetcodeLog.Debug("ignored connection request packet. bad version info\n");
                    return result;
                }

                ulong packetProtocolId = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(1 + Defines.VersionInfoBytes, 8));
                if (packetProtocolId != protocolId)
                {
                    NetcodeLog.Debug("ignored connection request packet. wrong protocol id\n");
                    return result;
                }

                ulong packetExpireTimestamp = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(1 + Defines.VersionInfoBytes + 8, 8));
                if (packetExpireTimestamp <= currentTimestamp)
                {
                    NetcodeLog.Debug("ignored connection request packet. connect token expired\n");
                    return result;
                }

                if (packetExpireTimestamp < minConnectTokenExpireTimestamp)
                {
                    NetcodeLog.Debug("ignored connection request packet. connect token predates the server start\n");
                    return result;
                }

                ReadOnlySpan<byte> packetNonce = buffer.Slice(1 + Defines.VersionInfoBytes + 8 + 8, Defines.ConnectTokenNonceBytes);

                int tokenOffset = 1 + Defines.VersionInfoBytes + 8 + 8 + Defines.ConnectTokenNonceBytes;

                if (!ConnectTokenPrivate.Decrypt(
                        buffer.Slice(tokenOffset, Defines.ConnectTokenPrivateBytes),
                        versionInfo, protocolId, packetExpireTimestamp, packetNonce, privateKey))
                {
                    NetcodeLog.Debug("ignored connection request packet. connect token failed to decrypt\n");
                    return result;
                }

                result.Type = PacketType.ConnectionRequest;
                result.Sequence = 0;
                result.ConnectTokenExpireTimestamp = packetExpireTimestamp;
                result.DataOffset = tokenOffset;
                result.DataLength = Defines.ConnectTokenPrivateBytes;
                return result;
            }
            else
            {
                // *** encrypted packets ***

                if (!hasReadPacketKey)
                {
                    NetcodeLog.Debug("ignored encrypted packet. no read packet key for this address\n");
                    return result;
                }

                if (buffer.Length < 1 + 1 + Protocol.MacBytes)
                {
                    NetcodeLog.Debug("ignored encrypted packet. packet is too small to be valid\n");
                    return result;
                }

                int packetType = prefixByte & 0xF;

                if (packetType >= PacketType.NumPackets)
                {
                    NetcodeLog.Debug("ignored encrypted packet. packet type is invalid\n");
                    return result;
                }

                if (!allowedPackets[packetType])
                {
                    NetcodeLog.Debug("ignored encrypted packet. packet type is not allowed\n");
                    return result;
                }

                int sequenceBytes = prefixByte >> 4;

                if (sequenceBytes < 1 || sequenceBytes > 8)
                {
                    NetcodeLog.Debug("ignored encrypted packet. sequence bytes is out of range [1,8]\n");
                    return result;
                }

                if (buffer.Length < 1 + sequenceBytes + Protocol.MacBytes)
                {
                    NetcodeLog.Debug("ignored encrypted packet. buffer is too small for sequence bytes + encryption mac\n");
                    return result;
                }

                ulong sequence = 0;
                for (int i = 0; i < sequenceBytes; i++)
                    sequence |= (ulong)buffer[1 + i] << (8 * i);

                // ignore the packet if it has already been received

                if (replayProtection != null && packetType >= PacketType.ConnectionKeepAlive)
                {
                    if (replayProtection.AlreadyReceived(sequence))
                    {
                        NetcodeLog.Debug("ignored packet. sequence already received (replay protection)\n");
                        return result;
                    }
                }

                // decrypt the per-packet type data

                Span<byte> additional = stackalloc byte[Defines.VersionInfoBytes + 8 + 1];
                {
                    var ad = new ByteWriter(additional);
                    ad.Bytes(Defines.VersionInfo);
                    ad.U64(protocolId);
                    ad.U8(prefixByte);
                }

                Span<byte> nonce = stackalloc byte[Aead.NonceBytesIetf];
                {
                    var n = new ByteWriter(nonce);
                    n.U32(0);
                    n.U64(sequence);
                }

                int encryptedStart = 1 + sequenceBytes;
                int encryptedBytes = buffer.Length - encryptedStart;

                if (encryptedBytes < Protocol.MacBytes)
                {
                    NetcodeLog.Debug("ignored encrypted packet. encrypted payload is too small\n");
                    return result;
                }

                if (!Aead.DecryptIetf(buffer.Slice(encryptedStart), encryptedBytes, additional, nonce, readPacketKey))
                {
                    NetcodeLog.Debug("ignored encrypted packet. failed to decrypt\n");
                    return result;
                }

                int decryptedBytes = encryptedBytes - Protocol.MacBytes;

                // update the latest replay protection sequence # (only after authentication)

                if (replayProtection != null && packetType >= PacketType.ConnectionKeepAlive)
                    replayProtection.AdvanceSequence(sequence);

                // validate decrypted size per packet type

                switch (packetType)
                {
                    case PacketType.ConnectionDenied:
                    case PacketType.ConnectionDisconnect:
                        if (decryptedBytes != 0)
                        {
                            NetcodeLog.Debug("ignored packet. decrypted packet data is wrong size\n");
                            return result;
                        }
                        break;

                    case PacketType.ConnectionChallenge:
                    case PacketType.ConnectionResponse:
                        if (decryptedBytes != 8 + Defines.ChallengeTokenBytes)
                        {
                            NetcodeLog.Debug("ignored packet. decrypted packet data is wrong size\n");
                            return result;
                        }
                        break;

                    case PacketType.ConnectionKeepAlive:
                        if (decryptedBytes != 8)
                        {
                            NetcodeLog.Debug("ignored connection keep alive packet. decrypted packet data is wrong size\n");
                            return result;
                        }
                        break;

                    case PacketType.ConnectionPayload:
                        if (decryptedBytes < 1)
                        {
                            NetcodeLog.Debug("ignored connection payload packet. payload is too small\n");
                            return result;
                        }
                        if (decryptedBytes > Defines.MaxPayloadBytes)
                        {
                            NetcodeLog.Debug("ignored connection payload packet. payload is too large\n");
                            return result;
                        }
                        break;

                    default:
                        return result;
                }

                result.Type = packetType;
                result.Sequence = sequence;
                result.DataOffset = encryptedStart;
                result.DataLength = decryptedBytes;
                return result;
            }
        }
    }

    // ------------------------------------------------------------------
    // replay protection (netcode_replay_protection_t)
    // ------------------------------------------------------------------

    internal sealed class ReplayProtection
    {
        public ulong MostRecentSequence;
        public readonly ulong[] ReceivedPacket = new ulong[Defines.ReplayProtectionBufferSize];

        public ReplayProtection()
        {
            Reset();
        }

        public void Reset()
        {
            MostRecentSequence = 0;
            Array.Fill(ReceivedPacket, ulong.MaxValue);
        }

        public bool AlreadyReceived(ulong sequence)
        {
            // written so it cannot overflow: "sequence + BUFFER_SIZE <= most_recent"
            // wraps for sequence values near UINT64_MAX and falsely rejects them

            if (MostRecentSequence >= Defines.ReplayProtectionBufferSize &&
                sequence <= MostRecentSequence - Defines.ReplayProtectionBufferSize)
                return true;

            int index = (int)(sequence % Defines.ReplayProtectionBufferSize);

            if (ReceivedPacket[index] == ulong.MaxValue)
                return false;

            if (ReceivedPacket[index] >= sequence)
                return true;

            return false;
        }

        public void AdvanceSequence(ulong sequence)
        {
            if (sequence > MostRecentSequence)
                MostRecentSequence = sequence;

            int index = (int)(sequence % Defines.ReplayProtectionBufferSize);

            ReceivedPacket[index] = sequence;
        }
    }

    // ------------------------------------------------------------------
    // payload packet queue (netcode_packet_queue_t, pooled buffers)
    // ------------------------------------------------------------------

    /// <summary>
    /// Fixed-capacity ring of received payloads. Each slot owns a MaxPayloadBytes
    /// buffer allocated on first use and reused forever after — the steady state
    /// allocates nothing.
    /// </summary>
    internal sealed class PacketQueue
    {
        private readonly byte[]?[] _buffers = new byte[Defines.PacketQueueSize][];
        private readonly int[] _lengths = new int[Defines.PacketQueueSize];
        private readonly ulong[] _sequences = new ulong[Defines.PacketQueueSize];
        private int _numPackets;
        private int _startIndex;

        public int Count => _numPackets;

        public void Clear()
        {
            _numPackets = 0;
            _startIndex = 0;
        }

        public bool Push(ReadOnlySpan<byte> payload, ulong sequence)
        {
            if (_numPackets == Defines.PacketQueueSize)
                return false;
            int index = (_startIndex + _numPackets) % Defines.PacketQueueSize;
            byte[] buffer = _buffers[index] ??= new byte[Defines.MaxPayloadBytes];
            payload.CopyTo(buffer);
            _lengths[index] = payload.Length;
            _sequences[index] = sequence;
            _numPackets++;
            return true;
        }

        /// <summary>Copy the oldest payload into <paramref name="destination"/>. Returns the payload length, or -1 when empty.</summary>
        public int Pop(Span<byte> destination, out ulong sequence)
        {
            if (_numPackets == 0)
            {
                sequence = 0;
                return -1;
            }
            int index = _startIndex;
            int length = _lengths[index];
            _buffers[index].AsSpan(0, length).CopyTo(destination);
            sequence = _sequences[index];
            _startIndex = (_startIndex + 1) % Defines.PacketQueueSize;
            _numPackets--;
            return length;
        }
    }

    // ------------------------------------------------------------------
    // network simulator (netcode_network_simulator_t)
    // ------------------------------------------------------------------

    /// <summary>
    /// Deterministic network conditions simulator for tests: latency, jitter,
    /// packet loss and duplicates. Same xorshift64* generator and seed as the C
    /// library, so a given configuration drops and delays the same packets.
    /// </summary>
    public sealed class NetworkSimulator
    {
        private const int NumPacketEntries = Protocol.MaxClients * 256;
        private const int NumPendingReceivePackets = Protocol.MaxClients * 64;
        private const ulong RngSeed = 0x9E3779B97F4A7C15UL;

        private struct PacketEntry
        {
            public Address From;
            public Address To;
            public double DeliveryTime;
            public byte[]? PacketData;
            public int PacketBytes;
        }

        /// <summary>One-way latency applied to every packet.</summary>
        public float LatencyMilliseconds;
        /// <summary>Random +/- jitter added to the latency.</summary>
        public float JitterMilliseconds;
        /// <summary>Percentage of packets dropped, 0..100.</summary>
        public float PacketLossPercent;
        /// <summary>Percentage of packets duplicated with a random extra delay, 0..100.</summary>
        public float DuplicatePacketPercent;

        private ulong _rngState = RngSeed;
        private double _time;
        private int _currentIndex;
        private int _numPendingReceivePackets;
        private readonly PacketEntry[] _packetEntries = new PacketEntry[NumPacketEntries];
        private readonly PacketEntry[] _pendingReceivePackets = new PacketEntry[NumPendingReceivePackets];

        /// <summary>Drop all queued packets and restore the deterministic RNG seed.</summary>
        public void Reset()
        {
            NetcodeLog.Debug("network simulator reset\n");
            for (int i = 0; i < NumPacketEntries; i++)
                _packetEntries[i] = default;
            for (int i = 0; i < _numPendingReceivePackets; i++)
                _pendingReceivePackets[i] = default;
            _currentIndex = 0;
            _numPendingReceivePackets = 0;
            _rngState = RngSeed;
        }

        private ulong RandomUInt64()
        {
            // xorshift64*: deterministic and self-contained
            ulong x = _rngState;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            _rngState = x;
            return unchecked(x * 0x2545F4914F6CDD1DUL);
        }

        private float RandomFloat(float a, float b)
        {
            float random = (float)(RandomUInt64() >> 40) / (1 << 24);
            return a + random * (b - a);
        }

        private void QueuePacket(in Address from, in Address to, ReadOnlySpan<byte> packetData, float delay)
        {
            ref PacketEntry entry = ref _packetEntries[_currentIndex];
            entry.From = from;
            entry.To = to;
            entry.PacketData ??= new byte[Defines.MaxPacketBytes];
            packetData.CopyTo(entry.PacketData);
            entry.PacketBytes = packetData.Length;
            entry.DeliveryTime = _time + delay;
            _currentIndex = (_currentIndex + 1) % NumPacketEntries;
        }

        /// <summary>Queue a packet for delivery, applying loss, latency, jitter and duplication.</summary>
        public void SendPacket(in Address from, in Address to, ReadOnlySpan<byte> packetData)
        {
            if (packetData.Length <= 0 || packetData.Length > Defines.MaxPacketBytes)
                throw new ArgumentException("packet size out of range", nameof(packetData));

            if (RandomFloat(0.0f, 100.0f) <= PacketLossPercent)
                return;

            float delay = LatencyMilliseconds / 1000.0f;

            if (JitterMilliseconds > 0.0f)
                delay += RandomFloat(-JitterMilliseconds, +JitterMilliseconds) / 1000.0f;

            QueuePacket(in from, in to, packetData, delay);

            if (RandomFloat(0.0f, 100.0f) <= DuplicatePacketPercent)
                QueuePacket(in from, in to, packetData, delay + RandomFloat(0.0f, 1.0f));
        }

        internal delegate void ReceiveHandler(in Address from, ReadOnlySpan<byte> packetData);

        /// <summary>Deliver every pending packet addressed to <paramref name="to"/> (up to maxPackets) into the handler.</summary>
        internal int ReceivePackets(in Address to, int maxPackets, ReceiveHandler handler)
        {
            int numPackets = 0;
            for (int i = 0; i < _numPendingReceivePackets; i++)
            {
                if (numPackets == maxPackets)
                    break;

                ref PacketEntry entry = ref _pendingReceivePackets[i];

                if (entry.PacketData == null)
                    continue;

                if (!entry.To.Equals(to))
                    continue;

                handler(in entry.From, entry.PacketData.AsSpan(0, entry.PacketBytes));
                entry.PacketData = null;
                numPackets++;
            }
            return numPackets;
        }

        /// <summary>Advance simulator time, making due packets available for receive.</summary>
        public void Update(double time)
        {
            _time = time;

            // discard any pending receive packets still in the buffer
            for (int i = 0; i < _numPendingReceivePackets; i++)
                _pendingReceivePackets[i].PacketData = null;

            _numPendingReceivePackets = 0;

            // move any packet entries ready for delivery into the pending receive buffer
            for (int i = 0; i < NumPacketEntries; i++)
            {
                if (_packetEntries[i].PacketData == null)
                    continue;

                if (_numPendingReceivePackets == NumPendingReceivePackets)
                    break;

                if (_packetEntries[i].DeliveryTime <= time)
                {
                    _pendingReceivePackets[_numPendingReceivePackets] = _packetEntries[i];
                    _numPendingReceivePackets++;
                    _packetEntries[i].PacketData = null;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // encryption manager (netcode_encryption_manager_t)
    // ------------------------------------------------------------------

    internal sealed class EncryptionManager
    {
        public const int MaxEncryptionMappings = Protocol.MaxClients * 4;

        public int NumEncryptionMappings;
        public readonly int[] Timeout = new int[MaxEncryptionMappings];
        public readonly double[] ExpireTime = new double[MaxEncryptionMappings];
        public readonly double[] LastAccessTime = new double[MaxEncryptionMappings];
        public readonly Address[] Address = new Address[MaxEncryptionMappings];
        public readonly int[] ClientIndex = new int[MaxEncryptionMappings];
        public readonly int[] ConnectTokenEntryIndex = new int[MaxEncryptionMappings];
        public readonly byte[] SendKey = new byte[Protocol.KeyBytes * MaxEncryptionMappings];
        public readonly byte[] ReceiveKey = new byte[Protocol.KeyBytes * MaxEncryptionMappings];

        public EncryptionManager()
        {
            Reset();
        }

        public void Reset()
        {
            NetcodeLog.Debug("reset encryption manager\n");

            NumEncryptionMappings = 0;

            for (int i = 0; i < MaxEncryptionMappings; i++)
            {
                ClientIndex[i] = -1;
                ConnectTokenEntryIndex[i] = -1;
                ExpireTime[i] = -1.0;
                LastAccessTime[i] = -1000.0;
                Address[i] = default;
            }

            Array.Clear(Timeout);
            Array.Clear(SendKey);
            Array.Clear(ReceiveKey);
        }

        public bool EntryExpired(int index, double time)
        {
            return (Timeout[index] > 0 && LastAccessTime[index] + Timeout[index] < time) ||
                   (ExpireTime[index] >= 0.0 && ExpireTime[index] < time);
        }

        public bool AddEncryptionMapping(in Address address, ReadOnlySpan<byte> sendKey, ReadOnlySpan<byte> receiveKey, double time, double expireTime, int timeout, int connectTokenEntryIndex = -1)
        {
            for (int i = 0; i < NumEncryptionMappings; i++)
            {
                if (Address[i].Equals(address) && !EntryExpired(i, time))
                {
                    Timeout[i] = timeout;
                    ExpireTime[i] = expireTime;
                    LastAccessTime[i] = time;
                    ConnectTokenEntryIndex[i] = connectTokenEntryIndex;
                    sendKey.CopyTo(SendKey.AsSpan(i * Protocol.KeyBytes, Protocol.KeyBytes));
                    receiveKey.CopyTo(ReceiveKey.AsSpan(i * Protocol.KeyBytes, Protocol.KeyBytes));
                    return true;
                }
            }

            for (int i = 0; i < MaxEncryptionMappings; i++)
            {
                if (Address[i].Type == AddressType.None ||
                    (EntryExpired(i, time) && ClientIndex[i] == -1))
                {
                    Timeout[i] = timeout;
                    Address[i] = address;
                    ExpireTime[i] = expireTime;
                    LastAccessTime[i] = time;
                    ConnectTokenEntryIndex[i] = connectTokenEntryIndex;
                    sendKey.CopyTo(SendKey.AsSpan(i * Protocol.KeyBytes, Protocol.KeyBytes));
                    receiveKey.CopyTo(ReceiveKey.AsSpan(i * Protocol.KeyBytes, Protocol.KeyBytes));
                    if (i + 1 > NumEncryptionMappings)
                        NumEncryptionMappings = i + 1;
                    return true;
                }
            }

            return false;
        }

        public bool RemoveEncryptionMapping(in Address address, double time)
        {
            for (int i = 0; i < NumEncryptionMappings; i++)
            {
                if (Address[i].Equals(address))
                {
                    ExpireTime[i] = -1.0;
                    LastAccessTime[i] = -1000.0;
                    ConnectTokenEntryIndex[i] = -1;
                    Address[i] = default;
                    SendKey.AsSpan(i * Protocol.KeyBytes, Protocol.KeyBytes).Clear();
                    ReceiveKey.AsSpan(i * Protocol.KeyBytes, Protocol.KeyBytes).Clear();

                    if (i + 1 == NumEncryptionMappings)
                    {
                        int index = i - 1;
                        while (index >= 0)
                        {
                            if (!EntryExpired(index, time) || ClientIndex[index] != -1)
                                break;
                            Address[index].Type = AddressType.None;
                            index--;
                        }
                        NumEncryptionMappings = index + 1;
                    }

                    return true;
                }
            }

            return false;
        }

        public int FindEncryptionMapping(in Address address, double time)
        {
            for (int i = 0; i < NumEncryptionMappings; i++)
            {
                if (Address[i].Equals(address) && !EntryExpired(i, time))
                {
                    LastAccessTime[i] = time;
                    return i;
                }
            }
            return -1;
        }

        public bool Touch(int index, in Address address, double time)
        {
            if (!Address[index].Equals(address))
                return false;
            LastAccessTime[index] = time;
            return true;
        }

        public void SetExpireTime(int index, double expireTime)
        {
            ExpireTime[index] = expireTime;
        }

        public int GetConnectTokenEntryIndex(int index)
        {
            if (index == -1)
                return -1;
            return ConnectTokenEntryIndex[index];
        }

        public Span<byte> GetSendKey(int index)
        {
            if (index == -1)
                return Span<byte>.Empty;
            return SendKey.AsSpan(index * Protocol.KeyBytes, Protocol.KeyBytes);
        }

        public Span<byte> GetReceiveKey(int index)
        {
            if (index == -1)
                return Span<byte>.Empty;
            return ReceiveKey.AsSpan(index * Protocol.KeyBytes, Protocol.KeyBytes);
        }

        public int GetTimeout(int index)
        {
            if (index == -1)
                return 0;
            return Timeout[index];
        }
    }

    // ------------------------------------------------------------------
    // sockets (thin non-blocking UDP wrapper; allocation-free send/receive)
    // ------------------------------------------------------------------

    internal sealed class NetcodeSocket : IDisposable
    {
        public Address Address;             // bound address (port filled in after bind)
        private readonly Socket _socket;
        private readonly SocketAddress _receiveAddress;
        private readonly SocketAddress _sendAddress;

        public enum CreateError
        {
            None = 0,
            CreateFailed,
            SockoptRcvbufFailed,
            SockoptSndbufFailed,
            BindFailed,
            GetSocknameFailed,
            EnablePacketTaggingFailed,
        }

        private NetcodeSocket(Socket socket, in Address address, SocketAddress receiveAddress, SocketAddress sendAddress)
        {
            _socket = socket;
            Address = address;
            _receiveAddress = receiveAddress;
            _sendAddress = sendAddress;
        }

        public static CreateError Create(in Address address, int sendBufferSize, int receiveBufferSize, bool enablePacketTagging, out NetcodeSocket? result)
        {
            result = null;

            AddressFamily family = address.Type == AddressType.IPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;

            Socket socket;
            try
            {
                socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            }
            catch (SocketException)
            {
                NetcodeLog.Error("error: failed to create socket\n");
                return CreateError.CreateFailed;
            }

            try
            {
                if (OperatingSystem.IsWindows())
                {
                    // stop hard client disconnects surfacing as recvfrom errors (ICMP port unreachable)
                    const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);
                    try
                    {
                        socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
                    }
                    catch (SocketException)
                    {
                        // best effort; matches the spirit, not the letter, of the C code path
                    }
                }

                if (address.Type == AddressType.IPv6)
                    socket.DualMode = false; // force IPv6 only, like the C library

                try
                {
                    socket.SendBufferSize = sendBufferSize;
                }
                catch (SocketException)
                {
                    socket.Dispose();
                    NetcodeLog.Error("error: failed to set socket send buffer size\n");
                    return CreateError.SockoptSndbufFailed;
                }

                try
                {
                    socket.ReceiveBufferSize = receiveBufferSize;
                }
                catch (SocketException)
                {
                    socket.Dispose();
                    NetcodeLog.Error("error: failed to set socket receive buffer size\n");
                    return CreateError.SockoptRcvbufFailed;
                }

                try
                {
                    socket.Bind(ToEndPoint(in address));
                }
                catch (SocketException)
                {
                    socket.Dispose();
                    NetcodeLog.Error($"error: failed to bind socket ({(address.Type == AddressType.IPv6 ? "ipv6" : "ipv4")})\n");
                    return CreateError.BindFailed;
                }

                Address bound = address;
                if (address.Port == 0)
                {
                    if (socket.LocalEndPoint is IPEndPoint localEndPoint)
                    {
                        bound.Port = (ushort)localEndPoint.Port;
                    }
                    else
                    {
                        socket.Dispose();
                        return CreateError.GetSocknameFailed;
                    }
                }

                socket.Blocking = false;

                if (enablePacketTagging)
                {
                    if (!TryEnablePacketTagging(socket, address.Type))
                    {
                        socket.Dispose();
                        NetcodeLog.Error("error: failed to enable packet tagging\n");
                        return CreateError.EnablePacketTaggingFailed;
                    }
                }

                var receiveAddress = new SocketAddress(family);
                var sendAddress = new SocketAddress(family);
                result = new NetcodeSocket(socket, in bound, receiveAddress, sendAddress);
                return CreateError.None;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        private static bool TryEnablePacketTagging(Socket socket, AddressType type)
        {
            // DSCP EF (46): low latency. best effort per platform; Windows would need
            // the Qwave QOS API, which is not ported — tagging is a no-op there.
            if (OperatingSystem.IsWindows())
                return true;

            try
            {
                if (type == AddressType.IPv6)
                {
                    // IPV6_TCLASS: 67 on linux, 36 on macOS/BSD
                    int optname = OperatingSystem.IsLinux() ? 67 : 36;
                    socket.SetRawSocketOption(41 /* IPPROTO_IPV6 */, optname, BitConverter.GetBytes(46));
                }
                else
                {
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService, 46);
                }
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        private static IPEndPoint ToEndPoint(in Address address)
        {
            if (address.Type == AddressType.IPv6)
            {
                Span<byte> bytes = stackalloc byte[16];
                for (int i = 0; i < 8; i++)
                {
                    ushort g = address.GetIPv6(i);
                    bytes[i * 2] = (byte)(g >> 8);
                    bytes[i * 2 + 1] = (byte)g;
                }
                return new IPEndPoint(new IPAddress(bytes), address.Port);
            }
            else
            {
                Span<byte> bytes = stackalloc byte[4];
                bytes[0] = address.GetIPv4(0);
                bytes[1] = address.GetIPv4(1);
                bytes[2] = address.GetIPv4(2);
                bytes[3] = address.GetIPv4(3);
                return new IPEndPoint(new IPAddress(bytes), address.Port);
            }
        }

        private static void AddressToSocketAddress(in Address address, SocketAddress socketAddress)
        {
            Span<byte> buffer = socketAddress.Buffer.Span;
            if (address.Type == AddressType.IPv4)
            {
                BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2, 2), address.Port);
                buffer[4] = address.GetIPv4(0);
                buffer[5] = address.GetIPv4(1);
                buffer[6] = address.GetIPv4(2);
                buffer[7] = address.GetIPv4(3);
            }
            else
            {
                BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2, 2), address.Port);
                buffer.Slice(4, 4).Clear(); // flowinfo
                for (int i = 0; i < 8; i++)
                {
                    ushort g = address.GetIPv6(i);
                    buffer[8 + i * 2] = (byte)(g >> 8);
                    buffer[8 + i * 2 + 1] = (byte)g;
                }
                buffer.Slice(24, 4).Clear(); // scope id
            }
        }

        private static void SocketAddressToAddress(SocketAddress socketAddress, ref Address address)
        {
            ReadOnlySpan<byte> buffer = socketAddress.Buffer.Span.Slice(0, socketAddress.Size);
            if (socketAddress.Family == AddressFamily.InterNetwork)
            {
                address.SetIPv4(buffer[4], buffer[5], buffer[6], buffer[7]);
                address.Port = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2));
            }
            else
            {
                address.Type = AddressType.IPv6;
                for (int i = 0; i < 8; i++)
                    address.SetIPv6Group(i, (ushort)((buffer[8 + i * 2] << 8) | buffer[8 + i * 2 + 1]));
                address.Port = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2));
            }
        }

        public void SendPacket(in Address to, ReadOnlySpan<byte> packetData)
        {
            AddressToSocketAddress(in to, _sendAddress);
            try
            {
                _socket.SendTo(packetData, SocketFlags.None, _sendAddress);
            }
            catch (SocketException)
            {
                // UDP send errors are semantically identical to a dropped packet.
                // A persistently dead socket surfaces as a connection timeout.
            }
        }

        /// <summary>Non-blocking receive. Returns 0 when no packet is available.</summary>
        public int ReceivePacket(ref Address from, Span<byte> packetData)
        {
            // ReceiveFrom requires Size >= the family maximum before every call, and
            // .NET 8 overwrites Size BEFORE checking the recvfrom result — so an empty
            // poll (EWOULDBLOCK, the common case on a non-blocking socket) zeroes it
            // and the next call throws ArgumentOutOfRangeException ("SocketAddress is
            // too small"). .NET 9 moved that assignment after the error check. Re-arm
            // the size each call; it is a field store, nothing allocates.
            _receiveAddress.Size = SocketAddress.GetMaximumAddressSize(_socket.AddressFamily);

            int result;
            try
            {
                result = _socket.ReceiveFrom(packetData, SocketFlags.None, _receiveAddress);
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode != SocketError.WouldBlock &&
                    e.SocketErrorCode != SocketError.ConnectionReset)
                {
                    NetcodeLog.Error($"error: recvfrom failed with error {e.SocketErrorCode}\n");
                }
                return 0;
            }

            if (result <= 0)
                return 0;

            SocketAddressToAddress(_receiveAddress, ref from);
            return result;
        }

        public void Dispose()
        {
            _socket.Dispose();
        }
    }

    // ------------------------------------------------------------------
    // shared send dispatch (netcode_send_packet_to_address)
    // ------------------------------------------------------------------

    /// <summary>Custom transport send hook: deliver <paramref name="packetData"/> to <paramref name="to"/>.</summary>
    public delegate void SendPacketOverrideDelegate(in Address to, ReadOnlySpan<byte> packetData);
    /// <summary>Custom transport receive hook: fill <paramref name="packetData"/> and <paramref name="from"/>, returning the byte count (0 when none).</summary>
    public delegate int ReceivePacketOverrideDelegate(ref Address from, Span<byte> packetData);
    /// <summary>Loopback payload delivery: (clientIndex, payload, packetSequence).</summary>
    public delegate void SendLoopbackPacketDelegate(int clientIndex, ReadOnlySpan<byte> packetData, ulong packetSequence);

    internal static class SendDispatch
    {
        public static void SendPacketToAddress(
            NetworkSimulator? simulator,
            SendPacketOverrideDelegate? sendPacketOverride,
            NetcodeSocket? socketIpv4,
            NetcodeSocket? socketIpv6,
            in Address from,
            in Address to,
            ReadOnlySpan<byte> packetData)
        {
            if (simulator != null)
            {
                simulator.SendPacket(in from, in to, packetData);
            }
            else if (sendPacketOverride != null)
            {
                sendPacketOverride(in to, packetData);
            }
            else if (to.Type == AddressType.IPv4)
            {
                socketIpv4?.SendPacket(in to, packetData);
            }
            else if (to.Type == AddressType.IPv6)
            {
                socketIpv6?.SendPacket(in to, packetData);
            }
        }
    }
}
