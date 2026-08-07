/*
    compat.c — the C half of the netcode.cs interop gate.

    Builds against the REAL C reference implementation by including netcode.c
    directly (the same technique the C repo's fuzz harnesses use), so it can
    reach the internal write/encrypt functions with fixed keys, nonces and
    timestamps and produce deterministic goldens.

    Subcommands:
        goldens <dir>            write golden files (fixed keys/nonces/timestamps)
        verify <dir>             read + decrypt + validate golden files (either side's)
        mint <file> <address>    mint a connect token with the shared test key
        server <port>            run a server session leg (connect/exchange/disconnect)
        client <port> <token>    run a client session leg against a server

    Exit code is the verdict.
*/

#include "netcode.c"

#include <stdio.h>
#include <string.h>

#define GOLDEN_PROTOCOL_ID 0x1122334455667788ULL
#define GOLDEN_CLIENT_ID 0x1122AABBCCDD3344ULL
#define GOLDEN_TIMEOUT_SECONDS 15
#define GOLDEN_EXPIRE_TIMESTAMP 0x1234567890ABCDEFULL
#define GOLDEN_CREATE_TIMESTAMP ( GOLDEN_EXPIRE_TIMESTAMP - 30 )
#define GOLDEN_CHALLENGE_SEQUENCE 0xBADDULL

#define SESSION_PROTOCOL_ID 0x1122334455667788ULL
#define SESSION_NUM_PAYLOADS 10

/* TEST KEY ONLY — the fixed key from the C reference test suite. published in
   two public repositories; obviously non-production. */
static uint8_t session_private_key[NETCODE_KEY_BYTES] = {
    0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
    0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
    0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
    0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };

static void fill_pattern( uint8_t * data, int bytes, int offset )
{
    int i;
    for ( i = 0; i < bytes; i++ )
        data[i] = (uint8_t) ( i + offset );
}

static int write_file( const char * dir, const char * name, const uint8_t * data, int bytes )
{
    char path[1024];
    snprintf( path, sizeof(path), "%s/%s", dir, name );
    FILE * file = fopen( path, "wb" );
    if ( !file )
    {
        printf( "error: could not open %s for writing\n", path );
        return 0;
    }
    fwrite( data, 1, (size_t) bytes, file );
    fclose( file );
    return 1;
}

static int read_file( const char * dir, const char * name, uint8_t * data, int expected_bytes )
{
    char path[1024];
    snprintf( path, sizeof(path), "%s/%s", dir, name );
    FILE * file = fopen( path, "rb" );
    if ( !file )
    {
        printf( "error: could not open %s for reading\n", path );
        return 0;
    }
    int bytes = (int) fread( data, 1, (size_t) expected_bytes + 1, file );
    fclose( file );
    if ( bytes != expected_bytes )
    {
        printf( "error: %s is %d bytes, expected %d\n", path, bytes, expected_bytes );
        return 0;
    }
    return 1;
}

/* golden object construction (shared between goldens + verify) */

static void golden_addresses( struct netcode_address_t * addresses )
{
    netcode_parse_address( "127.0.0.1:40000", &addresses[0] );
    netcode_parse_address( "[fe80::202:b3ff:fe1e:8329]:50000", &addresses[1] );
}

static void golden_private_token_struct( struct netcode_connect_token_private_t * token )
{
    memset( token, 0, sizeof( *token ) );
    token->client_id = GOLDEN_CLIENT_ID;
    token->timeout_seconds = GOLDEN_TIMEOUT_SECONDS;
    token->num_server_addresses = 2;
    golden_addresses( token->server_addresses );
    fill_pattern( token->client_to_server_key, NETCODE_KEY_BYTES, 2 );
    fill_pattern( token->server_to_client_key, NETCODE_KEY_BYTES, 3 );
    fill_pattern( token->user_data, NETCODE_USER_DATA_BYTES, 0 );
}

static void golden_keys_and_nonce( uint8_t * token_key, uint8_t * challenge_key, uint8_t * packet_key, uint8_t * nonce )
{
    fill_pattern( token_key, NETCODE_KEY_BYTES, 1 );
    fill_pattern( challenge_key, NETCODE_KEY_BYTES, 4 );
    fill_pattern( packet_key, NETCODE_KEY_BYTES, 5 );
    fill_pattern( nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES, 6 );
}

static int build_golden_private_token( uint8_t * buffer /* 1024 */ )
{
    struct netcode_connect_token_private_t token;
    golden_private_token_struct( &token );
    netcode_write_connect_token_private( &token, buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );

    return netcode_encrypt_connect_token_private( buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_VERSION_INFO,
                                                  GOLDEN_PROTOCOL_ID, GOLDEN_EXPIRE_TIMESTAMP, nonce, token_key ) == NETCODE_OK;
}

static int build_golden_challenge_token( uint8_t * buffer /* 300 */ )
{
    struct netcode_challenge_token_t token;
    memset( &token, 0, sizeof( token ) );
    token.client_id = GOLDEN_CLIENT_ID;
    fill_pattern( token.user_data, NETCODE_USER_DATA_BYTES, 0 );
    netcode_write_challenge_token( &token, buffer, NETCODE_CHALLENGE_TOKEN_BYTES );

    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );

    return netcode_encrypt_challenge_token( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, GOLDEN_CHALLENGE_SEQUENCE, challenge_key ) == NETCODE_OK;
}

static int do_goldens( const char * dir )
{
    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );

    /* 1. encrypted private connect token */

    uint8_t private_token[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    if ( !build_golden_private_token( private_token ) )
        return 0;
    if ( !write_file( dir, "private_token.bin", private_token, sizeof( private_token ) ) )
        return 0;

    /* 2. public connect token wrapping it */

    struct netcode_connect_token_t connect_token;
    memset( &connect_token, 0, sizeof( connect_token ) );
    memcpy( connect_token.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    connect_token.protocol_id = GOLDEN_PROTOCOL_ID;
    connect_token.create_timestamp = GOLDEN_CREATE_TIMESTAMP;
    connect_token.expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
    memcpy( connect_token.nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    memcpy( connect_token.private_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    connect_token.num_server_addresses = 2;
    golden_addresses( connect_token.server_addresses );
    fill_pattern( connect_token.client_to_server_key, NETCODE_KEY_BYTES, 2 );
    fill_pattern( connect_token.server_to_client_key, NETCODE_KEY_BYTES, 3 );
    connect_token.timeout_seconds = GOLDEN_TIMEOUT_SECONDS;

    uint8_t public_token[NETCODE_CONNECT_TOKEN_BYTES];
    netcode_write_connect_token( &connect_token, public_token, NETCODE_CONNECT_TOKEN_BYTES );
    if ( !write_file( dir, "public_token.bin", public_token, sizeof( public_token ) ) )
        return 0;

    /* 3. encrypted challenge token */

    uint8_t challenge_token[NETCODE_CHALLENGE_TOKEN_BYTES];
    if ( !build_golden_challenge_token( challenge_token ) )
        return 0;
    if ( !write_file( dir, "challenge_token.bin", challenge_token, sizeof( challenge_token ) ) )
        return 0;

    /* 4. every packet type, fixed keys and sequences */

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES * 2];
    int bytes;

    {
        struct netcode_connection_request_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        packet.protocol_id = GOLDEN_PROTOCOL_ID;
        packet.connect_token_expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
        memcpy( packet.connect_token_nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( packet.connect_token_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_request.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_denied_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 1ULL << 63, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_denied.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_challenge_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
        packet.challenge_token_sequence = GOLDEN_CHALLENGE_SEQUENCE;
        memcpy( packet.challenge_token_data, challenge_token, NETCODE_CHALLENGE_TOKEN_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), ( 1ULL << 63 ) + 5, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_challenge.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_response_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
        packet.challenge_token_sequence = GOLDEN_CHALLENGE_SEQUENCE;
        memcpy( packet.challenge_token_data, challenge_token, NETCODE_CHALLENGE_TOKEN_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x1F, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_response.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_keep_alive_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
        packet.client_index = 5;
        packet.max_clients = 32;
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x11223344, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_keepalive.bin", buffer, bytes ) )
            return 0;
    }

    {
        uint8_t payload_buffer[sizeof( struct netcode_connection_payload_packet_t ) + NETCODE_MAX_PAYLOAD_BYTES];
        struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) payload_buffer;
        packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        packet->payload_bytes = NETCODE_MAX_PAYLOAD_BYTES;
        fill_pattern( packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES, 0 );
        bytes = netcode_write_packet( packet, buffer, sizeof( buffer ), 1000, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_payload.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_disconnect_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 7, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_disconnect.bin", buffer, bytes ) )
            return 0;
    }

    printf( "goldens written to %s\n", dir );
    return 1;
}

#define VERIFY( condition )                                                     \
    do {                                                                        \
        if ( !(condition) )                                                     \
        {                                                                       \
            printf( "verify failed: %s, line %d\n", #condition, __LINE__ );     \
            return 0;                                                           \
        }                                                                       \
    } while (0)

static int do_verify( const char * dir )
{
    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );

    struct netcode_address_t expected_addresses[2];
    golden_addresses( expected_addresses );

    uint8_t expected_user_data[NETCODE_USER_DATA_BYTES];
    fill_pattern( expected_user_data, NETCODE_USER_DATA_BYTES, 0 );

    uint8_t expected_c2s[NETCODE_KEY_BYTES], expected_s2c[NETCODE_KEY_BYTES];
    fill_pattern( expected_c2s, NETCODE_KEY_BYTES, 2 );
    fill_pattern( expected_s2c, NETCODE_KEY_BYTES, 3 );

    /* 1. private connect token decrypts and reads back the golden fields */

    uint8_t private_token[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    if ( !read_file( dir, "private_token.bin", private_token, sizeof( private_token ) ) )
        return 0;

    VERIFY( netcode_decrypt_connect_token_private( private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_VERSION_INFO,
                                                   GOLDEN_PROTOCOL_ID, GOLDEN_EXPIRE_TIMESTAMP, nonce, token_key ) == NETCODE_OK );

    struct netcode_connect_token_private_t private_struct;
    VERIFY( netcode_read_connect_token_private( private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, &private_struct ) == NETCODE_OK );
    VERIFY( private_struct.client_id == GOLDEN_CLIENT_ID );
    VERIFY( private_struct.timeout_seconds == GOLDEN_TIMEOUT_SECONDS );
    VERIFY( private_struct.num_server_addresses == 2 );
    VERIFY( netcode_address_equal( &private_struct.server_addresses[0], &expected_addresses[0] ) );
    VERIFY( netcode_address_equal( &private_struct.server_addresses[1], &expected_addresses[1] ) );
    VERIFY( memcmp( private_struct.client_to_server_key, expected_c2s, NETCODE_KEY_BYTES ) == 0 );
    VERIFY( memcmp( private_struct.server_to_client_key, expected_s2c, NETCODE_KEY_BYTES ) == 0 );
    VERIFY( memcmp( private_struct.user_data, expected_user_data, NETCODE_USER_DATA_BYTES ) == 0 );

    /* 2. public connect token reads back */

    uint8_t public_token[NETCODE_CONNECT_TOKEN_BYTES];
    if ( !read_file( dir, "public_token.bin", public_token, sizeof( public_token ) ) )
        return 0;

    struct netcode_connect_token_t connect_token;
    VERIFY( netcode_read_connect_token( public_token, NETCODE_CONNECT_TOKEN_BYTES, &connect_token ) == NETCODE_OK );
    VERIFY( connect_token.protocol_id == GOLDEN_PROTOCOL_ID );
    VERIFY( connect_token.create_timestamp == GOLDEN_CREATE_TIMESTAMP );
    VERIFY( connect_token.expire_timestamp == GOLDEN_EXPIRE_TIMESTAMP );
    VERIFY( connect_token.timeout_seconds == GOLDEN_TIMEOUT_SECONDS );
    VERIFY( connect_token.num_server_addresses == 2 );
    VERIFY( netcode_address_equal( &connect_token.server_addresses[0], &expected_addresses[0] ) );
    VERIFY( netcode_address_equal( &connect_token.server_addresses[1], &expected_addresses[1] ) );

    /* 3. challenge token decrypts and reads back */

    uint8_t challenge_token[NETCODE_CHALLENGE_TOKEN_BYTES];
    if ( !read_file( dir, "challenge_token.bin", challenge_token, sizeof( challenge_token ) ) )
        return 0;

    VERIFY( netcode_decrypt_challenge_token( challenge_token, NETCODE_CHALLENGE_TOKEN_BYTES, GOLDEN_CHALLENGE_SEQUENCE, challenge_key ) == NETCODE_OK );

    struct netcode_challenge_token_t challenge_struct;
    VERIFY( netcode_read_challenge_token( challenge_token, NETCODE_CHALLENGE_TOKEN_BYTES, &challenge_struct ) == NETCODE_OK );
    VERIFY( challenge_struct.client_id == GOLDEN_CLIENT_ID );
    VERIFY( memcmp( challenge_struct.user_data, expected_user_data, NETCODE_USER_DATA_BYTES ) == 0 );

    /* 4. every packet type reads (and decrypts) back */

    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 1, sizeof( allowed_packets ) );

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES * 2];
    uint64_t sequence;

    {
        int bytes = 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES;
        if ( !read_file( dir, "packet_request.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_request_packet_t * packet = (struct netcode_connection_request_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, token_key, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_REQUEST_PACKET );
        VERIFY( packet->protocol_id == GOLDEN_PROTOCOL_ID );
        VERIFY( packet->connect_token_expire_timestamp == GOLDEN_EXPIRE_TIMESTAMP );
        free( packet );
    }

    {
        int bytes = 1 + 8 + NETCODE_MAC_BYTES;      /* prefix + 8 sequence bytes + mac */
        if ( !read_file( dir, "packet_denied.bin", buffer, bytes ) )
            return 0;
        void * packet = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( ( (uint8_t*) packet )[0] == NETCODE_CONNECTION_DENIED_PACKET );
        VERIFY( sequence == 1ULL << 63 );
        free( packet );
    }

    {
        int bytes = 1 + 8 + 8 + NETCODE_CHALLENGE_TOKEN_BYTES + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_challenge.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_challenge_packet_t * packet = (struct netcode_connection_challenge_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_CHALLENGE_PACKET );
        VERIFY( packet->challenge_token_sequence == GOLDEN_CHALLENGE_SEQUENCE );
        VERIFY( sequence == ( 1ULL << 63 ) + 5 );
        free( packet );
    }

    {
        int bytes = 1 + 1 + 8 + NETCODE_CHALLENGE_TOKEN_BYTES + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_response.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_response_packet_t * packet = (struct netcode_connection_response_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_RESPONSE_PACKET );
        VERIFY( packet->challenge_token_sequence == GOLDEN_CHALLENGE_SEQUENCE );
        VERIFY( sequence == 0x1F );
        free( packet );
    }

    {
        int bytes = 1 + 4 + 8 + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_keepalive.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_keep_alive_packet_t * packet = (struct netcode_connection_keep_alive_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET );
        VERIFY( packet->client_index == 5 );
        VERIFY( packet->max_clients == 32 );
        VERIFY( sequence == 0x11223344 );
        free( packet );
    }

    {
        int bytes = 1 + 2 + NETCODE_MAX_PAYLOAD_BYTES + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_payload.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
        VERIFY( packet->payload_bytes == NETCODE_MAX_PAYLOAD_BYTES );
        uint8_t expected_payload[NETCODE_MAX_PAYLOAD_BYTES];
        fill_pattern( expected_payload, NETCODE_MAX_PAYLOAD_BYTES, 0 );
        VERIFY( memcmp( packet->payload_data, expected_payload, NETCODE_MAX_PAYLOAD_BYTES ) == 0 );
        VERIFY( sequence == 1000 );
        free( packet );
    }

    {
        int bytes = 1 + 1 + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_disconnect.bin", buffer, bytes ) )
            return 0;
        void * packet = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( ( (uint8_t*) packet )[0] == NETCODE_CONNECTION_DISCONNECT_PACKET );
        VERIFY( sequence == 7 );
        free( packet );
    }

    printf( "verify passed: %s\n", dir );
    return 1;
}

static int do_mint( const char * filename, const char * server_address )
{
    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    fill_pattern( user_data, NETCODE_USER_DATA_BYTES, 0 );

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    if ( netcode_generate_connect_token( 1, &server_address, &server_address, 60, 15, client_id,
                                         SESSION_PROTOCOL_ID, session_private_key, user_data, connect_token ) != NETCODE_OK )
    {
        printf( "error: failed to mint connect token\n" );
        return 0;
    }

    FILE * file = fopen( filename, "wb" );
    if ( !file )
        return 0;
    fwrite( connect_token, 1, NETCODE_CONNECT_TOKEN_BYTES, file );
    fclose( file );
    printf( "minted connect token (C) -> %s\n", filename );
    return 1;
}

static int do_server( int port )
{
    char bind_address[64];
    snprintf( bind_address, sizeof(bind_address), "127.0.0.1:%d", port );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.protocol_id = SESSION_PROTOCOL_ID;
    memcpy( server_config.private_key, session_private_key, NETCODE_KEY_BYTES );

    struct netcode_server_t * server = netcode_server_create( bind_address, &server_config, 0.0 );
    if ( !server )
    {
        printf( "error: failed to create server\n" );
        return 0;
    }

    netcode_server_start( server, 1 );

    uint8_t payload[NETCODE_MAX_PACKET_SIZE];
    fill_pattern( payload, NETCODE_MAX_PACKET_SIZE, 0 );

    int payloads_received = 0;
    int client_was_connected = 0;
    double time = 0.0;
    double delta_time = 0.01;
    int iterations = 6000;      /* 60 seconds of real time at 10ms per iteration */
    int result = 0;

    printf( "C server listening on %s\n", bind_address );

    int i;
    for ( i = 0; i < iterations; i++ )
    {
        netcode_server_update( server, time );

        if ( netcode_server_client_connected( server, 0 ) )
        {
            client_was_connected = 1;

            netcode_server_send_packet( server, 0, payload, NETCODE_MAX_PACKET_SIZE );

            while ( 1 )
            {
                int packet_bytes;
                uint64_t packet_sequence;
                uint8_t * packet = netcode_server_receive_packet( server, 0, &packet_bytes, &packet_sequence );
                if ( !packet )
                    break;
                if ( packet_bytes != NETCODE_MAX_PACKET_SIZE || memcmp( packet, payload, NETCODE_MAX_PACKET_SIZE ) != 0 )
                {
                    printf( "error: C server received bad payload\n" );
                    netcode_server_free_packet( server, packet );
                    netcode_server_destroy( server );
                    return 0;
                }
                payloads_received++;
                netcode_server_free_packet( server, packet );
            }
        }
        else if ( client_was_connected )
        {
            /* the client disconnected. success requires that we saw its payloads and
               that the disconnect was client initiated, not a timeout. */
            int reason = netcode_server_client_disconnect_reason( server, 0 );
            if ( payloads_received >= SESSION_NUM_PAYLOADS && reason == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT )
            {
                printf( "C server: client connected, %d payloads received, clean client disconnect\n", payloads_received );
                result = 1;
            }
            else
            {
                printf( "error: C server: payloads_received=%d disconnect_reason=%d\n", payloads_received, reason );
            }
            break;
        }

        netcode_sleep( delta_time );
        time += delta_time;
    }

    if ( !client_was_connected )
        printf( "error: C server: no client connected within the time limit\n" );

    netcode_server_destroy( server );
    return result;
}

static int do_client( int port, const char * token_file )
{
    (void) port;

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    {
        FILE * file = fopen( token_file, "rb" );
        if ( !file )
        {
            printf( "error: could not open token file %s\n", token_file );
            return 0;
        }
        int bytes = (int) fread( connect_token, 1, NETCODE_CONNECT_TOKEN_BYTES, file );
        fclose( file );
        if ( bytes != NETCODE_CONNECT_TOKEN_BYTES )
        {
            printf( "error: token file is %d bytes\n", bytes );
            return 0;
        }
    }

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );

    struct netcode_client_t * client = netcode_client_create( "0.0.0.0:0", &client_config, 0.0 );
    if ( !client )
    {
        printf( "error: failed to create client\n" );
        return 0;
    }

    netcode_client_connect( client, connect_token );

    uint8_t payload[NETCODE_MAX_PACKET_SIZE];
    fill_pattern( payload, NETCODE_MAX_PACKET_SIZE, 0 );

    int payloads_received = 0;
    int payloads_sent = 0;
    double time = 0.0;
    double delta_time = 0.01;
    int iterations = 6000;
    int result = 0;

    int i;
    for ( i = 0; i < iterations; i++ )
    {
        netcode_client_update( client, time );

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
        {
            netcode_client_send_packet( client, payload, NETCODE_MAX_PACKET_SIZE );
            payloads_sent++;

            while ( 1 )
            {
                int packet_bytes;
                uint64_t packet_sequence;
                uint8_t * packet = netcode_client_receive_packet( client, &packet_bytes, &packet_sequence );
                if ( !packet )
                    break;
                if ( packet_bytes != NETCODE_MAX_PACKET_SIZE || memcmp( packet, payload, NETCODE_MAX_PACKET_SIZE ) != 0 )
                {
                    printf( "error: C client received bad payload\n" );
                    netcode_client_free_packet( client, packet );
                    netcode_client_destroy( client );
                    return 0;
                }
                payloads_received++;
                netcode_client_free_packet( client, packet );
            }

            /* keep sending past the receive threshold so the other side reliably
               sees its quota before the disconnect lands */
            if ( payloads_received >= SESSION_NUM_PAYLOADS && payloads_sent >= SESSION_NUM_PAYLOADS * 2 )
            {
                printf( "C client: connected as client %d, %d payloads received, disconnecting\n",
                        netcode_client_index( client ), payloads_received );
                netcode_client_disconnect( client );
                result = 1;
                break;
            }
        }
        else if ( netcode_client_state( client ) < NETCODE_CLIENT_STATE_DISCONNECTED )
        {
            printf( "error: C client entered error state %d\n", netcode_client_state( client ) );
            break;
        }

        netcode_sleep( delta_time );
        time += delta_time;
    }

    if ( !result && payloads_received < SESSION_NUM_PAYLOADS )
        printf( "error: C client: only %d payloads received\n", payloads_received );

    netcode_client_destroy( client );
    return result;
}

int main( int argc, char ** argv )
{
    if ( netcode_init() != NETCODE_OK )
    {
        printf( "error: failed to initialize netcode\n" );
        return 1;
    }

    netcode_log_level( NETCODE_LOG_LEVEL_ERROR );

    int ok = 0;

    if ( argc == 3 && strcmp( argv[1], "goldens" ) == 0 )
        ok = do_goldens( argv[2] );
    else if ( argc == 3 && strcmp( argv[1], "verify" ) == 0 )
        ok = do_verify( argv[2] );
    else if ( argc == 4 && strcmp( argv[1], "mint" ) == 0 )
        ok = do_mint( argv[2], argv[3] );
    else if ( argc == 3 && strcmp( argv[1], "server" ) == 0 )
        ok = do_server( atoi( argv[2] ) );
    else if ( argc == 4 && strcmp( argv[1], "client" ) == 0 )
        ok = do_client( atoi( argv[2] ), argv[3] );
    else
        printf( "usage: compat-c goldens <dir> | verify <dir> | mint <file> <address> | server <port> | client <port> <token>\n" );

    netcode_term();

    return ok ? 0 : 1;
}
