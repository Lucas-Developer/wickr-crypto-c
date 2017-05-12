//
//  stream.c
//  Crypto
//
//  Created by Tom Leavy on 4/11/17.
//
//

#include "transport_ctx.h"
#include "memory.h"
#include "stream.pb-c.h"
#include "protobuf_util.h"
#include "stream_cipher.h"
#include "protocol.h"
#include "transport_priv.h"


static uint8_t __wickr_handshake_version_to_key_exchange(uint8_t handshake_version)
{
    switch (handshake_version) {
        case 1:
            return 4;
            break;
        default:
            return 0;
    }
}

static bool __wickr_transport_ctx_create_mac(wickr_transport_ctx_t *ctx, wickr_transport_packet_t *packet)
{
    if (!ctx || !packet) {
        return false;
    }
    
    wickr_buffer_t *data_to_sign = wickr_transport_packet_serialize(packet);
    
    if (!data_to_sign) {
        return false;
    }
    
    wickr_ecdsa_result_t *signature = wickr_identity_sign(ctx->local_identity->id_chain->node, &ctx->engine, data_to_sign);
    wickr_buffer_destroy(&data_to_sign);
    
    if (!signature) {
        return false;
    }
    
    wickr_buffer_t *signature_buffer = wickr_ecdsa_result_serialize(signature);
    wickr_ecdsa_result_destroy(&signature);

    if (!signature_buffer) {
        return false;
    }
    
    packet->mac = signature_buffer;
    
    return true;
}

static bool __wickr_transport_ctx_verify_mac(wickr_transport_ctx_t *ctx, wickr_transport_packet_t *packet, wickr_buffer_t *packet_buffer)
{
    if (!ctx || !packet || !packet->mac) {
        return false;
    }
    
    if (packet_buffer->length <= packet->mac->length) {
        return false;
    }
    
    wickr_ecdsa_result_t *signature = wickr_ecdsa_result_create_from_buffer(packet->mac);
    
    if (!signature) {
        return false;
    }
    
    /* Create a temp buffer with a length that puts it's end before the start of the mac */
    wickr_buffer_t validation_buffer;
    validation_buffer.bytes = packet_buffer->bytes;
    validation_buffer.length = packet_buffer->length - packet->mac->length;
    
    bool return_val = ctx->engine.wickr_crypto_engine_ec_verify(signature, ctx->remote_identity->id_chain->node->sig_key, &validation_buffer);
    
    wickr_ecdsa_result_destroy(&signature);
    
    return return_val;
    
}

static void __wickr_transport_ctx_update_status(wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    if (!ctx) {
        return;
    }
    
    ctx->status = status;
    ctx->callbacks.on_state(ctx, status);
}

wickr_transport_ctx_t *wickr_transport_ctx_create(const wickr_crypto_engine_t engine, wickr_node_t *local_identity, wickr_node_t *remote_identity, uint32_t evo_count, wickr_transport_callbacks_t callbacks)
{
    if (!local_identity || !remote_identity) {
        return NULL;
    }
    
    if (evo_count != 0 && (evo_count > PACKET_PER_EVO_MAX || evo_count < PACKET_PER_EVO_MIN)) {
        return NULL;
    }
    
    wickr_transport_ctx_t *ctx = wickr_alloc_zero(sizeof(wickr_transport_ctx_t));
    
    if (!ctx) {
        return NULL;
    }
    
    ctx->status = TRANSPORT_STATUS_NONE;
    ctx->engine = engine;
    ctx->local_identity = local_identity;
    ctx->remote_identity = remote_identity;
    ctx->callbacks = callbacks;
    ctx->evo_count = evo_count == 0 ? PACKET_PER_EVO_DEFAULT : evo_count;
    return ctx;
}

wickr_transport_ctx_t *wickr_transport_ctx_copy(wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    wickr_node_t *local_copy = wickr_node_copy(ctx->local_identity);
    
    if (!local_copy) {
        return NULL;
    }
    
    wickr_node_t *remote_copy = wickr_node_copy(ctx->remote_identity);
    
    if (!remote_copy) {
        wickr_node_destroy(&local_copy);
        return NULL;
    }
    
    wickr_stream_ctx_t *tx_copy = wickr_stream_ctx_copy(ctx->tx_stream);
    
    if (!tx_copy && ctx->tx_stream) {
        wickr_node_destroy(&local_copy);
        wickr_node_destroy(&remote_copy);
        return NULL;
    }
    
    wickr_stream_ctx_t *rx_copy = wickr_stream_ctx_copy(ctx->rx_stream);
    
    if (!rx_copy && ctx->rx_stream) {
        wickr_node_destroy(&local_copy);
        wickr_node_destroy(&remote_copy);
        wickr_stream_ctx_destroy(&tx_copy);
        return NULL;
    }
    
    wickr_transport_ctx_t *copy = wickr_alloc_zero(sizeof(wickr_transport_ctx_t));
    
    if (!copy) {
        wickr_node_destroy(&local_copy);
        wickr_node_destroy(&remote_copy);
        wickr_stream_ctx_destroy(&tx_copy);
        wickr_stream_ctx_destroy(&rx_copy);
        return NULL;
    }
    
    copy->engine = ctx->engine;
    copy->local_identity = local_copy;
    copy->remote_identity = remote_copy;
    copy->tx_stream = tx_copy;
    copy->rx_stream = rx_copy;
    copy->status = ctx->status;
    copy->callbacks = ctx->callbacks;
    copy->evo_count = ctx->evo_count;
    
    return copy;
}

void wickr_transport_ctx_destroy(wickr_transport_ctx_t **ctx)
{
    if (!ctx || !*ctx) {
        return;
    }
    
    wickr_node_destroy(&(*ctx)->local_identity);
    wickr_node_destroy(&(*ctx)->remote_identity);
    wickr_stream_ctx_destroy(&(*ctx)->tx_stream);
    wickr_stream_ctx_destroy(&(*ctx)->rx_stream);
    
    wickr_free(*ctx);
    *ctx = NULL;
}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_packet_create(wickr_transport_ctx_t *ctx, Wickr__Proto__Handshake *handshake)
{
    size_t packed_size = wickr__proto__handshake__get_packed_size(handshake);
    
    wickr_buffer_t *handshake_buffer = wickr_buffer_create_empty(packed_size);
    
    if (!handshake_buffer) {
        return NULL;
    }
    
    wickr__proto__handshake__pack(handshake, handshake_buffer->bytes);
    
    uint64_t seq_number = 0;
    
    /* If we have a tx_stream, we want to use the next seq number is has available */
    if (ctx->tx_stream) {
        seq_number = ctx->tx_stream->last_seq + 1;
    }
    
    wickr_transport_packet_t *handshake_packet = wickr_transport_packet_create(seq_number, PAYLOAD_TYPE_HANDSHAKE, handshake_buffer, NULL);
    
    if (!handshake_packet) {
        wickr_buffer_destroy(&handshake_buffer);
        return NULL;
    }
    
    if (!__wickr_transport_ctx_create_mac(ctx, handshake_packet)) {
        wickr_transport_packet_destroy(&handshake_packet);
        return NULL;
    }
    
    /* If we have a tx_stream we need to update the seq_number so that we don't have duplicate numbers used */
    if (ctx->tx_stream) {
        ctx->tx_stream->last_seq = seq_number;
    }
    
    return handshake_packet;
}

static Wickr__Proto__Handshake *__wickr_transport_ctx_handshake_packet_unpack(wickr_transport_ctx_t *ctx,
                                                                wickr_transport_packet_t *packet,
                                                                Wickr__Proto__Handshake__PayloadCase expected_payload)
{
    if (!ctx || !packet) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = wickr__proto__handshake__unpack(NULL, packet->body->length, packet->body->bytes);
    
    if (!handshake_data) {
        return NULL;
    }
    
    if (handshake_data->version != CURRENT_HANDSHAKE_VERSION ||
        handshake_data->payload_case != expected_payload)
    {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        return NULL;
    }
    
    return handshake_data;
}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_generate_tx_key_exchange(wickr_transport_ctx_t *ctx,
                                                                                          Wickr__Proto__Handshake__PayloadCase phase,
                                                                                          wickr_stream_key_t *tx_key,
                                                                                          wickr_ec_key_t *seed_key,
                                                                                          uint8_t version)
{
    if (!ctx ||
        !tx_key ||
        version != CURRENT_HANDSHAKE_VERSION ||
        phase == WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED ||
        phase == WICKR__PROTO__HANDSHAKE__PAYLOAD__NOT_SET)
    {
        return NULL;
    }
    
    if (phase == WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE && !seed_key) {
        return NULL;
    }
    
    wickr_ec_key_t *packet_exchange_key = ctx->engine.wickr_crypto_engine_ec_rand_key(ctx->engine.default_curve);
    
    if (!packet_exchange_key) {
        return NULL;
    }
    
    wickr_buffer_t *tx_key_buffer = wickr_stream_key_serialize(tx_key);
    
    if (!tx_key_buffer) {
        wickr_ec_key_destroy(&packet_exchange_key);
        return NULL;
    }
    
    uint8_t key_ex_version = __wickr_handshake_version_to_key_exchange(CURRENT_HANDSHAKE_VERSION);
    
    if (!key_ex_version) {
        wickr_buffer_destroy(&tx_key_buffer);
        wickr_ec_key_destroy(&packet_exchange_key);
        return NULL;
    }
    
    wickr_key_exchange_t *key_exchange = wickr_key_exchange_create_with_data(&ctx->engine,
                                                                             ctx->local_identity->id_chain,
                                                                             ctx->remote_identity,
                                                                             packet_exchange_key,
                                                                             tx_key_buffer,
                                                                             ctx->engine.default_cipher,
                                                                             key_ex_version);
    
    wickr_buffer_destroy_zero(&tx_key_buffer);
    
    if (!key_exchange) {
        wickr_ec_key_destroy(&packet_exchange_key);
        return NULL;
    }
    
    Wickr__Proto__Handshake__KeyExchange key_exchange_p = WICKR__PROTO__HANDSHAKE__KEY_EXCHANGE__INIT;
    key_exchange_p.has_sender_pub = true;
    key_exchange_p.sender_pub.data = packet_exchange_key->pub_data->bytes;
    key_exchange_p.sender_pub.len = packet_exchange_key->pub_data->length;
    key_exchange_p.has_exchange_data = true;
    key_exchange_p.exchange_data.data = key_exchange->exchange_data->bytes;
    key_exchange_p.exchange_data.len = key_exchange->exchange_data->length;
    
    Wickr__Proto__Handshake__Response response = WICKR__PROTO__HANDSHAKE__RESPONSE__INIT;
    response.key_exchange = &key_exchange_p;
    response.drop = false;
    
    Wickr__Proto__Handshake__Seed seed = WICKR__PROTO__HANDSHAKE__SEED__INIT;
    
    if (seed_key) {
        seed.has_pubkey = true;
        seed.pubkey.data = seed_key->pub_data->bytes;
        seed.pubkey.len = seed_key->pub_data->length;
        response.response_key = &seed;
    }
    
    Wickr__Proto__Handshake return_handshake = WICKR__PROTO__HANDSHAKE__INIT;
    return_handshake.payload_case = phase;
    return_handshake.response = &response;
    return_handshake.version = version;
    
    
    wickr_transport_packet_t *packet = __wickr_transport_ctx_handshake_packet_create(ctx, &return_handshake);
    wickr_ec_key_destroy(&packet_exchange_key);
    wickr_key_exchange_destroy(&key_exchange);
    
    if (!packet) {
        return NULL;
    }
    
    return packet;
}

static bool __wickr_transport_ctx_update_remote_keypair(wickr_transport_ctx_t *ctx, ProtobufCBinaryData pubkey_data)
{
    if (!ctx) {
        return false;
    }
    
    wickr_buffer_t remote_keypair_buffer = { pubkey_data.len, pubkey_data.data };
    wickr_ec_key_t *remote_keypair = ctx->engine.wickr_crypto_engine_ec_key_import(&remote_keypair_buffer, false);
    
    if (!remote_keypair) {
        return false;
    }
    
    wickr_ephemeral_keypair_t *remote_eph_keypair = wickr_ephemeral_keypair_create(0, remote_keypair, NULL);
    
    if (!remote_keypair) {
        wickr_ec_key_destroy(&remote_keypair);
        return false;
    }
    
    if (!wickr_node_rotate_keypair(ctx->remote_identity, remote_eph_keypair, false)) {
        wickr_ephemeral_keypair_destroy(&remote_eph_keypair);
        return false;
    }
    
    return true;
}

static void __wickr_transport_ctx_update_tx_stream(wickr_transport_ctx_t *ctx, wickr_stream_ctx_t *tx_stream)
{
    wickr_stream_ctx_destroy(&ctx->tx_stream);
    ctx->tx_stream = tx_stream;
}

static void __wickr_transport_ctx_update_rx_stream(wickr_transport_ctx_t *ctx, wickr_stream_ctx_t *rx_stream)
{
    wickr_stream_ctx_destroy(&ctx->rx_stream);
    ctx->rx_stream = rx_stream;
}

static bool __wickr_transport_ctx_set_handshake_key(wickr_transport_ctx_t *ctx, wickr_ec_key_t *handshake_key)
{
    if (!ctx || !handshake_key) {
        return false;
    }
    
    wickr_ec_key_t *copy_key = wickr_ec_key_copy(handshake_key);
    
    if (!copy_key) {
        return false;
    }
    
    wickr_ephemeral_keypair_t *ephemeral_key = wickr_ephemeral_keypair_create(0, copy_key, NULL);
    
    if (!ephemeral_key) {
        return false;
    }
    
    if (!wickr_node_rotate_keypair(ctx->local_identity, ephemeral_key, false)) {
        wickr_ephemeral_keypair_destroy(&ephemeral_key);
        return false;
    }
    
    return true;
}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_respond(wickr_transport_ctx_t *ctx, ProtobufCBinaryData pubkey_data, uint8_t version)
{
    if (!ctx ) {
        return NULL;
    }
    
    if (!__wickr_transport_ctx_update_remote_keypair(ctx, pubkey_data)) {
        return NULL;
    }
    
    wickr_stream_key_t *tx_key = wickr_stream_key_create_rand(ctx->engine, ctx->engine.default_cipher, ctx->evo_count);
    
    if (!tx_key) {
        wickr_ephemeral_keypair_destroy(&ctx->remote_identity->ephemeral_keypair);
        return NULL;
    }
    
    Wickr__Proto__Handshake__PayloadCase phase = ctx->status == TRANSPORT_STATUS_NONE ? WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE : WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH;
    
    wickr_ec_key_t *key = NULL;

    if (phase == WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE) {
        key = ctx->engine.wickr_crypto_engine_ec_rand_key(ctx->engine.default_curve);
        
        if (!key) {
            wickr_stream_key_destroy(&tx_key);
            return NULL;
        }
        
        if (!__wickr_transport_ctx_set_handshake_key(ctx, key)) {
            wickr_stream_key_destroy(&tx_key);
            return NULL;
        }
    }
    
    wickr_transport_packet_t *packet = __wickr_transport_ctx_handshake_generate_tx_key_exchange(ctx,
                                                                        phase,
                                                                        tx_key,
                                                                        key,
                                                                        version);
    
    wickr_ec_key_destroy(&key);
    wickr_ephemeral_keypair_destroy(&ctx->remote_identity->ephemeral_keypair);
    
    if (!packet) {
        wickr_stream_key_destroy(&tx_key);
        return NULL;
    }
    
    
    wickr_stream_ctx_t *tx_stream = wickr_stream_ctx_create(ctx->engine, tx_key, STREAM_DIRECTION_ENCODE);
    
    if (!tx_stream) {
        wickr_transport_packet_destroy(&packet);
        wickr_stream_key_destroy(&tx_key);
        return NULL;
    }
    
    __wickr_transport_ctx_update_tx_stream(ctx, tx_stream);
    
    return packet;

}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_seed_respond(wickr_transport_ctx_t *ctx, wickr_transport_packet_t *handshake)
{
    if (!ctx || !handshake) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = __wickr_transport_ctx_handshake_packet_unpack(ctx, handshake, WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED);
    
    if (!handshake_data) {
        return NULL;
    }
    
    if (!handshake_data->seed->has_pubkey) {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        return NULL;
    }
    
    wickr_transport_packet_t *return_packet = __wickr_transport_ctx_handshake_respond(ctx, handshake_data->seed->pubkey, handshake_data->version);
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);
    
    return return_packet;
}

static wickr_stream_key_t *__wickr_transport_ctx_handshake_decode_rx_key(wickr_transport_ctx_t *ctx,
                                                                  Wickr__Proto__Handshake__KeyExchange *return_exchange,
                                                                  uint8_t version)
{
    if (!ctx || !return_exchange || version != CURRENT_HANDSHAKE_VERSION) {
        return NULL;
    }
    
    uint8_t key_ex_version = __wickr_handshake_version_to_key_exchange(version);
    
    if (!return_exchange->has_exchange_data || !return_exchange->has_sender_pub || !key_ex_version)
    {
        return NULL;
    }
    
    wickr_buffer_t key_exchange_buffer = { return_exchange->exchange_data.len, return_exchange->exchange_data.data };
    wickr_buffer_t exchange_key_buffer = { return_exchange->sender_pub.len, return_exchange->sender_pub.data };
    
    wickr_key_exchange_t exchange;
    exchange.ephemeral_key_id = 0;
    exchange.node_id = ctx->local_identity->id_chain->node->identifier;
    exchange.exchange_data = &key_exchange_buffer;
    
    wickr_ec_key_t *ec_key = ctx->engine.wickr_crypto_engine_ec_key_import(&exchange_key_buffer, false);
    
    if (!ec_key) {
        return NULL;
    }
    
    wickr_buffer_t *rx_key_buffer = wickr_key_exchange_derive_data(&ctx->engine, ctx->remote_identity->id_chain, ctx->local_identity, ec_key, &exchange, key_ex_version);
    
    wickr_ephemeral_keypair_destroy(&ctx->local_identity->ephemeral_keypair);
    wickr_ec_key_destroy(&ec_key);
    
    if (!rx_key_buffer) {
        return NULL;
    }
    
    wickr_stream_key_t *rx_key = wickr_stream_key_create_from_buffer(rx_key_buffer);
    wickr_buffer_destroy_zero(&rx_key_buffer);

    return rx_key;
}

static Wickr__Proto__Handshake *__wickr_transport_ctx_handshake_process_response(wickr_transport_ctx_t *ctx, wickr_transport_packet_t *return_handshake)
{
    if (!ctx || !return_handshake) {
        return NULL;
    }
    
    switch (ctx->status) {
        case TRANSPORT_STATUS_NONE:
        case TRANSPORT_STATUS_ERROR:
        case TRANSPORT_STATUS_ACTIVE:
            return NULL;
        default:
            break;
    }
    
    Wickr__Proto__Handshake__PayloadCase phase = ctx->status == TRANSPORT_STATUS_SEEDED ? WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE : WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH;
    
    Wickr__Proto__Handshake *handshake_data = __wickr_transport_ctx_handshake_packet_unpack(ctx,
                                                                              return_handshake,
                                                                              phase);
    
    if (!handshake_data) {
        return NULL;
    }
    
    Wickr__Proto__Handshake__KeyExchange *key_exchange;
    
    switch (phase) {
        case WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE:
            key_exchange = handshake_data->response->key_exchange;
            break;
        case WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH:
            key_exchange = handshake_data->finish->key_exchange;
            break;
        default:
            wickr__proto__handshake__free_unpacked(handshake_data, NULL);
            return NULL;
    }
   
    wickr_stream_key_t *rx_key = __wickr_transport_ctx_handshake_decode_rx_key(ctx, key_exchange, handshake_data->version);
    
    if (!rx_key) {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        return NULL;
    }
    
    wickr_stream_ctx_t *rx_stream = wickr_stream_ctx_create(ctx->engine, rx_key, STREAM_DIRECTION_DECODE);
    
    if (!rx_stream) {
        wickr_stream_key_destroy(&rx_key);
        return NULL;
    }
    
    __wickr_transport_ctx_update_rx_stream(ctx, rx_stream);
    
    return handshake_data;
}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_process_return(wickr_transport_ctx_t *ctx, wickr_transport_packet_t *return_handshake)
{
    if (!ctx || !return_handshake) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = __wickr_transport_ctx_handshake_process_response(ctx, return_handshake);
    
    if (!handshake_data) {
        return NULL;
    }
    
    wickr_transport_packet_t *return_packet = __wickr_transport_ctx_handshake_respond(ctx, handshake_data->response->response_key->pubkey, handshake_data->version);
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);
    
    return return_packet;
}

static bool __wickr_transport_ctx_handshake_finish(wickr_transport_ctx_t *ctx, wickr_transport_packet_t *finish_handshake)
{
    if (!ctx || !finish_handshake) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = __wickr_transport_ctx_handshake_process_response(ctx, finish_handshake);
    
    if (!handshake_data) {
        return false;
    }
    
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);

    return true;
}

static wickr_buffer_t *__wickr_transport_ctx_decode_pkt(wickr_transport_ctx_t *ctx, wickr_transport_packet_t *pkt)
{
    if (!ctx || !pkt) {
        return NULL;
    }
    
    wickr_cipher_result_t *cipher_result = wickr_cipher_result_from_buffer(pkt->body);
    
    if (!cipher_result) {
        return NULL;
    }
    
    wickr_buffer_t *aad_buffer = wickr_transport_packet_make_meta_buffer(pkt);
    
    if (!aad_buffer) {
        wickr_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    wickr_buffer_t *return_buffer = wickr_stream_ctx_decode(ctx->rx_stream, cipher_result, aad_buffer, pkt->seq_num);
    wickr_cipher_result_destroy(&cipher_result);
    wickr_buffer_destroy(&aad_buffer);
    
    return return_buffer;
}

static wickr_transport_packet_t *__wickr_transport_ctx_encode_pkt(wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    if (!ctx || !data) {
        return NULL;
    }
    
    uint64_t next_pkt_seq = ctx->tx_stream->last_seq + 1;
    
    wickr_buffer_t temp_body = { 0, NULL };
    wickr_transport_packet_t *pkt = wickr_transport_packet_create(next_pkt_seq, PAYLOAD_TYPE_CIPHERTEXT, &temp_body, NULL);
    
    if (!pkt) {
        return NULL;
    }
    
    wickr_buffer_t *aad_buffer = wickr_transport_packet_make_meta_buffer(pkt);
    
    if (!aad_buffer) {
        wickr_transport_packet_destroy(&pkt);
        return NULL;
    }
    
    wickr_cipher_result_t *cipher_result = wickr_stream_ctx_encode(ctx->tx_stream, data, aad_buffer, next_pkt_seq);
    wickr_buffer_destroy(&aad_buffer);
    
    if (!cipher_result) {
        wickr_transport_packet_destroy(&pkt);
        return NULL;
    }
    
    wickr_buffer_t *serialized = wickr_cipher_result_serialize(cipher_result);
    wickr_cipher_result_destroy(&cipher_result);
    
    if (!serialized) {
        wickr_transport_packet_destroy(&pkt);
        return NULL;
    }
    
    pkt->body = serialized;
    
    return pkt;
}

void wickr_transport_ctx_start(wickr_transport_ctx_t *ctx)
{
    if (!ctx || ctx->status == TRANSPORT_STATUS_ERROR) {
        return;
    }
    
    wickr_ec_key_t *handshake_key = ctx->engine.wickr_crypto_engine_ec_rand_key(ctx->engine.default_curve);
    
    if (!handshake_key) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    Wickr__Proto__Handshake__Seed seed = WICKR__PROTO__HANDSHAKE__SEED__INIT;
    seed.has_pubkey = true;
    seed.pubkey.data = handshake_key->pub_data->bytes;
    seed.pubkey.len = handshake_key->pub_data->length;
    
    Wickr__Proto__Handshake handshake = WICKR__PROTO__HANDSHAKE__INIT;
    handshake.payload_case = WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED;
    handshake.seed = &seed;
    handshake.version = CURRENT_HANDSHAKE_VERSION;
    
    wickr_transport_packet_t *handshake_pkt = __wickr_transport_ctx_handshake_packet_create(ctx, &handshake);
    
    if (!handshake_pkt) {
        wickr_ec_key_destroy(&handshake_key);
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    bool result = __wickr_transport_ctx_set_handshake_key(ctx, handshake_key);
    wickr_ec_key_destroy(&handshake_key);
    
    if (!result) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    wickr_buffer_t *serialized_packet = wickr_transport_packet_serialize(handshake_pkt);
    wickr_transport_packet_destroy(&handshake_pkt);
    
    if (!serialized_packet) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_SEEDED);
    
    ctx->callbacks.tx(ctx, serialized_packet);
}

void wickr_transport_ctx_process_tx_buffer(wickr_transport_ctx_t *ctx, wickr_buffer_t *buffer)
{
    if (!ctx || !buffer || ctx->status == TRANSPORT_STATUS_ERROR) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    if (ctx->status != TRANSPORT_STATUS_ACTIVE) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    wickr_transport_packet_t *tx_packet = __wickr_transport_ctx_encode_pkt(ctx, buffer);
    
    if (!tx_packet) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    wickr_buffer_t *out_buffer = wickr_transport_packet_serialize(tx_packet);
    wickr_transport_packet_destroy(&tx_packet);
    
    if (!out_buffer) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    ctx->callbacks.tx(ctx, out_buffer);
}

void wickr_transport_ctx_process_rx_buffer(wickr_transport_ctx_t *ctx, wickr_buffer_t *buffer)
{
    if (!ctx || !buffer || ctx->status == TRANSPORT_STATUS_ERROR) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    wickr_transport_packet_t *packet = wickr_transport_packet_create_from_buffer(buffer, ctx->remote_identity->id_chain->node->sig_key->curve.signature_size);
    
    if (!packet) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    bool valid_mac = __wickr_transport_ctx_verify_mac(ctx, packet, buffer);
    
    /* The mac is not required in the condition that we are passed the handshake, the body type of the packet is ciphertext,
       and the cipher of the rx stream is authenticated. In this scenario we rely on the cipher level authentication instead of an explicit mac
     */
    if (!valid_mac) {
        if (ctx->status == TRANSPORT_STATUS_ACTIVE && packet->body_type == PAYLOAD_TYPE_CIPHERTEXT &&
            ctx->rx_stream->key->cipher_key->cipher.is_authenticated) {
            valid_mac = true;
        }
    }
    
    if (!valid_mac) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    wickr_transport_packet_t *volley_packet = NULL;
    wickr_buffer_t *return_buffer = NULL;
    
    switch (ctx->status) {
        case TRANSPORT_STATUS_NONE:
            volley_packet = __wickr_transport_ctx_handshake_seed_respond(ctx, packet);
            
            if (!volley_packet) {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            }
            else {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_TX_INIT);
            }
            
            break;
        case TRANSPORT_STATUS_TX_INIT:
            if (!__wickr_transport_ctx_handshake_finish(ctx, packet)) {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            }
            else {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ACTIVE);
            }
            break;
        case TRANSPORT_STATUS_SEEDED:
            volley_packet = __wickr_transport_ctx_handshake_process_return(ctx, packet);
            
            if (!volley_packet) {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            }
            else {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ACTIVE);
            }
            break;
        case TRANSPORT_STATUS_ACTIVE:
            
            if (packet->body_type == PAYLOAD_TYPE_HANDSHAKE) {
                volley_packet = __wickr_transport_ctx_handshake_seed_respond(ctx, packet);
                
                if (!volley_packet) {
                    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
                }
                else {
                    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_TX_INIT);
                }
            }
            else {
                return_buffer = __wickr_transport_ctx_decode_pkt(ctx, packet);
            }
            
            break;
        default:
            break;
    }
    
    /* Make sure to adjust the rx_stream seq num to compensate for any control messages received */
    if (ctx->rx_stream && ctx->rx_stream->last_seq != packet->seq_num) {
        ctx->rx_stream->last_seq = packet->seq_num;
    }
    
    wickr_transport_packet_destroy(&packet);
    
    if (volley_packet) {
        wickr_buffer_t *packet_buffer = wickr_transport_packet_serialize(volley_packet);
        wickr_transport_packet_destroy(&volley_packet);
        
        if (!packet_buffer) {
            __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            return;
        }
        ctx->callbacks.tx(ctx, packet_buffer);
    }
    
    if (return_buffer) {
        ctx->callbacks.rx(ctx, return_buffer);
    }
    
}

