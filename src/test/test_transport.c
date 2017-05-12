
#include "test_transport.h"
#include "transport_ctx.h"
#include "transport_priv.h"
#include "stream_cipher.h"
#include "externs.h"

/* Test Transports */
wickr_transport_ctx_t *alice_transport = NULL;
wickr_transport_ctx_t *bob_transport = NULL;

/* Static helper variables */

/* Alice */
static wickr_buffer_t *last_tx_alice = NULL;
static wickr_buffer_t *last_rx_alice = NULL;
static wickr_transport_status last_status_alice = TRANSPORT_STATUS_NONE;

/* Bob */
static wickr_buffer_t *last_tx_bob = NULL;
static wickr_buffer_t *last_rx_bob = NULL;
static wickr_transport_status last_status_bob = TRANSPORT_STATUS_NONE;

/* Test Callbacks for Alice */
bool wickr_test_transport_tx_alice(wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    wickr_buffer_destroy(&last_tx_alice);
    last_tx_alice = data;
    
    wickr_transport_ctx_process_rx_buffer(bob_transport, data);
    
    return true;
}

bool wickr_test_transport_tx_alice_no_send(wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    wickr_buffer_destroy(&last_tx_alice);
    last_tx_alice = data;
    return true;
}

bool wickr_test_transport_rx_alice(wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    wickr_buffer_destroy(&last_rx_alice);
    last_rx_alice = data;
    
    return true;
}

void wickr_test_transport_status_alice(wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    last_status_alice = status;
}

/* Test callbacks for Bob */
bool wickr_test_transport_tx_bob(wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    wickr_buffer_destroy(&last_tx_bob);
    last_tx_bob = data;
    
    wickr_transport_ctx_process_rx_buffer(alice_transport, data);
    
    return true;
}

bool wickr_test_transport_tx_bob_no_send(wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    wickr_buffer_destroy(&last_tx_bob);
    last_tx_bob = data;
    
    return true;
}

bool wickr_test_transport_rx_bob(wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    wickr_buffer_destroy(&last_rx_bob);
    last_rx_bob = data;
    
    return true;
}

void wickr_test_transport_status_bob(wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    last_status_bob = status;
}

static wickr_transport_callbacks_t test_callbacks_alice = { wickr_test_transport_tx_alice,
    wickr_test_transport_rx_alice,
    wickr_test_transport_status_alice };


static wickr_transport_callbacks_t test_callbacks_bob = { wickr_test_transport_tx_bob,
    wickr_test_transport_rx_bob,
    wickr_test_transport_status_bob };

void test_packet_send(wickr_transport_ctx_t *sender_ctx, wickr_buffer_t **last_packet, wickr_buffer_t **expected, int pkt_number)
{
    wickr_buffer_t *test_buffer = engine.wickr_crypto_engine_crypto_random(32);
    wickr_transport_ctx_process_tx_buffer(sender_ctx, test_buffer);
    
    /* The tx callback for alice will produce the encrypted packets */
    SHOULD_BE_FALSE(wickr_buffer_is_equal(test_buffer, *last_packet, NULL));
    SHOULD_BE_TRUE((*last_packet)->length > test_buffer->length);
    
    uint64_t *bytes = (uint64_t *)(*last_packet)->bytes;
    SHOULD_EQUAL(bytes[0], pkt_number);
    SHOULD_EQUAL((*last_packet)->bytes[sizeof(uint64_t)], PAYLOAD_TYPE_CIPHERTEXT);
    
    wickr_buffer_t temp_buffer;
    temp_buffer.bytes = (*last_packet)->bytes[sizeof(uint64_t) + 1];
    temp_buffer.length = (*last_packet)->length - sizeof(uint64_t) - 1;
    
    SHOULD_BE_FALSE(wickr_buffer_is_equal(test_buffer, &temp_buffer, NULL));
    
    /* The rx callback for bob will produce the original buffer after decryption */
    SHOULD_BE_TRUE(wickr_buffer_is_equal(test_buffer, *expected, NULL));
    SHOULD_NOT_EQUAL(test_buffer, *expected);
    
    wickr_buffer_destroy(&test_buffer);
}

void reset_alice_bob()
{
    const wickr_crypto_engine_t default_engine = wickr_crypto_engine_get_default();

    wickr_node_t *alice_node_1 = createUserNode("alice", hex_char_to_buffer("alice_device"));
    wickr_node_t *bob_node_1 = createUserNode("bob", hex_char_to_buffer("bob_device"));
    wickr_node_t *alice_node_2 = wickr_node_copy(alice_node_1);
    wickr_node_t *bob_node_2 = wickr_node_copy(bob_node_1);
    
    SHOULD_NOT_BE_NULL(alice_node_1);
    SHOULD_NOT_BE_NULL(bob_node_1);
    SHOULD_NOT_BE_NULL(alice_node_2);
    SHOULD_NOT_BE_NULL(bob_node_2);
    
    wickr_transport_ctx_destroy(&alice_transport);
    wickr_transport_ctx_destroy(&bob_transport);
    
    SHOULD_BE_TRUE(alice_transport = wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, 0, test_callbacks_alice));
    SHOULD_BE_TRUE(bob_transport = wickr_transport_ctx_create(default_engine, bob_node_2, alice_node_2, 0, test_callbacks_bob));
    
    last_status_bob = TRANSPORT_STATUS_NONE;
    last_status_alice = TRANSPORT_STATUS_NONE;
    wickr_buffer_destroy_zero(&last_tx_alice);
    wickr_buffer_destroy_zero(&last_tx_bob);
    wickr_buffer_destroy_zero(&last_rx_alice);
    wickr_buffer_destroy_zero(&last_rx_bob);
}

DESCRIBE(wickr_transport_ctx, "wickr_transport_ctx")
{
    const wickr_crypto_engine_t default_engine = wickr_crypto_engine_get_default();
    
    wickr_node_t *alice_node_1 = createUserNode("alice", hex_char_to_buffer("alice_device"));
    wickr_node_t *bob_node_1 = createUserNode("bob", hex_char_to_buffer("bob_device"));
    wickr_node_t *alice_node_2 = wickr_node_copy(alice_node_1);
    wickr_node_t *bob_node_2 = wickr_node_copy(bob_node_1);
    
    SHOULD_NOT_BE_NULL(alice_node_1);
    SHOULD_NOT_BE_NULL(bob_node_1);
    SHOULD_NOT_BE_NULL(alice_node_2);
    SHOULD_NOT_BE_NULL(bob_node_2);
    
    IT("can be initialized for both parties")
    {
        
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, NULL, NULL,0, test_callbacks_alice));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, alice_node_1, NULL, 0, test_callbacks_alice));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, NULL, alice_node_1, 0, test_callbacks_alice));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, PACKET_PER_EVO_MIN - 1, test_callbacks_alice));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, PACKET_PER_EVO_MAX + 1, test_callbacks_alice));

        SHOULD_BE_TRUE(alice_transport = wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, 0, test_callbacks_alice));
        SHOULD_BE_TRUE(bob_transport = wickr_transport_ctx_create(default_engine, bob_node_2, alice_node_2, 0, test_callbacks_bob));
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_NONE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_NONE);
        SHOULD_BE_NULL(last_rx_alice);
        SHOULD_BE_NULL(last_rx_bob);
        SHOULD_BE_NULL(last_tx_alice);
        SHOULD_BE_NULL(last_tx_bob);
        
        SHOULD_BE_NULL(alice_transport->rx_stream);
        SHOULD_BE_NULL(alice_transport->tx_stream);
        
        SHOULD_BE_NULL(bob_transport->tx_stream);
        SHOULD_BE_NULL(bob_transport->rx_stream);
        
        SHOULD_EQUAL(alice_transport->evo_count, PACKET_PER_EVO_DEFAULT);
        SHOULD_EQUAL(bob_transport->evo_count, PACKET_PER_EVO_DEFAULT);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->local_identity->id_chain->node->sig_key->pub_data, alice_node_1->id_chain->node->sig_key->pub_data, NULL));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->local_identity->id_chain->node->sig_key->pub_data, bob_node_1->id_chain->node->sig_key->pub_data, NULL));

    }
    END_IT
    
    reset_alice_bob();
    
    IT("should not allow you to transmit packets if no handshake has happened")
    {
        wickr_buffer_t *rand_buffer = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(alice_transport, rand_buffer);
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, last_status_alice);
        wickr_buffer_destroy(&rand_buffer);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("will have a failed handshake if the incorrect signature keys are used for either party")
    {
        /* Case: Alice presents an invalid signature for herself */
        wickr_ec_key_destroy(&alice_transport->local_identity->id_chain->node->sig_key);
        alice_transport->local_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        reset_alice_bob();

        /* Case: Bob presents an invalid signature for his response to alice */
        wickr_ec_key_destroy(&bob_transport->local_identity->id_chain->node->sig_key);
        bob_transport->local_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_NOT_BE_NULL(last_tx_bob);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        
        reset_alice_bob();
        
        /* Case: Alice has the incorrect signature key for bob */
        wickr_ec_key_destroy(&alice_transport->remote_identity->id_chain->node->sig_key);
        alice_transport->remote_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_NOT_BE_NULL(last_tx_bob);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        
        reset_alice_bob();
        
        /* Case: Bob has the incorrect signature key for alice */
        wickr_ec_key_destroy(&bob_transport->remote_identity->id_chain->node->sig_key);
        bob_transport->remote_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        reset_alice_bob();
        
        /* Case: Alice presents an improperly signed "Final" packet */
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Swap Alice key so that we produce a signature by the wrong key */
        wickr_ec_key_destroy(&alice_transport->local_identity->id_chain->node->sig_key);
        alice_transport->local_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        /* Process the final packet from alice that was signed incorrectly */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);

    }
    END_IT
    
    reset_alice_bob();
    
    wickr_buffer_t *actual_handshake = NULL;
    
    IT("should handle corrupted packets at the initial seed packet of the handshake")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Swap the proper packet with a bad one */
        actual_handshake = last_tx_alice;
        last_tx_alice = engine.wickr_crypto_engine_crypto_random(1024);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    IT("should reject handshake info after the error occures (initial)")
    {
        wickr_transport_ctx_process_rx_buffer(bob_transport, actual_handshake);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(bob_transport->tx_stream);
        SHOULD_BE_NULL(bob_transport->rx_stream);
    }
    END_IT
    
    IT("should reject sending data in the error state (Initial)")
    {
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(bob_transport, test_data);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(last_tx_bob);
        SHOULD_BE_NULL(last_rx_alice);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject in transit packet modification of handshake packets (initial)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Swap the first byte of the packet */
        last_tx_alice->bytes[0] = 0x5;
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject non handshake packets when expecting handshake packets (initial)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Change the type of the packet */
        SHOULD_EQUAL(last_tx_alice->bytes[sizeof(uint64_t)], PAYLOAD_TYPE_HANDSHAKE);
        last_tx_alice->bytes[sizeof(uint64_t)] = (uint8_t)PAYLOAD_TYPE_CIPHERTEXT;
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should handle corrupted packets at the response packet of the handshake")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Swap the proper packet with a bad one */
        actual_handshake = last_tx_bob;
        last_tx_bob = engine.wickr_crypto_engine_crypto_random(1024);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    IT("should reject handshake after the error occures (return)")
    {
        wickr_transport_ctx_process_rx_buffer(alice_transport, actual_handshake);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(alice_transport->tx_stream);
        SHOULD_BE_NULL(alice_transport->rx_stream);
    }
    END_IT
    
    IT("should reject sending data in the error state (return)")
    {
        wickr_buffer_destroy_zero(&last_rx_alice);
        
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(bob_transport, test_data);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_NOT_BE_NULL(last_tx_bob);
        SHOULD_BE_NULL(last_rx_alice);
        
        wickr_buffer_destroy_zero(&test_data);
    }
    END_IT
    
    IT("should reject sending data in the TX Init state")
    {
        wickr_buffer_destroy_zero(&last_rx_bob);
        wickr_buffer_destroy_zero(&last_tx_alice);
        
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_data);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);

        SHOULD_BE_NULL(last_tx_alice);
        SHOULD_BE_NULL(last_rx_bob);
        
        wickr_buffer_destroy_zero(&test_data);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject in transit packet modification of handshake packets (return)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Swap the first byte of the packet */
        last_tx_bob->bytes[0] = 0x5;
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject non handshake packets when expecting a handshake packet (return)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Swap the first byte of the packet */
        SHOULD_EQUAL(last_tx_bob->bytes[sizeof(uint64_t)], PAYLOAD_TYPE_HANDSHAKE);
        last_tx_bob->bytes[sizeof(uint64_t)] = (uint8_t)PAYLOAD_TYPE_CIPHERTEXT;
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should handle corrupted packets at the final packet of the handshake")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        /* Swap the proper packet with a bad one */
        actual_handshake = last_tx_alice;
        last_tx_alice = engine.wickr_crypto_engine_crypto_random(1024);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    
    IT("should reject handshake and content after the error occures (final)")
    {
        wickr_transport_ctx_process_rx_buffer(bob_transport, actual_handshake);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_NOT_BE_NULL(bob_transport->tx_stream);
        SHOULD_BE_NULL(bob_transport->rx_stream);
        
        wickr_buffer_t *test_content = engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_content);
        SHOULD_NOT_BE_NULL(last_tx_alice);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(last_rx_bob, test_content, NULL));
        
        wickr_buffer_destroy_zero(&test_content);
    }
    END_IT
    
    IT("should reject sending data in the error state (final)")
    {
        wickr_buffer_destroy_zero(&last_tx_bob);
        wickr_buffer_destroy_zero(&last_tx_alice);
        
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(bob_transport, test_data);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(last_tx_bob);
        SHOULD_BE_NULL(last_rx_alice);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should handle corrupted packets at the final packet of the handshake")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        /* Swap the proper packet with a bad one */
        last_tx_alice->bytes[0] = 0x5;
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should not handle non handshake payloads when expecting handshake payloads (final)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        /* Change the type of the packet */
        SHOULD_EQUAL(last_tx_alice->bytes[sizeof(uint64_t)], PAYLOAD_TYPE_HANDSHAKE);
        last_tx_alice->bytes[sizeof(uint64_t)] = (uint8_t)PAYLOAD_TYPE_CIPHERTEXT;
        
        //TODO: Expose signature function so that we can get a valid signature with the incorrect type
        
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("under proper conditions it can establish a connection via a secure handshake")
    {
        wickr_transport_ctx_start(alice_transport);
        
        /* No packets are provided to the callback during the handshake as they are internal */
        SHOULD_BE_NULL(last_rx_bob);
        SHOULD_BE_NULL(last_rx_alice);
        
        /* Check that handshake packets were sent properly */
        SHOULD_NOT_BE_NULL(last_tx_alice);
        SHOULD_NOT_BE_NULL(last_tx_bob);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ACTIVE);
        
        SHOULD_NOT_BE_NULL(alice_transport->rx_stream);
        SHOULD_NOT_BE_NULL(alice_transport->tx_stream);
        SHOULD_NOT_BE_NULL(bob_transport->rx_stream);
        SHOULD_NOT_BE_NULL(bob_transport->tx_stream);
        
        SHOULD_EQUAL(alice_transport->rx_stream->direction, STREAM_DIRECTION_DECODE);
        SHOULD_EQUAL(bob_transport->rx_stream->direction, STREAM_DIRECTION_DECODE);
        SHOULD_EQUAL(alice_transport->tx_stream->direction, STREAM_DIRECTION_ENCODE);
        SHOULD_EQUAL(bob_transport->tx_stream->direction, STREAM_DIRECTION_ENCODE);
        
        /* Determine that the rx stream key material for Alice matches the tx stream key material for Bob */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->rx_stream->key->cipher_key->key_data, bob_transport->tx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->rx_stream->key->evolution_key, bob_transport->tx_stream->key->evolution_key, NULL));
        SHOULD_EQUAL(alice_transport->rx_stream->key->packets_per_evolution, bob_transport->tx_stream->key->packets_per_evolution);

        /* Determine that the rx stream key material for Alice is different than the rx stream key material for Bob */
        SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_transport->rx_stream->key->cipher_key->key_data, bob_transport->rx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_transport->rx_stream->key->evolution_key, bob_transport->rx_stream->key->evolution_key, NULL));
        
        /* Determine that the rx stream for Bob matches the tx stream for Alice */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->tx_stream->key->cipher_key->key_data, bob_transport->rx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->tx_stream->key->evolution_key, bob_transport->rx_stream->key->evolution_key, NULL));
        SHOULD_EQUAL(alice_transport->tx_stream->key->packets_per_evolution, bob_transport->rx_stream->key->packets_per_evolution);
        
        /* Determine that the tx stream key material for Alice is different than the tx stream key material for Bob */
        SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_transport->tx_stream->key->cipher_key->key_data, bob_transport->tx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_transport->tx_stream->key->evolution_key, bob_transport->tx_stream->key->evolution_key, NULL));
        
    }
    END_IT
    
    IT("can transmit secure packets after the handshake is established")
    {
        test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, 1);
        test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, 1);
    }
    END_IT
    
    IT("can transmit many secure packets")
    {
        
        for (int i = 0; i < 10000; i++) {
            test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, i + 2);
        }
        
        for (int i = 0; i < 10000; i++) {
            test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, i + 2);
        }
         
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_transport_ctx_t *copy = wickr_transport_ctx_copy(alice_transport);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->local_identity->dev_id, alice_transport->local_identity->dev_id, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->remote_identity->dev_id, alice_transport->remote_identity->dev_id, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->tx_stream->iv_factory->seed, alice_transport->tx_stream->iv_factory->seed, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->rx_stream->key->evolution_key, alice_transport->rx_stream->key->evolution_key, NULL));
        SHOULD_EQUAL(copy->status, alice_transport->status);
        SHOULD_EQUAL(copy->evo_count, alice_transport->evo_count);
        
        wickr_transport_ctx_destroy(&copy);
        
    }
    END_IT
    
    wickr_transport_ctx_destroy(&alice_transport);
    wickr_transport_ctx_destroy(&bob_transport);
    wickr_buffer_destroy(&last_rx_alice);
    wickr_buffer_destroy(&last_tx_alice);
    wickr_buffer_destroy(&last_rx_bob);
    wickr_buffer_destroy(&last_tx_bob);
    
    SHOULD_BE_NULL(alice_transport);
    SHOULD_BE_NULL(bob_transport);
}
END_DESCRIBE
