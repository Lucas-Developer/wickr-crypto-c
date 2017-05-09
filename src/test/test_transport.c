
#include "test_transport.h"
#include "transport_ctx.h"
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
    wickr_buffer_destroy(&last_tx_alice);
    last_tx_alice = data;
    
    wickr_transport_ctx_process_rx_buffer(alice_transport, data);
    
    return true;
}

bool wickr_test_transport_rx_bob(wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    wickr_buffer_destroy(&last_rx_alice);
    last_rx_alice = data;
    
    return true;
}

void wickr_test_transport_status_bob(wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    last_status_alice = status;
}

static wickr_transport_callbacks_t test_callbacks_alice = { wickr_test_transport_tx_alice,
    wickr_test_transport_rx_alice,
    wickr_test_transport_status_alice };

static wickr_transport_callbacks_t test_callbacks_bob = { wickr_test_transport_tx_bob,
    wickr_test_transport_rx_bob,
    wickr_test_transport_status_bob };



DESCRIBE(wickr_transport_ctx, "wickr_transport_ctx")
{
    const wickr_crypto_engine_t default_engine = wickr_crypto_engine_get_default();
    
    IT("can be initialized for both parties")
    {
        wickr_node_t *alice_node_1 = createUserNode("alice", hex_char_to_buffer("alice_device"));
        wickr_node_t *bob_node_1 = createUserNode("bob", hex_char_to_buffer("bob_device"));
        wickr_node_t *alice_node_2 = wickr_node_copy(alice_node_1);
        wickr_node_t *bob_node_2 = wickr_node_copy(bob_node_1);
        
        SHOULD_NOT_BE_NULL(alice_node_1);
        SHOULD_NOT_BE_NULL(bob_node_1);
        SHOULD_NOT_BE_NULL(alice_node_2);
        SHOULD_NOT_BE_NULL(bob_node_2);
        
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, NULL, NULL, test_callbacks_alice));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, alice_node_1, NULL, test_callbacks_alice));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, NULL, alice_node_1, test_callbacks_alice));
        
        SHOULD_BE_TRUE(alice_transport = wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, test_callbacks_alice));
        SHOULD_BE_TRUE(bob_transport = wickr_transport_ctx_create(default_engine, bob_node_2, alice_node_2, test_callbacks_bob));
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_NONE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_NONE);
        SHOULD_BE_NULL(last_rx_alice);
        SHOULD_BE_NULL(last_rx_bob);
        SHOULD_BE_NULL(last_tx_alice);
        SHOULD_BE_NULL(last_tx_bob);
    }
    END_IT
    
    IT("can establish a connection via a secure handshake")
    {
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_rx_alice);
        SHOULD_NOT_BE_NULL(last_tx_alice);
        SHOULD_NOT_BE_NULL(last_rx_bob);
        SHOULD_NOT_BE_NULL(last_tx_bob);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ACTIVE);
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
