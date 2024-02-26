#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <coap3/coap.h>
#include <stddef.h>
#include <cbor.h>

extern "C" {
	#include "../kyber/ref/api.h"
	#include "../kyber/ref/randombytes.h"
}

#define membersof(x) (sizeof(x)/ sizeof(x[0]))


extern "C" {
    #include "../kyber/ref/api.h"
    #include "../kyber/ref/randombytes.h"
}

static int have_response = 0;

int resolve_address(const char *host, const char *service, coap_address_t *dst) {
    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    int error, len = -1;

    memset(&hints, 0, sizeof(hints));
    memset(dst, 0, sizeof(*dst));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(host, service, &hints, &res);

    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return error;
    }

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        switch (ainfo->ai_family) {
            case AF_INET6:
            case AF_INET:
                len = dst->size = ainfo->ai_addrlen;
                memcpy(&dst->addr.sin6, ainfo->ai_addr, dst->size);
                goto finish;
            default:
                ;
        }
    }

    finish:
    freeaddrinfo(res);
    return len;
}

uint8_t *client_process(cbor_item_t *pa) {
    uint8_t *ct = (uint8_t *)malloc(pqcrystals_kyber512_CIPHERTEXTBYTES);
    uint8_t ss[pqcrystals_kyber512_BYTES];
    uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
    size_t i;
    cbor_item_t *ma = cbor_new_definite_array(pqcrystals_kyber512_CIPHERTEXTBYTES);

    pqcrystals_kyber512_ref_enc(ct, ss, pk);

    size_t j;

    return ct;
}

coap_session_t *session = nullptr;

int main(void) {
    printf("Starting ... \n");
    coap_set_log_level(COAP_LOG_WARN);
    coap_context_t *ctx = nullptr;
    coap_address_t dst;
    coap_pdu_t *pdu = nullptr;
    int result = EXIT_FAILURE;

    coap_startup();
    coap_set_log_level(COAP_LOG_WARN);

    if (resolve_address("localhost", "5683", &dst) < 0) {
        coap_log_crit("failed to resolve address\n");
        goto finish;
    }

    if (!(ctx = coap_new_context(nullptr))) {
        coap_log_emerg("cannot create libcoap context\n");
        goto finish;
    }

    coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

    if (!(session = coap_new_client_session(ctx, nullptr, &dst, COAP_PROTO_UDP))) {
        coap_log_emerg("cannot create client session\n");
        goto finish;
    }

    coap_register_response_handler(ctx, [](auto, auto,
                                                  const coap_pdu_t *received,
                                                  auto) -> coap_response_t {
        have_response += 1;
        coap_pdu_t *response = nullptr;
        size_t len;
        if (have_response == 1) {
            uint8_t pa[pqcrystals_kyber512_PUBLICKEYBYTES];
            printf("testa\n");
            coap_get_data(received, &len, (const uint8_t **) &pa);
            printf("testc\n");
            uint8_t a = membersof(pa);
            cbor_item_t *pa_cbor = cbor_new_definite_array(a);
            uint8_t *result = client_process(pa_cbor);

            response = coap_pdu_init(COAP_MESSAGE_NON, COAP_RESPONSE_CODE_CONTENT, coap_new_message_id(session),
                                     coap_session_max_pdu_size(session));
            coap_add_data(response, strlen((char *) result), result);
            free(result);
        }
        coap_show_pdu(COAP_LOG_WARN, response);
        return COAP_RESPONSE_OK;
    });









    pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET, coap_new_message_id(session), coap_session_max_pdu_size(session));

    if (!pdu) {
        coap_log_emerg("cannot create PDU\n");
        goto finish;
    }

    coap_add_option(pdu, COAP_OPTION_URI_PATH, 5, reinterpret_cast<const uint8_t *>("pa"));

    if (coap_send(session, pdu) == COAP_INVALID_MID) {
        coap_log_err("cannot send CoAP pdu\n");
        goto finish;
    }

    while (have_response < 2)
        coap_io_process(ctx, COAP_IO_WAIT);

    result = EXIT_SUCCESS;

    finish:
    coap_session_release(session);
    coap_free_context(ctx);
    coap_cleanup();

    return result;
}

