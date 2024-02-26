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
    coap_context_t *ctx = nullptr;
    coap_opt_iterator_t opt_iter;
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

        if (have_response == 1) {
            uint8_t pa[pqcrystals_kyber512_PUBLICKEYBYTES];
            coap_get_data(received, (size_t *) pqcrystals_kyber512_PUBLICKEYBYTES, (const uint8_t **) &pa);
            /* Got some data, check if block option is set. Behavior is undefined if
    * both, Block1 and Block2 are present. */
            block_opt = get_block(received, &opt_iter);
            if (!block_opt) {
              /* There is no block option set, just read the data and we are done. */
              if (coap_get_data(received, &len, &databuf))
        	append_to_output(databuf, len);
            } else {
              unsigned short blktype = opt_iter.type;
        
              /* TODO: check if we are looking at the correct block number */
              if (coap_get_data(received, &len, &databuf))
        	append_to_output(databuf, len);

              if (COAP_OPT_BLOCK_MORE(block_opt)) {
	        /* more bit is set */
        	debug("found the M bit, block size is %u, block nr. %u\n",
	              COAP_OPT_BLOCK_SZX(block_opt), COAP_OPT_BLOCK_NUM(block_opt));

	        /* create pdu with request for next block */
	        pdu = coap_new_request(ctx, method, NULL); /* first, create bare PDU w/o any option  */
	        if ( pdu ) {
	          /* add URI components from optlist */
	  for (option = optlist; option; option = option->next ) {
	    switch (COAP_OPTION_KEY(*(coap_option *)option->data)) {
	    case COAP_OPTION_URI_HOST :
	    case COAP_OPTION_URI_PORT :
	    case COAP_OPTION_URI_PATH :
	    case COAP_OPTION_URI_QUERY :
	      coap_add_option ( pdu, COAP_OPTION_KEY(*(coap_option *)option->data),
				COAP_OPTION_LENGTH(*(coap_option *)option->data),
				COAP_OPTION_DATA(*(coap_option *)option->data) );
	      break;
	    default:
	      ;			/* skip other options */
	    }
	  }

	  /* finally add updated block option from response, clear M bit */
	  /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
	  debug("query block %d\n", (COAP_OPT_BLOCK_NUM(block_opt) + 1));
	  coap_add_option(pdu, blktype, coap_encode_var_bytes(buf, 
	      ((COAP_OPT_BLOCK_NUM(block_opt) + 1) << 4) | 
              COAP_OPT_BLOCK_SZX(block_opt)), buf);

	  if (received->hdr->type == COAP_MESSAGE_CON)
	    tid = coap_send_confirmed(ctx, remote, pdu);
	  else 
	    tid = coap_send(ctx, remote, pdu);

	  if (tid == COAP_INVALID_TID) {
	    debug("message_handler: error sending new request");
            coap_delete_pdu(pdu);
	  } else {
	    set_timeout(&max_wait, wait_seconds);
            if (received->hdr->type != COAP_MESSAGE_CON)
              coap_delete_pdu(pdu);
          }

	  return;
	}
      }
    }
  }
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

