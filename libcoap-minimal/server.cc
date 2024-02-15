/* minimal CoAP server
 *
 * Copyright (C) 2018-2023 Olaf Bergmann <bergmann@tzi.org>
 */

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "./common.hh"
#include <coap3/coap.h>

#include <stddef.h>
#include <cbor.h>
#define membersof(x) (sizeof(x)/ sizeof(x[0]))

extern "C" {
	#include "../kyber/ref/api.h"
	#include "../kyber/ref/randombytes.h"
}

int resolve_address(const char *host, const char *service, coap_address_t *dst);

cbor_item_t* init_pa(uint8_t* pk, uint8_t* sk) {
    cbor_item_t *pa = cbor_new_definite_array(pqcrystals_kyber512_PUBLICKEYBYTES);

    pqcrystals_kyber512_ref_keypair(pk, sk);
    size_t i;
    for (i=0; i<pqcrystals_kyber512_PUBLICKEYBYTES; i++) {
        cbor_array_set(pa, i, cbor_build_uint8(pk[i]));
    }

    return pa;
}

void server_process(uint8_t* sk, const uint8_t** ma) {
    
    uint8_t ss[pqcrystals_kyber512_BYTES];
    uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES];
    uint8_t a = membersof(ma);
    uint8_t b = membersof(ma[0]);
    cbor_item_t *pa = cbor_new_definite_array(a*b);
    for (int i =0; i<a; i++) {
    	for (int j = 0; j<b; j++) {
    	    cbor_array_set(pa, i*b+j, cbor_build_uint8(ma[i][j]));
    	}
    }
    size_t i;
    
    for(i=0; i<pqcrystals_kyber512_CIPHERTEXTBYTES; i++) {
        uint8_t a = cbor_get_uint8(cbor_array_get(pa,i));
        ct[i] = a;
    }
    //Ici on décode le secret
    pqcrystals_kyber512_ref_dec(ss, ct, sk);
    
}
uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];

int main(void) {
  coap_context_t  *ctx = nullptr;
  coap_address_t dst;
  coap_resource_t *resource = nullptr;
  coap_resource_t *resource_pa = nullptr;
  coap_endpoint_t *endpoint = nullptr;

  int result = EXIT_FAILURE;;
  //coap_str_const_t *ruri = coap_make_str_const("hello");
  coap_str_const_t *ruri_pa = coap_make_str_const("pa");

    coap_startup();

  if (resolve_address("localhost", "5683", &dst) < 0) {
    coap_log_crit("failed to resolve address\n");
    goto finish;
  }

  ctx = coap_new_context(nullptr);

  if (!ctx || !(endpoint = coap_new_endpoint(ctx, &dst, COAP_PROTO_UDP))) {
    coap_log_emerg("cannot initialize context\n");
    goto finish;
  }

  resource_pa = coap_resource_init(ruri_pa, 0);
  coap_register_handler(resource_pa, COAP_REQUEST_GET,
                        [](auto, auto,const coap_pdu_t *request,auto,coap_pdu_t *response) {

      coap_pdu_code_t code = coap_pdu_get_code(request);

      if (code = COAP_RESPONSE_CODE_VALID){
          const uint8_t** ma;
          size_t* sizer;
          *sizer = pqcrystals_kyber512_CIPHERTEXTBYTES;
          coap_get_data(request,sizer, ma);
          server_process(sk, ma);

          coap_show_pdu(COAP_LOG_WARN, request);
          coap_pdu_set_code(response, COAP_RESPONSE_CODE_VALID );
          coap_show_pdu(COAP_LOG_WARN, response);
      }else {

          coap_show_pdu(COAP_LOG_WARN, request);
          coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
          coap_add_data(response, (int) pqcrystals_kyber512_PUBLICKEYBYTES, (const uint8_t *) init_pa(pk, sk));
          coap_show_pdu(COAP_LOG_WARN, response);
      }
  });

  coap_add_resource(ctx, resource);

  while (true) { coap_io_process(ctx, COAP_IO_WAIT); }

  result = EXIT_SUCCESS;
 finish:

  coap_free_context(ctx);
  coap_cleanup();
  
  return result;
}
