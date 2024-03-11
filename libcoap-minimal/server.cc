/* minimal CoAP server
 *
 * Copyright (C) 2018-2023 Olaf Bergmann <bergmann@tzi.org>
 */
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <coap3/coap.h>
#include <cbor.h>

#define membersof(x) (sizeof(x)/ sizeof(x[0]))



extern "C" {
	#include "../kyber/ref/api.h"
	#include "../kyber/ref/randombytes.h"
}

int
resolve_address(const char *host, const char *service, coap_address_t *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  int error, len=-1;

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

void server_process(uint8_t* sk, const uint8_t** ma) {
    
    
    uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES];
    uint8_t a = membersof(ma);
    uint8_t b = membersof(ma[0]);
    uint8_t ss[pqcrystals_kyber512_BYTES];
    cbor_item_t *pa = cbor_new_definite_array(a*b);
    printf("Avant double for\n");
    uint8_t tt = 0;
    for (int i =0; i<a; i++) {
    	printf("Dans premier dor %d\n",membersof(ma[i]));
    	for (int j = 0; j<membersof(ma[i]); j++) {
    	    printf("j : %d\n",j);
    	    printf("ma[i] ? : %d\n",*ma[i]);
    	    printf("%d\n",ma[i][j]);
    	    cbor_array_set(pa, tt, cbor_build_uint8(ma[i][j]));
    	    tt+=1;
    	}
    	printf("Second for fait\n");
    }
    size_t i;
    printf("Avant for cr\n");
    for(i=0; i<pqcrystals_kyber512_CIPHERTEXTBYTES; i++) {
        uint8_t a = cbor_get_uint8(cbor_array_get(pa,i));
        ct[i] = a;
    }
    printf("Après for cr\n");
    //Ici on décode le secret
    pqcrystals_kyber512_ref_dec(ss, ct, sk);
    int loop;
    for(loop = 0; loop < pqcrystals_kyber512_BYTES; loop++)
      printf("%d \n", ss[loop]);
}
uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];


cbor_item_t* init_pa(uint8_t* pk, uint8_t* sk) {
    cbor_item_t *pa = cbor_new_definite_array(pqcrystals_kyber512_PUBLICKEYBYTES);
    printf("Coucou\n");
    pqcrystals_kyber512_ref_keypair(pk, sk);
    size_t i;
    for (i=0; i<pqcrystals_kyber512_PUBLICKEYBYTES; i++) {
        cbor_array_set(pa, i, cbor_build_uint8(pk[i]));
    }
    return pa;
}

static int have_response = 0;

int main(void) {
  printf("Starting ... \n");
  uint8_t ss[pqcrystals_kyber512_BYTES];
  coap_context_t  *ctx = nullptr;
  coap_address_t dst;
  coap_resource_t *resource_pa = nullptr;
  coap_endpoint_t *endpoint = nullptr;
  coap_set_log_level(COAP_LOG_WARN);
  int result = EXIT_FAILURE;;
  //coap_str_const_t *ruri = coap_make_str_const("hello");
  coap_str_const_t *ruri_pa = coap_make_str_const("start");

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
      coap_log(LOG_INFO,"test\n");
      printf("request\n");
      if (have_response == 1){
          printf("if\n");
          const uint8_t** ma;
          size_t sizer;
          coap_get_data(request,&sizer, ma);
          server_process(sk, ma);

          coap_show_pdu(COAP_LOG_WARN, request);
          coap_pdu_set_code(response, COAP_RESPONSE_CODE_VALID );
          coap_show_pdu(COAP_LOG_WARN, response);
          have_response = 2;
      }else {
          printf("else\n");
          have_response = 1;
          coap_show_pdu(COAP_LOG_WARN, request);
          coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
          coap_add_data(response, (int) pqcrystals_kyber512_PUBLICKEYBYTES, (const uint8_t *) init_pa(pk, sk));
          coap_show_pdu(COAP_LOG_WARN, response);
      }
  });
  printf("Add ressource incomming ... \n");
  coap_add_resource(ctx, resource_pa);
  printf("Ressource added ... \n");
  while (have_response<2) { coap_io_process(ctx, COAP_IO_WAIT); }

  result = EXIT_SUCCESS;
 finish:

  coap_free_context(ctx);
  coap_cleanup();
  return result;
}





