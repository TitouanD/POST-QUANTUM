#include<stdio.h>
#include "ref/api.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "ref/kem.h"
#include <cbor.h>
#include "ref/randombytes.h"

#define NTESTS 1000

cbor_item_t* first_server(uint8_t* pk, uint8_t* sk) {
  printf("\nTest\n");
  //Ce sont des pointeurs pour des arrays qu'il faudra garder tout le long
  //uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
  //uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];

  cbor_item_t *pa = cbor_new_definite_array(pqcrystals_kyber512_PUBLICKEYBYTES);
  
  //Ici on génère une clé publique à partir d'une clé privée
  pqcrystals_kyber512_ref_keypair(pk, sk);
  size_t i;
  for (i=0; i<pqcrystals_kyber512_PUBLICKEYBYTES; i++) {
  	cbor_array_set(pa, i, cbor_build_uint8(pk[i]));
  }
  
  return pa;
}

cbor_item_t* client_process(cbor_item_t* pa) {
  uint8_t ss[pqcrystals_kyber512_BYTES];
  uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES];
  uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
  size_t i;
  cbor_item_t *ma = cbor_new_definite_array(pqcrystals_kyber512_CIPHERTEXTBYTES);
  for(i=0; i<pqcrystals_kyber512_PUBLICKEYBYTES; i++) {
  	uint8_t a = cbor_get_uint8(cbor_array_get(pa,i));
  	pk[i] = a;
  }
  
  //Ici on encode le secret avec la clé publique
  pqcrystals_kyber512_ref_enc(ct, ss, pk);
  
  size_t j;
  for (j=0; j<pqcrystals_kyber512_CIPHERTEXTBYTES; j++) {
  	cbor_array_set(ma, i, cbor_build_uint8(ct[j]));
  }
  
  //On renvoit le message encodé
  return ma;
}

void final_server(uint8_t* sk, cbor_item_t* ma) {
  uint8_t ss[pqcrystals_kyber512_BYTES];
  uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES];
  
  size_t i;
  for(i=0; i<pqcrystals_kyber512_CIPHERTEXTBYTES; i++) {
  	uint8_t a = cbor_get_uint8(cbor_array_get(ma,i));
  	ct[i] = a;
  }

  //Ici on décode le secret
  pqcrystals_kyber512_ref_dec(ss, ct, sk);
}
