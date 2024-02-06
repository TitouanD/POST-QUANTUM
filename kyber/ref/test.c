#include<stdio.h>
#include <dlfcn.h>      /* defines dlopen(), etc.       */
#include "api.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "randombytes.h"

#define NTESTS 1000

int main() {
printf("\nTest\n");
  uint8_t pk = 8;
  uint8_t sk = 4;

  //Alice generates a public key
  pqcrystals_kyber512_ref_keypair(pk, sk);
  return 0;
}
