#ifdef WITH_SGX 
#include "sgx_trts.h"
void randombytes(unsigned char *buf, unsigned long len){
    // TODO: Not really used within the enclave, but it failure should be handled
    sgx_read_rand(buf, len);
}
#else
#include <stdio.h>
void randombytes(unsigned char *buf, unsigned long len){
    FILE *f;
    f = fopen("/dev/urandom", "r");
    fread(buf, len, 1, f);
    fclose(f);
}
#endif
