#include "utils.h"

// Modified https://stackoverflow.com/questions/50627097/hexlify-and-unhexlify-functions-in-c
int a2v(char c) {
    if ((c >= '0') && (c <= '9')) return c - '0';
    if ((c >= 'a') && (c <= 'f')) return c - 'a' + 10;
    if ((c >= 'A') && (c <= 'F')) return c - 'A' + 10;
    else return 0;
}

char v2a(int c) {
    const char hex[] = "0123456789abcdef";
    return hex[c];
}

void hexlifyn(char *bstr, int bstr_len, char *hstr) {
    char *phstr=hstr;
    for(int i=0; i<bstr_len;i++) {
        *phstr++ =v2a((bstr[i]>>4)&0x0F);
        *phstr++ =v2a((bstr[i])&0x0F);
    }
    *phstr++ ='\0';
}

void unhexlifyn(char *hstr, int hstr_len, char *bstr) {
    char *pbstr=bstr;
    for(int i=0;i<hstr_len; i += 2)
        *pbstr++ =(a2v(hstr[i])<<4)+a2v(hstr[i+1]);
    *pbstr++ ='\0';
}


#ifndef WITH_SGX
void dump(uint8_t *prefix, uint8_t *buf, unsigned long len){
    char out[2*len+1];
    hexlifyn(buf, len, out);
    fprintf(stderr, "%s%s\n", prefix, out);
}

void print_random_keys(void){
    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk,sk);
    dump("PK: ", pk, crypto_box_PUBLICKEYBYTES);
    dump("SK: ", sk, crypto_box_SECRETKEYBYTES);
}

int cmp(const void *a, const void *b) {
    return (*(double*)a - *(double*)b);
}

int print_stats(const char *name, double *a, int l){
    double avg = 0.0;
    for (int i=0; i<l; i++)
        avg += a[i];
    avg /= l;
    avg /= (CLOCKS_PER_SEC/1000);

    double med;
    if (l % 2)
        med = a[l/2];
    else
        med = (a[l/2 - 1] + a[l/2])/2;
    med /= (CLOCKS_PER_SEC/1000);
    
    qsort(a, l, sizeof(double), cmp);
    double min = a[0]/(CLOCKS_PER_SEC/1000);
    double max = a[l-1]/(CLOCKS_PER_SEC/1000);
    
    printf("%s: min/max/avg/med: %5.2f /%5.2f /%5.2f /%5.2f [ms]\n", name, min, max, avg, med);
}

#endif