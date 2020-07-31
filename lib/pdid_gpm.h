#ifdef WITH_SGX
extern "C" {
#include <stdlib.h>
#include <stdio.h>
#include "defines.h"
}
#include "shim.h"
#else

#include <stdio.h>
#include "defines.h"

struct {
    unsigned char username[USERNAME_LEN];
    unsigned char meta[META_LEN];
} users;

typedef void *shim_ctx_ptr_t;

void put_state(const char* key, uint8_t* val, uint32_t val_len, shim_ctx_ptr_t ctx);
void get_state(const char* key, uint8_t* val, uint32_t max_val_len, uint32_t* val_len, shim_ctx_ptr_t ctx);
#endif

int gpm_new_pdid(uint8_t *c, shim_ctx_ptr_t ctx);
int gpm_auth(uint8_t *s2g_m, uint8_t *c_hat, shim_ctx_ptr_t ctx);