#ifndef PDID_H
#define PDID_H

#include <stdio.h>
#include <string.h>
#include "defines.h"
#include "utils.h"

// User's state after initiating the authentication
typedef struct user_state{
    uint8_t xu[PDID_ECC_SCALAR_BYTES];
    uint8_t Xu[PDID_ECC_POINT_BYTES];
    uint8_t r[PDID_ECC_SCALAR_BYTES];
};

int user_reg(uint8_t *U, uint8_t *pwd, uint8_t *c_tilde);
int user_auth_init(uint8_t *U, uint8_t *pwd, struct user_state *s, uint8_t *u2s_msg);
int server_auth_init(uint8_t *u2s_msg, uint8_t *srv_name, uint8_t *sks, uint8_t *Xs, uint8_t *s2g_m);
// e_u and e_s used in HMQV
int get_e(uint8_t *X, uint8_t *id, uint8_t *e);
int server_auth_finish(uint8_t *c_hat, uint8_t *sks, uint8_t *Xs, uint8_t *s2u_m, uint8_t *SK);
int user_auth_finish(uint8_t *U, uint8_t *pwd,  uint8_t *srv_name, struct user_state *s, uint8_t *s2u_m, uint8_t *SK);

#endif
