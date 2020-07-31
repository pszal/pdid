#include "pdid_gpm.h"

int gpm_new_pdid(uint8_t *c, shim_ctx_ptr_t ctx){
    uint8_t mraw[C_TILDE_LEN], *m;
    if (crypto_box_open(mraw, c, C_TILDE_LEN, ZONCE, DUMMY_PK, GPM_SKEY))
        return -1;
    m = mraw + crypto_box_ZEROBYTES;
    // check if username is registered
    uint32_t ret_len = 0;
    uint8_t tmp[META_LEN];
    // FIXME: It seems like FPCv1.0 has a bug logging
    // "Enclave: VIOLATION!!! Oh oh! cmac does not match!" when a single method
    // calls both get_state() and put_state(). Comment the following get_state()
    // line to get rid of that while testing with this FPC version.
    get_state(m, tmp, META_LEN, &ret_len, ctx);
    if (ret_len)
        return -1;
    // register username
    put_state(m, m+USERNAME_LEN, META_LEN, ctx);

    #ifdef PDID_DEBUG
    dump("\nGPM Registration", NULL, 0);
    dump("gpm:c~:", c, C_TILDE_LEN);
    dump("gpm:m~:", mraw, C_TILDE_LEN);
    dump("gpm:U:", m, USERNAME_LEN);
    dump("gpm:M:", tmp, META_LEN);
    #endif

    return 0;
}

int gpm_auth(uint8_t *s2g_m, uint8_t *c_hat, shim_ctx_ptr_t ctx){
    // TODO: Add (blockchain-dependent) inclusion verification
    // Decrypt and parse the message from server
    uint8_t *pks = s2g_m + C_BAR_LEN;
    uint8_t mraw[C_BAR_LEN], *m, *U, *alpha, *Xu, *xs, *eu, *es;
    if (crypto_box_open(mraw, s2g_m, C_BAR_LEN, ZONCE, pks, GPM_SKEY))
        return -1;
    m = mraw + crypto_box_ZEROBYTES;
    U = m;
    m += USERNAME_LEN;
    alpha = m;
    m += PDID_ECC_POINT_BYTES;
    Xu = m;
    m += PDID_ECC_POINT_BYTES;
    xs = m;
    m += PDID_ECC_SCALAR_BYTES;
    eu = m;
    m += PDID_ECC_SCALAR_BYTES;
    es = m;

    // check if user is registered
    uint32_t ret_len = 0;
    uint8_t tmp[META_LEN];
    get_state(U, tmp, META_LEN, &ret_len, ctx);
    if (!ret_len)
        return -1;
    m = tmp;

    // Parse meta
    uint8_t *ks, *ps, *Ps, *Pu, *c;
    ks = m;
    m += PDID_ECC_SCALAR_BYTES;
    ps = m;
    m += PDID_ECC_SCALAR_BYTES;
    Ps = m;
    m += PDID_ECC_POINT_BYTES;
    Pu = m;
    m += PDID_ECC_POINT_BYTES;
    c = m;

    // beta <- alpha^ks
    uint8_t beta[PDID_ECC_POINT_BYTES];
    pdid_ecc_mult(beta, ks, alpha);

    // SK <- HMQV(...)
    uint8_t pSK[PDID_ECC_POINT_BYTES];
    pdid_ecc_hmqv(Xu, xs, Pu, ps, eu, es, pSK);
    uint8_t SK[crypto_hash_BYTES];
    crypto_hash(SK, pSK, PDID_ECC_POINT_BYTES);

    // c_hat <- Penc(pks, beta | c | SK) 
    uint8_t m_hat[C_HAT_LEN];
    memset(m_hat, 0, crypto_box_ZEROBYTES);
    int offset = crypto_box_ZEROBYTES;
    memcpy(m_hat + offset, beta, PDID_ECC_POINT_BYTES);
    offset += PDID_ECC_POINT_BYTES;
    memcpy(m_hat + offset, c, C_LEN);
    offset += C_LEN;
    memcpy(m_hat + offset, SK, crypto_hash_BYTES);
    crypto_box(c_hat, m_hat, C_HAT_LEN, ZONCE, pks, GPM_SKEY);
    
    #ifdef PDID_DEBUG
    dump("\nGPM Auth", NULL, 0);
    dump("gpm:ps:", ps, PDID_ECC_SCALAR_BYTES);
    dump("gpm:Ps:", Ps, PDID_ECC_POINT_BYTES);
    dump("gpm:Pu:", Pu, PDID_ECC_POINT_BYTES);
    dump("gpm:ks:", ks, PDID_ECC_SCALAR_BYTES);
    dump("gpm:c:", c, C_LEN);
    dump("gpm:U:", U, USERNAME_LEN);
    dump("gpm:Xu:", Xu, PDID_ECC_POINT_BYTES);
    dump("gpm:a:", alpha, PDID_ECC_POINT_BYTES);
    dump("gpm:B:", beta, PDID_ECC_POINT_BYTES);
    dump("gpm:xs:", xs, PDID_ECC_SCALAR_BYTES);
    dump("gpm:eu:", eu, PDID_ECC_SCALAR_BYTES);
    dump("gpm:es:", es, PDID_ECC_SCALAR_BYTES);
    dump("gpm:pks:", pks, crypto_box_PUBLICKEYBYTES);
    dump("gpm:pSK:", pSK, PDID_ECC_POINT_BYTES);
    dump("gpm:SK:", SK, crypto_hash_BYTES);
    dump("gpm:c^:", c_hat, C_HAT_LEN);
    dump("gpm:m^:", m_hat, C_HAT_LEN);
    #endif

    return 0;
}

// Emulate blockchain functionality for local tests
#ifndef WITH_SGX  
void get_state(const char* key, uint8_t* val, uint32_t max_val_len, uint32_t* val_len, shim_ctx_ptr_t ctx){
    if (memcmp(key, users.username, USERNAME_LEN)){
        *val_len = 0;
        return;
    }
    memcpy(val, users.meta, META_LEN);
    *val_len = META_LEN;
}

void put_state(const char* key, uint8_t* val, uint32_t val_len, shim_ctx_ptr_t ctx){
    memcpy(users.username, key, USERNAME_LEN);
    memcpy(users.meta, val, val_len);
}
#endif
