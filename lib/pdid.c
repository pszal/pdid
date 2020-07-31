#include "pdid.h"
#include "utils.h"


int user_reg(uint8_t *U, uint8_t *pwd, uint8_t *c_tilde){
    // ps <-R Zq; Ps <- [base]*ps
    uint8_t ps[PDID_ECC_SCALAR_BYTES];
    uint8_t Ps[PDID_ECC_POINT_BYTES];
    ecc_make_key(Ps, ps);

    // pu <-R Zq; Pu <- [base]*pu
    uint8_t pu[PDID_ECC_SCALAR_BYTES];
    uint8_t Pu[PDID_ECC_POINT_BYTES];
    ecc_make_key(Pu, pu);

    // k <- OPRF(ks, pwd)
    // ks <-R Zq 
    uint8_t ks[PDID_ECC_SCALAR_BYTES];
    pdid_ecc_random_secret(ks);
    // tmp <- (H'(pwd))^ks
    uint8_t hash[PDID_ECC_POINT_BYTES];
    uint8_t tmp[PDID_ECC_POINT_BYTES];
    if (!pdid_hash_prime(hash, pwd))
        return -1;
    pdid_ecc_mult(tmp, ks, hash);

    // k <- H(pwd, tmp)
    int pwdlen = strlen(pwd);
    uint8_t m1[pwdlen+PDID_ECC_POINT_BYTES];
    memcpy(m1, pwd, pwdlen);
    memcpy(m1+pwdlen, tmp, PDID_ECC_POINT_BYTES);
    uint8_t k[crypto_hash_BYTES];
    crypto_hash(k, m1, pwdlen+PDID_ECC_POINT_BYTES);

    // c <- AENnc(k, pu | Pu | Ps)
    uint8_t c[C_LEN], m2[C_LEN];
    memset(m2, 0, crypto_secretbox_ZEROBYTES);
    int offset = crypto_secretbox_ZEROBYTES;
    memcpy(m2+offset, pu, PDID_ECC_SCALAR_BYTES);
    offset += PDID_ECC_SCALAR_BYTES;
    memcpy(m2+offset, Pu, PDID_ECC_POINT_BYTES);
    offset += PDID_ECC_POINT_BYTES;
    memcpy(m2+offset, Ps, PDID_ECC_POINT_BYTES);
    crypto_secretbox(c, m2, C_LEN, ZONCE, k);

    // c_tilde <- PEnc(pkb, U | ks | ps | Ps | Pu | c)
    uint8_t m3[C_TILDE_LEN];
    memset(m3, 0, crypto_box_ZEROBYTES);
    offset = crypto_box_ZEROBYTES;
    memcpy(m3+offset, U, USERNAME_LEN);
    offset += USERNAME_LEN;
    memcpy(m3+offset, ks, PDID_ECC_SCALAR_BYTES);
    offset += PDID_ECC_SCALAR_BYTES;
    memcpy(m3+offset, ps, PDID_ECC_SCALAR_BYTES);
    offset += PDID_ECC_SCALAR_BYTES;
    memcpy(m3+offset, Ps, PDID_ECC_POINT_BYTES);
    offset += PDID_ECC_POINT_BYTES;
    memcpy(m3+offset, Pu, PDID_ECC_POINT_BYTES);
    offset += PDID_ECC_POINT_BYTES;
    memcpy(m3+offset, c, C_LEN);
    // TODO: add real nonce here (the same for other PKE messages)
    crypto_box(c_tilde, m3, C_TILDE_LEN, ZONCE, GPM_PKEY, DUMMY_SK);

    #ifdef PDID_DEBUG
    dump("\nUser Registration", NULL, 0);
    dump("usr:H':", hash, PDID_ECC_POINT_BYTES);
    dump("usr:H'^ks:", tmp, PDID_ECC_POINT_BYTES);
    dump("usr:ps:", ps, PDID_ECC_SCALAR_BYTES);
    dump("usr:Ps:", Ps, PDID_ECC_POINT_BYTES);
    dump("usr:pu:", pu, PDID_ECC_SCALAR_BYTES);
    dump("usr:Pu:", Pu, PDID_ECC_POINT_BYTES);
    dump("usr:ks:", ks, PDID_ECC_SCALAR_BYTES);
    dump("usr:k:", k, crypto_hash_BYTES);
    dump("usr:m:", m2, C_LEN);
    dump("usr:c:", c, C_LEN);
    dump("usr:m3:", m3, C_TILDE_LEN);
    dump("usr:c~:", c_tilde, C_TILDE_LEN);
    #endif

    return 0;
}


// All state is recorded in S, u2s_msg is populated and ready to be sent to server
int user_auth_init(uint8_t *U, uint8_t *pwd, struct user_state *s, uint8_t *u2s_msg){
    // xu <-R Zq; Xu <- [base]*xu
    ecc_make_key(s->Xu, s->xu);

    // r <-R Zq; alpha <- (H'(pwd))^r
    pdid_ecc_random_secret(s->r);
    uint8_t h[PDID_ECC_POINT_BYTES];
    if (!pdid_hash_prime(h, pwd))
        return -1;
    uint8_t alpha[PDID_ECC_POINT_BYTES];
    pdid_ecc_mult(alpha, s->r, h);

    // Message (U | alpha | Xu) to Srv
    memcpy(u2s_msg, U, USERNAME_LEN);
    int offset = USERNAME_LEN;
    memcpy(u2s_msg + offset, alpha, PDID_ECC_POINT_BYTES);
    offset += PDID_ECC_POINT_BYTES;
    memcpy(u2s_msg + offset, s->Xu, PDID_ECC_POINT_BYTES);

    #ifdef PDID_DEBUG
    dump("\nUser Auth Init", NULL, 0);
    dump("usr:H':", h, PDID_ECC_POINT_BYTES);
    dump("usr:xu:", s->xu, PDID_ECC_SCALAR_BYTES);
    dump("usr:Xu:", s->Xu, PDID_ECC_POINT_BYTES);
    dump("usr:r:", s->r, PDID_ECC_SCALAR_BYTES);
    dump("usr:a:", alpha, PDID_ECC_POINT_BYTES);
    dump("usr:u2s:", u2s_msg, U2S_MSG_LEN);
    #endif

    return 0;
}

// sks (secret decryption key) and Xs are populated and it is the only state
// that server keeps after this method is executed
int server_auth_init(uint8_t *u2s_msg, uint8_t *srv_name, uint8_t *sks, uint8_t *Xs, uint8_t *s2g_m){
    // Parse the message
    uint8_t *U, *alpha, *Xu;
    U = u2s_msg;
    alpha = u2s_msg + USERNAME_LEN;
    Xu = alpha + PDID_ECC_POINT_BYTES; 

    // xs <-R Zq; Xs <- [base]*xs
    uint8_t xs[PDID_ECC_SCALAR_BYTES];
    ecc_make_key(Xs, xs);

    // eu <- H(Xs, U); es <- H(Xu, S)
    uint8_t eu[PDID_ECC_SCALAR_BYTES];
    get_e(Xs, U, eu);
    uint8_t es[PDID_ECC_SCALAR_BYTES];
    get_e(Xu, srv_name, es);

    // (pks, sks) <- Gen()
    uint8_t pks[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(pks, sks);

    // c_bar <- PEnc(pkb, U | alpha | Xu | xs | eu | es); send c_bar | pks
    uint8_t m[C_BAR_LEN];
    memset(m, 0, crypto_box_ZEROBYTES);
    int offset = crypto_box_ZEROBYTES;
    memcpy (m + offset, U, USERNAME_LEN);
    offset += USERNAME_LEN;
    memcpy(m + offset, alpha, PDID_ECC_POINT_BYTES);
    offset += PDID_ECC_POINT_BYTES;
    memcpy(m + offset, Xu, PDID_ECC_POINT_BYTES);
    offset += PDID_ECC_POINT_BYTES;
    memcpy(m + offset, xs, PDID_ECC_SCALAR_BYTES);
    offset += PDID_ECC_SCALAR_BYTES;
    memcpy(m + offset, eu, PDID_ECC_SCALAR_BYTES);
    offset += PDID_ECC_SCALAR_BYTES;
    memcpy(m + offset, es, PDID_ECC_SCALAR_BYTES);
    offset += PDID_ECC_SCALAR_BYTES;
    crypto_box(s2g_m, m, C_BAR_LEN, ZONCE, GPM_PKEY, sks);
    memcpy(s2g_m + C_BAR_LEN, pks, crypto_box_PUBLICKEYBYTES);

    #ifdef PDID_DEBUG
    dump("\nServer Auth Init", NULL, 0);
    dump("srv:xs:", xs, PDID_ECC_SCALAR_BYTES);
    dump("srv:Xs:", Xs, PDID_ECC_POINT_BYTES);
    dump("srv:U:", U, USERNAME_LEN);
    dump("srv:Xu:", Xu, PDID_ECC_POINT_BYTES);
    dump("srv:a:", alpha, PDID_ECC_POINT_BYTES);
    dump("srv:m:", m, C_BAR_LEN);
    dump("srv:c-:", s2g_m, C_BAR_LEN);
    dump("srv:pks:", pks, crypto_box_PUBLICKEYBYTES);
    dump("srv:sks:", sks, crypto_box_SECRETKEYBYTES);
    dump("srv:s2g:", s2g_m, S2G_MSG_LEN);
    #endif

    return 0;
}

int get_e(uint8_t *X, uint8_t *id, uint8_t *e){
    uint8_t m[PDID_ECC_POINT_BYTES + USERNAME_LEN];
    memcpy(m, X, PDID_ECC_POINT_BYTES);
    memcpy(m+PDID_ECC_POINT_BYTES, id, USERNAME_LEN);
    uint8_t h[crypto_hash_BYTES];
    crypto_hash(h, m, PDID_ECC_POINT_BYTES + USERNAME_LEN);
    memcpy(e, h, PDID_ECC_SCALAR_BYTES);
}


int server_auth_finish(uint8_t *c_hat, uint8_t *sks, uint8_t *Xs, uint8_t *s2u_m, uint8_t *SK){
    // Decrypt and parse
    uint8_t m_hat[C_HAT_LEN], *m, *beta, *c;
    if (crypto_box_open(m_hat, c_hat, C_HAT_LEN, ZONCE, GPM_PKEY, sks))
        return -1;
    m = m_hat + crypto_box_ZEROBYTES;
    beta = m;
    m += PDID_ECC_POINT_BYTES;
    c = m;
    m += C_LEN;

    // set shared secret
    memcpy(SK, m, crypto_hash_BYTES);

    // send (beta | Xs | c) to User
    memcpy(s2u_m, beta, PDID_ECC_POINT_BYTES);
    int offset = PDID_ECC_POINT_BYTES;
    memcpy(s2u_m + offset, Xs, PDID_ECC_POINT_BYTES);
    offset += PDID_ECC_POINT_BYTES;
    memcpy(s2u_m + offset, c, C_LEN);

    #ifdef PDID_DEBUG
    dump("\nServer Auth Finish", NULL, 0);
    dump("srv:c:", c, C_LEN);
    dump("srv:B:", beta, PDID_ECC_POINT_BYTES);
    dump("srv:Xs:", Xs, PDID_ECC_POINT_BYTES);
    dump("srv:SK:", SK, crypto_hash_BYTES);
    dump("srv:c^:", c_hat, C_HAT_LEN);
    dump("srv:m^:", m_hat, C_HAT_LEN);
    dump("srv:sks:", sks, crypto_box_SECRETKEYBYTES);
    #endif

    return 0;
}

int user_auth_finish(uint8_t *U, uint8_t *pwd,  uint8_t *srv_name, struct user_state *s, uint8_t *s2u_m, uint8_t *SK){
    // parse
    uint8_t *beta, *Xs, *c;
    beta = s2u_m;
    Xs = beta + PDID_ECC_POINT_BYTES;
    c = Xs + PDID_ECC_POINT_BYTES;

    // Binvr <-  beta^(1/r)
    uint8_t invr[PDID_ECC_SCALAR_BYTES], Binvr[PDID_ECC_POINT_BYTES];
    pdid_ecc_inv(invr, s->r);
    pdid_ecc_mult(Binvr, invr, beta);

    // k <- H(pwd, Binvr)
    int pwdlen = strlen(pwd);
    uint8_t tmp[pwdlen+PDID_ECC_POINT_BYTES];
    memcpy(tmp, pwd, pwdlen);
    memcpy(tmp+pwdlen, Binvr, PDID_ECC_POINT_BYTES);
    uint8_t k[crypto_hash_BYTES];
    crypto_hash(k, tmp, pwdlen+PDID_ECC_POINT_BYTES);

    // (pu, *Pu, *Ps) <- ADec(k, c)
    uint8_t *pu, *Pu, *Ps, m[C_LEN];
    if (crypto_secretbox_open(m, c, C_LEN, ZONCE, k))
        return -1;
    pu = m + crypto_secretbox_ZEROBYTES;
    Pu = pu + PDID_ECC_SCALAR_BYTES;
    Ps = Pu + PDID_ECC_POINT_BYTES;

    // eu <- H(Xs, U); es <- H(Xu, S)
    uint8_t eu[PDID_ECC_SCALAR_BYTES];
    get_e(Xs, U, eu);
    uint8_t es[PDID_ECC_SCALAR_BYTES];
    get_e(s->Xu, srv_name, es);

    // SK <- HMQV(...)
    uint8_t pSK[PDID_ECC_POINT_BYTES];
    pdid_ecc_hmqv(Xs, s->xu, Ps, pu, es, eu, pSK);
    crypto_hash(SK, pSK, PDID_ECC_POINT_BYTES);

    #ifdef PDID_DEBUG
    dump("\nUser Auth Finish", NULL, 0);
    dump("usr:c:", c, C_LEN);
    dump("srv:B:", beta, PDID_ECC_POINT_BYTES);
    dump("usr:r:", s->r, PDID_ECC_SCALAR_BYTES);
    dump("usr:B-1r:", Binvr, PDID_ECC_POINT_BYTES);
    dump("usr:k:", k, crypto_hash_BYTES);
    dump("usr:Ps:", Ps, PDID_ECC_POINT_BYTES);
    dump("usr:pu:", pu, PDID_ECC_SCALAR_BYTES);
    dump("usr:Pu:", Pu, PDID_ECC_POINT_BYTES);
    dump("usr:eu:", eu, PDID_ECC_SCALAR_BYTES);
    dump("usr:es:", es, PDID_ECC_SCALAR_BYTES);
    dump("usr:pSK:", pSK, PDID_ECC_POINT_BYTES);
    dump("usr:SK:", SK, crypto_hash_BYTES);
    #endif

    return 0;
}
