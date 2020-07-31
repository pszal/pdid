#ifndef DEFINES_H
#define DEFINES_H

#include "ecc.h"
#ifndef WITH_NACL
#include "tweetnacl.h"
#else
#include "crypto_box.h"
#include "crypto_hash.h"
#include "crypto_secretbox.h"
#include "randombytes.h"
#endif

//#define PDID_DEBUG

// TODO: static for now, just for easy parsing. get_e() assumes that for srv_id too.
#define USERNAME_LEN 8

// Ciphertext c, stored by the GPM as part of password metadata
#define C_LEN (crypto_secretbox_ZEROBYTES + PDID_ECC_SCALAR_BYTES + 2*PDID_ECC_POINT_BYTES)

// Ciphertext c~, sent from U to GPM  (Assume that box_ZEROBYTES == secretbox_ZEROBYTES)
#define C_TILDE_LEN (USERNAME_LEN + 2*C_LEN + PDID_ECC_SCALAR_BYTES)

// Pwd metadata (w/o username)
#define META_LEN (C_TILDE_LEN-crypto_box_ZEROBYTES-USERNAME_LEN)

// User to Srv message
#define U2S_MSG_LEN (USERNAME_LEN + 2*PDID_ECC_POINT_BYTES)

// Ciphertext c-
#define C_BAR_LEN (crypto_box_ZEROBYTES + USERNAME_LEN + 2*PDID_ECC_POINT_BYTES + 3*PDID_ECC_SCALAR_BYTES) 

// c- | pk, sent from S to GPM
#define S2G_MSG_LEN (C_BAR_LEN + crypto_box_PUBLICKEYBYTES)

// Ciphertext c^
#define C_HAT_LEN (crypto_box_ZEROBYTES + PDID_ECC_POINT_BYTES + C_LEN + crypto_hash_BYTES)

// (beta | Xs | c) to User
#define S2U_MSG_LEN (2*PDID_ECC_POINT_BYTES + C_LEN)

// Nonce isn't needed since no AEnc() is executed twice under the same key
#define ZONCE "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

// Dummy keys for tweetnacl's pubkey auth-enc
#define DUMMY_PK "\x80\xb5\x6d\x40\x1a\xd4\x4f\x31\x9a\xcc\xed\x96\xb2\x4b\x79\x16\x8b\x6f\x2d\x7c\x22\x76\xd1\xce\x4e\x4f\x8f\x1b\x7c\x14\xfd\x21"
#define DUMMY_SK "\xf8\xb1\x7\x1\xdc\xa4\xe\x1f\xb0\xf7\x39\xc0\xd7\xa7\x3c\x5e\x6c\x37\xaa\x10\xd0\x25\x6f\x6d\x29\x69\x7c\x8a\x37\x3d\x36\x54"

// Abstracts key management for tests
#define GPM_PKEY "\x8c\x8b\x8a\xc8\x23\x37\x2b\x14\x3f\xa2\x83\x67\xd8\x4c\xa1\xfa\x8d\xbb\x63\xec\x21\x8a\x40\xd8\x1b\x1f\x2a\xa0\x9e\xba\x53\x63"
#define GPM_SKEY "\x1b\xc9\x67\x70\x36\x67\x75\xa7\xe8\x3e\xda\x54\xfd\xcd\x11\x56\xd3\x53\xbd\x2c\xa1\xe9\x47\xe3\xe1\x2e\xed\xc1\x1c\x79\x1c\xb9"


#endif