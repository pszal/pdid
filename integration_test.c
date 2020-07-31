#include <time.h> 
#include <stdlib.h>
#include "lib/pdid.h"
#include "lib/pdid_gpm.h"

#define MAX_LEN 1024

const char fstr[] = "export %s='{\"Args\":[\"%s\",\"%s\"]}'\n"; 

int main(){
    const char password[] = "123456"; 
    const char server_name[] = "serv.com"; 
    char username[] = "alice12";
    
    // Registration
    unsigned char c_tilde[C_TILDE_LEN];
    if (user_reg(username, password, c_tilde)) // User's side
        return -1;
    // prepare command
    char c_tilde_hex[2*C_TILDE_LEN+1];
    hexlifyn(c_tilde, C_TILDE_LEN, c_tilde_hex);
    printf("Generating PDID registration and authorization requests:\n\n");
    char cmd[MAX_LEN];
    sprintf(cmd, fstr, "REQ_newPDID", "newPDID", c_tilde_hex);
    printf(cmd);

    // just test if everything goes well
    // unsigned char c_tilde2[C_TILDE_LEN];
    // unhexlifyn(c_tilde_hex, strlen(c_tilde_hex), c_tilde2);
    // if (gpm_new_pdid(c_tilde2, NULL)) // GPM's side
    //     return -1;
    

    // Authentication 1: User to Server
    struct user_state s;
    unsigned char u2s_msg[U2S_MSG_LEN];
    if (user_auth_init(username, password, &s, u2s_msg))
        return -1;

    // Authentication 2: Server to GPM
    unsigned char sks[crypto_box_SECRETKEYBYTES];
    uint8_t Xs[PDID_ECC_POINT_BYTES];
    unsigned char s2g_m[S2G_MSG_LEN];
    if (server_auth_init(u2s_msg, server_name, sks, Xs, s2g_m))
        return -1;


    char s2g_m_hex[2*S2G_MSG_LEN+1];
    hexlifyn(s2g_m, S2G_MSG_LEN, s2g_m_hex);
    sprintf(cmd, fstr, "REQ_authPDID", "authPDID", s2g_m_hex);
    printf(cmd);
    printf("./test.sh\n\nInstall the GPM's chaincode and run the above in another terminal.\n");
    printf("After you get the last response's data, unbase64 it and paste here:\n");
    char c_hat_hex[2*C_HAT_LEN+1];
    scanf("%s", c_hat_hex);
    uint8_t c_hat[C_HAT_LEN];
    unhexlifyn(c_hat_hex, strlen(c_hat_hex), c_hat);
    // Authentication 3: GPM to Server

    // if (gpm_auth(s2g_m, c_hat, NULL))
    //     return -1;

    // Authentication 4: Server to User
    uint8_t s2u_m[S2U_MSG_LEN];
    uint8_t SKs[crypto_hash_BYTES];
    if (server_auth_finish(c_hat, sks, Xs, s2u_m, SKs))
        return -1;

    // Authentication 5: User
    uint8_t SKu[crypto_hash_BYTES];
    if (user_auth_finish(username, password, server_name, &s, s2u_m, SKu))
        return -1;

    // Check if the session keys are identical
    dump("SKs:", SKs, crypto_hash_BYTES);
    dump("SKu:", SKu, crypto_hash_BYTES);

    return 0;
}
