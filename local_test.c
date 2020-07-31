#include <time.h> 
#include <stdlib.h>
#include "lib/pdid.h"
#include "lib/pdid_gpm.h"


int main(){
    return run_tests(100);
}
    
int run_tests(int runs){
    const char password[] = "123456"; 
    const char server_name[] = "serv.com"; 
    char username[USERNAME_LEN];
    
    // Time measurement arrays (in ms)
    double user_reg_ta[runs];
    double user_auth_init_ta[runs];
    double user_auth_finish_ta[runs];
    double user_auth_total_ta[runs];
    double gpm_new_pdid_ta[runs];
    double gpm_auth_ta[runs];
    double server_auth_init_ta[runs];
    double server_auth_finish_ta[runs];
    double server_auth_total_ta[runs];
    clock_t t;

    // Start tests
    printf("Running %d tests\n", runs);
    for (int i=0; i<runs; i++){
        // Generate a username
        sprintf(username, "%d", 1000000 + i);

        // Registration
        unsigned char c_tilde[C_TILDE_LEN];
        t = clock();
        if (user_reg(username, password, c_tilde)) // User's side
            return -1;
        t = clock() - t;
        user_reg_ta[i] = (double)t;
        t = clock();
        if (gpm_new_pdid(c_tilde, NULL)) // GPM's side
            return -1;
        t = clock() - t;
        gpm_new_pdid_ta[i] = (double)t;

        // Authentication 1: User to Server
        struct user_state s;
        unsigned char u2s_msg[U2S_MSG_LEN];
        t = clock();
        if (user_auth_init(username, password, &s, u2s_msg))
            return -1;
        t = clock() - t;
        user_auth_init_ta[i] = (double)t;

        // Authentication 2: Server to GPM
        unsigned char sks[crypto_box_SECRETKEYBYTES];
        uint8_t Xs[PDID_ECC_POINT_BYTES];
        unsigned char s2g_m[S2G_MSG_LEN];
        t = clock();
        if (server_auth_init(u2s_msg, server_name, sks, Xs, s2g_m))
            return -1;
        t = clock() - t;
        server_auth_init_ta[i] = (double)t;

        // Authentication 3: GPM to Server
        uint8_t c_hat[C_HAT_LEN];
        t = clock();
        if (gpm_auth(s2g_m, c_hat, NULL))
            return -1;
        t = clock() - t;
        gpm_auth_ta[i] = (double)t;

        // Authentication 4: Server to User
        uint8_t s2u_m[S2U_MSG_LEN];
        uint8_t SKs[crypto_hash_BYTES];
        t = clock();
        if (server_auth_finish(c_hat, sks, Xs, s2u_m, SKs))
            return -1;
        t = clock() - t;
        server_auth_finish_ta[i] = (double)t;

        // Authentication 5: User
        uint8_t SKu[crypto_hash_BYTES];
        t = clock();
        if (user_auth_finish(username, password, server_name, &s, s2u_m, SKu))
            return -1;
        t = clock() - t;
        user_auth_finish_ta[i] = (double)t;

        user_auth_total_ta[i] = user_auth_init_ta[i] + user_auth_finish_ta[i];
        server_auth_total_ta[i] = server_auth_init_ta[i] + server_auth_finish_ta[i];

        // Check if the session keys are identical
        if (memcmp(SKs, SKu, crypto_hash_BYTES))
            return -1;
        fprintf(stderr, ".");
    }
    printf("\n");
    print_stats("Usr Reg  ", user_reg_ta, runs);
    print_stats("Usr AuthT", user_auth_total_ta, runs);
    print_stats("Usr Auth1", user_auth_init_ta, runs);
    print_stats("Usr Auth2", user_auth_finish_ta, runs);
    print_stats("GPM Reg  ", gpm_new_pdid_ta, runs);
    print_stats("GPM Auth ", gpm_auth_ta, runs);
    print_stats("Srv AuthT", server_auth_total_ta, runs);
    print_stats("Srv Auth1", server_auth_init_ta, runs);
    print_stats("Srv Auth2", server_auth_finish_ta, runs);
    return 0;
}
