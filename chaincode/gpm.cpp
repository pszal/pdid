#include "shim.h"
#include "logging.h"
#include <string>

extern "C" {
#include "pdid.h"
}
#include "pdid_gpm.h"

#define OK "OK"
#define FAILED "FAILED"

int init( uint8_t* resp, uint32_t max_resp_len, uint32_t* resp_len, shim_ctx_ptr_t ctx)
{
    return 0;
}

std::string newPDID(std::string msg, shim_ctx_ptr_t ctx)
{
    std::string result;
    LOG_DEBUG("newPDID()");

    // TODO: add sanity checks
    unsigned char c_tilde[C_TILDE_LEN];
    unhexlifyn(msg.c_str(), 2*C_TILDE_LEN, c_tilde);
    if (gpm_new_pdid(c_tilde, ctx))
        return FAILED;
    return OK;
}

std::string authPDID(std::string msg, shim_ctx_ptr_t ctx)
{
    std::string result;
    LOG_DEBUG("authPDID()");
    // TODO: implement blockchain-specific inclusion proof verification here
    // TODO: add sanity checks
    unsigned char s2g_m[S2G_MSG_LEN];
    unhexlifyn(msg.c_str(), 2*C_HAT_LEN, s2g_m);
    unsigned char c_hat[C_HAT_LEN];
    if (gpm_auth(s2g_m, c_hat, ctx))
        return FAILED;
    char c_hat_hex[C_HAT_LEN*2+1];
    hexlifyn(c_hat, C_HAT_LEN, c_hat_hex);
    return c_hat_hex;
}

int invoke( uint8_t* resp, uint32_t max_resp_len, uint32_t* resp_len, shim_ctx_ptr_t ctx)
{
    LOG_DEBUG("GPM invoke()");

    std::string method;
    std::vector<std::string> params;
    get_func_and_params(method, params, ctx);
    std::string msg = params[0];
    std::string result;

    if (method == "newPDID")
    {
        double t = get_time_ms();
        result = newPDID(msg, ctx);
        LOG_DEBUG("newPDID() executed within: %f", get_time_ms()-t);
    }
    else if (method == "authPDID")
    {
        double t = get_time_ms();
        result = authPDID(msg, ctx);
        LOG_DEBUG("authPDID() executed within: %f", get_time_ms()-t);
    }
    else
    {
        LOG_DEBUG("GPM: no method found: transaction '%s'", method);
        return -1;
    }

    // check that result fits into resp
    int size = result.size();
    if (max_resp_len < size)
    {
        LOG_DEBUG("GPM: Response buffer too small");
        *resp_len = 0;
        return -1;
    }

    memcpy(resp, result.c_str(), size);
    *resp_len = size;
    LOG_DEBUG("GPM: Response: %s", result.c_str());
    return 0;
}
