#include <dm/config.h>
#include <dm/base64.h>
#include <log.h>
#include <buff.h>
#include "ntlm.h"
#include "strings.h"
#include "proxy.h"
#include "parser.h"
#include "auth.h"
#include "auth-challenge.h"
#include "ntlm-osx.h"
#include <inttypes.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

#define PREFIX "NTLM "

struct ntlm_ctx_t {
    struct challenge_ctx_t *cctx;
    struct ntlm_ctx *ntlm_ctx;
};

static int get_ntlm_context(char* server, struct ntlm_ctx *ntlm_ctx)
{
    int ret = 0;
    UInt32 returnpasswordLength = 0;
    char *passwordBuffer = NULL;
    SecKeychainItemRef itemref = NULL;
    UInt32 attributeTags[1];
    UInt32 formatConstants[1];
    SecKeychainAttributeInfo attributeInfo;
    SecKeychainAttributeList *attributeList = NULL;
    OSStatus res = 0;
    char *account = NULL;
    char *password = NULL;
    char *passwordWide = NULL;

    NETLOG3("Attempting to get proxy creds for %s", server);

    if (!server) {
        NETLOG3("%s: Attempt to lookup credentials when no server specified")
        ret = 1;
        goto out;
    }

    res = SecKeychainFindInternetPassword(NULL,
                                          strlen(server),
                                          server,
                                          0, NULL,
                                          0, NULL,
                                          0, NULL,
                                          0,
                                          kSecProtocolTypeAny,
                                          kSecAuthenticationTypeAny,
                                          &returnpasswordLength,
                                          (void**)&passwordBuffer,
                                          &itemref);
    if (res != noErr) {
        NETLOG3("%s: SecKeychainFindInternetPassword failed, error = %d", __FUNCTION__, (int)res);
        ret = 1;
        goto out;
    }

    *attributeTags = kSecAccountItemAttr;
    *formatConstants = CSSM_DB_ATTRIBUTE_FORMAT_STRING;
    attributeInfo.count = 1;
    attributeInfo.tag = attributeTags;
    attributeInfo.format = formatConstants;
    res = SecKeychainItemCopyAttributesAndData(itemref, &attributeInfo, NULL, &attributeList, 0, NULL);

    if (res != noErr) {
        NETLOG3("%s: SecKeychainItemCopyAttributesAndData failed, error = %d", __FUNCTION__, (int)res);
        ret = 1;
        goto out;
    }

    SecKeychainAttribute accountNameAttribute = attributeList->attr[0];
    account = calloc(accountNameAttribute.length + 1, 1);
    if (!account)
        goto mem_err;
    memcpy(account, accountNameAttribute.data, accountNameAttribute.length);

    // In the keychain, account is "DOMAIN\username", which we need to split
    int delimiterPosition = -1;
    for (int i = 0; i < accountNameAttribute.length; i++) {
        if (account[i] == '\\') {
            delimiterPosition = i;
            break;
        }
    }

    int usernameLength = accountNameAttribute.length - (1 + delimiterPosition);
    if (usernameLength <= 0) {
        NETLOG3("%s: credentials for %s had no username specified", __FUNCTION__, server);
        res = 1;
        goto out;
    }

    if (delimiterPosition <= 0) {
        ntlm_ctx->domain = NULL;
        ntlm_ctx->w_domain = NULL;
        ntlm_ctx->w_domain_len = 0;
        NETLOG5("Domain for NTLM not provided");
    } else {
        ntlm_ctx->domain = calloc(delimiterPosition + 1, 1);
        if (!ntlm_ctx->domain)
            goto mem_err;
        memcpy(ntlm_ctx->domain, account, delimiterPosition);
        ntlm_ctx->w_domain = calloc((delimiterPosition + 1) * 2, 1);
        if (!ntlm_ctx->w_domain)
            goto mem_err;
        for (int i = 0; i < delimiterPosition; i++)
            ntlm_ctx->w_domain[i * 2] = ntlm_ctx->domain[i];
        ntlm_ctx->w_domain_len = delimiterPosition * 2;
        NETLOG5("Domain for NTLM: %s", ntlm_ctx->domain);
    }

    ntlm_ctx->username = calloc(usernameLength + 1, 1);
    if (!ntlm_ctx->username)
        goto mem_err;
    memcpy(ntlm_ctx->username, account + delimiterPosition + 1, usernameLength);
    ntlm_ctx->w_username = calloc((usernameLength + 1) * 2, 1);
    if (!ntlm_ctx->w_username)
        goto mem_err;
    for (int i = 0; i < usernameLength; i++)
        ntlm_ctx->w_username[i * 2] = toupper(ntlm_ctx->username[i]);
    ntlm_ctx->w_username_len = usernameLength * 2;
    NETLOG5("username for NTLM: %s", ntlm_ctx->username);

    password = calloc(returnpasswordLength + 1, 1);
    if (!password)
        goto mem_err;
    memcpy(password, passwordBuffer, returnpasswordLength);

    passwordWide = calloc((returnpasswordLength + 1) * 2, 1);
    if (!passwordWide)
        goto mem_err;
    for (int i = 0; i < returnpasswordLength; i++)
        passwordWide[i * 2] = password[i];

    ntlm_ctx->ntlm_hash = calloc(1, 32 + 2);
    if (!ntlm_ctx->ntlm_hash)
        goto mem_err;
    CC_MD4(passwordWide, returnpasswordLength * 2, ntlm_ctx->ntlm_hash);

    if (0 != gethostname((char*)ntlm_ctx->hostname, 255)) {
        int e = errno;
        NETLOG("%s: Failed to get hostname %d %s", __FUNCTION__, e, strerror(e));
        ret = 1;
        goto out;
    }

out:
    if (passwordBuffer)
        SecKeychainItemFreeContent(NULL, passwordBuffer);
    if (itemref)
        CFRelease(itemref);
    if (attributeList)
        SecKeychainItemFreeAttributesAndData(attributeList, NULL);
    if (account)
        free(account);
    if (passwordWide) {
        bzero(passwordWide, returnpasswordLength * 2);
        free(passwordWide);
    }
    if (password) {
        bzero(password, returnpasswordLength);
        free(password);
    }

    return ret;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
    ret = 1;
    goto out;
}

struct ntlm_ctx_t * ntlm_osx_init_auth(struct challenge_ctx_t *cctx)
{
    struct ntlm_ctx_t *ntlm = NULL;

    assert(cctx && cctx->auth);

    ntlm = calloc(1, sizeof(*ntlm));
    if (!ntlm)
        goto out;

    struct ntlm_ctx *context = calloc(1, sizeof(struct ntlm_ctx));
    if (!context) {
        free(ntlm);
        ntlm = NULL;
        goto out;
    }
    cctx->nr_steps = 2;
    ntlm->cctx = cctx;
    ntlm->ntlm_ctx = context;
out:
    return ntlm;
}


void ntlm_osx_reset_auth(struct ntlm_ctx_t *ntlm)
{
    if (!ntlm)
        return;

    if (ntlm->ntlm_ctx) {
        free(ntlm->ntlm_ctx->ntlm_hash);
        free(ntlm->ntlm_ctx);
    }
    struct ntlm_ctx *context = calloc(1, sizeof(struct ntlm_ctx));
    ntlm->ntlm_ctx = context;
}

void ntlm_osx_free_auth(struct ntlm_ctx_t *ntlm)
{
    if (!ntlm)
        return;

    ntlm_osx_reset_auth(ntlm);

    free(ntlm->ntlm_ctx->username);
    free(ntlm->ntlm_ctx->domain);
    free(ntlm->ntlm_ctx->w_username);
    free(ntlm->ntlm_ctx->w_domain);
    free(ntlm->ntlm_ctx->ntlm_hash);
    free(ntlm->ntlm_ctx);
    free(ntlm);
}

int ntlm_osx_clt(struct ntlm_ctx_t *ntlm, bool force_saved_auth,
        unsigned char *buf_in_data, size_t buf_in_data_len,
        unsigned char **buf_out_data, size_t *buf_out_data_len,
        int *logon_required, int *needs_reconnect)
{
    int ret = -1;

    if (!ntlm || !ntlm->cctx)
        goto out;

    if (ntlm->cctx->step > ntlm->cctx->nr_steps) {
        NETLOG("%s: failing, nr_steps exceeded", __FUNCTION__);
        *logon_required = 1;
        ret = 0;
        goto out;
    }

    if (!ntlm->cctx->target_name) {
        NETLOG("%s: bug, target_name empty", __FUNCTION__);
        goto out;
    }


    if (0 != get_ntlm_context(ntlm->cctx->target_name, ntlm->ntlm_ctx)) {
        NETLOG("%s: No credentials found for %s", __FUNCTION__, ntlm->cctx->target_name);
        *logon_required = 1;
        ret = 0;
        goto out;
    }

    *logon_required = 0;

    if (ntlm_get_next_token(ntlm->ntlm_ctx, buf_in_data, buf_in_data_len,
                buf_out_data, buf_out_data_len) < 0) {
        NETLOG("%s: ERROR on ntlm_get_next_token", __FUNCTION__);
        goto out;
    }

    ret = 0;
out:
    return ret;
}
