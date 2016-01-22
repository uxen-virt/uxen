#include <dm/config.h>
#include <dm/base64.h>
#include <log.h>
#include <buff.h>
#include "ntlm.h"
#include "strings.h"
#include "proxy.h"
#include "parser.h"
#include "auth-challenge.h"
#include <inttypes.h>

#include <windows.h>
#define SECURITY_WIN32 1
#include <sspi.h>
#include <security.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <wincrypt.h>

#define CRED_TMP_PREFIX "tmp_"

#if 0
SECURITY_STATUS SspiUnmarshalAuthIdentity(unsigned long, char*, void*);
SECURITY_STATUS SspiFreeAuthIdentity(void*);
#endif
__attribute__((__stdcall__)) __attribute__((dllimport)) SECURITY_STATUS SspiUnmarshalAuthIdentity(
    unsigned long, char *, void *);
__attribute__((__stdcall__)) __attribute__((dllimport)) SECURITY_STATUS SspiFreeAuthIdentity(
        void *);

struct sspi_ctx_t {
    struct challenge_ctx_t *cctx;
    int initialized;
    int handle_acquired;
    CredHandle handle;
    CtxtHandle ctx;
};

static HINSTANCE security_lib = NULL;
static PSecurityFunctionTableW security_ft = NULL;

static const wchar_t *const pkg_names[] = {
    L"Kerberos",
    L"Negotiate",
    L"NTLM"
};

static const char *
get_sspi_str_status(SECURITY_STATUS sspi_status)
{
    switch(sspi_status) {
    case SEC_E_OK:
        return "SEC_E_OK";
    case SEC_I_COMPLETE_NEEDED:
        return "SEC_I_COMPLETE_NEEDED";
    case SEC_I_CONTINUE_NEEDED:
        return "SEC_I_CONTINUE_NEEDED";
    case SEC_I_COMPLETE_AND_CONTINUE:
        return "SEC_I_COMPLETE_AND_CONTINUE";
    case SEC_E_INSUFFICIENT_MEMORY:
        return "SEC_E_INSUFFICIENT_MEMORY";
    case SEC_E_INTERNAL_ERROR:
        return "SEC_E_INTERNAL_ERROR";
    case SEC_E_INVALID_HANDLE:
        return "SEC_E_INVALID_HANDLE";
    case SEC_E_INVALID_TOKEN:
        return "SEC_E_INVALID_TOKEN";
    case SEC_E_LOGON_DENIED:
        return "SEC_E_LOGON_DENIED";
    case SEC_E_UNSUPPORTED_FUNCTION:
        return "SEC_E_UNSUPPORTED_FUNCTION";
    case SEC_E_NO_CREDENTIALS:
        return "SEC_E_NO_CREDENTIALS";
    case SEC_E_TARGET_UNKNOWN:
        return "SEC_E_TARGET_UNKNOWN";
    case SEC_E_SECPKG_NOT_FOUND:
        return "SEC_E_SECPKG_NOT_FOUND";
    case SEC_E_BAD_PKGID:
        return "SEC_E_BAD_PKGID";
    case SEC_E_NO_IMPERSONATION:
        return "SEC_E_NO_IMPERSONATION";
    case SEC_E_NO_AUTHENTICATING_AUTHORITY:
        return "SEC_E_NO_AUTHENTICATING_AUTHORITY";
    case SEC_E_UNTRUSTED_ROOT:
        return "SEC_E_UNTRUSTED_ROOT";
    case SEC_E_WRONG_PRINCIPAL:
        return "SEC_E_WRONG_PRINCIPAL";
    case SEC_E_TIME_SKEW:
        return "SEC_E_TIME_SKEW";
    default:
        break;
    }

    return "UNKNOWN ERROR";
}

static int sspi_get_auth_data(const char *target_name, void **pp_auth)
{
    int ret = -1;
    PCREDENTIALA pcred = NULL;
    BOOL ok;
    int i;
    DATA_BLOB data_in = {0};
    DATA_BLOB data_out = {0};
    DATA_BLOB optional_entropy = {0};
    char key[ARRAYSIZE(IE7_cred_key)] = IE7_cred_key;
    uint16_t temp[ARRAYSIZE(key)] = {0};
    SECURITY_STATUS sec_status = 0;

    ok = CredReadA((LPCSTR)target_name, CRED_TYPE_GENERIC, 0, &pcred);
    NETLOG5("%s: try CredReadA from %s ret %d", __FUNCTION__, target_name, (int) ok);
    if (ok != TRUE) {
        char *tmp = NULL;

        // try the session one
        if (asprintf(&tmp, "%s%s", CRED_TMP_PREFIX, target_name) < 0) {
            warnx("%s: malloc", __FUNCTION__);
            goto out;
        }
        ok = CredReadA((LPCSTR)tmp, CRED_TYPE_GENERIC, 0, &pcred);
        NETLOG5("%s: try CredReadA from %s ret %d", __FUNCTION__, tmp, (int) ok);
        free(tmp);
    }
    if (ok != TRUE) {
        NETLOG5("%s: CredReadA failed, err %d", __FUNCTION__, (int) GetLastError());
        goto out;
    }

    for (i = 0; i < ARRAYSIZE(key); ++i)
        temp[i] = (uint16_t)(key[i] * 4);

    optional_entropy.pbData = (BYTE*)(&temp);
    optional_entropy.cbData = sizeof(temp);

    data_in.pbData = (BYTE*)pcred->CredentialBlob;
    data_in.cbData = pcred->CredentialBlobSize;
    ok = CryptUnprotectData(&data_in, NULL, &optional_entropy, NULL, NULL, 0, &data_out);
    if (ok != TRUE) {
        NETLOG5("%s: CryptUnprotectData failed, err %d", __FUNCTION__, (int) GetLastError());
        goto out;
    }
    sec_status = SspiUnmarshalAuthIdentity((unsigned long)data_out.cbData, (char*)data_out.pbData,
            pp_auth);
    if (sec_status != SEC_E_OK || !*pp_auth) {
        NETLOG2("%s: SspiUnmarshalAuthIdentity failed, sec_status = 0x%lx (%s)",
                __FUNCTION__,
                (unsigned long) sec_status,
                get_sspi_str_status(sec_status));
        goto out;
    }

    ret = 0;
out:
    if (data_out.pbData) {
        SecureZeroMemory(data_out.pbData, data_out.cbData);
        LocalFree(data_out.pbData);
    }
    if (pcred) {
        SecureZeroMemory(pcred->CredentialBlob, pcred->CredentialBlobSize);
        CredFree(pcred);
    }
    return ret;
}

int sspi_init()
{
    int rc = 0, i;

    INIT_SECURITY_INTERFACE_W init_sec_interface = NULL;
    PSecPkgInfoW pkgInfo = NULL;
    SEC_WCHAR *package = NULL;

    security_lib = LoadLibrary("security.dll");
    if (!security_lib) {
        NETLOG("security.dll load failed");
        return -1;
    }

    init_sec_interface = (INIT_SECURITY_INTERFACE_W)GetProcAddress(security_lib, "InitSecurityInterfaceW");
    if (!init_sec_interface) {
        NETLOG("failed to locate DLL entry point");
        return -1;
    }

    security_ft = init_sec_interface();
    if (!security_ft) {
        NETLOG("no function table");
        return -1;
    }

    for (i = 0; i < _NUMBER_OF_PACKAGES_; i++) {
        package = (SEC_WCHAR*)pkg_names[i];
        pkg_ctx[i].initialized = false;
        rc = security_ft->QuerySecurityPackageInfoW(package, &pkgInfo);
        if (rc != SEC_E_OK) {
            NETLOG("%s: error, %ls package not found", __FUNCTION__, package);
            continue;
        }
        pkg_ctx[i].initialized = true;
        pkg_ctx[i].max_token_length = pkgInfo->cbMaxToken;
        security_ft->FreeContextBuffer(pkgInfo);
        NETLOG2("%s: initialized sspi package %ls, cbMaxToken = %d", __FUNCTION__, package, (int) pkg_ctx[i].max_token_length);
    }

    return 0;
}

void sspi_exit()
{
    if (security_lib)
        FreeLibrary(security_lib);
    security_lib = NULL;
}

struct sspi_ctx_t * sspi_init_auth(struct challenge_ctx_t *cctx)
{
    struct sspi_ctx_t *sspi;

    sspi = calloc(1, sizeof(*sspi));
    if (!sspi)
        goto out;
    sspi->cctx = cctx;

out:
    return sspi;
}


void sspi_reset_auth(struct sspi_ctx_t *sspi)
{
    if (!sspi || !sspi->cctx)
        return;

    if (!sspi->cctx->custom_ntlm && sspi->initialized) {
        if (sspi->handle_acquired)
            FreeCredentialsHandle(&sspi->handle);
        sspi->handle_acquired = 0;
        DeleteSecurityContext(&sspi->ctx);
        sspi->initialized = 0;
    }
    memset(&sspi->ctx, 0, sizeof(sspi->ctx));
}

void sspi_free_auth(struct sspi_ctx_t *sspi)
{
    sspi_reset_auth(sspi);
    memset(sspi, 0, sizeof(*sspi));
    free(sspi);
}

int sspi_clt(struct sspi_ctx_t *sspi, bool force_saved_auth,
        unsigned char *buf_in_data, size_t buf_in_data_len,
        unsigned char **buf_out_data, size_t *buf_out_data_len,
        int *logon_required, int *needs_reconnect)
{
    int ret = -1;
    int rc;
    enum pkg_type pkg;
    const char *proxy_name;
    struct http_auth *auth;
    unsigned char *sspibuf = NULL;
    SecBuffer buf_in = {0};
    SecBuffer buf_out = {0};
    SecBufferDesc buf_in_desc = {0};
    SecBufferDesc buf_out_desc = {0};
    ULONG attrs = 0;
    TimeStamp tsDummy = {{0, 0}};
    SECURITY_STATUS sec_status = 0;
    ULONG context_req_fl = 0;

    assert(sspi && sspi->cctx && sspi->cctx->auth);
    auth = sspi->cctx->auth;

    proxy_name = auth->proxy->name;
    if (auth->proxy->canon_name && (auth->proxy->ct == AUTH_TYPE_NEGOTIATE ||
        auth->proxy->ct == AUTH_TYPE_KERBEROS)) {

        proxy_name = auth->proxy->canon_name;
    }
    assert(proxy_name);

    if (!security_ft)
        goto out;
    rc = get_package(auth->type);
    if (rc < 0) {
        NETLOG("%s: auth package not initialized", __FUNCTION__);
        goto out;
    }
    pkg = rc;

    if (force_saved_auth && sspi->handle_acquired) {
        FreeCredentialsHandle(&sspi->handle);
        sspi->handle_acquired = 0;
    }

    if (!sspi->handle_acquired) {
        TimeStamp useBefore = {{0, 0}};
        SEC_WCHAR *package = (SEC_WCHAR*)pkg_names[pkg];
        void *p_auth;
        int r;

        p_auth = NULL;
        if (force_saved_auth) {
            r = sspi_get_auth_data(proxy_name, &p_auth);
            if (r < 0) {
                char *tmp = NULL;
                asprintf(&tmp, "HTTP/%s", proxy_name);
                if (tmp) {
                    p_auth = NULL;
                    r = sspi_get_auth_data(tmp, &p_auth);
                    free(tmp);
                }
            }
            if (r < 0) {
                AUXL2("no saved creds found, giving up");
                *logon_required = 1;
                p_auth = NULL;
                ret = 0;
                goto out;
            }

            AUXL4("using PSEC_WINNT_AUTH_IDENTITY_OPAQUE saved by krypton");
        }


        /* 1. The client obtains a representation of the credential set
         * for the user via the SSPI AcquireCredentialsHandle function.
         */
        sec_status = security_ft->AcquireCredentialsHandleW(NULL,
                                               package,
                                               SECPKG_CRED_OUTBOUND,
                                               NULL,
                                               p_auth,
                                               NULL,
                                               NULL,
                                               &(sspi->handle),
                                               &useBefore);
        AUXL4("AcquireCredentialsHandle: package = %ls sec_status = 0x%lx (%s)",
                package, (unsigned long) sec_status, get_sspi_str_status(sec_status));
        if (p_auth)
            SspiFreeAuthIdentity(p_auth);

        if (sec_status != SEC_E_OK) {
            NETLOG("%s: failed to acquire credentials with error %lX, package %ls",
                    __FUNCTION__, (unsigned long) sec_status, package);
            goto out;
        }

        sspi->handle_acquired = 1;
    }

    sspibuf = calloc(1, pkg_ctx[pkg].max_token_length + 1);
    if (!sspibuf) {
        warnx("%s: malloc", __FUNCTION__);
        goto out;
    }
    *buf_out_data = sspibuf;

    buf_in_desc.ulVersion = SECBUFFER_VERSION;
    buf_in_desc.cBuffers = 1;
    buf_in_desc.pBuffers = &buf_in;
    buf_in.BufferType = SECBUFFER_TOKEN;
    buf_in.pvBuffer = buf_in_data;
    buf_in.cbBuffer = buf_in_data_len;

    buf_out_desc.ulVersion = SECBUFFER_VERSION;
    buf_out_desc.cBuffers = 1;
    buf_out_desc.pBuffers = &buf_out;
    buf_out.BufferType = SECBUFFER_TOKEN;
    buf_out.pvBuffer = sspibuf;
    buf_out.cbBuffer = pkg_ctx[pkg].max_token_length;

    *logon_required = 0;

    /* 2. The client calls the SSPI InitializeSecurityContext function
     * to obtain an authentication request token. The client sends this token to the server.
     */
    context_req_fl = 0;
#if 0
    context_req_fl = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION;
#endif
    sec_status = security_ft->InitializeSecurityContextW(
        &(sspi->handle),
        buf_in_data ? &(sspi->ctx) : NULL,
        sspi->cctx->target_name,
        context_req_fl,
        0,
        0,
        buf_in_data ? &buf_in_desc : NULL,
        0,
        &(sspi->ctx),
        &buf_out_desc,
        &attrs,
        &tsDummy);

    sspi->initialized = 1;

    /* Check for completion */
    if (sec_status == SEC_I_COMPLETE_AND_CONTINUE || sec_status == SEC_I_COMPLETE_NEEDED /*||
        sec_status == SEC_I_CONTINUE_NEEDED */) {
            if (security_ft->CompleteAuthToken) {
                SECURITY_STATUS tmp_sec_status;

                tmp_sec_status = (security_ft->CompleteAuthToken)(&(sspi->ctx), &buf_out_desc);
                AUXL4("CompleteAuthToken: sec_status = 0x%lx (%s)", (unsigned long) tmp_sec_status, get_sspi_str_status(sec_status));
                (void)tmp_sec_status;
            }
            if (sec_status == SEC_I_COMPLETE_NEEDED)
                sec_status = SEC_E_OK;
            else if (sec_status == SEC_I_COMPLETE_AND_CONTINUE)
                sec_status = SEC_I_CONTINUE_NEEDED;
    }

    AUXL4("InitializeSecurityContext: target_name:%ls, context_req_fl:0x%lx, IN:%lu bytes%s, OUT:%lu bytes, ret = 0x%lx (%s)",
            sspi->cctx->target_name,
            (unsigned long) context_req_fl,
            (unsigned long) (buf_in_data ? buf_in_data_len : 0),
            buf_in_data ? "" : " (null)",
            (unsigned long) buf_out.cbBuffer,
            (unsigned long) sec_status, get_sspi_str_status(sec_status));

    if (sec_status == SEC_E_LOGON_DENIED) {
        *logon_required = 1;
        ret = 0;
        goto out;
    }

    if (sec_status == SEC_E_INVALID_HANDLE) {
        NETLOG("%s: InitializeSecurityContext ret sec_status 0x%lx (%s). Reconnect ?",
                __FUNCTION__, (unsigned long) sec_status,
                get_sspi_str_status(sec_status));
        *needs_reconnect = 1;
        ret = 0;
        goto out;
    }

    if (sec_status != SEC_E_OK && sec_status != SEC_I_CONTINUE_NEEDED) {
        NETLOG("%s: InitializeSecurityContext error, sec_status is 0x%lx (%s)", __FUNCTION__,
                (unsigned long) sec_status, get_sspi_str_status(sec_status));
        goto out;
    }

    *buf_out_data_len = buf_out.cbBuffer;
    ret = 0;
out:
    return ret;
}
