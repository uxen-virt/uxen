/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <log.h>
#include <buff.h>
#include "cert.h"

struct hcert_ctx {
    HCERTSTORE hstore;
    PCCERT_CONTEXT ecert;
    PCCERT_CONTEXT *certs;
    size_t ncerts;
    size_t ic;
};

bool hcert_enabled(void)
{
    return true;
}

struct hcert_ctx *
hcert_open_chain(size_t ncerts)
{
    struct hcert_ctx *hcx = NULL;

    hcx = (struct hcert_ctx*) calloc(1, sizeof(*hcx));
    if (!hcx)
        goto mem_err;

    hcx->hstore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (HCRYPTPROV_LEGACY) NULL,
        CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, NULL);
    if (!hcx->hstore) {
        NETLOG2("%s: CertOpenStore err %d", __FUNCTION__, (int) GetLastError());
        goto err;
    }

    hcx->ncerts = ncerts;
    hcx->ic = 0;
    hcx->certs = (PCCERT_CONTEXT*) calloc(1, ncerts * sizeof(*hcx->certs));
    if (!hcx->certs)
        goto mem_err;

out:
    return hcx;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
err:
    if (hcx) {
        free(hcx->certs);
        free(hcx);
    }
    hcx = NULL;
    goto out;
}

int hcert_add_cert(struct hcert_ctx *hcx, uint8_t *cert, size_t len)
{
    int ret = -1;
    BOOL ok;
    PCCERT_CONTEXT pcert_ctx = NULL;
    PCCERT_CONTEXT ecert = NULL;

    if (!hcx || !hcx->hstore || !hcx->ncerts)
        goto out;

    if (hcx->ic >= hcx->ncerts) {
        NETLOG2("%s: bug, too many certs", __FUNCTION__);
        goto out;
    }

    pcert_ctx = CertCreateCertificateContext(X509_ASN_ENCODING, (const BYTE *)cert, (DWORD) len);
    if (!pcert_ctx) {
        NETLOG2("%s: CertCreateCertificateContext error %d", __FUNCTION__, (int) GetLastError());
        goto out;
    }

    ok = CertAddCertificateContextToStore(hcx->hstore, pcert_ctx, CERT_STORE_ADD_ALWAYS,
            hcx->ic ? NULL : &ecert);
    if (ok != TRUE) {
        NETLOG2("%s: CertAddCertificateContextToStore error %d", __FUNCTION__, (int) GetLastError());
        goto cleanup;
    }

    if (ecert)
        hcx->ecert = ecert;

    NETLOG5("%s: adding cert of len %lu", __FUNCTION__, (unsigned long) len);
    hcx->certs[hcx->ic++] = pcert_ctx;
    ret = 0;
out:
    return ret;
cleanup:
    if (pcert_ctx)
        CertFreeCertificateContext(pcert_ctx);
    if (ecert)
        CertFreeCertificateContext(ecert);
    ret = -1;
    goto out;

}

int hcert_get_chain(struct hcert_ctx *hcx, const char *hostname, uint32_t *err_code,
                    uint32_t *policy_code, PCCERT_CHAIN_CONTEXT *chain_context_out,
                    enum cert_type type, bool verify)
{
    int ret = -1;
    BOOL r;
    wchar_t *whostname = NULL;
    CERT_CHAIN_PARA chain_para;
    DWORD chain_flags ;
    PCCERT_CHAIN_CONTEXT chain_context = NULL;
    CERT_CHAIN_POLICY_PARA policy_para;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA extra_policy_para;
    CERT_CHAIN_POLICY_STATUS policy_status;
    static const LPSTR server_usage[] = {
        szOID_PKIX_KP_SERVER_AUTH,
        szOID_SERVER_GATED_CRYPTO,
        szOID_SGC_NETSCAPE
    };
    static const LPSTR client_usage[] = {
        szOID_PKIX_KP_CLIENT_AUTH
    };

    if (err_code) {
        *err_code = CERT_TRUST_IS_NOT_VALID_FOR_USAGE;
    }

    if (policy_code) {
        *policy_code = (uint32_t) TRUST_E_FAIL;
    }

    if (chain_context_out) {
        *chain_context_out = NULL;
    }

    if (!hcx || !hcx->hstore || !hcx->ncerts || !hcx->certs || !hcx->certs[0] || !hcx->ecert) {
         goto out;
    }

    NETLOG5("%s: for %lu certs", __FUNCTION__, (unsigned long) hcx->ic);
    memset(&chain_para, 0, sizeof(chain_para));
    chain_para.cbSize = sizeof(chain_para);
    chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chain_para.RequestedUsage.Usage.cUsageIdentifier = (type == server ? ARRAYSIZE(server_usage) : ARRAYSIZE(client_usage));
    chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = (LPSTR *) (type == server ? server_usage : client_usage);
    chain_flags = CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

    r = CertGetCertificateChain(NULL, hcx->ecert, NULL, hcx->ecert->hCertStore, &chain_para, chain_flags,
            NULL, &chain_context);
    if (!r) {
        NETLOG2("%s: CertGetCertificateChain error %d", __FUNCTION__, (int) GetLastError());
        ret = HCERT_INVALID;
        goto out;
    }

    // If certificate is invalid for usage or caller doesn't want verification then bail out now
    if ((chain_context->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_VALID_FOR_USAGE) ||
        !verify) {
        goto out;
    }

    memset(&extra_policy_para, 0, sizeof(extra_policy_para));
    extra_policy_para.cbSize = sizeof(extra_policy_para);
    extra_policy_para.dwAuthType = (type == server ? AUTHTYPE_SERVER : AUTHTYPE_CLIENT);
    if (hostname)
        whostname = buff_unicode_encode(hostname);
    extra_policy_para.pwszServerName = whostname;
    memset(&policy_para, 0, sizeof(policy_para));
    policy_para.cbSize = sizeof(policy_para);
    policy_para.dwFlags = 0;
    policy_para.pvExtraPolicyPara = &extra_policy_para;
    memset(&policy_status, 0, sizeof(policy_status));
    policy_status.cbSize = sizeof(policy_status);
    r = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain_context,
            &policy_para, &policy_status);
    if (!r) {
        NETLOG2("%s: CertVerifyCertificateChainPolicy error %d", __FUNCTION__, (int) GetLastError());
        ret = HCERT_INVALID;
        goto out;
    }

    if (policy_code) {
        *policy_code = (uint32_t) policy_status.dwError;
    }

out:
    if (chain_context) {
        NETLOG5("%s: chain_context->TrustStatus.dwErrorStatus = 0x%x", __FUNCTION__,
                (unsigned int) chain_context->TrustStatus.dwErrorStatus);

        if (err_code) {
            *err_code = (uint32_t) chain_context->TrustStatus.dwErrorStatus;
        }

        if (chain_context->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_VALID_FOR_USAGE) {
            NETLOG2("%s: not valid for usage %d", __FUNCTION__, type);
            ret = HCERT_INVALID;
        } else if (chain_context->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) {
            NETLOG2("%s: certificate revoked", __FUNCTION__);
            ret = HCRET_REVOKED;
        } else if (chain_context->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
            ret = HCRET_OTHER_ERR;
        } else {
            ret = HCERT_OK;
        }

        if (chain_context_out) {
            *chain_context_out = chain_context;
        } else {
            CertFreeCertificateChain(chain_context);
        }
    }
    if (whostname) {
        free(whostname);
    }
    return ret;
}

void hcert_free(struct hcert_ctx *hcx)
{
    if (!hcx)
        return;

    if (hcx->ic > 0) {
        do {
            hcx->ic--;
            /* this aparently calls CertFreeCertificateContext as well */
            CertDeleteCertificateFromStore(hcx->certs[hcx->ic]);
        } while (hcx->ic);
    }

    if (hcx->ecert)
        CertFreeCertificateContext(hcx->ecert);
    hcx->ecert = NULL;
    CertCloseStore(hcx->hstore, 0);
    free(hcx->certs);
    free(hcx);
}
