/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <nickel.h>
#include <log.h>
#include "proxy.h"
#include "auth.h"
#include "ntlm.h"

#if defined(_WIN32)
#include <windows.h>
#define SECURITY_WIN32 1
#include <wincrypt.h>
#elif defined(__APPLE__)
#import <CommonCrypto/CommonDigest.h>
#endif

#ifdef WORDS_BIGENDIAN
#error BIGENDIAN not supported at the moment
#endif

/*
 * code based on CHROME's http/http_auth_handler_ntlm_portable.cc
 * plus added NTLMv2 code according to http://davenport.sourceforge.net/ntlm.htm specs
 */

// Byte order swapping.
#define SWAP16(x) ((((x) & 0xff) << 8) | (((x) >> 8) & 0xff))
#define SWAP32(x) ((SWAP16((x) & 0xffff) << 16) | (SWAP16((x) >> 16)))

enum {
  NTLM_NegotiateUnicode             = 0x00000001,
  NTLM_NegotiateOEM                 = 0x00000002,
  NTLM_RequestTarget                = 0x00000004,
  NTLM_Unknown1                     = 0x00000008,
  NTLM_NegotiateSign                = 0x00000010,
  NTLM_NegotiateSeal                = 0x00000020,
  NTLM_NegotiateDatagramStyle       = 0x00000040,
  NTLM_NegotiateLanManagerKey       = 0x00000080,
  NTLM_NegotiateNetware             = 0x00000100,
  NTLM_NegotiateNTLMKey             = 0x00000200,
  NTLM_Unknown2                     = 0x00000400,
  NTLM_Unknown3                     = 0x00000800,
  NTLM_NegotiateDomainSupplied      = 0x00001000,
  NTLM_NegotiateWorkstationSupplied = 0x00002000,
  NTLM_NegotiateLocalCall           = 0x00004000,
  NTLM_NegotiateAlwaysSign          = 0x00008000,
  NTLM_TargetTypeDomain             = 0x00010000,
  NTLM_TargetTypeServer             = 0x00020000,
  NTLM_TargetTypeShare              = 0x00040000,
  NTLM_NegotiateNTLM2Key            = 0x00080000,
  NTLM_RequestInitResponse          = 0x00100000,
  NTLM_RequestAcceptResponse        = 0x00200000,
  NTLM_RequestNonNTSessionKey       = 0x00400000,
  NTLM_NegotiateTargetInfo          = 0x00800000,
  NTLM_Unknown4                     = 0x01000000,
  NTLM_Unknown5                     = 0x02000000,
  NTLM_Unknown6                     = 0x04000000,
  NTLM_Unknown7                     = 0x08000000,
  NTLM_Unknown8                     = 0x10000000,
  NTLM_Negotiate128                 = 0x20000000,
  NTLM_NegotiateKeyExchange         = 0x40000000,
  NTLM_Negotiate56                  = 0x80000000
};

// We send these flags with our type 1 message.
enum {
  NTLM_TYPE1_FLAGS = (NTLM_NegotiateUnicode |
                      NTLM_NegotiateOEM |
                      NTLM_RequestTarget |
                      NTLM_NegotiateNTLMKey |
                      NTLM_NegotiateAlwaysSign |
                      NTLM_NegotiateNTLM2Key |
                      NTLM_NegotiateTargetInfo)
};

static const char NTLM_SIGNATURE[] = "NTLMSSP";
static const char NTLM_TYPE1_MARKER[] = { 0x01, 0x00, 0x00, 0x00 };
static const char NTLM_TYPE2_MARKER[] = { 0x02, 0x00, 0x00, 0x00 };
static const char NTLM_TYPE3_MARKER[] = { 0x03, 0x00, 0x00, 0x00 };

enum {
  NTLM_TYPE1_HEADER_LEN = 32,
  NTLM_TYPE2_HEADER_LEN = 32,
  NTLM_TYPE3_HEADER_LEN = 64,

  LM_HASH_LEN = 16,
  LM_RESP_LEN = 24,

  NTLM_HASH_LEN = 16,
  NTLM_RESP_LEN = 24
};

struct type2_msg {
    uint32_t flags;              // NTLM_Xxx bitwise combination
    uint8_t challenge[8];        // 8 byte challenge
    const uint8_t *target;       // target string (type depends on flags)
    uint32_t target_len;         // target length in bytes
    const uint8_t *info;         // targen info
    uint32_t info_len;           // target info length in bytes
};

static int md5(const uint8_t *buf, size_t len, uint8_t *hash16)
{
#if defined(_WIN32)
    int ret = -1;
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hCryptHash;
    DWORD md5HashLen = 16;

    assert(hash16);
    memset(hash16, 0, md5HashLen);
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        NETLOG("%s: CryptAcquireContext failed %u", __FUNCTION__,
                (unsigned int) GetLastError());
        goto out;
    }

    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hCryptHash)) {
        NETLOG("%s: CryptCreateHash failed %u", __FUNCTION__,
                (unsigned int) GetLastError());
        CryptReleaseContext(hCryptProv, 0);
        goto out;
    }

    CryptHashData(hCryptHash, buf, len, 0);
    CryptGetHashParam(hCryptHash, HP_HASHVAL, hash16, &md5HashLen, 0);

    CryptDestroyHash(hCryptHash);
    CryptReleaseContext(hCryptProv, 0);
    ret = 0;
out:
    return ret;
#elif defined(__APPLE__)
    CC_MD5(buf, len, hash16);
    return 0;
#endif
}


#if defined(_WIN32)
// Set odd parity bit (in least significant bit position).
static uint8_t des_set_key_parity(uint8_t x)
{
    if ((((x >> 7) ^ (x >> 6) ^ (x >> 5) ^
        (x >> 4) ^ (x >> 3) ^ (x >> 2) ^
        (x >> 1)) & 0x01) == 0) {

        x |= 0x01;
    } else {
        x &= 0xfe;
    }

    return x;
}

static void des_make_key(const uint8_t *raw, uint8_t *key)
{
    key[0] = des_set_key_parity(raw[0]);
    key[1] = des_set_key_parity((raw[0] << 7) | (raw[1] >> 1));
    key[2] = des_set_key_parity((raw[1] << 6) | (raw[2] >> 2));
    key[3] = des_set_key_parity((raw[2] << 5) | (raw[3] >> 3));
    key[4] = des_set_key_parity((raw[3] << 4) | (raw[4] >> 4));
    key[5] = des_set_key_parity((raw[4] << 3) | (raw[5] >> 5));
    key[6] = des_set_key_parity((raw[5] << 2) | (raw[6] >> 6));
    key[7] = des_set_key_parity((raw[6] << 1));
}

struct KeyBlob {
    BLOBHEADER header;
    DWORD key_size;
    BYTE key_data[8];
};

static int des_encrypt(const uint8_t *key, const uint8_t *src, uint8_t *hash)
{
    int ret = -1;
    BOOL ok;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY h_key;
    struct KeyBlob key_blob;
    DWORD cipher_mode = CRYPT_MODE_ECB;
    DWORD hash_len = 8;

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        NETLOG("%s: CryptAcquireContext failed %u", __FUNCTION__,
                (unsigned int) GetLastError());
        goto out;
    }

    key_blob.header.bType = PLAINTEXTKEYBLOB;
    key_blob.header.bVersion = CUR_BLOB_VERSION;
    key_blob.header.reserved = 0;
    key_blob.header.aiKeyAlg = CALG_DES;
    key_blob.key_size = 8;  // 64 bits
    memcpy(key_blob.key_data, key, 8);

    ok = CryptImportKey(hCryptProv, (BYTE *) (&key_blob), sizeof(key_blob), 0, 0, &h_key);
    // Destroy the copy of the key.
    SecureZeroMemory(key_blob.key_data, sizeof(key_blob.key_data));
    if (!ok) {
        NETLOG("%s: CryptImportKey failed %u", __FUNCTION__,
                (unsigned int) GetLastError());
        goto out;
    }

    // No initialization vector required.
    if (!CryptSetKeyParam(h_key, KP_MODE, (BYTE *)(&cipher_mode), 0)) {
        NETLOG("%s: CryptSetKeyParam failed %u", __FUNCTION__,
                (unsigned int) GetLastError());
        goto out;
    }

    // CryptoAPI requires us to copy the plaintext to the output buffer first.
    CopyMemory(hash, src, 8);
    // Pass a 'Final' of FALSE, otherwise CryptEncrypt appends one additional
    // block of padding to the data.
    CryptEncrypt(h_key, 0, FALSE, 0, hash, &hash_len, 8);

    CryptDestroyKey(h_key);
    CryptReleaseContext(hCryptProv, 0);
    ret = 0;
out:
    return ret;
}
#endif


static uint16_t read_uint16t(const uint8_t **buf) {
    uint16_t x;

    x = ((uint16_t) ((*buf)[0])) | (((uint16_t) ((*buf)[1])) << 8);

    *buf += sizeof(x);
    return x;
}

static uint32_t read_uint32t(const uint8_t **buf) {
    uint32_t x;
    x = ((uint32_t) ((*buf)[0]))            |
        (((uint32_t) ((*buf)[1])) << 8)     |
        (((uint32_t) ((*buf)[2])) << 16)    |
        (((uint32_t) ((*buf)[3])) << 24);

    *buf += sizeof(x);
    return x;
}


static uint8_t *
write_bytes(uint8_t *buf, const uint8_t *data, size_t data_len)
{

    if (data_len)
        memcpy(buf, data, data_len);
    return buf + data_len;
}

static uint8_t *
write_DWORD(uint8_t *buf, uint32_t dword)
{

#ifdef WORDS_BIGENDIAN
  // NTLM uses little endian on the wire.
  dword = SWAP32(dword);
#endif

  return write_bytes(buf, (const uint8_t *)&dword, sizeof(dword));
}

static uint8_t *
write_sec_buf(uint8_t *buf, uint16_t length, uint32_t offset)
{
#ifdef WORDS_BIGENDIAN
    length = SWAP16(length);
    offset = SWAP32(offset);
#endif
    // Len: 2 bytes.
    buf = write_bytes(buf, (const uint8_t *) &length, sizeof(length));
    // MaxLen: 2 bytes. The sender should set it to the value of Len. The
    // recipient must ignore it.
    buf = write_bytes(buf, (const uint8_t *) &length, sizeof(length));
    // BufferOffset: 4 bytes.
    buf = write_bytes(buf, (const uint8_t *) &offset, sizeof(offset));

    return buf;
}

#if defined(_WIN32)
// lm_response generates the LM response given a 16-byte password hash and the
// challenge from the Type-2 message.
//
// param hash
//       16-byte password hash
// param challenge
//       8-byte challenge from Type-2 message
// param response
//       24-byte buffer to contain the LM response upon return
static int lm_response(const uint8_t *hash, const uint8_t *challenge, uint8_t *response)
{
    uint8_t keybytes[21], k1[8], k2[8], k3[8];

    memcpy(keybytes, hash, 16);
    memset(keybytes + 16, 0, 5);

    des_make_key(keybytes     , k1);
    des_make_key(keybytes +  7, k2);
    des_make_key(keybytes + 14, k3);

    des_encrypt(k1, challenge, response);
    des_encrypt(k2, challenge, response + 8);
    des_encrypt(k3, challenge, response + 16);

    return 0;
}
#endif

static int
hmac_md5_ntlm(const uint8_t *in_hash, const uint8_t *data, size_t data_len, uint8_t *out_hash)
{
    int ret = -1;
    uint8_t *content = NULL, hash[16];
    uint8_t b_key[64], i_pad[64], o_pad[64];
    int i;

    memset(i_pad, 0x36, sizeof(i_pad));
    memset(o_pad, 0x5c, sizeof(o_pad));
    memset(b_key, 0, sizeof(b_key));
    memcpy(b_key, in_hash, 16);

    for (i = 0; i < 64; i++) {
        i_pad[i] ^= b_key[i];
        o_pad[i] ^= b_key[i];
    }

    content = calloc(1, 64 + 16 + data_len);
    if (!content)
        goto mem_err;

    memcpy(content, i_pad, 64);
    memcpy(content + 64, data, data_len);
    if (md5(content, 64 + data_len, hash) < 0) {
        NETLOG("%s: md5 ERROR", __FUNCTION__);
        goto err;
    }
    memcpy(content, o_pad, 64);
    memcpy(content + 64, hash, 16);
    if (md5(content, 64 + 16, out_hash) < 0) {
        NETLOG("%s: md5 ERROR (2)", __FUNCTION__);
        goto err;
    }

    ret = 0;
out:
    free(content);
    return ret;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
err:
    ret = -1;
    goto out;
}

static int parse_type2_msg(struct ntlm_ctx *ntlm, uint8_t *in_token,
        size_t in_len, struct type2_msg *msg)
{
    int ret = -1;
    const uint8_t *cursor = (const uint8_t *) in_token;
    uint32_t blen, offset;

    // Make sure in_buf is long enough to contain a meaningful type2 msg.
    //
    // 0  NTLMSSP Signature
    // 8  NTLM Message Type
    // 12 Target Name
    // 20 Flags
    // 24 Challenge
    // 32 end of header, start of optional data blocks
    //

    assert(in_token && in_len);
    if (in_len < NTLM_TYPE2_HEADER_LEN) {
        NETLOG("%s:  wrong type 2 NTLM message len %lu", __FUNCTION__,
                (unsigned long) in_len);
        goto out;
    }

    // verify NTLMSSP signature
    if (memcmp(cursor, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE)) != 0) {
        NETLOG("%s: wrong type 2 NTLM signature", __FUNCTION__);
        goto out;
    }
    cursor += sizeof(NTLM_SIGNATURE);

    // verify Type-2 marker
    if (memcmp(cursor, NTLM_TYPE2_MARKER, sizeof(NTLM_TYPE2_MARKER)) != 0) {
        NETLOG("%s: wrong type 2 NTLM marker", __FUNCTION__);
        goto out;
    }
    cursor += sizeof(NTLM_TYPE2_MARKER);

    // read target name security buffer
    blen = read_uint16t(&cursor);
    read_uint16t(&cursor);  // discard next 16-bit value
    offset = read_uint32t(&cursor);  // get offset from in_buf
    msg->target_len = 0;
    msg->target = NULL;
    // Check the offset / length combo is in range of the input buffer, including
    // integer overflow checking.
    if (offset + blen > offset && offset + blen <= in_len) {
        msg->target_len = blen;
        msg->target = ((const uint8_t *) in_token) + offset;
    }

    // read flags
    msg->flags = read_uint32t(&cursor);

    // read challenge
    memcpy(msg->challenge, cursor, sizeof(msg->challenge));
    cursor += sizeof(msg->challenge);

    assert(cursor - in_token <= NTLM_TYPE2_HEADER_LEN);
    if ((msg->flags & NTLM_NegotiateTargetInfo) && in_len > NTLM_TYPE2_HEADER_LEN + 8) {
        // (32) Context (optional) 8 bytes (two consecutive longs)
        read_uint32t(&cursor);
        read_uint32t(&cursor);

        // (40) Target Information (optional) security buffer Length, Allocated Space, Offset
        blen = read_uint16t(&cursor);
        read_uint16t(&cursor);
        offset = read_uint32t(&cursor);

        if (offset + blen > offset && offset + blen <= in_len) {
            msg->info_len = blen;
            msg->info = ((const uint8_t *) in_token) + offset;
        }
    }

    if (NLOG_LEVEL > 4) {
        NETLOG5("%s: NTLM type 2 message, challenge (and info), flags 0x%x", __FUNCTION__,
                (unsigned int) msg->flags);
        netlog_print_esc("target", (const char *)msg->target, msg->target_len);
        netlog_print_esc("challenge", (const char *)msg->challenge, sizeof(msg->challenge));
        if (msg->info && msg->info_len)
            netlog_print_esc("info", (const char *)msg->info, msg->info_len);
    }

    ret = 0;
out:
    return ret;
}

static int generate_type1_msg(struct ntlm_ctx *ntlm, uint8_t **out_token, size_t *out_len)
{
    int ret = -1;
    uint8_t *cursor;

    *out_token = calloc(1, NTLM_TYPE1_HEADER_LEN);
    if (!*out_token) {
        warnx("%s: malloc", __FUNCTION__);
        goto out;
    }
    *out_len = NTLM_TYPE1_HEADER_LEN;

    //
    // Write out type 1 message.
    //
    cursor = *out_token;

    // 0 : signature
    cursor = write_bytes(cursor, (const uint8_t *)NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));

    // 8 : marker
    cursor = write_bytes(cursor, (const uint8_t *)NTLM_TYPE1_MARKER, sizeof(NTLM_TYPE1_MARKER));

    // 12 : flags
    cursor = write_DWORD(cursor, NTLM_TYPE1_FLAGS);

#if 0
    // 16 : supplied domain security buffer (empty)
    cursor = write_sec_buf(cursor, 0, 0);

    // 24 : supplied workstation security buffer (empty)
    cursor = write_sec_buf(cursor, 0, 0);
#endif

    ret = 0;
out:
    return ret;
}

static int generate_type3_msg(struct ntlm_ctx *ntlm, uint8_t *in_token, size_t in_len,
        uint8_t **out_token, size_t *out_len)
{
    int ret = -1;
    struct type2_msg msg;
    bool unicode = false;
    uint8_t lm_resp[LM_RESP_LEN];
    uint8_t ntlm_resp[NTLM_RESP_LEN];
    uint8_t *ntlmv2_buf = NULL;
    size_t ntlm_buf_len = NTLM_RESP_LEN;
    uint8_t *cursor;
    uint32_t offset;
    const uint8_t *domain_ptr;
    const uint8_t *user_ptr;
    const uint8_t *host_ptr;
    uint32_t domain_len = 0, user_len = 0, host_len = 0;
    uint8_t w_hostname[256 * 2 + 2];
    uint8_t rand_8_bytes[8];
    bool use_ntlmv2 = false;

    assert(in_token && in_len);

    memset(&msg, 0, sizeof(msg));
    if (parse_type2_msg(ntlm, in_token, in_len, &msg) < 0)
        goto out;

    if (in_len) {
        size_t l;

        l = sizeof(rand_8_bytes);
        if (l > in_len)
            l = in_len;
        memcpy(rand_8_bytes, in_token, l);
    }
    if (generate_random_bytes(rand_8_bytes, sizeof(rand_8_bytes)) < 0) {
#if defined(_WIN32)
        NETLOG5("%s: error on generate_random_bytes %u", __FUNCTION__,
                (unsigned int) GetLastError());
#else
        NETLOG5("%s: error on generate_random_bytes %d", __FUNCTION__, errno);
#endif
        goto err;
    }
    unicode = (msg.flags & NTLM_NegotiateUnicode) != 0;

    //
    // Get domain name.
    //
    if (ntlm->w_domain && ntlm->w_domain_len) {
        if (unicode) {
            domain_ptr = ntlm->w_domain;
            domain_len = ntlm->w_domain_len;
        } else {
            domain_ptr = ntlm->domain;
            domain_len = strlen((char *)ntlm->domain);
        }
    }

    //
    // Get user name.
    //
    if (unicode) {
        user_ptr = ntlm->w_username;
        user_len = ntlm->w_username_len;
    } else {
        user_ptr = ntlm->username;
        user_len = strlen((char *)ntlm->username);
    }

    //
    // Get workstation name (use local machine's hostname).
    //
    if (unicode) {
        unsigned int i;

        memset(w_hostname, 0, sizeof(w_hostname));
        assert(sizeof(ntlm->hostname) <= 256);
        for (i = 0; i < sizeof(ntlm->hostname); i++) {
            if (!ntlm->hostname[i] || i * 2 >= sizeof(w_hostname))
                break;
            w_hostname[i * 2] = ntlm->hostname[i];
        }
        host_ptr = w_hostname;
        host_len = i * 2;
    } else {
        host_ptr = ntlm->hostname;
        host_len = strlen((char *)ntlm->hostname);
    }

    // NTLMv2
    if ((msg.flags & NTLM_NegotiateTargetInfo) && msg.info && msg.info_len) {
        size_t i, j, max_v2_len;
        uint8_t hash1[16], hash2[16];
        int64_t now_ns;

        memset(lm_resp, 0, sizeof(lm_resp));

        max_v2_len = 16 + 28 + msg.info_len;
        // HMAC(passwordHash, uppercase(userName | domain))
        j = ntlm->w_username_len;
        if (ntlm->w_domain)
            j += ntlm->w_domain_len;

        if (max_v2_len < j)
            max_v2_len = j;

        ntlmv2_buf = calloc(1, max_v2_len + 2);
        if (!ntlmv2_buf)
            goto mem_err;

        // XXX: How do we do this in wchar?
        for (int i = 0; i < ntlm->w_username_len; i++) {
            ntlmv2_buf[i] = toupper(ntlm->w_username[i]);
        }

        if (ntlm->w_domain)
            memcpy(ntlmv2_buf + ntlm->w_username_len, ntlm->w_domain, ntlm->w_domain_len);

        if (hmac_md5_ntlm(ntlm->ntlm_hash, ntlmv2_buf, j, hash1) < 0)
            goto err;

        // LMv2
        {
            uint8_t lm_hash[16];

            memcpy(lm_resp, msg.challenge, 8);
            memcpy(lm_resp + 8, rand_8_bytes, 8);
            if (hmac_md5_ntlm(hash1, lm_resp, 8 + 8, lm_hash) < 0)
                goto err;
            memcpy(lm_resp, lm_hash, 16);
            memcpy(lm_resp + 16, rand_8_bytes, 8);
        }

        // NTLMv2 blob
        memset(ntlmv2_buf, 0, max_v2_len);
        i = 16;

        // 0 Blob Signature 0x01010000
        ntlmv2_buf[i++] = 0x01;
        ntlmv2_buf[i++] = 0x01;
        ntlmv2_buf[i++] = 0x00;
        ntlmv2_buf[i++] = 0x00;

        // 4 Reserved long (0x00000000)
        i += 4;

        // 8 Timestamp Little-endian, 64-bit signed value number of tenths of a microsecond
        // since January 1, 1601.
        now_ns = ni_get_pcap_ts(NULL, NULL);
        now_ns /= 100LL; // ns -> 0.1us
        now_ns += 116444736000000000LL; // 1601 -> 1970
        for (j = 0; j < 8; j++) {
            ntlmv2_buf[i++] = (uint8_t) (now_ns & 0xff);
            now_ns >>= 8;
        }

        // 16 Client Nonce 8 bytes
        memcpy(ntlmv2_buf + i, rand_8_bytes, 8);
        i += 8;

        // 24 Unknown 4 bytes (zeroes)
        i += 4;

        // 28 Target Information Target Information block (from the Type 2 message).
        memcpy(ntlmv2_buf + i, msg.info, msg.info_len);
        i += msg.info_len;

        assert(sizeof(msg.challenge) == 8);
        memcpy(ntlmv2_buf + 8, msg.challenge, 8);
        if (hmac_md5_ntlm(hash1, ntlmv2_buf + 8, i - 8, hash2) < 0)
            goto err;

        memcpy(ntlmv2_buf, hash2, 16);

        ntlm_buf_len = i;
        use_ntlmv2 = true;
        if (NLOG_LEVEL > 4)
            netlog_print_esc("ntlmv2_buf for hash2", (const char *)ntlmv2_buf, ntlm_buf_len);
    } else {
#if defined(_WIN32)
        // NTLMv1
        ntlm_buf_len = NTLM_RESP_LEN;
        if ((msg.flags & NTLM_NegotiateNTLM2Key)) {
            uint8_t temp[16];
            uint8_t session_hash[16];

            memcpy(lm_resp, rand_8_bytes, 8);
            memset(lm_resp + 8, 0, LM_RESP_LEN - 8);

            memcpy(temp, msg.challenge, 8);
            memcpy(temp + 8, lm_resp, 8);
            if (md5(temp, 16, session_hash) < 0) {
                NETLOG("%s: md5 error", __FUNCTION__);
                goto err;
            }

            lm_response(ntlm->ntlm_hash, session_hash, ntlm_resp);
        } else {
            lm_response(ntlm->ntlm_hash, msg.challenge, ntlm_resp);

            // According to http://davenport.sourceforge.net/ntlm.html#ntlmVersion2,
            // the correct way to not send the LM hash is to send the NTLM hash twice
            // in both the LM and NTLM response fields.
            lm_response(ntlm->ntlm_hash, msg.challenge, lm_resp);
        }
#else
        NETLOG("%s: NTLMv1 not supported", __FUNCTION__);
        goto err;
#endif
    }

    //
    // Now that we have generated all of the strings, we can allocate out_buf.
    //
    *out_len = NTLM_TYPE3_HEADER_LEN + host_len + domain_len + user_len +
             LM_RESP_LEN + ntlm_buf_len;
    *out_token = calloc(1, *out_len);
    if (!*out_token)
        goto mem_err;

    //
    // Finally, we assemble the Type-3 msg :-)
    //
    cursor = *out_token;

    // 0 : signature
    cursor = write_bytes(cursor, (uint8_t *) NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));

    // 8 : marker
    cursor = write_bytes(cursor, (uint8_t *) NTLM_TYPE3_MARKER, sizeof(NTLM_TYPE3_MARKER));

    // 12 : LM response sec buf
    offset = NTLM_TYPE3_HEADER_LEN + domain_len + user_len + host_len;
    cursor = write_sec_buf(cursor, LM_RESP_LEN, offset);
    memcpy((*out_token) + offset, lm_resp, LM_RESP_LEN);

    // 20 : NTLM response sec buf
    offset += LM_RESP_LEN;

    if (use_ntlmv2) {
        cursor = write_sec_buf(cursor, ntlm_buf_len, offset);
        memcpy((*out_token) + offset, ntlmv2_buf, ntlm_buf_len);
    } else {
        cursor = write_sec_buf(cursor, NTLM_RESP_LEN, offset);
        memcpy((*out_token) + offset, ntlm_resp, NTLM_RESP_LEN);
    }

    // 28 : domain name sec buf
    offset = NTLM_TYPE3_HEADER_LEN;
    cursor = write_sec_buf(cursor, domain_len, offset);
    if (domain_len)
        memcpy((*out_token) + offset, domain_ptr, domain_len);

    // 36 : user name sec buf
    offset += domain_len;
    cursor = write_sec_buf(cursor, user_len, offset);
    memcpy((*out_token) + offset, user_ptr, user_len);

    // 44 : workstation (host) name sec buf
    offset += user_len;
    cursor = write_sec_buf(cursor, host_len, offset);
    memcpy((*out_token) + offset, host_ptr, host_len);

    // 52 : session key sec buf (not used)
    cursor = write_sec_buf(cursor, 0, 0);

    // 60 : negotiated flags
    cursor = write_DWORD(cursor, msg.flags & NTLM_TYPE1_FLAGS);

    ret = 0;
out:
    free(ntlmv2_buf);
    return ret;
mem_err:
    warnx("%s: malloc", __FUNCTION__);
err:
    ret = -1;
    goto out;
}

int ntlm_get_next_token(struct ntlm_ctx *ntlm, uint8_t *in_token, size_t in_len,
        uint8_t **out_token, size_t *out_len)
{
    int ret = -1;

    if (!in_token)
        ret = generate_type1_msg(ntlm, out_token, out_len);
    else
        ret = generate_type3_msg(ntlm, in_token, in_len, out_token, out_len);

    return ret;
}
