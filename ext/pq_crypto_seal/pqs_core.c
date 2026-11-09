#include "pqs_core.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

typedef struct {
    const uint8_t *data;
    size_t len;
} pqs_span;

static void pqs_zero(uint8_t *buffer, size_t len) {
    for (size_t index = 0; index < len; index++)
        buffer[index] = 0;
}

void pqs_wipe(void *buffer, size_t len) {
    if (buffer != NULL && len != 0)
        OPENSSL_cleanse(buffer, len);
}

pqs_status pqs_copy(uint8_t *restrict dst, size_t dst_len, const uint8_t *restrict src,
                    size_t src_len) {
    if (src_len > dst_len)
        return PQS_ERR_ARGUMENT;
    if (src_len == 0)
        return PQS_OK;
    if (dst == NULL || src == NULL)
        return PQS_ERR_ARGUMENT;
    for (size_t index = 0; index < src_len; index++)
        dst[index] = src[index];
    return PQS_OK;
}

int pqs_equal(const uint8_t *left, const uint8_t *right, size_t len) {
    if (len == 0)
        return 1;
    if (left == NULL || right == NULL)
        return 0;
    return CRYPTO_memcmp(left, right, len) == 0;
}

pqs_status pqs_random(uint8_t *output, size_t len) {
    size_t offset = 0;

    if (len != 0 && output == NULL)
        return PQS_ERR_ARGUMENT;
    pqs_zero(output, len);
    while (offset < len) {
        size_t remaining = len - offset;
        int chunk = (int)(remaining > PQS_RANDOM_CHUNK_SIZE ? PQS_RANDOM_CHUNK_SIZE : remaining);
        if (RAND_bytes(output + offset, chunk) != 1) {
            pqs_wipe(output, len);
            return PQS_ERR_CRYPTO;
        }
        offset += (size_t)chunk;
    }
    return PQS_OK;
}

pqs_status pqs_sha256(uint8_t output[PQS_SHA256_BYTES], const uint8_t *input, size_t len) {
    uint8_t digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_len = 0;
    pqs_status status = PQS_ERR_CRYPTO;

    if (output == NULL || (len != 0 && input == NULL))
        return PQS_ERR_ARGUMENT;
    if (EVP_Digest(input, len, digest, &digest_len, EVP_sha256(), NULL) == 1 &&
        digest_len == PQS_SHA256_BYTES)
        status = pqs_copy(output, PQS_SHA256_BYTES, digest, PQS_SHA256_BYTES);
    pqs_wipe(digest, sizeof(digest));
    return status;
}

static int pqs_mac_update_spans(EVP_MAC_CTX *ctx, const pqs_span *spans, size_t count) {
    for (size_t index = 0; index < count; index++) {
        if (spans[index].len != 0 && EVP_MAC_update(ctx, spans[index].data, spans[index].len) != 1)
            return 0;
    }
    return 1;
}

static pqs_status pqs_hmac_sha256(EVP_MAC *mac, uint8_t output[PQS_SHA256_BYTES],
                                  const uint8_t key[PQS_SHA256_BYTES], const pqs_span *spans,
                                  size_t count) {
    char digest_name[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
                           OSSL_PARAM_construct_end()};
    uint8_t block[PQS_SHA256_BYTES] = {0};
    size_t block_len = 0;
    pqs_status status = PQS_ERR_CRYPTO;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);

    if (ctx != NULL && EVP_MAC_init(ctx, key, PQS_SHA256_BYTES, params) == 1 &&
        pqs_mac_update_spans(ctx, spans, count) &&
        EVP_MAC_final(ctx, block, &block_len, sizeof(block)) == 1 && block_len == PQS_SHA256_BYTES)
        status = pqs_copy(output, PQS_SHA256_BYTES, block, PQS_SHA256_BYTES);
    EVP_MAC_CTX_free(ctx);
    pqs_wipe(block, sizeof(block));
    return status;
}

static pqs_status pqs_hkdf_expand(EVP_MAC *mac, uint8_t *okm, size_t okm_len,
                                  const uint8_t prk[PQS_SHA256_BYTES], const uint8_t *info,
                                  size_t info_len) {
    uint8_t block[PQS_SHA256_BYTES] = {0};
    size_t previous_len = 0;
    size_t produced = 0;
    unsigned int counter = 1;
    pqs_status status = PQS_OK;

    while (status == PQS_OK && produced < okm_len) {
        const uint8_t counter_byte = (uint8_t)counter;
        const pqs_span spans[] = {{block, previous_len}, {info, info_len}, {&counter_byte, 1}};
        status = pqs_hmac_sha256(mac, block, prk, spans, sizeof(spans) / sizeof(spans[0]));
        if (status == PQS_OK) {
            size_t take = okm_len - produced < sizeof(block) ? okm_len - produced : sizeof(block);
            status = pqs_copy(okm + produced, okm_len - produced, block, take);
            produced += take;
            previous_len = sizeof(block);
            counter++;
        }
    }
    pqs_wipe(block, sizeof(block));
    return status;
}

pqs_status pqs_hkdf_sha256(uint8_t *okm, size_t okm_len, const uint8_t *ikm, size_t ikm_len,
                           const uint8_t *info, size_t info_len) {
    const uint8_t salt[PQS_SHA256_BYTES] = {0};
    uint8_t prk[PQS_SHA256_BYTES] = {0};
    pqs_status status;
    EVP_MAC *mac;

    if (okm == NULL || okm_len == 0 || okm_len > PQS_HKDF_MAX_OUTPUT)
        return PQS_ERR_ARGUMENT;
    if ((ikm_len != 0 && ikm == NULL) || (info_len != 0 && info == NULL))
        return PQS_ERR_ARGUMENT;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL)
        return PQS_ERR_CRYPTO;
    {
        const pqs_span extract[] = {{ikm, ikm_len}};
        status = pqs_hmac_sha256(mac, prk, salt, extract, 1);
    }
    if (status == PQS_OK)
        status = pqs_hkdf_expand(mac, okm, okm_len, prk, info, info_len);
    EVP_MAC_free(mac);
    pqs_wipe(prk, sizeof(prk));
    if (status != PQS_OK)
        pqs_wipe(okm, okm_len);
    return status;
}

void pqs_aead_job_wipe(pqs_aead_job *job) {
    pqs_wipe(job->key, sizeof(job->key));
    pqs_wipe(job->nonce, sizeof(job->nonce));
    pqs_wipe(job->tag, sizeof(job->tag));
}

void *pqs_aead_seal(void *arg) {
    pqs_aead_job *job = (pqs_aead_job *)arg;
    int rc = aegis256_encrypt_detached(job->output, job->tag, PQS_TAG_BYTES, job->input,
                                       job->input_len, job->ad, job->ad_len, job->nonce, job->key);

    job->status = rc == 0 ? PQS_OK : PQS_ERR_CRYPTO;
    return NULL;
}

void *pqs_aead_open(void *arg) {
    pqs_aead_job *job = (pqs_aead_job *)arg;
    int rc = aegis256_decrypt_detached(job->output, job->input, job->input_len, job->tag,
                                       PQS_TAG_BYTES, job->ad, job->ad_len, job->nonce, job->key);

    job->status = rc == 0 ? PQS_OK : PQS_ERR_AUTH;
    if (job->status != PQS_OK)
        pqs_wipe(job->output, job->input_len);
    return NULL;
}

void pqs_stream_init_storage(pqs_stream *stream) {
    pqs_zero((uint8_t *)&stream->state, sizeof(stream->state));
    atomic_init(&stream->busy, false);
    stream->mode = PQS_MODE_NONE;
    stream->phase = PQS_PHASE_EMPTY;
}

void pqs_stream_wipe(pqs_stream *stream) {
    pqs_wipe(&stream->state, sizeof(stream->state));
    stream->mode = PQS_MODE_NONE;
    stream->phase = PQS_PHASE_EMPTY;
}

pqs_status pqs_stream_acquire(pqs_stream *stream) {
    if (atomic_exchange_explicit(&stream->busy, true, memory_order_acquire))
        return PQS_ERR_BUSY;
    return PQS_OK;
}

void pqs_stream_release(pqs_stream *stream) {
    atomic_store_explicit(&stream->busy, false, memory_order_release);
}

pqs_status pqs_stream_start(pqs_stream *stream, pqs_mode mode, const uint8_t *key,
                            const uint8_t *nonce, const uint8_t *ad, size_t ad_len) {
    if (mode != PQS_MODE_ENCRYPT && mode != PQS_MODE_DECRYPT)
        return PQS_ERR_ARGUMENT;
    if (key == NULL || nonce == NULL || (ad_len != 0 && ad == NULL))
        return PQS_ERR_ARGUMENT;
    aegis256_state_init(&stream->state, ad, ad_len, nonce, key);
    stream->mode = mode;
    stream->phase = PQS_PHASE_ACTIVE;
    return PQS_OK;
}

pqs_status pqs_stream_check_update(const pqs_stream *stream) {
    if (stream->phase == PQS_PHASE_FINALIZED)
        return PQS_ERR_FINALIZED;
    if (stream->phase != PQS_PHASE_ACTIVE)
        return PQS_ERR_UNINITIALIZED;
    return PQS_OK;
}

void *pqs_stream_update(void *arg) {
    pqs_update_job *job = (pqs_update_job *)arg;
    pqs_stream *stream = job->stream;
    int rc = -1;

    if (stream->mode == PQS_MODE_ENCRYPT)
        rc = aegis256_state_encrypt_update(&stream->state, job->output, job->input, job->len);
    else if (stream->mode == PQS_MODE_DECRYPT)
        rc = aegis256_state_decrypt_update(&stream->state, job->output, job->input, job->len);
    job->status = rc == 0 ? PQS_OK : PQS_ERR_CRYPTO;
    return NULL;
}

static pqs_status pqs_stream_check_final(const pqs_stream *stream, pqs_mode mode) {
    if (stream->mode != mode)
        return PQS_ERR_WRONG_MODE;
    return pqs_stream_check_update(stream);
}

void pqs_stream_finish(pqs_stream *stream) {
    pqs_wipe(&stream->state, sizeof(stream->state));
    stream->phase = PQS_PHASE_FINALIZED;
}

pqs_status pqs_stream_encrypt_final(pqs_stream *stream, uint8_t tag[PQS_TAG_BYTES]) {
    pqs_status status = pqs_stream_check_final(stream, PQS_MODE_ENCRYPT);

    if (status != PQS_OK)
        return status;
    pqs_zero(tag, PQS_TAG_BYTES);
    if (aegis256_state_encrypt_final(&stream->state, tag, PQS_TAG_BYTES) != 0)
        status = PQS_ERR_CRYPTO;
    pqs_stream_finish(stream);
    return status;
}

pqs_status pqs_stream_decrypt_final(pqs_stream *stream, const uint8_t tag[PQS_TAG_BYTES]) {
    pqs_status status = pqs_stream_check_final(stream, PQS_MODE_DECRYPT);

    if (status != PQS_OK)
        return status;
    if (aegis256_state_decrypt_final(&stream->state, tag, PQS_TAG_BYTES) != 0)
        status = PQS_ERR_AUTH;
    pqs_stream_finish(stream);
    return status;
}
