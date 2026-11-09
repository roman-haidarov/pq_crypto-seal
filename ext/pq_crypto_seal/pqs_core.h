#ifndef PQS_CORE_H
#define PQS_CORE_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "aegis.h"

#define PQS_KEY_BYTES         32U
#define PQS_NONCE_BYTES       32U
#define PQS_TAG_BYTES         32U
#define PQS_SHA256_BYTES      32U
#define PQS_HKDF_MAX_OUTPUT   ((size_t)255U * PQS_SHA256_BYTES)
#define PQS_RANDOM_CHUNK_SIZE 0x7fffffffU

typedef enum {
    PQS_OK = 0,
    PQS_ERR_ARGUMENT = -1,
    PQS_ERR_CRYPTO = -2,
    PQS_ERR_AUTH = -3,
    PQS_ERR_BUSY = -4,
    PQS_ERR_UNINITIALIZED = -5,
    PQS_ERR_FINALIZED = -6,
    PQS_ERR_WRONG_MODE = -7
} pqs_status;

typedef enum { PQS_MODE_NONE = 0, PQS_MODE_ENCRYPT = 1, PQS_MODE_DECRYPT = 2 } pqs_mode;

typedef enum { PQS_PHASE_EMPTY = 0, PQS_PHASE_ACTIVE = 1, PQS_PHASE_FINALIZED = 2 } pqs_phase;

typedef struct {
    uint8_t key[PQS_KEY_BYTES];
    uint8_t nonce[PQS_NONCE_BYTES];
    uint8_t tag[PQS_TAG_BYTES];
    const uint8_t *ad;
    size_t ad_len;
    const uint8_t *input;
    size_t input_len;
    uint8_t *output;
    pqs_status status;
} pqs_aead_job;

typedef struct {
    aegis256_state state;
    atomic_bool busy;
    pqs_mode mode;
    pqs_phase phase;
} pqs_stream;

typedef struct {
    pqs_stream *stream;
    const uint8_t *input;
    uint8_t *output;
    size_t len;
    pqs_status status;
} pqs_update_job;

void pqs_wipe(void *buffer, size_t len);
pqs_status pqs_copy(uint8_t *restrict dst, size_t dst_len, const uint8_t *restrict src,
                    size_t src_len);
int pqs_equal(const uint8_t *left, const uint8_t *right, size_t len);

pqs_status pqs_random(uint8_t *output, size_t len);
pqs_status pqs_sha256(uint8_t output[PQS_SHA256_BYTES], const uint8_t *input, size_t len);
pqs_status pqs_hkdf_sha256(uint8_t *okm, size_t okm_len, const uint8_t *ikm, size_t ikm_len,
                           const uint8_t *info, size_t info_len);

void pqs_aead_job_wipe(pqs_aead_job *job);
void *pqs_aead_seal(void *job);
void *pqs_aead_open(void *job);

void pqs_stream_init_storage(pqs_stream *stream);
void pqs_stream_wipe(pqs_stream *stream);
pqs_status pqs_stream_acquire(pqs_stream *stream);
void pqs_stream_release(pqs_stream *stream);
pqs_status pqs_stream_start(pqs_stream *stream, pqs_mode mode, const uint8_t *key,
                            const uint8_t *nonce, const uint8_t *ad, size_t ad_len);
pqs_status pqs_stream_check_update(const pqs_stream *stream);
void pqs_stream_finish(pqs_stream *stream);
void *pqs_stream_update(void *job);
pqs_status pqs_stream_encrypt_final(pqs_stream *stream, uint8_t tag[PQS_TAG_BYTES]);
pqs_status pqs_stream_decrypt_final(pqs_stream *stream, const uint8_t tag[PQS_TAG_BYTES]);

#endif
