#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#include "pqs_core.h"
#include "vendor/libaegis/src/aegis256/aegis256_soft.h"

#define THREADS     8
#define ITERATIONS  200
#define LARGE_BYTES (256U * 1024U)

static atomic_int failures;

#define STRINGIFY_VALUE(value) #value
#define STRINGIFY(value)       STRINGIFY_VALUE(value)

#define CHECK(condition)                                                                        \
    do {                                                                                        \
        if (!(condition)) {                                                                     \
            fputs(__FILE__ ":" STRINGIFY(__LINE__) ": check failed: " #condition "\n", stderr); \
            atomic_fetch_add(&failures, 1);                                                     \
        }                                                                                       \
    } while (0)

static int hex_value(char digit) {
    if (digit >= '0' && digit <= '9')
        return digit - '0';
    if (digit >= 'a' && digit <= 'f')
        return digit - 'a' + 10;
    return -1;
}

static size_t from_hex(uint8_t *output, size_t capacity, const char *hex) {
    size_t len = 0;

    while (hex[0] != '\0' && hex[1] != '\0' && len < capacity) {
        int high = hex_value(hex[0]);
        int low = hex_value(hex[1]);
        if (high < 0 || low < 0)
            abort();
        output[len++] = (uint8_t)((high << 4) | low);
        hex += 2;
    }
    return len;
}

static void fill_pattern(uint8_t *buffer, size_t len, uint8_t seed) {
    for (size_t index = 0; index < len; index++)
        buffer[index] = (uint8_t)(seed + index * 31U);
}

static void test_copy_bounds(void) {
    uint8_t dst[4] = {0};
    const uint8_t src[5] = {1, 2, 3, 4, 5};

    CHECK(pqs_copy(dst, sizeof(dst), src, 4) == PQS_OK);
    CHECK(dst[3] == 4);
    CHECK(pqs_copy(dst, sizeof(dst), src, 5) == PQS_ERR_ARGUMENT);
    CHECK(pqs_copy(NULL, 0, NULL, 0) == PQS_OK);
    CHECK(pqs_copy(NULL, 4, src, 1) == PQS_ERR_ARGUMENT);
    CHECK(pqs_equal(src, dst, sizeof(dst)));
    CHECK(!pqs_equal(src + 1, dst, sizeof(dst)));
    CHECK(pqs_equal(NULL, NULL, 0));
}

static void test_random_and_sha256(void) {
    uint8_t random[64] = {0};
    uint8_t digest[PQS_SHA256_BYTES] = {0};
    uint8_t expected[PQS_SHA256_BYTES] = {0};
    const uint8_t abc[] = {'a', 'b', 'c'};

    CHECK(pqs_random(NULL, 0) == PQS_OK);
    CHECK(pqs_random(NULL, 1) == PQS_ERR_ARGUMENT);
    CHECK(pqs_random(random, sizeof(random)) == PQS_OK);
    from_hex(expected, sizeof(expected),
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(pqs_sha256(digest, abc, sizeof(abc)) == PQS_OK);
    CHECK(pqs_equal(digest, expected, sizeof(digest)));
    CHECK(pqs_sha256(digest, NULL, 0) == PQS_OK);
}

static void test_hkdf(void) {
    uint8_t ikm[22];
    uint8_t okm[42] = {0};
    uint8_t expected[42] = {0};
    static uint8_t large[PQS_HKDF_MAX_OUTPUT + 1];

    for (size_t index = 0; index < sizeof(ikm); index++)
        ikm[index] = 0x0b;
    from_hex(
        expected, sizeof(expected),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    CHECK(pqs_hkdf_sha256(okm, sizeof(okm), ikm, sizeof(ikm), NULL, 0) == PQS_OK);
    CHECK(pqs_equal(okm, expected, sizeof(okm)));
    CHECK(pqs_hkdf_sha256(large, PQS_HKDF_MAX_OUTPUT, ikm, sizeof(ikm), ikm, 3) == PQS_OK);
    CHECK(pqs_hkdf_sha256(large, PQS_HKDF_MAX_OUTPUT + 1, ikm, 1, NULL, 0) == PQS_ERR_ARGUMENT);
    CHECK(pqs_hkdf_sha256(okm, 0, ikm, 1, NULL, 0) == PQS_ERR_ARGUMENT);
    CHECK(pqs_hkdf_sha256(okm, 1, NULL, 1, NULL, 0) == PQS_ERR_ARGUMENT);
}

static void job_keys(pqs_aead_job *job) {
    from_hex(job->key, sizeof(job->key),
             "1001000000000000000000000000000000000000000000000000000000000000");
    from_hex(job->nonce, sizeof(job->nonce),
             "1000020000000000000000000000000000000000000000000000000000000000");
}

static void test_aead_vector(void) {
    uint8_t ad[8] = {0};
    uint8_t message[14] = {0};
    uint8_t ciphertext[14] = {0};
    uint8_t opened[14] = {0};
    uint8_t expected_ct[14] = {0};
    uint8_t expected_tag[PQS_TAG_BYTES] = {0};
    pqs_aead_job job = {0};

    from_hex(ad, sizeof(ad), "0001020304050607");
    from_hex(message, sizeof(message), "000102030405060708090a0b0c0d");
    from_hex(expected_ct, sizeof(expected_ct), "f373079ed84b2709faee37358458");
    from_hex(expected_tag, sizeof(expected_tag),
             "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9");
    job_keys(&job);
    job.ad = ad;
    job.ad_len = sizeof(ad);
    job.input = message;
    job.input_len = sizeof(message);
    job.output = ciphertext;
    pqs_aead_seal(&job);
    CHECK(job.status == PQS_OK);
    CHECK(pqs_equal(ciphertext, expected_ct, sizeof(ciphertext)));
    CHECK(pqs_equal(job.tag, expected_tag, sizeof(expected_tag)));

#ifndef HAS_HW_AES
    {
        uint8_t soft_ciphertext[sizeof(ciphertext)] = {0};
        uint8_t soft_tag[PQS_TAG_BYTES] = {0};
        const aegis256_implementation *soft = &aegis256_soft_implementation;

        CHECK(soft->encrypt_detached(soft_ciphertext, soft_tag, sizeof(soft_tag), message,
                                     sizeof(message), ad, sizeof(ad), job.nonce, job.key) == 0);
        CHECK(pqs_equal(soft_ciphertext, expected_ct, sizeof(soft_ciphertext)));
        CHECK(pqs_equal(soft_tag, expected_tag, sizeof(soft_tag)));
    }
#endif

    job.input = ciphertext;
    job.output = opened;
    pqs_aead_open(&job);
    CHECK(job.status == PQS_OK);
    CHECK(pqs_equal(opened, message, sizeof(message)));

    job.tag[0] ^= 1;
    pqs_aead_open(&job);
    CHECK(job.status == PQS_ERR_AUTH);
    CHECK(opened[0] == 0 && opened[13] == 0);
    pqs_aead_job_wipe(&job);
}

static void test_aead_lengths(void) {
    static const size_t lengths[] = {0, 1, 15, 16, 31, 32, 33, 63, 64, 65, 1000, LARGE_BYTES};
    uint8_t *message = calloc(1, LARGE_BYTES);
    uint8_t *ciphertext = calloc(1, LARGE_BYTES);
    uint8_t *opened = calloc(1, LARGE_BYTES);
    uint8_t ad[33] = {0};

    if (message == NULL || ciphertext == NULL || opened == NULL)
        abort();
    fill_pattern(message, LARGE_BYTES, 7);
    fill_pattern(ad, sizeof(ad), 9);
    for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]); index++) {
        pqs_aead_job job = {0};
        job_keys(&job);
        job.ad = ad;
        job.ad_len = index % sizeof(ad);
        job.input = message;
        job.input_len = lengths[index];
        job.output = ciphertext;
        pqs_aead_seal(&job);
        CHECK(job.status == PQS_OK);
        job.input = ciphertext;
        job.output = opened;
        pqs_aead_open(&job);
        CHECK(job.status == PQS_OK);
        CHECK(pqs_equal(opened, message, lengths[index]));
        pqs_aead_job_wipe(&job);
    }
    free(message);
    free(ciphertext);
    free(opened);
}

static void stream_feed(pqs_stream *stream, uint8_t *output, const uint8_t *input, size_t len,
                        size_t chunk) {
    for (size_t offset = 0; offset < len; offset += chunk) {
        pqs_update_job job = {0};
        job.stream = stream;
        job.input = input + offset;
        job.output = output + offset;
        job.len = len - offset < chunk ? len - offset : chunk;
        CHECK(pqs_stream_check_update(stream) == PQS_OK);
        pqs_stream_update(&job);
        CHECK(job.status == PQS_OK);
    }
}

static void test_stream_matches_one_shot(void) {
    enum { LEN = 5000 };
    static uint8_t message[LEN], one_shot[LEN], streamed[LEN], opened[LEN];
    uint8_t ad[16] = {0};
    uint8_t tag[PQS_TAG_BYTES] = {0};
    pqs_aead_job job = {0};
    pqs_stream stream;

    fill_pattern(message, LEN, 3);
    fill_pattern(ad, sizeof(ad), 5);
    job_keys(&job);
    job.ad = ad;
    job.ad_len = sizeof(ad);
    job.input = message;
    job.input_len = LEN;
    job.output = one_shot;
    pqs_aead_seal(&job);
    CHECK(job.status == PQS_OK);

    pqs_stream_init_storage(&stream);
    CHECK(pqs_stream_check_update(&stream) == PQS_ERR_UNINITIALIZED);
    CHECK(pqs_stream_encrypt_final(&stream, tag) == PQS_ERR_WRONG_MODE);
    CHECK(pqs_stream_acquire(&stream) == PQS_OK);
    CHECK(pqs_stream_acquire(&stream) == PQS_ERR_BUSY);
    CHECK(pqs_stream_start(&stream, PQS_MODE_ENCRYPT, job.key, job.nonce, ad, sizeof(ad)) ==
          PQS_OK);
    stream_feed(&stream, streamed, message, LEN, 777);
    CHECK(pqs_stream_encrypt_final(&stream, tag) == PQS_OK);
    CHECK(pqs_stream_encrypt_final(&stream, tag) == PQS_ERR_FINALIZED);
    CHECK(pqs_stream_check_update(&stream) == PQS_ERR_FINALIZED);
    CHECK(pqs_equal(streamed, one_shot, LEN));
    CHECK(pqs_equal(tag, job.tag, sizeof(tag)));

    CHECK(pqs_stream_start(&stream, PQS_MODE_DECRYPT, job.key, job.nonce, ad, sizeof(ad)) ==
          PQS_OK);
    CHECK(pqs_stream_encrypt_final(&stream, tag) == PQS_ERR_WRONG_MODE);
    stream_feed(&stream, opened, streamed, LEN, 333);
    CHECK(pqs_stream_decrypt_final(&stream, tag) == PQS_OK);
    CHECK(pqs_equal(opened, message, LEN));

    CHECK(pqs_stream_start(&stream, PQS_MODE_DECRYPT, job.key, job.nonce, ad, sizeof(ad)) ==
          PQS_OK);
    stream_feed(&stream, opened, streamed, LEN, LEN);
    tag[1] ^= 1;
    CHECK(pqs_stream_decrypt_final(&stream, tag) == PQS_ERR_AUTH);
    CHECK(pqs_stream_start(&stream, PQS_MODE_NONE, job.key, job.nonce, NULL, 0) ==
          PQS_ERR_ARGUMENT);
    pqs_stream_release(&stream);
    pqs_stream_wipe(&stream);
    pqs_aead_job_wipe(&job);
}

typedef struct {
    pqs_stream *shared;
    int acquired;
    int rejected;
    uint8_t input[1024];
    uint8_t output[1024];
} contention_worker;

static void *contention_main(void *arg) {
    contention_worker *worker = (contention_worker *)arg;

    for (int iteration = 0; iteration < ITERATIONS; iteration++) {
        if (pqs_stream_acquire(worker->shared) != PQS_OK) {
            worker->rejected++;
            continue;
        }
        if (pqs_stream_check_update(worker->shared) == PQS_OK) {
            pqs_update_job job = {worker->shared, worker->input, worker->output,
                                  sizeof(worker->input), PQS_ERR_CRYPTO};
            pqs_stream_update(&job);
            CHECK(job.status == PQS_OK);
        }
        worker->acquired++;
        pqs_stream_release(worker->shared);
    }
    return NULL;
}

static void *independent_main(void *arg) {
    uint8_t seed = *(const uint8_t *)arg;
    uint8_t ikm[32], okm[96], digest[PQS_SHA256_BYTES], random[48];
    uint8_t message[300], sealed[300], opened[300];

    fill_pattern(ikm, sizeof(ikm), seed);
    fill_pattern(message, sizeof(message), seed);
    for (int iteration = 0; iteration < ITERATIONS / 4; iteration++) {
        pqs_aead_job job = {0};
        CHECK(pqs_hkdf_sha256(okm, sizeof(okm), ikm, sizeof(ikm), &seed, 1) == PQS_OK);
        CHECK(pqs_sha256(digest, okm, sizeof(okm)) == PQS_OK);
        CHECK(pqs_random(random, sizeof(random)) == PQS_OK);
        CHECK(pqs_copy(job.key, sizeof(job.key), okm, PQS_KEY_BYTES) == PQS_OK);
        CHECK(pqs_copy(job.nonce, sizeof(job.nonce), digest, PQS_NONCE_BYTES) == PQS_OK);
        job.input = message;
        job.input_len = sizeof(message);
        job.output = sealed;
        pqs_aead_seal(&job);
        job.input = sealed;
        job.output = opened;
        pqs_aead_open(&job);
        CHECK(job.status == PQS_OK && pqs_equal(opened, message, sizeof(message)));
        pqs_aead_job_wipe(&job);
    }
    return NULL;
}

static void test_threads(void) {
    static contention_worker workers[THREADS];
    pthread_t threads[THREADS];
    uint8_t seeds[THREADS];
    uint8_t key[PQS_KEY_BYTES] = {1};
    uint8_t nonce[PQS_NONCE_BYTES] = {2};
    pqs_stream shared;
    int acquired = 0;

    pqs_stream_init_storage(&shared);
    CHECK(pqs_stream_acquire(&shared) == PQS_OK);
    CHECK(pqs_stream_start(&shared, PQS_MODE_ENCRYPT, key, nonce, NULL, 0) == PQS_OK);
    pqs_stream_release(&shared);
    for (int index = 0; index < THREADS; index++) {
        workers[index].shared = &shared;
        fill_pattern(workers[index].input, sizeof(workers[index].input), (uint8_t)index);
        if (pthread_create(&threads[index], NULL, contention_main, &workers[index]) != 0)
            abort();
    }
    for (int index = 0; index < THREADS; index++) {
        pthread_join(threads[index], NULL);
        acquired += workers[index].acquired;
        CHECK(workers[index].acquired + workers[index].rejected == ITERATIONS);
    }
    CHECK(acquired > 0);
    pqs_stream_wipe(&shared);

    for (int index = 0; index < THREADS; index++) {
        seeds[index] = (uint8_t)(index + 1);
        if (pthread_create(&threads[index], NULL, independent_main, &seeds[index]) != 0)
            abort();
    }
    for (int index = 0; index < THREADS; index++)
        pthread_join(threads[index], NULL);
}

int main(void) {
    if (aegis_init() != 0) {
        fputs("aegis_init failed\n", stderr);
        return 1;
    }
    test_copy_bounds();
    test_random_and_sha256();
    test_hkdf();
    test_aead_vector();
    test_aead_lengths();
    test_stream_matches_one_shot();
    test_threads();
    if (atomic_load(&failures) != 0) {
        fputs("pqs_core tests: FAILED\n", stderr);
        return 1;
    }
    puts("pqs_core tests: ok");
    return 0;
}
