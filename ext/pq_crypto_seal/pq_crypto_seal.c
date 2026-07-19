#include "ruby.h"
#include "ruby/thread.h"
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "aegis.h"
#include "aegis256.h"

#define KEY_BYTES       32
#define NONCE_BYTES     32
#define TAG_BYTES       32
#define NOGVL_THRESHOLD 32768

typedef struct {
    aegis256_state state;
    int mode;
    int finalized;
} seal_state;

static VALUE mPQCrypto, mSeal, mNative, cEncryptor, cDecryptor, eAuth;

static void secure_free(void *ptr) {
    seal_state *st = (seal_state *)ptr;
    if (st != NULL) {
        OPENSSL_cleanse(st, sizeof(*st));
        xfree(st);
    }
}

static size_t state_memsize(const void *ptr) {
    return ptr ? sizeof(seal_state) : 0;
}

static const rb_data_type_t state_type = {"PQCrypto::Seal::NativeState",
                                          {0, secure_free, state_memsize, 0, {0}},
                                          0,
                                          0,
                                          RUBY_TYPED_FREE_IMMEDIATELY};

static VALUE state_alloc(VALUE klass) {
    seal_state *st;
    VALUE obj = TypedData_Make_Struct(klass, seal_state, &state_type, st);
    memset(st, 0, sizeof(*st));
    return obj;
}

static void require_length(VALUE str, long expected, const char *name) {
    StringValue(str);
    if (RSTRING_LEN(str) != expected)
        rb_raise(rb_eArgError, "%s must be %ld bytes", name, expected);
}

static VALUE native_random_bytes(VALUE self, VALUE length_value) {
    (void)self;
    long length = NUM2LONG(length_value);
    if (length < 0)
        rb_raise(rb_eArgError, "length must be non-negative");
    VALUE out = rb_str_new(NULL, length);
    long offset = 0;
    while (offset < length) {
        int chunk = (int)((length - offset) > INT_MAX ? INT_MAX : (length - offset));
        if (RAND_bytes((unsigned char *)RSTRING_PTR(out) + offset, chunk) != 1) {
            rb_raise(rb_eRuntimeError, "OpenSSL RAND_bytes failed");
        }
        offset += chunk;
    }
    return out;
}

static VALUE native_sha256(VALUE self, VALUE input) {
    (void)self;
    StringValue(input);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_Digest(RSTRING_PTR(input), (size_t)RSTRING_LEN(input), digest, &length, EVP_sha256(),
                   NULL) != 1 ||
        length != 32) {
        rb_raise(rb_eRuntimeError, "OpenSSL SHA-256 failed");
    }
    return rb_str_new((const char *)digest, 32);
}

static VALUE native_hkdf_sha256(VALUE self, VALUE ikm, VALUE info, VALUE length_value) {
    (void)self;
    StringValue(ikm);
    StringValue(info);

    long requested = NUM2LONG(length_value);
    if (requested <= 0 || requested > 8160) {
        rb_raise(rb_eArgError, "invalid HKDF output length");
    }

    const long ikm_len_long = RSTRING_LEN(ikm);
    const long info_len_long = RSTRING_LEN(info);
    if (ikm_len_long < 0 || ikm_len_long > INT_MAX) {
        rb_raise(rb_eArgError, "HKDF input key material is too large");
    }
    if (info_len_long < 0) {
        rb_raise(rb_eArgError, "HKDF info length is invalid");
    }

    const size_t ikm_len = (size_t)ikm_len_long;
    const size_t info_len = (size_t)info_len_long;
    if (info_len > SIZE_MAX - 33U) {
        rb_raise(rb_eArgError, "HKDF info is too large");
    }

    VALUE out = rb_str_new(NULL, requested);
    const size_t expand_capacity = 32U + info_len + 1U;
    unsigned char *expand_input = ALLOC_N(unsigned char, expand_capacity);
    unsigned char salt[32] = {0};
    unsigned char prk[32] = {0};
    unsigned char t[32] = {0};
    unsigned int digest_len = 0;
    size_t t_len = 0;
    size_t produced = 0;
    unsigned int block = 1;

    if (HMAC(EVP_sha256(), salt, (int)sizeof(salt), (const unsigned char *)RSTRING_PTR(ikm),
             ikm_len, prk, &digest_len) == NULL ||
        digest_len != sizeof(prk)) {
        OPENSSL_cleanse(expand_input, expand_capacity);
        xfree(expand_input);
        OPENSSL_cleanse(prk, sizeof(prk));
        OPENSSL_cleanse(t, sizeof(t));
        rb_raise(rb_eRuntimeError, "OpenSSL HMAC-SHA256 extract failed");
    }

    while (produced < (size_t)requested) {
        size_t input_len = 0;
        if (t_len != 0) {
            memcpy(expand_input, t, t_len);
            input_len += t_len;
        }
        if (info_len != 0) {
            memcpy(expand_input + input_len, RSTRING_PTR(info), info_len);
            input_len += info_len;
        }
        expand_input[input_len++] = (unsigned char)block;

        digest_len = 0;
        if (HMAC(EVP_sha256(), prk, (int)sizeof(prk), expand_input, input_len, t, &digest_len) ==
                NULL ||
            digest_len != sizeof(t)) {
            OPENSSL_cleanse(expand_input, expand_capacity);
            xfree(expand_input);
            OPENSSL_cleanse(prk, sizeof(prk));
            OPENSSL_cleanse(t, sizeof(t));
            rb_raise(rb_eRuntimeError, "OpenSSL HMAC-SHA256 expand failed");
        }

        t_len = sizeof(t);
        size_t remaining = (size_t)requested - produced;
        size_t copy_len = remaining < t_len ? remaining : t_len;
        memcpy((unsigned char *)RSTRING_PTR(out) + produced, t, copy_len);
        produced += copy_len;
        block++;
    }

    OPENSSL_cleanse(expand_input, expand_capacity);
    xfree(expand_input);
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(t, sizeof(t));
    RB_GC_GUARD(ikm);
    RB_GC_GUARD(info);
    return out;
}

static VALUE native_hkdf_backend(VALUE self) {
    (void)self;
    return rb_str_new_cstr("rfc5869-hmac-sha256-v1");
}

typedef struct {
    const uint8_t *key, *nonce, *ad, *input, *tag;
    uint8_t *output, *out_tag;
    size_t adlen, input_len;
    int result;
} one_shot_args;

static void *encrypt_without_gvl(void *ptr) {
    one_shot_args *a = (one_shot_args *)ptr;
    a->result = aegis256_encrypt_detached(a->output, a->out_tag, TAG_BYTES, a->input, a->input_len,
                                          a->ad, a->adlen, a->nonce, a->key);
    return NULL;
}

static void *decrypt_without_gvl(void *ptr) {
    one_shot_args *a = (one_shot_args *)ptr;
    a->result = aegis256_decrypt_detached(a->output, a->input, a->input_len, a->tag, TAG_BYTES,
                                          a->ad, a->adlen, a->nonce, a->key);
    return NULL;
}

static VALUE native_encrypt(VALUE self, VALUE key, VALUE nonce, VALUE ad, VALUE plaintext) {
    (void)self;
    require_length(key, KEY_BYTES, "key");
    require_length(nonce, NONCE_BYTES, "nonce");
    StringValue(ad);
    StringValue(plaintext);
    VALUE ciphertext = rb_str_new(NULL, RSTRING_LEN(plaintext));
    VALUE tag = rb_str_new(NULL, TAG_BYTES);
    one_shot_args args = {(uint8_t *)RSTRING_PTR(key),
                          (uint8_t *)RSTRING_PTR(nonce),
                          (uint8_t *)RSTRING_PTR(ad),
                          (uint8_t *)RSTRING_PTR(plaintext),
                          NULL,
                          (uint8_t *)RSTRING_PTR(ciphertext),
                          (uint8_t *)RSTRING_PTR(tag),
                          (size_t)RSTRING_LEN(ad),
                          (size_t)RSTRING_LEN(plaintext),
                          -1};
    if (args.input_len >= NOGVL_THRESHOLD)
        rb_thread_call_without_gvl(encrypt_without_gvl, &args, RUBY_UBF_IO, NULL);
    else
        encrypt_without_gvl(&args);
    RB_GC_GUARD(key);
    RB_GC_GUARD(nonce);
    RB_GC_GUARD(ad);
    RB_GC_GUARD(plaintext);
    if (args.result != 0)
        rb_raise(rb_eRuntimeError, "AEGIS-256 encryption failed");
    return rb_ary_new_from_args(2, ciphertext, tag);
}

static VALUE native_decrypt(VALUE self, VALUE key, VALUE nonce, VALUE ad, VALUE ciphertext,
                            VALUE tag) {
    (void)self;
    require_length(key, KEY_BYTES, "key");
    require_length(nonce, NONCE_BYTES, "nonce");
    require_length(tag, TAG_BYTES, "tag");
    StringValue(ad);
    StringValue(ciphertext);
    VALUE plaintext = rb_str_new(NULL, RSTRING_LEN(ciphertext));
    one_shot_args args = {(uint8_t *)RSTRING_PTR(key),
                          (uint8_t *)RSTRING_PTR(nonce),
                          (uint8_t *)RSTRING_PTR(ad),
                          (uint8_t *)RSTRING_PTR(ciphertext),
                          (uint8_t *)RSTRING_PTR(tag),
                          (uint8_t *)RSTRING_PTR(plaintext),
                          NULL,
                          (size_t)RSTRING_LEN(ad),
                          (size_t)RSTRING_LEN(ciphertext),
                          -1};
    if (args.input_len >= NOGVL_THRESHOLD)
        rb_thread_call_without_gvl(decrypt_without_gvl, &args, RUBY_UBF_IO, NULL);
    else
        decrypt_without_gvl(&args);
    RB_GC_GUARD(key);
    RB_GC_GUARD(nonce);
    RB_GC_GUARD(ad);
    RB_GC_GUARD(ciphertext);
    RB_GC_GUARD(tag);
    if (args.result != 0) {
        OPENSSL_cleanse(RSTRING_PTR(plaintext), (size_t)RSTRING_LEN(plaintext));
        rb_raise(eAuth, "AEGIS-256 authentication failed");
    }
    return plaintext;
}

static VALUE native_secure_equal(VALUE self, VALUE a, VALUE b) {
    (void)self;
    StringValue(a);
    StringValue(b);
    if (RSTRING_LEN(a) != RSTRING_LEN(b))
        return Qfalse;
    return CRYPTO_memcmp(RSTRING_PTR(a), RSTRING_PTR(b), (size_t)RSTRING_LEN(a)) == 0 ? Qtrue
                                                                                      : Qfalse;
}

static VALUE state_initialize(VALUE self, VALUE key, VALUE nonce, VALUE ad) {
    seal_state *st;
    TypedData_Get_Struct(self, seal_state, &state_type, st);
    require_length(key, KEY_BYTES, "key");
    require_length(nonce, NONCE_BYTES, "nonce");
    StringValue(ad);
    aegis256_state_init(&st->state, (uint8_t *)RSTRING_PTR(ad), (size_t)RSTRING_LEN(ad),
                        (uint8_t *)RSTRING_PTR(nonce), (uint8_t *)RSTRING_PTR(key));
    st->finalized = 0;
    st->mode = rb_obj_is_kind_of(self, cEncryptor) ? 1 : 2;
    return self;
}

typedef struct {
    seal_state *st;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    int result;
} update_args;
static void *update_encrypt_nogvl(void *ptr) {
    update_args *a = ptr;
    a->result = aegis256_state_encrypt_update(&a->st->state, a->out, a->in, a->len);
    return NULL;
}
static void *update_decrypt_nogvl(void *ptr) {
    update_args *a = ptr;
    a->result = aegis256_state_decrypt_update(&a->st->state, a->out, a->in, a->len);
    return NULL;
}

static VALUE state_update(VALUE self, VALUE input) {
    seal_state *st;
    TypedData_Get_Struct(self, seal_state, &state_type, st);
    if (st->finalized)
        rb_raise(rb_eRuntimeError, "AEGIS state is finalized");
    StringValue(input);
    VALUE out = rb_str_new(NULL, RSTRING_LEN(input));
    update_args args = {st, (uint8_t *)RSTRING_PTR(input), (uint8_t *)RSTRING_PTR(out),
                        (size_t)RSTRING_LEN(input), -1};
    void *(*fn)(void *) = st->mode == 1 ? update_encrypt_nogvl : update_decrypt_nogvl;
    if (args.len >= NOGVL_THRESHOLD)
        rb_thread_call_without_gvl(fn, &args, RUBY_UBF_IO, NULL);
    else
        fn(&args);
    RB_GC_GUARD(input);
    if (args.result != 0)
        rb_raise(rb_eRuntimeError, "AEGIS-256 update failed");
    return out;
}

static VALUE encrypt_final(VALUE self) {
    seal_state *st;
    TypedData_Get_Struct(self, seal_state, &state_type, st);
    if (st->finalized)
        rb_raise(rb_eRuntimeError, "AEGIS state is finalized");
    VALUE tag = rb_str_new(NULL, TAG_BYTES);
    int result = aegis256_state_encrypt_final(&st->state, (uint8_t *)RSTRING_PTR(tag), TAG_BYTES);
    st->finalized = 1;
    OPENSSL_cleanse(&st->state, sizeof(st->state));
    if (result != 0)
        rb_raise(rb_eRuntimeError, "AEGIS-256 finalization failed");
    return tag;
}

static VALUE decrypt_final(VALUE self, VALUE tag) {
    seal_state *st;
    TypedData_Get_Struct(self, seal_state, &state_type, st);
    if (st->finalized)
        rb_raise(rb_eRuntimeError, "AEGIS state is finalized");
    require_length(tag, TAG_BYTES, "tag");
    int result = aegis256_state_decrypt_final(&st->state, (uint8_t *)RSTRING_PTR(tag), TAG_BYTES);
    st->finalized = 1;
    OPENSSL_cleanse(&st->state, sizeof(st->state));
    if (result != 0)
        rb_raise(eAuth, "AEGIS-256 authentication failed");
    return Qtrue;
}

void Init_pq_crypto_seal(void) {
    if (OpenSSL_version_num() < 0x30000000L) {
        rb_raise(rb_eRuntimeError, "pq_crypto-seal requires OpenSSL 3.0 or newer at runtime");
    }
    if (aegis_init() != 0)
        rb_raise(rb_eRuntimeError, "libaegis initialization failed");
    mPQCrypto = rb_define_module("PQCrypto");
    mSeal = rb_define_module_under(mPQCrypto, "Seal");
    mNative = rb_define_module_under(mSeal, "Native");
    eAuth = rb_path2class("PQCrypto::Seal::AuthenticationError");

    rb_define_singleton_method(mNative, "random_bytes", native_random_bytes, 1);
    rb_define_singleton_method(mNative, "sha256", native_sha256, 1);
    rb_define_singleton_method(mNative, "hkdf_sha256", native_hkdf_sha256, 3);
    rb_define_singleton_method(mNative, "hkdf_backend", native_hkdf_backend, 0);
    rb_define_singleton_method(mNative, "aegis256_encrypt", native_encrypt, 4);
    rb_define_singleton_method(mNative, "aegis256_decrypt", native_decrypt, 5);
    rb_define_singleton_method(mNative, "secure_equal", native_secure_equal, 2);

    cEncryptor = rb_define_class_under(mNative, "Encryptor", rb_cObject);
    rb_define_alloc_func(cEncryptor, state_alloc);
    rb_define_method(cEncryptor, "initialize", state_initialize, 3);
    rb_define_method(cEncryptor, "update", state_update, 1);
    rb_define_method(cEncryptor, "final", encrypt_final, 0);

    cDecryptor = rb_define_class_under(mNative, "Decryptor", rb_cObject);
    rb_define_alloc_func(cDecryptor, state_alloc);
    rb_define_method(cDecryptor, "initialize", state_initialize, 3);
    rb_define_method(cDecryptor, "update", state_update, 1);
    rb_define_method(cDecryptor, "final", decrypt_final, 1);
}
