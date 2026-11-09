#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-warning-option"
#pragma clang diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wc23-extensions"
#pragma clang diagnostic ignored "-Wc2x-extensions"
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wcast-qual"
#pragma clang diagnostic ignored "-Wignored-attributes"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
#include <ruby.h>
#include <ruby/thread.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <stdint.h>

#include <openssl/crypto.h>

#include "pqs_core.h"

#define PQS_NOGVL_THRESHOLD 32768L
#define PQS_HKDF_BACKEND    "rfc5869-hmac-sha256-v1"

#ifdef RB_NOGVL_OFFLOAD_SAFE
#define PQS_NOGVL_FLAGS RB_NOGVL_OFFLOAD_SAFE
#else
#define PQS_NOGVL_FLAGS 0
#endif

static VALUE eAuthenticationError = Qnil;

typedef struct {
    void *(*fn)(void *);
    void *job;
} pqs_nogvl_call;

typedef struct {
    pqs_aead_job job;
    uint8_t *workspace;
    size_t workspace_len;
} pqs_aead_call;

typedef struct {
    const uint8_t *bytes;
    size_t len;
} pqs_output;

static const uint8_t *bytes_ptr(VALUE string) {
    return (const uint8_t *)RSTRING_PTR(string);
}

static uint8_t *mutable_bytes_ptr(VALUE string) {
    return (uint8_t *)RSTRING_PTR(string);
}

static size_t bytes_len(VALUE string) {
    return (size_t)RSTRING_LEN(string);
}

static void require_bytes(VALUE string, long expected, const char *name) {
    if (RSTRING_LEN(string) != expected)
        rb_raise(rb_eArgError, "%s must be %ld bytes", name, expected);
}

static pqs_status copy_bytes(uint8_t *dst, size_t dst_len, VALUE string) {
    return pqs_copy(dst, dst_len, bytes_ptr(string), bytes_len(string));
}

static int offload_input(long len) {
    return len >= PQS_NOGVL_THRESHOLD;
}

static void wipe_string(VALUE string) {
    pqs_wipe(RSTRING_PTR(string), bytes_len(string));
}

static void wipe_and_free(uint8_t *buffer, size_t len) {
    OPENSSL_clear_free(buffer, len);
}

static uint8_t *alloc_workspace(size_t ad_len, size_t input_len, size_t *total_len) {
    uint8_t *buffer;

    if (input_len > (SIZE_MAX - ad_len) / 2)
        rb_raise(rb_eArgError, "input is too large");
    *total_len = ad_len + 2 * input_len;
    buffer = OPENSSL_malloc(*total_len);
    if (buffer == NULL)
        rb_memerror();
    return buffer;
}

static VALUE output_string(VALUE arg) {
    const pqs_output *output = (const pqs_output *)arg;
    return rb_str_new((const char *)output->bytes, (long)output->len);
}

static int materialize_output(VALUE *output, const uint8_t *bytes, size_t len) {
    pqs_output result = {bytes, len};
    int state = 0;

    *output = rb_protect(output_string, (VALUE)&result, &state);
    return state;
}

static VALUE prepare_output(VALUE input, long len, int offload) {
    VALUE output = offload ? Qnil : rb_str_new(NULL, len);

    if (RSTRING_LEN(input) != len)
        rb_raise(rb_eArgError, "input length changed during allocation");
    return output;
}

static VALUE call_without_gvl(VALUE arg) {
    pqs_nogvl_call *call = (pqs_nogvl_call *)arg;
#ifdef HAVE_RB_NOGVL
    rb_nogvl(call->fn, call->job, NULL, NULL, PQS_NOGVL_FLAGS);
#else
    rb_thread_call_without_gvl(call->fn, call->job, NULL, NULL);
#endif
    return Qnil;
}

static int run_job(void *(*fn)(void *), void *job, int offload) {
    pqs_nogvl_call call = {fn, job};
    int state = 0;

    if (!offload) {
        fn(job);
        return 0;
    }
    rb_protect(call_without_gvl, (VALUE)&call, &state);
    return state;
}

NORETURN(static void raise_status(pqs_status status, const char *crypto_message,
                                  const char *wrong_mode_message));

static void raise_status(pqs_status status, const char *crypto_message,
                         const char *wrong_mode_message) {
    switch (status) {
    case PQS_ERR_BUSY:
        rb_raise(rb_eRuntimeError, "AEGIS state is in use");
    case PQS_ERR_UNINITIALIZED:
        rb_raise(rb_eRuntimeError, "AEGIS state is not initialized");
    case PQS_ERR_FINALIZED:
        rb_raise(rb_eRuntimeError, "AEGIS state is finalized");
    case PQS_ERR_WRONG_MODE:
        rb_raise(rb_eRuntimeError, "%s", wrong_mode_message);
    case PQS_ERR_AUTH:
        rb_raise(eAuthenticationError, "AEGIS-256 authentication failed");
    case PQS_ERR_ARGUMENT:
        rb_raise(rb_eArgError, "invalid argument");
    case PQS_OK:
    case PQS_ERR_CRYPTO:
    default:
        rb_raise(rb_eRuntimeError, "%s", crypto_message);
    }
}

static VALUE native_random_bytes(VALUE self, VALUE length_value) {
    long length = NUM2LONG(length_value);
    VALUE output;

    (void)self;
    if (length < 0)
        rb_raise(rb_eArgError, "length must be non-negative");
    output = rb_str_new(NULL, length);
    if (pqs_random(mutable_bytes_ptr(output), (size_t)length) != PQS_OK)
        rb_raise(rb_eRuntimeError, "OpenSSL RAND_bytes failed");
    return output;
}

static VALUE native_sha256(VALUE self, VALUE input) {
    uint8_t digest[PQS_SHA256_BYTES] = {0};
    pqs_status status;

    (void)self;
    StringValue(input);
    status = pqs_sha256(digest, bytes_ptr(input), bytes_len(input));
    RB_GC_GUARD(input);
    if (status != PQS_OK)
        rb_raise(rb_eRuntimeError, "OpenSSL SHA-256 failed");
    return rb_str_new((const char *)digest, (long)sizeof(digest));
}

static VALUE native_hkdf_sha256(VALUE self, VALUE ikm, VALUE info, VALUE length_value) {
    long requested = NUM2LONG(length_value);
    VALUE output;
    pqs_status status;

    (void)self;
    StringValue(ikm);
    StringValue(info);
    if (requested <= 0 || requested > (long)PQS_HKDF_MAX_OUTPUT)
        rb_raise(rb_eArgError, "invalid HKDF output length");
    output = rb_str_new(NULL, requested);
    status = pqs_hkdf_sha256(mutable_bytes_ptr(output), (size_t)requested, bytes_ptr(ikm),
                             bytes_len(ikm), bytes_ptr(info), bytes_len(info));
    RB_GC_GUARD(ikm);
    RB_GC_GUARD(info);
    if (status != PQS_OK)
        rb_raise(rb_eRuntimeError, "OpenSSL HKDF-SHA256 failed");
    return output;
}

static VALUE native_hkdf_backend(VALUE self) {
    (void)self;
    return rb_str_new_cstr(PQS_HKDF_BACKEND);
}

static VALUE native_secure_equal(VALUE self, VALUE left, VALUE right) {
    int equal;

    (void)self;
    StringValue(left);
    StringValue(right);
    if (RSTRING_LEN(left) != RSTRING_LEN(right))
        return Qfalse;
    equal = pqs_equal(bytes_ptr(left), bytes_ptr(right), bytes_len(left));
    RB_GC_GUARD(left);
    RB_GC_GUARD(right);
    return equal ? Qtrue : Qfalse;
}

static VALUE native_wipe(VALUE self, VALUE value) {
    (void)self;
    if (!RB_TYPE_P(value, T_STRING) || OBJ_FROZEN(value))
        return Qfalse;
    rb_str_modify(value);
    wipe_string(value);
    return Qtrue;
}

static void aead_call_prepare(pqs_aead_call *call, VALUE ad, VALUE input, int offload) {
    if (offload)
        call->workspace = alloc_workspace(bytes_len(ad), bytes_len(input), &call->workspace_len);
}

static pqs_status aead_call_attach(pqs_aead_call *call, VALUE key, VALUE nonce, VALUE ad,
                                   VALUE input) {
    pqs_aead_job *job = &call->job;
    pqs_status status = copy_bytes(job->key, sizeof(job->key), key);

    if (status == PQS_OK)
        status = copy_bytes(job->nonce, sizeof(job->nonce), nonce);
    job->ad_len = bytes_len(ad);
    job->input_len = bytes_len(input);
    job->ad = bytes_ptr(ad);
    job->input = bytes_ptr(input);
    if (status != PQS_OK || call->workspace == NULL)
        return status;
    status = pqs_copy(call->workspace, job->ad_len, job->ad, job->ad_len);
    if (status == PQS_OK)
        status = pqs_copy(call->workspace + job->ad_len, job->input_len,
                          job->input, job->input_len);
    job->ad = call->workspace;
    job->input = call->workspace + job->ad_len;
    return status;
}

static void aead_call_release(pqs_aead_call *call) {
    pqs_wipe(call->job.key, sizeof(call->job.key));
    pqs_wipe(call->job.nonce, sizeof(call->job.nonce));
    wipe_and_free(call->workspace, call->workspace_len);
}

static void aead_call_attach_or_raise(pqs_aead_call *call, pqs_status status) {
    if (status != PQS_OK) {
        aead_call_release(call);
        pqs_aead_job_wipe(&call->job);
        raise_status(status, "AEGIS-256 argument copy failed", "");
    }
}

static int aead_call_run(pqs_aead_call *call, void *(*fn)(void *), VALUE *output) {
    pqs_aead_job *job = &call->job;
    int offload = call->workspace != NULL;
    int state;

    job->output = offload ? call->workspace + job->ad_len + job->input_len : mutable_bytes_ptr(*output);
    job->status = PQS_ERR_CRYPTO;
    state = run_job(fn, job, offload);
    if (offload && state == 0 && job->status == PQS_OK)
        state = materialize_output(output, job->output, job->input_len);
    if (!offload && job->status != PQS_OK)
        wipe_string(*output);
    aead_call_release(call);
    return state;
}

static VALUE native_encrypt(VALUE self, VALUE key, VALUE nonce, VALUE ad, VALUE plaintext) {
    pqs_aead_call call = {0};
    VALUE ciphertext;
    VALUE tag;
    long len;
    int offload;
    int state;

    (void)self;
    StringValue(key);
    StringValue(nonce);
    StringValue(ad);
    StringValue(plaintext);
    len = RSTRING_LEN(plaintext);
    offload = offload_input(len);
    ciphertext = prepare_output(plaintext, len, offload);
    require_bytes(key, PQS_KEY_BYTES, "key");
    require_bytes(nonce, PQS_NONCE_BYTES, "nonce");

    aead_call_prepare(&call, ad, plaintext, offload);
    aead_call_attach_or_raise(&call, aead_call_attach(&call, key, nonce, ad, plaintext));
    state = aead_call_run(&call, pqs_aead_seal, &ciphertext);
    RB_GC_GUARD(key);
    RB_GC_GUARD(nonce);
    RB_GC_GUARD(ad);
    RB_GC_GUARD(plaintext);
    if (state != 0) {
        pqs_aead_job_wipe(&call.job);
        rb_jump_tag(state);
    }
    if (call.job.status != PQS_OK) {
        pqs_aead_job_wipe(&call.job);
        rb_raise(rb_eRuntimeError, "AEGIS-256 encryption failed");
    }
    tag = rb_str_new((const char *)call.job.tag, (long)sizeof(call.job.tag));
    pqs_aead_job_wipe(&call.job);
    return rb_assoc_new(ciphertext, tag);
}

static VALUE native_decrypt(VALUE self, VALUE key, VALUE nonce, VALUE ad, VALUE ciphertext,
                            VALUE tag) {
    pqs_aead_call call = {0};
    pqs_status status;
    VALUE plaintext;
    long len;
    int offload;
    int state;

    (void)self;
    StringValue(key);
    StringValue(nonce);
    StringValue(ad);
    StringValue(ciphertext);
    StringValue(tag);
    len = RSTRING_LEN(ciphertext);
    offload = offload_input(len);
    plaintext = prepare_output(ciphertext, len, offload);
    require_bytes(key, PQS_KEY_BYTES, "key");
    require_bytes(nonce, PQS_NONCE_BYTES, "nonce");
    require_bytes(tag, PQS_TAG_BYTES, "tag");

    aead_call_prepare(&call, ad, ciphertext, offload);
    status = aead_call_attach(&call, key, nonce, ad, ciphertext);
    if (status == PQS_OK)
        status = copy_bytes(call.job.tag, sizeof(call.job.tag), tag);
    aead_call_attach_or_raise(&call, status);
    state = aead_call_run(&call, pqs_aead_open, &plaintext);
    pqs_aead_job_wipe(&call.job);
    RB_GC_GUARD(key);
    RB_GC_GUARD(nonce);
    RB_GC_GUARD(ad);
    RB_GC_GUARD(ciphertext);
    RB_GC_GUARD(tag);
    if (state != 0)
        rb_jump_tag(state);
    if (call.job.status != PQS_OK)
        raise_status(call.job.status, "AEGIS-256 decryption failed", "");
    return plaintext;
}

static void stream_free(void *ptr) {
    if (ptr != NULL) {
        pqs_wipe(ptr, sizeof(pqs_stream));
        xfree(ptr);
    }
}

static size_t stream_memsize(const void *ptr) {
    return ptr == NULL ? 0 : sizeof(pqs_stream);
}

static const rb_data_type_t stream_type = {
    .wrap_struct_name = "PQCrypto::Seal::NativeState",
    .function =
        {
            .dmark = NULL,
            .dfree = stream_free,
            .dsize = stream_memsize,
        },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

static VALUE stream_alloc(VALUE klass) {
    pqs_stream *stream;
    VALUE object = TypedData_Make_Struct(klass, pqs_stream, &stream_type, stream);

    pqs_stream_init_storage(stream);
    return object;
}

static pqs_stream *stream_get(VALUE self) {
    pqs_stream *stream;

    TypedData_Get_Struct(self, pqs_stream, &stream_type, stream);
    return stream;
}

static void stream_acquire(pqs_stream *stream, uint8_t *workspace, size_t workspace_len) {
    pqs_status status = pqs_stream_acquire(stream);

    if (status != PQS_OK) {
        wipe_and_free(workspace, workspace_len);
        raise_status(status, "AEGIS state lock failed", "");
    }
}

static VALUE stream_initialize(VALUE self, VALUE key, VALUE nonce, VALUE ad, pqs_mode mode) {
    pqs_stream *stream = stream_get(self);
    pqs_status status;

    StringValue(key);
    StringValue(nonce);
    StringValue(ad);
    require_bytes(key, PQS_KEY_BYTES, "key");
    require_bytes(nonce, PQS_NONCE_BYTES, "nonce");
    stream_acquire(stream, NULL, 0);
    status = pqs_stream_start(stream, mode, bytes_ptr(key), bytes_ptr(nonce), bytes_ptr(ad),
                              bytes_len(ad));
    pqs_stream_release(stream);
    RB_GC_GUARD(key);
    RB_GC_GUARD(nonce);
    RB_GC_GUARD(ad);
    if (status != PQS_OK)
        raise_status(status, "AEGIS-256 initialization failed", "");
    return self;
}

static VALUE encryptor_initialize(VALUE self, VALUE key, VALUE nonce, VALUE ad) {
    return stream_initialize(self, key, nonce, ad, PQS_MODE_ENCRYPT);
}

static VALUE decryptor_initialize(VALUE self, VALUE key, VALUE nonce, VALUE ad) {
    return stream_initialize(self, key, nonce, ad, PQS_MODE_DECRYPT);
}

NORETURN(static VALUE stream_initialize_copy(VALUE self, VALUE source));

static VALUE stream_initialize_copy(VALUE self, VALUE source) {
    (void)self;
    (void)source;
    rb_raise(rb_eTypeError, "AEGIS state cannot be copied");
}

static void stream_begin_update(pqs_stream *stream, uint8_t *workspace, size_t workspace_len) {
    pqs_status status;

    stream_acquire(stream, workspace, workspace_len);
    status = pqs_stream_check_update(stream);
    if (status != PQS_OK) {
        pqs_stream_release(stream);
        wipe_and_free(workspace, workspace_len);
        raise_status(status, "AEGIS-256 update failed", "");
    }
}

static void stream_end_update(pqs_stream *stream, pqs_update_job *job, int state) {
    if (state != 0 || job->status != PQS_OK)
        pqs_stream_finish(stream);
    pqs_stream_release(stream);
}

static VALUE stream_update(VALUE self, VALUE input) {
    pqs_stream *stream = stream_get(self);
    pqs_update_job job = {0};
    uint8_t *workspace = NULL;
    size_t workspace_len = 0;
    VALUE output;
    long len;
    int offload;
    int state;

    StringValue(input);
    len = RSTRING_LEN(input);
    offload = offload_input(len);
    output = prepare_output(input, len, offload);
    if (offload)
        workspace = alloc_workspace(0, (size_t)len, &workspace_len);
    stream_begin_update(stream, workspace, workspace_len);

    job.stream = stream;
    job.len = (size_t)len;
    job.input = bytes_ptr(input);
    job.output = offload ? workspace + job.len : mutable_bytes_ptr(output);
    job.status = PQS_ERR_CRYPTO;
    if (offload) {
        (void)pqs_copy(workspace, job.len, job.input, job.len);
        job.input = workspace;
    }
    state = run_job(pqs_stream_update, &job, offload);
    if (offload && state == 0 && job.status == PQS_OK)
        state = materialize_output(&output, job.output, job.len);
    stream_end_update(stream, &job, state);
    wipe_and_free(workspace, workspace_len);
    RB_GC_GUARD(input);
    RB_GC_GUARD(self);
    if (!offload && job.status != PQS_OK)
        wipe_string(output);
    if (state != 0)
        rb_jump_tag(state);
    if (job.status != PQS_OK)
        raise_status(job.status, "AEGIS-256 update failed", "");
    return output;
}

static VALUE encryptor_final(VALUE self) {
    pqs_stream *stream = stream_get(self);
    uint8_t tag[PQS_TAG_BYTES] = {0};
    pqs_status status;
    VALUE result;

    stream_acquire(stream, NULL, 0);
    status = pqs_stream_encrypt_final(stream, tag);
    pqs_stream_release(stream);
    if (status != PQS_OK) {
        pqs_wipe(tag, sizeof(tag));
        raise_status(status, "AEGIS-256 finalization failed",
                     "AEGIS encrypt state is not initialized");
    }
    result = rb_str_new((const char *)tag, (long)sizeof(tag));
    pqs_wipe(tag, sizeof(tag));
    return result;
}

static VALUE decryptor_final(VALUE self, VALUE tag) {
    pqs_stream *stream = stream_get(self);
    pqs_status status;

    StringValue(tag);
    require_bytes(tag, PQS_TAG_BYTES, "tag");
    stream_acquire(stream, NULL, 0);
    status = pqs_stream_decrypt_final(stream, bytes_ptr(tag));
    pqs_stream_release(stream);
    RB_GC_GUARD(self);
    RB_GC_GUARD(tag);
    if (status != PQS_OK)
        raise_status(status, "AEGIS-256 finalization failed",
                     "AEGIS decrypt state is not initialized");
    return Qtrue;
}

static VALUE define_stream_class(VALUE under, const char *name,
                                 VALUE (*initialize)(VALUE, VALUE, VALUE, VALUE)) {
    VALUE klass = rb_define_class_under(under, name, rb_cObject);

    rb_define_alloc_func(klass, stream_alloc);
    rb_define_method(klass, "initialize", initialize, 3);
    rb_define_method(klass, "initialize_copy", stream_initialize_copy, 1);
    rb_define_method(klass, "update", stream_update, 1);
    return klass;
}

void Init_pq_crypto_seal(void);

void Init_pq_crypto_seal(void) {
    VALUE mSeal;
    VALUE mNative;
    VALUE cEncryptor;
    VALUE cDecryptor;

    if (OpenSSL_version_num() < 0x30000000UL)
        rb_raise(rb_eRuntimeError, "pq_crypto-seal requires OpenSSL 3.0 or newer at runtime");
    if (aegis_init() != 0)
        rb_raise(rb_eRuntimeError, "libaegis initialization failed");

    mSeal = rb_define_module_under(rb_define_module("PQCrypto"), "Seal");
    mNative = rb_define_module_under(mSeal, "Native");
    eAuthenticationError = rb_path2class("PQCrypto::Seal::AuthenticationError");
    rb_gc_register_address(&eAuthenticationError);

    rb_define_singleton_method(mNative, "random_bytes", native_random_bytes, 1);
    rb_define_singleton_method(mNative, "sha256", native_sha256, 1);
    rb_define_singleton_method(mNative, "hkdf_sha256", native_hkdf_sha256, 3);
    rb_define_singleton_method(mNative, "hkdf_backend", native_hkdf_backend, 0);
    rb_define_singleton_method(mNative, "aegis256_encrypt", native_encrypt, 4);
    rb_define_singleton_method(mNative, "aegis256_decrypt", native_decrypt, 5);
    rb_define_singleton_method(mNative, "secure_equal", native_secure_equal, 2);
    rb_define_singleton_method(mNative, "wipe", native_wipe, 1);

    cEncryptor = define_stream_class(mNative, "Encryptor", encryptor_initialize);
    rb_define_method(cEncryptor, "final", encryptor_final, 0);
    cDecryptor = define_stream_class(mNative, "Decryptor", decryptor_initialize);
    rb_define_method(cDecryptor, "final", decryptor_final, 1);
}
