#include "p11-kit/pkcs11.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <p11-kit/p11-kit.h>

#include <assert.h>
#include <openssl/kdf.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#endif

_Noreturn void fail(const char *format, ...) {
    assert(format);
    va_list vl;
    va_start(vl, format);
    vfprintf(stderr, format, vl);
    va_end(vl);
    exit(1);
}

uint8_t *pkcs11_derive_shared_secret_malloc(EVP_PKEY *pubkey1, size_t *out_len) {
    X509 *cert = NULL;
    CK_FUNCTION_LIST_PTR_PTR modules = NULL;
    modules = p11_kit_modules_load_and_initialize(0);
    if (!modules)
        fail("p11_kit_modules_load_and_initialize returns NULL");
    
    for (int i = 0; modules[i] != NULL; i++) {
        CK_RV rv = CKR_OK;
        CK_ULONG n_slots = 0;
        CK_FUNCTION_LIST_PTR m = modules[i];
        const char *module_name = p11_kit_module_get_name(m);
        printf("Found module %s\n", module_name);
        if (strncmp(module_name, "opensc", sizeof("opensc")) != 0) {
            m->C_Finalize(NULL_PTR);
            free((void *)module_name);
            continue;
        }
        rv = m->C_GetSlotList(CK_FALSE, NULL, &n_slots);
        if (rv != CKR_OK)
            fail("C_GetSlotList returns %s", p11_kit_strerror(rv));
        if(n_slots == 0) {
            printf("No slot on the module, continue\n");
            continue;
        }
        CK_SLOT_ID_PTR slots = malloc(sizeof(CK_SLOT_ID) * n_slots);
        rv = m->C_GetSlotList(CK_FALSE, slots, &n_slots);
        if (rv != CKR_OK)
            fail("C_GetSlotList returns %s", p11_kit_strerror(rv));
        for (int i = 0;i < n_slots;i++) {
            CK_SLOT_INFO info = {};
            rv = m->C_GetSlotInfo(slots[i], &info);
            if (rv != CKR_OK)
                fail("C_GetSlotInfo for slot %ld returns %s", slots[i], p11_kit_strerror(rv));
            printf("Slot %ld info:\n", slots[i]);
            printf("Description: %s\n", info.slotDescription);
            printf("manufactureId: %s\n", info.manufacturerID);
            CK_SESSION_HANDLE handle = 0;
            rv = m->C_OpenSession(slots[i], CKF_SERIAL_SESSION, NULL, NULL, &handle);
            if (rv != CKR_OK)
                fail("C_OpenSession returns %s", p11_kit_strerror(rv));
            
            rv = m->C_Login(handle, CKU_USER, (CK_UTF8CHAR_PTR) "123456", 6);
            if (rv != CKR_OK)
                fail("C_login returns %s", p11_kit_strerror(rv));

            CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
            
            CK_ATTRIBUTE pattern[] = {
                {CKA_CLASS, &class, sizeof(class)},
                {CKA_LABEL, "KEY MAN key", sizeof("KEY MAN key") - 1}
            };

            rv = m->C_FindObjectsInit(handle, pattern, 2);
            if (rv != CKR_OK)
                fail("C_FindObjectsInit returns %s", p11_kit_strerror(rv));
            CK_OBJECT_HANDLE objects[2];
            CK_ULONG nobjects = 0;
            rv = m->C_FindObjects(handle, objects, 2, &nobjects);
            if (rv != CKR_OK)
                fail("C_FindObjects returns %s", p11_kit_strerror(rv));
            if (nobjects == 0) {
                printf("No matching object found\n");
                m->C_CloseSession(handle);
                break;
            }
            rv = m->C_FindObjectsFinal(handle);
            if (rv != CKR_OK)
                fail("C_FindObjectsFinal returns %s", p11_kit_strerror(rv));
            
            CK_ECDH1_DERIVE_PARAMS params = {
                .kdf = CKD_NULL,
                .pSharedData = NULL,
                .ulSharedDataLen = 0,
            };
            size_t len = 0;
            uint8_t *buf = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
            if(EVP_PKEY_set_utf8_string_param(pubkey1, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED) != 1)
                fail("Failed to set point-format to uncompressed");

            len = EVP_PKEY_get1_encoded_public_key(pubkey1, &buf);
            if (len == 0)
                fail("Failed to get encoded public key");
#else
            EC_KEY *ec_pubkey1 = EVP_PKEY_get0_EC_KEY(pubkey1);
            if (EC_KEY_check_key(ec_pubkey1) != 1)
                fail("EC_KEY not valid");
            len = EC_POINT_point2oct(EC_KEY_get0_group(ec_pubkey1), EC_KEY_get0_public_key(ec_pubkey1), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
            if(!len)
                fail("EC_POINT_point2oct returns %zu", len);
            buf = OPENSSL_malloc(len);
            len = EC_POINT_point2oct(EC_KEY_get0_group(ec_pubkey1), EC_KEY_get0_public_key(ec_pubkey1), POINT_CONVERSION_UNCOMPRESSED, buf, len, NULL);
            if (!len)
                fail("EC_POINT_point2oct returns %zu", len);
#endif
            params.pPublicData = buf;
            params.ulPublicDataLen = len;
            CK_BBOOL vtrue = CK_TRUE;
            CK_BBOOL vfalse = CK_FALSE;
            CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
            CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
            CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
            CK_ULONG newkey_len = (EVP_PKEY_bits(pubkey1) + 7) / 8;
            CK_ATTRIBUTE newkey_template[] = {
                {CKA_TOKEN, &vfalse, sizeof(vfalse)},
                {CKA_CLASS, &newkey_class, sizeof(newkey_class)},
                {CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
                {CKA_VALUE_LEN, &newkey_len, sizeof(newkey_len)},
                {CKA_SENSITIVE, &vfalse, sizeof(vfalse)},
                {CKA_EXTRACTABLE, &vtrue, sizeof(vtrue)},
                {CKA_ENCRYPT, &vtrue, sizeof(vtrue)},
                {CKA_DECRYPT, &vtrue, sizeof(vtrue)}
            };
            CK_MECHANISM mechanism;
            mechanism.mechanism = CKM_ECDH1_DERIVE;
            mechanism.pParameter = &params;
            mechanism.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);
            CK_BBOOL can_derive = CK_FALSE;
            CK_ATTRIBUTE derive_template = {
                .type = CKA_DERIVE,
                .pValue = &can_derive,
                .ulValueLen = sizeof(can_derive)
            };

            rv = m->C_GetAttributeValue(handle, objects[0], &derive_template, 1);
            if (rv != CKR_OK)
                fail("C_GetAttributeValue returns %s", p11_kit_strerror(rv));
            if (!can_derive)
                fail("The key object doesn't support derive");
            
            rv = m->C_DeriveKey(handle, &mechanism, objects[0], newkey_template, sizeof(newkey_template) / sizeof(CK_ATTRIBUTE), &newkey);
            if (rv != CKR_OK)
                fail("C_DeriveKey returns %s", p11_kit_strerror(rv));
            CK_ATTRIBUTE sk_template = {
                .type = CKA_VALUE
            };
            rv = m->C_GetAttributeValue(handle, newkey, &sk_template, 1);
            if (rv != CKR_OK)
                fail("C_GetAttributeValue returns %s", p11_kit_strerror(rv));
            uint8_t *sk = OPENSSL_malloc(sk_template.ulValueLen);
            sk_template.pValue = sk;
            rv = m->C_GetAttributeValue(handle, newkey, &sk_template, 1);
            if (rv != CKR_OK)
                fail("C_GetAttributeValue returns %s", p11_kit_strerror(rv));
            rv = m->C_DestroyObject(handle, newkey);
            if (rv != CKR_SESSION_READ_ONLY && rv != CKR_OK)
                fail("C_DestroyObject returns %s", p11_kit_strerror(rv));
            m->C_CloseSession(handle);
            m->C_Finalize(NULL_PTR);
            p11_kit_modules_finalize_and_release(modules);
            *out_len = newkey_len;
            OPENSSL_free(slots);
            OPENSSL_free(buf);
            free((void *)module_name);
            return sk;
        }
    }
     p11_kit_modules_finalize_and_release(modules);
     return NULL;
}

void generate_hmac_from_shared_secret(uint8_t *sk, size_t sk_len, uint8_t *out, size_t len) {
    assert(sk);
    assert(sk_len);
    assert(out);
    assert(len);
    int r;
    EVP_PKEY_CTX *hctx = NULL;
    hctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (hctx == NULL)
        fail("EVP_PKEY_CTX_new_id returns NULL");
    
    r = EVP_PKEY_derive_init(hctx);
    if (r != 1)
        fail("EVP_PKEY_derive_init returns %d", r);
    
    r = EVP_PKEY_CTX_hkdf_mode(hctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);
    if (r != 1)
        fail("EVP_PKEY_CTX_hkdf_mode returns %d", r);
    
    r = EVP_PKEY_CTX_set_hkdf_md(hctx, EVP_sha512());
    if (r != 1)
        fail("EVP_PKEY_CTX_set_hkdf_md returns %d", r);
    
    r = EVP_PKEY_CTX_set1_hkdf_key(hctx, sk, sk_len);
    if (r != 1)
        fail("EVP_PKEY_CTX_set1_hkdf_key returns %d", r);
    
    r = EVP_PKEY_derive(hctx, out, &len);
    if (r != 1)
        fail("EVP_PKEY_derive returns %d", r);
    
    printf("hsecret length is %zu\n", len);
    EVP_PKEY_CTX_free(hctx);
}

int main()
{
    FILE *f = fopen("pubkey1.crt", "r");
    if (!f)
        fail("fopen pubkey1.crt returns NULL");
    EVP_PKEY *pubkey1 = NULL;
    d2i_PUBKEY_fp(f, &pubkey1);
    fclose(f);
    if (!pubkey1)
        fail("d2i_PUBKEY_fp returns NULL");
    size_t sk_len = 0;
    uint8_t *sk = pkcs11_derive_shared_secret_malloc(pubkey1, &sk_len);
    uint8_t hs[72] = {};
    generate_hmac_from_shared_secret(sk, sk_len, hs, 72);
    f = fopen("hkdf-secret.bin", "r");
    if (!f)
        fail("fopen hkdf-secret.bin returns NULL");
    uint8_t fhs[72] = {};
    fread(fhs, 1, 72, f);
    fclose(f);
    int r = memcmp(hs, fhs, 72);
    if (r != 0)
        fail("memcmp %p with %p returns %d", hs, fhs, r);
    else
        printf("HKDF secret is same");
    EVP_PKEY_free(pubkey1);
    OPENSSL_free(sk);
    return 0;
}
