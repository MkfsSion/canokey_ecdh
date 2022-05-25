#include "p11-kit/pkcs11.h"
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <p11-kit/p11-kit.h>

#include <assert.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <locale.h>
#include <string.h>

_Noreturn void fail(const char *format, ...) {
    assert(format);
    va_list vl;
    va_start(vl, format);
    vfprintf(stderr, format, vl);
    va_end(vl);
    exit(1);
}

EVP_PKEY *generate_ec_key(int nid) {
    int r = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY *ret = NULL;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL)
        fail("EVP_PKEY_CTX_new_id returns NULL");
    
    r = EVP_PKEY_paramgen_init((pctx));
    if (r != 1)
        fail("EVP_PKEY_paramgen_init returns %d", r);
    
    r = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid);
    if (r != 1)
        fail("EVP_PKEY_CTX_set_ec_paramgen_curve_nid returns %d", r);
    
    r = EVP_PKEY_paramgen(pctx, &params);
    if (r != 1)
        fail("EVP_PKEY_paramgen returns %d", r);

    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx)
        fail("EVP_PKEY_CTX_new returns NULL");
    
    r = EVP_PKEY_keygen_init(kctx);
    if (r != 1)    
        fail("EVP_PKEY_keygen_init returns: %d", r);
    
    r = EVP_PKEY_keygen(kctx, &ret);
    if (r != 1)
        fail("EVP_PKEY_keygen returns %d", r);
    printf("EVP_PKEY with NID \"%s\" generated success\n", OBJ_nid2sn(nid));
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    return ret;
}

X509 *pkcs11_get_certificates(void) {
    X509 *cert = NULL;
    CK_FUNCTION_LIST_PTR_PTR modules = NULL;
    modules = p11_kit_modules_load_and_initialize(0);
    if (!modules)
        fail("p11_kit_modules_load_and_initialize returns NULL");
    
    for (int i = 0; modules[i] != NULL; i++) {
        CK_RV rv = CKR_OK;
        CK_ULONG n_slots = 0;
        CK_FUNCTION_LIST_PTR m = modules[i];
        printf("Found module %s\n", p11_kit_module_get_name(m));
        if (strncmp(p11_kit_module_get_name(m), "opensc", sizeof("opensc")) != 0)
            continue;
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

            CK_OBJECT_CLASS class = CKO_CERTIFICATE;
            
            CK_ATTRIBUTE pattern[] = {
                {CKA_CLASS, &class, sizeof(class)},
                {CKA_LABEL, "Certificate for Key Management", sizeof("Certificate for Key Management") - 1}
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
            CK_ATTRIBUTE cert_obj = {
                .type = CKA_VALUE
            };
            rv = m->C_GetAttributeValue(handle, objects[0], &cert_obj, 1);
            if (rv != CKR_OK)
                fail("C_GetAttributeValue returns %s", p11_kit_strerror(rv));
            void *buffer = malloc(cert_obj.ulValueLen);
            cert_obj.pValue = buffer;
            rv = m->C_GetAttributeValue(handle, objects[0], &cert_obj, 1);
            if (rv != CKR_OK)
                fail("C_GetAttributeValue returns %s", p11_kit_strerror(rv));
            cert = d2i_X509(NULL, (const uint8_t **) &cert_obj.pValue, cert_obj.ulValueLen);
            m->C_CloseSession(handle);
            free(slots);
            free(buffer);
            p11_kit_modules_finalize_and_release(modules);
            return cert;
        }
    }
     p11_kit_modules_finalize_and_release(modules);
     return cert;
}

void generate_hmac_shared_secret(EVP_PKEY *privkey1, EVP_PKEY *pubkey2, uint8_t *out, size_t len) {
    assert(privkey1);
    assert(pubkey2);
    assert(out);
    assert(len);
    int r;
    EVP_PKEY_CTX *kctx = NULL, *hctx = NULL;
    size_t secret_len = 0;
    uint8_t *secret = NULL;
    kctx = EVP_PKEY_CTX_new(privkey1, NULL);
    if (kctx == NULL)
        fail("EVP_PKEY_CTX_new returns NULL");
    
    r = EVP_PKEY_derive_init(kctx);
    if (r != 1)
        fail("EVP_PKEY_derive_init returns %d", r);

    r = EVP_PKEY_derive_set_peer(kctx, pubkey2);
    if (r != 1)
        fail("EVP_PKEY_derive_set_peer returns %d", r);
    
    r = EVP_PKEY_derive(kctx, NULL, &secret_len);
    if (r != 1)
        fail("EVP_PKEY_derive returns %d", r);
    
    secret = OPENSSL_malloc(secret_len);
    if (secret == NULL)
        fail("OPENSSL_malloc returns NULL");

    r = EVP_PKEY_derive(kctx, secret, &secret_len);
    if (r != 1)
        fail("EVP_PKEY_derive returns %d", r);

    printf("secret length is %zu\n", secret_len);
    FILE *f = fopen("shared-secret.bin", "w");
    if (!f)
        fail("fopen shared-secret.bin returns NULL");
    fwrite(secret, 1, secret_len, f);
    fclose(f);
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
    
    r = EVP_PKEY_CTX_set1_hkdf_key(hctx, secret, secret_len);
    if (r != 1)
        fail("EVP_PKEY_CTX_set1_hkdf_key returns %d", r);
    
    r = EVP_PKEY_derive(hctx, out, &len);
    if (r != 1)
        fail("EVP_PKEY_derive returns %d", r);
    
    printf("hsecret length is %zu\n", len);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(hctx);
    OPENSSL_free(secret);
}

int main(void) {
    X509 *cert = pkcs11_get_certificates();
    if (cert == NULL)
        fail("Fail to acquire X509 certificate");
    X509_NAME *name = X509_get_subject_name(cert);
    if (name == NULL)
        fail("Failed to acquire X509 certificate name");
    printf("Certifciate: %s\n", X509_NAME_oneline(name, NULL, 0));
    EVP_PKEY *pubkey2 = X509_get0_pubkey(cert);
    int nid = NID_undef;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    uint8_t *curve_name = NULL;
    size_t len = 0;
    if (!EVP_PKEY_get_group_name(pubkey2, NULL, 0, &len) || len == 0)
        fail("Failed to determine curve group name length");
    len += 1;
    curve_name = OPENSSL_malloc(len);
    if (!curve_name)
        fail("Out of memory");
    if (!EVP_PKEY_get_group_name(pubkey2, curve_name, len, &len))
        fail("Failed to get curve group name");
    nid = OBJ_sn2nid(curve_name);
    OPENSSL_free(curve_name);
#else
    if (EC_KEY_check_key(EVP_PKEY_get0_EC_KEY(pubkey2)) != 1)
        fail("EC_KEY not valid");
    nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pubkey2)));
#endif
    EVP_PKEY *pkey1 = generate_ec_key(nid);
    uint8_t hs[72];
    generate_hmac_shared_secret(pkey1, pubkey2, hs, 72);
    FILE *f = fopen("hkdf-secret.bin", "w");
    fwrite(hs, 1, 72, f);
    fclose(f);
    f = fopen("pubkey1.crt", "w");
    i2d_PUBKEY_fp(f, pkey1);
    fclose(f);
    EVP_PKEY_free(pkey1);
    X509_free(cert);
    return 0;
}
