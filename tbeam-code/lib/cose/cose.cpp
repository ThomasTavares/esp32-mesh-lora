#include "cose.h"
#include <cbor.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <esp_system.h>
#include <esp_random.h>
#include <esp_log.h>
#include <cstring>
#include <vector>

using namespace std;

static const char* TAG = "CoseCrypto";
static const int COSE_ALG_AES_256_GCM = 3; 

// Helper to build the Enc_structure for AAD
// Enc_structure = [ "Encrypt0", protected_headers, external_aad ]
static vector<uint8_t> get_aad(const uint8_t* protected_hdr, size_t protected_len) {
    vector<uint8_t> aad_buffer(20 + protected_len); 
    
    CborEncoder encoder, array_encoder;
    cbor_encoder_init(&encoder, aad_buffer.data(), aad_buffer.size(), 0);
    
    cbor_encoder_create_array(&encoder, &array_encoder, 3);
    cbor_encode_text_stringz(&array_encoder, "Encrypt0");
    cbor_encode_byte_string(&array_encoder, protected_hdr, protected_len);
    cbor_encode_byte_string(&array_encoder, NULL, 0);
    cbor_encoder_close_container(&encoder, &array_encoder);
    
    size_t len = cbor_encoder_get_buffer_size(&encoder, aad_buffer.data());
    aad_buffer.resize(len);
    
    return aad_buffer;
}

// Helper to build the Sig_structure for COSE_Sign1
// Sig_structure = [ "Signature1", protected_headers, external_aad, payload ]
static vector<uint8_t> get_sig_structure(const uint8_t* protected_hdr, size_t protected_len, 
                                         const uint8_t* payload, size_t payload_len) {
    vector<uint8_t> sig_buffer(32 + protected_len + payload_len); 
    
    CborEncoder encoder, array_encoder;
    cbor_encoder_init(&encoder, sig_buffer.data(), sig_buffer.size(), 0);
    
    cbor_encoder_create_array(&encoder, &array_encoder, 4);
    cbor_encode_text_stringz(&array_encoder, "Signature1");
    cbor_encode_byte_string(&array_encoder, protected_hdr, protected_len);
    cbor_encode_byte_string(&array_encoder, NULL, 0);
    cbor_encode_byte_string(&array_encoder, payload, payload_len);
    cbor_encoder_close_container(&encoder, &array_encoder);
    
    size_t len = cbor_encoder_get_buffer_size(&encoder, sig_buffer.data());
    sig_buffer.resize(len);
    
    return sig_buffer;
}

esp_err_t CoseCrypto::encrypt(const vector<uint8_t>& plaintext, 
                              const vector<uint8_t>& key, 
                              vector<uint8_t>& out_cose_data) {
    if (key.size() != KEY_SIZE) {
        ESP_LOGE(TAG, "Invalid key size");
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t iv[IV_SIZE];
    esp_fill_random(iv, IV_SIZE);

    size_t estimated_size = plaintext.size() + TAG_SIZE + 100;
    out_cose_data.resize(estimated_size);

    CborEncoder encoder, array_encoder, map_encoder;
    cbor_encoder_init(&encoder, out_cose_data.data(), out_cose_data.size(), 0);

    // Outer Structure
    cbor_encode_tag(&encoder, COSE_TAG_ENCRYPT0);
    cbor_encoder_create_array(&encoder, &array_encoder, 3);

    // Protected Headers
    uint8_t protected_header_buf[32]; // Small buffer for just the Alg ID
    CborEncoder prot_enc, prot_map;
    cbor_encoder_init(&prot_enc, protected_header_buf, sizeof(protected_header_buf), 0);
    cbor_encoder_create_map(&prot_enc, &prot_map, 1);
    cbor_encode_int(&prot_map, 1); // Label 1: Alg
    cbor_encode_int(&prot_map, COSE_ALG_AES_256_GCM);
    cbor_encoder_close_container(&prot_enc, &prot_map);
    size_t protected_len = cbor_encoder_get_buffer_size(&prot_enc, protected_header_buf);

    cbor_encode_byte_string(&array_encoder, protected_header_buf, protected_len);

    // Unprotected Headers (IV)
    cbor_encoder_create_map(&array_encoder, &map_encoder, 1);
    cbor_encode_int(&map_encoder, 5); // Label 5: IV
    cbor_encode_byte_string(&map_encoder, iv, IV_SIZE);
    cbor_encoder_close_container(&array_encoder, &map_encoder);

    // Ciphertext + Tag calculation
    vector<uint8_t> aad = get_aad(protected_header_buf, protected_len);

    size_t total_encrypted_len = plaintext.size() + TAG_SIZE;
    vector<uint8_t> encrypted_buf(total_encrypted_len);
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), KEY_SIZE * 8);

    int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), 
                                        iv, IV_SIZE, 
                                        aad.data(), aad.size(), 
                                        plaintext.data(), encrypted_buf.data(), 
                                        TAG_SIZE, encrypted_buf.data() + plaintext.size());

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        ESP_LOGE(TAG, "Encryption failed: -0x%04x", -ret);
        return ESP_FAIL;
    }

    cbor_encode_byte_string(&array_encoder, encrypted_buf.data(), total_encrypted_len);
    cbor_encoder_close_container(&encoder, &array_encoder);

    out_cose_data.resize(cbor_encoder_get_buffer_size(&encoder, out_cose_data.data()));
    return ESP_OK;
}

esp_err_t CoseCrypto::decrypt(const vector<uint8_t>& cose_data, 
                              const vector<uint8_t>& key, 
                              vector<uint8_t>& out_plaintext) {
    if (key.size() != KEY_SIZE) return ESP_ERR_INVALID_ARG;

    CborParser parser;
    CborValue it, array_it;
    CborError err;

    // Init Parser
    if ((err = cbor_parser_init(cose_data.data(), cose_data.size(), 0, &parser, &it)) != CborNoError) {
        ESP_LOGE(TAG, "CBOR Parser init failed: %d", err);
        return ESP_FAIL;
    }

    // Check Tag (COSE_Encrypt0 = 16)
    CborTag tag;
    if (cbor_value_get_tag(&it, &tag) == CborNoError) {
        if (tag != COSE_TAG_ENCRYPT0) {
            ESP_LOGW(TAG, "Wrong Tag: %llu (Expected %d)", tag, COSE_TAG_ENCRYPT0);
            return ESP_FAIL;
        }
        cbor_value_advance(&it);
    }

    // Enter Array
    if (!cbor_value_is_array(&it)) {
        ESP_LOGE(TAG, "Not an array");
        return ESP_FAIL;
    }
    
    size_t array_len = 0;
    cbor_value_get_array_length(&it, &array_len);
    if (array_len < 3) { 
        ESP_LOGE(TAG, "Array too short: %d", (int)array_len);
        return ESP_FAIL;
    }

    if ((err = cbor_value_enter_container(&it, &array_it)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to enter array: %d", err);
        return ESP_FAIL;
    }

    // Get Protected Headers (Item 0)
    vector<uint8_t> protected_header;
    size_t prot_len;
    
    if (!cbor_value_is_byte_string(&array_it)) {
        ESP_LOGE(TAG, "Protected header is not a byte string");
        return ESP_FAIL;
    }
    
    if ((err = cbor_value_calculate_string_length(&array_it, &prot_len)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to calculate protected header length: %d", err);
        return ESP_FAIL;
    }
    
    protected_header.resize(prot_len);
    size_t actual_len = prot_len;
    if ((err = cbor_value_copy_byte_string(&array_it, protected_header.data(), &actual_len, NULL)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to read Protected Headers: %d", err);
        return ESP_FAIL;
    }
    
    cbor_value_advance(&array_it);

    // Get Unprotected Headers (Item 1)
    CborValue map_it;
    if (!cbor_value_is_map(&array_it)) {
        ESP_LOGE(TAG, "Header 2 is NOT a map");
        return ESP_FAIL;
    }
    
    if ((err = cbor_value_enter_container(&array_it, &map_it)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to enter Unprotected Map: %d", err);
        return ESP_FAIL;
    }
    
    uint8_t iv[IV_SIZE];
    bool iv_found = false;

    while (!cbor_value_at_end(&map_it)) {
        if (!cbor_value_is_integer(&map_it)) {
            cbor_value_advance(&map_it); 
            cbor_value_advance(&map_it); 
            continue;
        }

        int label;
        cbor_value_get_int(&map_it, &label);
        cbor_value_advance(&map_it);

        if (label == 5) { // Label 5 = IV
            if (cbor_value_is_byte_string(&map_it)) {
                size_t len = IV_SIZE;
                err = cbor_value_copy_byte_string(&map_it, iv, &len, NULL);
                
                if (err == CborNoError && len == IV_SIZE) {
                    iv_found = true;
                } else {
                    ESP_LOGE(TAG, "IV error: err=%d, len=%d", err, (int)len);
                }
            } else {
                ESP_LOGW(TAG, "Key 5 found but not a bstr");
            }
        }
        
        if ((err = cbor_value_advance(&map_it)) != CborNoError) {
            ESP_LOGE(TAG, "Map iteration error: %d", err);
            break;
        }
    }
    cbor_value_leave_container(&array_it, &map_it);

    if (!iv_found) {
        ESP_LOGE(TAG, "IV not found in headers");
        return ESP_FAIL;
    }

    // Get Ciphertext (Item 2)
    vector<uint8_t> ciphertext_with_tag;
    size_t ct_len;
    
    if (!cbor_value_is_byte_string(&array_it)) {
        ESP_LOGE(TAG, "Ciphertext is not a byte string");
        return ESP_FAIL;
    }
    
    if ((err = cbor_value_calculate_string_length(&array_it, &ct_len)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to calculate ciphertext length: %d", err);
        return ESP_FAIL;
    }
    
    ciphertext_with_tag.resize(ct_len);
    size_t actual_ct_len = ct_len;
    if ((err = cbor_value_copy_byte_string(&array_it, ciphertext_with_tag.data(), &actual_ct_len, NULL)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to read Ciphertext: %d", err);
        return ESP_FAIL;
    }

    if (ct_len < TAG_SIZE) {
        ESP_LOGE(TAG, "Ciphertext too short");
        return ESP_FAIL;
    }

    // Decrypt
    vector<uint8_t> aad = get_aad(protected_header.data(), protected_header.size());

    size_t cipher_len = ct_len - TAG_SIZE;
    out_plaintext.resize(cipher_len);
    const uint8_t* tag_ptr = ciphertext_with_tag.data() + cipher_len;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), KEY_SIZE * 8);

    int ret = mbedtls_gcm_auth_decrypt(&gcm, cipher_len, 
                                       iv, IV_SIZE, 
                                       aad.data(), aad.size(),
                                       tag_ptr, TAG_SIZE, 
                                       ciphertext_with_tag.data(), out_plaintext.data());
    
    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        ESP_LOGE(TAG, "Auth/Decryption failed: -0x%04x", -ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t CoseCrypto::sign(const vector<uint8_t>& payload, 
                           const vector<uint8_t>& private_key, 
                           vector<uint8_t>& out_cose_data) {
    if (private_key.size() != KEY_SIZE) return ESP_ERR_INVALID_ARG;

    // Encode Protected Headers
    uint8_t protected_header_buf[16]; 
    CborEncoder prot_enc, prot_map;
    cbor_encoder_init(&prot_enc, protected_header_buf, sizeof(protected_header_buf), 0);
    cbor_encoder_create_map(&prot_enc, &prot_map, 1);
    cbor_encode_int(&prot_map, 1); // Label 1: Alg
    cbor_encode_int(&prot_map, COSE_ALG_ES256);
    cbor_encoder_close_container(&prot_enc, &prot_map);
    size_t protected_len = cbor_encoder_get_buffer_size(&prot_enc, protected_header_buf);

    // Build Sig_structure and Hash it (SHA-256)
    vector<uint8_t> sig_structure = get_sig_structure(protected_header_buf, protected_len, payload.data(), payload.size());
    uint8_t hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); 
    mbedtls_sha256_update(&sha_ctx, sig_structure.data(), sig_structure.size());
    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    // Setup MbedTLS ECDSA & Entropy
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    esp_err_t ret = ESP_OK;

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"cose", 4) != 0) {
        ret = ESP_FAIL; goto cleanup;
    }

    // Load Group and Private Key explicitly
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(&d, private_key.data(), private_key.size());

    // Sign the Hash
    if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof(hash), mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        ESP_LOGE(TAG, "ECDSA Sign failed");
        ret = ESP_FAIL; goto cleanup;
    }

    // Convert Signature to 64 bytes (R || S)
    uint8_t signature[SIG_SIZE];
    mbedtls_mpi_write_binary(&r, signature, 32);
    mbedtls_mpi_write_binary(&s, signature + 32, 32);

    // Assemble Final COSE_Sign1 CBOR
    out_cose_data.resize(payload.size() + SIG_SIZE + 64);
    CborEncoder encoder, array_encoder, unprot_map;
    cbor_encoder_init(&encoder, out_cose_data.data(), out_cose_data.size(), 0);

    cbor_encode_tag(&encoder, COSE_TAG_SIGN1);
    cbor_encoder_create_array(&encoder, &array_encoder, 4);

    cbor_encode_byte_string(&array_encoder, protected_header_buf, protected_len);
    
    cbor_encoder_create_map(&array_encoder, &unprot_map, 0);
    cbor_encoder_close_container(&array_encoder, &unprot_map);
    
    cbor_encode_byte_string(&array_encoder, payload.data(), payload.size());
    cbor_encode_byte_string(&array_encoder, signature, SIG_SIZE);

    cbor_encoder_close_container(&encoder, &array_encoder);
    out_cose_data.resize(cbor_encoder_get_buffer_size(&encoder, out_cose_data.data()));

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}

esp_err_t CoseCrypto::verify(const vector<uint8_t>& cose_data, 
                             const vector<uint8_t>& public_key, 
                             vector<uint8_t>& out_payload) {
    if (public_key.size() != 64) {
        ESP_LOGE(TAG, "Invalid public key size. Expected 64 bytes.");
        return ESP_ERR_INVALID_ARG;
    }

    CborParser parser;
    CborValue it, array_it;
    
    if (cbor_parser_init(cose_data.data(), cose_data.size(), 0, &parser, &it) != CborNoError) {
        ESP_LOGE(TAG, "Failed to initialize CBOR parser");
        return ESP_FAIL;
    }

    // Safely Check and Skip Tag
    if (cbor_value_is_tag(&it)) {
        CborTag tag;
        cbor_value_get_tag(&it, &tag);
        if (tag != COSE_TAG_SIGN1) {
            ESP_LOGE(TAG, "Invalid COSE Tag. Expected 18, got %llu", (unsigned long long)tag);
            return ESP_FAIL;
        }
        cbor_value_skip_tag(&it); 
    }

    if (!cbor_value_is_array(&it)) {
        ESP_LOGE(TAG, "COSE Sign1 message is not an array");
        return ESP_FAIL;
    }

    size_t array_len = 0;
    cbor_value_get_array_length(&it, &array_len);
    if (array_len < 4) {
        ESP_LOGE(TAG, "COSE Sign1 array too short (must be 4 elements)");
        return ESP_FAIL;
    }

    cbor_value_enter_container(&it, &array_it);

    // Extract Protected Headers
    if (!cbor_value_is_byte_string(&array_it)) {
        ESP_LOGE(TAG, "Protected headers must be a byte string");
        return ESP_FAIL;
    }
    size_t prot_len;
    cbor_value_calculate_string_length(&array_it, &prot_len);
    vector<uint8_t> protected_header(prot_len);
    cbor_value_copy_byte_string(&array_it, protected_header.data(), &prot_len, NULL);
    cbor_value_advance(&array_it);

    // Skip Unprotected Headers
    cbor_value_advance(&array_it); 

    // Extract Payload
    if (!cbor_value_is_byte_string(&array_it)) {
        ESP_LOGE(TAG, "Payload must be a byte string");
        return ESP_FAIL;
    }
    size_t payload_len;
    cbor_value_calculate_string_length(&array_it, &payload_len);
    out_payload.resize(payload_len);
    cbor_value_copy_byte_string(&array_it, out_payload.data(), &payload_len, NULL);
    cbor_value_advance(&array_it);

    // Extract Signature
    if (!cbor_value_is_byte_string(&array_it)) {
        ESP_LOGE(TAG, "Signature must be a byte string");
        return ESP_FAIL;
    }
    size_t sig_len;
    cbor_value_calculate_string_length(&array_it, &sig_len);
    if (sig_len != SIG_SIZE) {
        ESP_LOGE(TAG, "Invalid signature size. Expected %d, got %d", (int)SIG_SIZE, (int)sig_len);
        return ESP_FAIL;
    }
    uint8_t signature[SIG_SIZE];
    cbor_value_copy_byte_string(&array_it, signature, &sig_len, NULL);

    // Reconstruct Sig_structure and Hash
    vector<uint8_t> sig_structure = get_sig_structure(protected_header.data(), protected_header.size(), out_payload.data(), payload_len);
    
    uint8_t hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); // 0 = SHA-256, 1 = SHA-224
    mbedtls_sha256_update(&sha_ctx, sig_structure.data(), sig_structure.size());
    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    // Verify Signature using MbedTLS
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    esp_err_t err_ret = ESP_OK;
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    
    // Format uncompressed public key (0x04 || X || Y) so MbedTLS can parse it natively
    uint8_t pub_buf[65];
    pub_buf[0] = 0x04;
    memcpy(pub_buf + 1, public_key.data(), 64);
    
    int ret_pub = mbedtls_ecp_point_read_binary(&grp, &Q, pub_buf, sizeof(pub_buf));
    
    if (ret_pub == 0) {
        mbedtls_mpi_read_binary(&r, signature, 32);
        mbedtls_mpi_read_binary(&s, signature + 32, 32);

        int ret_verify = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &Q, &r, &s);
        if (ret_verify != 0) {
            ESP_LOGE(TAG, "ECDSA Verification failed: -0x%04x", -ret_verify);
            err_ret = ESP_FAIL;
        }
    }
    else {
        ESP_LOGE(TAG, "Failed to parse public key: -0x%04x", -ret_pub);
        err_ret = ESP_FAIL;
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return err_ret;
}

esp_err_t CoseCrypto::generate_test_keypair(std::vector<uint8_t>& priv_key, std::vector<uint8_t>& pub_key) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    esp_err_t ret = ESP_OK;
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"cose_test", 9) != 0) {
        ret = ESP_FAIL; goto cleanup;
    }
    
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        ret = ESP_FAIL; goto cleanup;
    }
    
    // Extract 32-byte Private Key
    priv_key.resize(32);
    mbedtls_mpi_write_binary(&d, priv_key.data(), 32);
    
    // Extract 64-byte Raw Public Key (Skip the 0x04 uncompressed identifier byte)
    pub_key.resize(64);
    uint8_t pub_buf[65];
    size_t olen;
    if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub_buf, sizeof(pub_buf)) == 0) {
        memcpy(pub_key.data(), pub_buf + 1, 64); 
    } else {
        ret = ESP_FAIL;
    }
    
cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}