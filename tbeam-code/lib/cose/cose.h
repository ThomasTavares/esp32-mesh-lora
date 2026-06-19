#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>
#include "esp_err.h"

// Constants for COSE Encryption
const uint8_t COSE_TAG_ENCRYPT0 = 16;
const int COSE_ALG_A256GCM = 3; // ID for AES-GCM-256

// Constants for COSE Signing
const uint8_t COSE_TAG_SIGN1 = 18;
const int COSE_ALG_ES256 = -7; // ID for ECDSA w/ SHA-256

class CoseCrypto {
private:
    static const size_t KEY_SIZE = 32; // 256 bits
    static const size_t IV_SIZE = 12;  // 96 bits (Standard for GCM)
    static const size_t TAG_SIZE = 16; // 128 bits
    static const size_t SIG_SIZE = 64; // 512 bits (32 bytes R + 32 bytes S for ES256)
    
public:
    /**
    * @brief Encrypts data using AES-256-GCM and formats it as a COSE_Encrypt0 message.
    * @param plaintext The data to encrypt.
    * @param key The 32-byte (256-bit) symmetric key.
    * @param out_cose_data The vector to store the resulting COSE message.
    * @return esp_err_t ESP_OK on success.
    */
    static esp_err_t encrypt(const std::vector<uint8_t>& plaintext, 
                             const std::vector<uint8_t>& key, 
                             std::vector<uint8_t>& out_cose_data);

    /**
    * @brief Decrypts a COSE_Encrypt0 message.
    * @param cose_data The COSE message to decrypt.
    * @param key The 32-byte (256-bit) symmetric key.
    * @param out_plaintext The vector to store the decrypted data.
    * @return esp_err_t ESP_OK on success.
    */
    static esp_err_t decrypt(const std::vector<uint8_t>& cose_data, 
                             const std::vector<uint8_t>& key, 
                             std::vector<uint8_t>& out_plaintext);

    /**
    * @brief Signs data using ECDSA (ES256) and formats it as a COSE_Sign1 message.
    * @param payload The data to sign.
    * @param private_key The 32-byte (256-bit) ECC private key (P-256).
    * @param out_cose_data The vector to store the resulting COSE message.
    * @return esp_err_t ESP_OK on success.
    */
    static esp_err_t sign(const std::vector<uint8_t>& payload, 
                          const std::vector<uint8_t>& private_key, 
                          std::vector<uint8_t>& out_cose_data);

    /**
    * @brief Verifies a COSE_Sign1 message.
    * @param cose_data The COSE message to verify.
    * @param public_key The 64-byte uncompressed ECC public key (X and Y coordinates).
    * @param out_payload The vector to store the extracted payload if verification succeeds.
    * @return esp_err_t ESP_OK on success.
    */
    static esp_err_t verify(const std::vector<uint8_t>& cose_data, 
                            const std::vector<uint8_t>& public_key, 
                            std::vector<uint8_t>& out_payload);

    /**
    * @brief Generates a random, mathematically valid P-256 keypair for testing.
    */
    static esp_err_t generate_test_keypair(std::vector<uint8_t>& priv_key, std::vector<uint8_t>& pub_key);
};