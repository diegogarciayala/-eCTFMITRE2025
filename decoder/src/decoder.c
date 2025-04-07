/**
 * @file    decoder.c
 * @author  TrustLab Team
 * @brief   eCTF Secure Satellite TV Decoder Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"

/**********************************************************
 **************** FUNCTION DECLARATIONS *******************
 **********************************************************/
// Flash memory operations
int simple_flash_page_erase(uint32_t addr);
int simple_flash_write(uint32_t addr, uint8_t* data, int len);
int simple_flash_read(uint32_t addr, uint8_t* data, int len);

// Host communication
void init_host_communication(void);

/**********************************************************
 *********** COMMUNICATION COMMAND DEFINITIONS ************
 **********************************************************/
// Command definitions
#define LIST_CMD        0x01
#define SUBSCRIBE_CMD   0x02
#define FRAME_CMD       0x03

// Response definitions
#define SUCCESS         0x80
#define ERROR           0x81
#define RESULT          0x82
#define FRAME_OUT       0x83

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the project.mk file. */
#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"

// Forward declarations for crypto functions
extern int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);
extern int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);
extern int hash(void *data, size_t len, uint8_t *hash_out);
#endif

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

// Cryptography constants
#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32
#define CMAC_SIZE 16
#define ENCODER_ID_SIZE 8
#define NONCE_SIZE 8
#define HEADER_SIZE 12  // 4-byte seq_num + 4-byte channel + 4-byte encoder_id
#define FLASH_DEVICE_ID_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))

// Flash storage
// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
// Calculate the flash address where master keys are stored
#define FLASH_KEYS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

#pragma pack(push, 1)
typedef struct {
    uint32_t         encoder_id;        // 4 bytes
    decoder_id_t     decoder_id;        // 4 bytes (tipo uint32_t)
    timestamp_t      start_timestamp;   // 8 bytes
    timestamp_t      end_timestamp;     // 8 bytes
    channel_id_t     channel;           // 4 bytes
} subscription_with_id_t;
#pragma pack(pop)

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

// Custom frame structures for our implementation
typedef struct {
    uint32_t seq_num;         // Sequence number for this frame
    uint32_t channel;         // Channel ID
    uint8_t encoder_id[8];    // Encoder ID (8 bytes)
    uint8_t encrypted_data[]; // Variable length encrypted data
} encoded_frame_t;

// Structure for master keys stored in flash
typedef struct {
    uint8_t master_key[KEY_SIZE];
    uint8_t signature_key[KEY_SIZE];
    uint8_t encoder_id[ENCODER_ID_SIZE];
} decoder_keys_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

// Track last sequence number to prevent replay attacks
uint32_t last_seq_num = 0;

// Master keys and encoder ID
decoder_keys_t decoder_keys;

// Derived keys for each channel
uint8_t channel_keys[MAX_CHANNEL_COUNT][KEY_SIZE];

// Buffer for debug output
char output_buf[128];

decoder_id_t DEVICE_ID = 0; // Inicializado a 0

/**********************************************************
 ******************** REFERENCE FLAG **********************
 **********************************************************/

/* DO NOT MODIFY THIS FUNCTION! This is the 'flag' code that
 * the automated grader is looking for. This function should
 * be called from your main */
void boot_flag() {
    // If the program calls this function, the flag will be read and printed
    char flag_buf[64];
    sprintf(flag_buf, "boot flag: %p", boot_flag);
    print_debug(flag_buf);
}

/**********************************************************
 ***************** CRYPTO HELPER FUNCTIONS ****************
 **********************************************************/

/**
 * @brief Create a nonce from sequence number and channel ID
 *
 * @param seq_num Sequence number
 * @param channel_id Channel ID
 * @param nonce Output buffer for nonce (8 bytes)
 */
void create_nonce_from_seq_channel(uint32_t seq_num, uint32_t channel_id, uint8_t *nonce) {
    // Pack seq_num (4 bytes) and channel_id (4 bytes) into a 8-byte nonce
    memcpy(nonce, &seq_num, sizeof(uint32_t));
    memcpy(nonce + sizeof(uint32_t), &channel_id, sizeof(uint32_t));
}

#ifdef CRYPTO_EXAMPLE
/**
 * @brief Implement AES-CTR encryption/decryption
 *
 * @param key The encryption/decryption key
 * @param in Input data
 * @param len Length of input data
 * @param nonce The nonce for CTR mode
 * @param out Output buffer for results
 * @return int 0 on success, error code otherwise
 */
int aes_ctr_crypt(uint8_t *key, uint8_t *in, size_t len, uint8_t *nonce, uint8_t *out) {
    // For this implementation, we'll use ECB mode to simulate CTR
    // This is a simplified version for the CTF context

    // Create a counter block
    uint8_t counter_block[AES_BLOCK_SIZE];
    uint8_t encrypted_counter[AES_BLOCK_SIZE];
    uint32_t counter = 0;
    int result;

    // For each block
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        // Create the counter block = nonce + counter
        memcpy(counter_block, nonce, NONCE_SIZE);
        memcpy(counter_block + NONCE_SIZE, &counter, sizeof(counter));
        counter++;

        // Encrypt the counter
        result = encrypt_sym(counter_block, AES_BLOCK_SIZE, key, encrypted_counter);
        if (result != 0) {
            return result;
        }

        // XOR the input with the encrypted counter
        for (size_t j = 0; j < AES_BLOCK_SIZE && (i + j) < len; j++) {
            out[i + j] = in[i + j] ^ encrypted_counter[j];
        }
    }

    return 0;
}

/**
 * @brief Implement AES-CMAC for message authentication
 *
 * @param key The key used for CMAC
 * @param message The message to authenticate
 * @param len Length of the message
 * @param mac Output buffer for the CMAC value (16 bytes)
 * @return int 0 on success, error code otherwise
 */
int aes_cmac(uint8_t *key, uint8_t *message, size_t len, uint8_t *mac) {
    // Simplified CMAC implementation for CTF
    // In a real-world scenario, use a proper CMAC implementation

    // For simplicity, we're using AES in ECB mode and padding
    uint8_t padded_message[AES_BLOCK_SIZE * ((len / AES_BLOCK_SIZE) + 1)];
    memset(padded_message, 0, sizeof(padded_message));
    memcpy(padded_message, message, len);

    // Add padding
    padded_message[len] = 0x80;  // 1 followed by zeros

    // Encrypt the last block to generate the MAC
    size_t padded_len = ((len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    return encrypt_sym(padded_message + padded_len - AES_BLOCK_SIZE,
                       AES_BLOCK_SIZE, key, mac);
}

/**
 * @brief Verify a CMAC value against a message
 *
 * @param key The key used for CMAC
 * @param message The message to verify
 * @param len Length of the message
 * @param mac The CMAC value to verify against
 * @return int 1 if verified, 0 if not verified, negative on error
 */
int verify_aes_cmac(uint8_t *key, uint8_t *message, size_t len, uint8_t *mac) {
    uint8_t calculated_mac[CMAC_SIZE];
    int result = aes_cmac(key, message, len, calculated_mac);

    if (result != 0) {
        return result;
    }

    // Compare the MACs
    if (memcmp(calculated_mac, mac, CMAC_SIZE) == 0) {
        return 1;  // Verified
    } else {
        return 0;  // Not verified
    }
}

/**
 * @brief Derive a key from the master key using AES-CMAC
 *
 * @param master_key The master key
 * @param context Context string for key derivation
 * @param salt Optional salt for additional entropy (can be NULL)
 * @param derived_key Output buffer for the derived key
 * @return int 0 on success, error code otherwise
 */
int derive_key_from_master(uint8_t *master_key, const char *context,
                           uint8_t *salt, uint8_t *derived_key) {
    // Create a context message: salt + context string
    uint8_t context_message[64];
    size_t context_len = 0;

    if (salt != NULL) {
        memcpy(context_message, salt, 16);
        context_len += 16;
    }

    size_t context_str_len = strlen(context);
    memcpy(context_message + context_len, context, context_str_len);
    context_len += context_str_len;

    // First 16 bytes - use CMAC directly
    int result = aes_cmac(master_key, context_message, context_len, derived_key);
    if (result != 0) {
        return result;
    }

    // For the second 16 bytes, modify the context slightly
    context_message[context_len] = 0x01;
    return aes_cmac(master_key, context_message, context_len + 1, derived_key + CMAC_SIZE);
}
#endif

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

// This function checks if the decoder is currently subscribed to a channel
// by looping through the active channel subscriptions
bool is_subscribed(channel_id_t channel) {
    // Emergency channel is always subscribed
    if (channel == EMERGENCY_CHANNEL) {
        return true;
    }

    timestamp_t current_time = 0;  // In a real system this would be a real timestamp

    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active &&
            decoder_status.subscribed_channels[i].id == channel &&
            decoder_status.subscribed_channels[i].start_timestamp <= current_time &&
            decoder_status.subscribed_channels[i].end_timestamp >= current_time) {
            return true;
        }
    }
    return false;
}

int find_free_channel_slot() {
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (!decoder_status.subscribed_channels[i].active) {
            return i;
        }
    }
    // No free slots
    return -1;
}

// Custom function for printing hex data in debug
void custom_print_hex(uint8_t *data, size_t len) {
    size_t pos = 0;

    for (size_t i = 0; i < len && pos < sizeof(output_buf)-3; i++) {
        pos += sprintf(output_buf + pos, "%02x", data[i]);
    }

    output_buf[pos] = '\0';
    print_debug(output_buf);
}

/**
 * @brief Initialize the derived channel keys from the master key
 *
 * @return int 0 on success, error code otherwise
 */
int initialize_channel_keys() {
    char context[32];

    // Derive keys for each channel
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        sprintf(context, "CHANNEL_%d", i);

        #ifdef CRYPTO_EXAMPLE
        // Use the decoder_id as salt for additional key diversity
        uint8_t salt[16];
        memset(salt, 0, sizeof(salt));
        memcpy(salt, &DEVICE_ID, sizeof(DEVICE_ID));

        int result = derive_key_from_master(decoder_keys.master_key, context, salt, channel_keys[i]);
        if (result != 0) {
            sprintf(output_buf, "Error deriving key for channel %d: %d", i, result);
            print_debug(output_buf);
            return result;
        }
        #endif
    }

    return 0;
}

/**
 * @brief Process a subscription message and update channel subscriptions
 *
 * @param subscription Pointer to subscription data
 * @param len Length of subscription data
 * @return int 0 on success, negative on error
 */
int process_subscription(uint8_t *subscription, size_t len) {
    // Subscription format: encoder_id (8 bytes) + subscription_data (20 bytes) + signature (16 bytes)
    if (len < (ENCODER_ID_SIZE + sizeof(subscription_with_id_t) + CMAC_SIZE)) {
        print_debug("Invalid subscription length");
        return -1;
    }

    // Extract subscription components
    uint8_t *encoder_id_ptr = subscription;
    subscription_with_id_t *sub_data = (subscription_with_id_t*)(subscription + ENCODER_ID_SIZE);
    // Get signature position (used for verification in CRYPTO_EXAMPLE)
uint8_t *signature_ptr = subscription + ENCODER_ID_SIZE + sizeof(subscription_with_id_t);

    // Verify encoder ID matches the one stored
    if (memcmp(encoder_id_ptr, decoder_keys.encoder_id, ENCODER_ID_SIZE) != 0) {
        print_debug("Encoder ID mismatch");
        return -2;
    }

    // Verify decoder ID matches this device
    if (sub_data->decoder_id != DEVICE_ID) {
        sprintf(output_buf, "Decoder ID mismatch: expected %u, got %u", DEVICE_ID, sub_data->decoder_id);
        print_debug(output_buf);
        return -3;
    }

    #ifdef CRYPTO_EXAMPLE
    // Verify signature using AES-CMAC
    if (verify_aes_cmac(decoder_keys.signature_key,
                        subscription,
                        ENCODER_ID_SIZE + sizeof(subscription_with_id_t),
                        signature_ptr) != 1) {
        print_debug("Signature verification failed");
        return -4;
    }
    #endif

    // Find a free slot or existing subscription for this channel
    int slot = -1;
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active &&
            decoder_status.subscribed_channels[i].id == sub_data->channel) {
            slot = i;
            break;
        }
    }

    // If no existing subscription, find a free slot
    if (slot == -1) {
        slot = find_free_channel_slot();
        if (slot == -1) {
            print_debug("No free channel slots available");
            return -5;
        }
    }

    // Update or create subscription
    decoder_status.subscribed_channels[slot].active = true;
    decoder_status.subscribed_channels[slot].id = sub_data->channel;
    decoder_status.subscribed_channels[slot].start_timestamp = sub_data->start_timestamp;
    decoder_status.subscribed_channels[slot].end_timestamp = sub_data->end_timestamp;

    // Update flash with new subscription info
    if (simple_flash_page_erase(FLASH_STATUS_ADDR) != 0) {
        print_debug("Failed to erase flash page for subscription update");
        return -6;
    }

    if (simple_flash_write(FLASH_STATUS_ADDR, (uint8_t*)&decoder_status, sizeof(decoder_status)) != 0) {
        print_debug("Failed to write subscription to flash");
        return -7;
    }

    sprintf(output_buf, "Added subscription for channel %u, from %llu to %llu",
            sub_data->channel, sub_data->start_timestamp, sub_data->end_timestamp);
    print_debug(output_buf);

    return 0;
}

/**
 * @brief Process an encoded frame and decrypt it if valid
 *
 * @param frame Pointer to encoded frame
 * @param len Length of the encoded frame
 * @param output Pointer to output buffer for decoded frame
 * @return int Number of bytes in decoded frame, or negative on error
 */
int process_frame(uint8_t *frame, size_t len, uint8_t *output) {
    // Ensure frame is large enough for minimum structure
    if (len < sizeof(encoded_frame_t)) {
        print_debug("Frame too small");
        return -1;
    }

    // Parse the frame header
    encoded_frame_t *enc_frame = (encoded_frame_t*)frame;
    uint32_t seq_num = enc_frame->seq_num;
    uint32_t channel_id = enc_frame->channel;

    // Calculate encrypted data size
    size_t encrypted_data_len = len - sizeof(encoded_frame_t);

    // Check sequence number to prevent replay attacks
    if (seq_num <= last_seq_num && last_seq_num != 0) {
        sprintf(output_buf, "Replay attack detected: seq_num %u <= last_seq_num %u", seq_num, last_seq_num);
        print_debug(output_buf);
        return -2;
    }

    // Update last sequence number
    last_seq_num = seq_num;

    // Verify subscription for this channel
    if (!is_subscribed(channel_id)) {
        sprintf(output_buf, "Not subscribed to channel %u", channel_id);
        print_debug(output_buf);
        return -3;
    }

    #ifdef CRYPTO_EXAMPLE
    // Create nonce from sequence number and channel ID
    uint8_t nonce[NONCE_SIZE];
    create_nonce_from_seq_channel(seq_num, channel_id, nonce);

    // Get the appropriate key for this channel
    uint8_t *channel_key = channel_keys[channel_id % MAX_CHANNEL_COUNT];

    // Decrypt the frame data
    int result = aes_ctr_crypt(channel_key,
                              enc_frame->encrypted_data,
                              encrypted_data_len,
                              nonce,
                              output);

    if (result != 0) {
        sprintf(output_buf, "Decryption failed with error: %d", result);
        print_debug(output_buf);
        return -4;
    }
    #else
    // For non-crypto builds, just copy the data (for testing)
    memcpy(output, enc_frame->encrypted_data, encrypted_data_len);
    #endif

    // Extract timestamp from decrypted data (assuming timestamp is at the end of the frame)
    timestamp_t timestamp;
    memcpy(&timestamp, output + encrypted_data_len - sizeof(timestamp_t) - sizeof(uint32_t), sizeof(timestamp_t));

    // For real systems: validate timestamp to ensure it's within acceptable range

    // Create the frame packet for TV
    frame_packet_t tv_frame;
    tv_frame.channel = channel_id;
    tv_frame.timestamp = timestamp;

    // Copy frame data (excluding timestamp and sequence number at the end)
    size_t actual_frame_size = encrypted_data_len - sizeof(timestamp_t) - sizeof(uint32_t);
    if (actual_frame_size > FRAME_SIZE) {
        actual_frame_size = FRAME_SIZE;
    }

    memcpy(tv_frame.data, output, actual_frame_size);

    // Copy the final frame to output
    memcpy(output, &tv_frame, sizeof(frame_packet_t));

    sprintf(output_buf, "Decoded frame for channel %u, seq %u, timestamp %llu",
            channel_id, seq_num, timestamp);
    print_debug(output_buf);

    return sizeof(frame_packet_t);
}

/**
 * @brief List all active subscriptions
 */
void list_subscriptions() {
    list_response_t response;
    response.n_channels = 0;

    // Emergency channel is always available
    response.channel_info[response.n_channels].channel = EMERGENCY_CHANNEL;
    response.channel_info[response.n_channels].start = 0;
    response.channel_info[response.n_channels].end = DEFAULT_CHANNEL_TIMESTAMP;
    response.n_channels++;

    // Add all active subscriptions
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active &&
            decoder_status.subscribed_channels[i].id != EMERGENCY_CHANNEL) {
            response.channel_info[response.n_channels].channel = decoder_status.subscribed_channels[i].id;
            response.channel_info[response.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            response.channel_info[response.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            response.n_channels++;

            if (response.n_channels >= MAX_CHANNEL_COUNT) {
                break;
            }
        }
    }

    // Send the response
    write_packet(RESP_MSG, &response, sizeof(uint32_t) + (response.n_channels * sizeof(channel_info_t)));
}

/**
 * @brief Initialize the decoder
 */
void initialize_decoder() {
    // First, try to read the device ID from flash
    simple_flash_read(FLASH_DEVICE_ID_ADDR, (uint8_t*)&DEVICE_ID, sizeof(DEVICE_ID));

    sprintf(output_buf, "Device ID: %u", DEVICE_ID);
    print_debug(output_buf);

    // Try to read the status from flash
    simple_flash_read(FLASH_STATUS_ADDR, (uint8_t*)&decoder_status, sizeof(decoder_status));

    // If this is the first boot, initialize the flash
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        print_debug("First boot detected, initializing flash");

        // Initialize the decoder status
        memset(&decoder_status, 0, sizeof(decoder_status));
        decoder_status.first_boot = FLASH_FIRST_BOOT;

        // Set up emergency channel subscription
        decoder_status.subscribed_channels[0].active = true;
        decoder_status.subscribed_channels[0].id = EMERGENCY_CHANNEL;
        decoder_status.subscribed_channels[0].start_timestamp = 0;
        decoder_status.subscribed_channels[0].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;

        // Write the initialized status to flash
        if (simple_flash_page_erase(FLASH_STATUS_ADDR) != 0) {
            print_debug("Failed to erase flash for initialization");
            return;
        }

        if (simple_flash_write(FLASH_STATUS_ADDR, (uint8_t*)&decoder_status, sizeof(decoder_status)) != 0) {
            print_debug("Failed to write initial status to flash");
            return;
        }
    }

    // Try to read the keys from flash
    simple_flash_read(FLASH_KEYS_ADDR, (uint8_t*)&decoder_keys, sizeof(decoder_keys));

    // Initialize the channel keys
    initialize_channel_keys();
}

/**
 * @brief Main function
 */
int main(void) {
    // Initialize UART for host communication
    init_host_communication();

    // Print startup message
    print_debug("Satellite TV Decoder starting up...");

    // Call boot flag for reference
    boot_flag();

    // Initialize the decoder
    initialize_decoder();

    // Buffer for incoming messages
    uint8_t message_buf[512];
    uint8_t output_buf[512];
    uint16_t len;
    msg_type_t cmd;

    // Main loop
    while (1) {
        if (read_packet(&cmd, message_buf, &len) == 0) {
            switch (cmd) {
                case LIST_MSG:
                    // List active subscriptions
                    list_subscriptions();
                    break;

                case SUBSCRIBE_MSG:
                    // Process subscription message
                    if (process_subscription(message_buf, len) == 0) {
                        write_packet(DEBUG_MSG, NULL, 0);
                    } else {
                        write_packet(ERROR_MSG, NULL, 0);
                    }
                    break;

                case DECODE_MSG:
                    // Process an encoded frame
                    int result = process_frame(message_buf, len, output_buf);
                    if (result > 0) {
                        write_packet(FRAME_MSG, output_buf, result);
                    } else {
                        write_packet(ERROR_MSG, NULL, 0);
                    }
                    break;

                default:
                    // Unknown command
                    write_packet(ERROR_MSG, NULL, 0);
                    break;
            }
        }
    }

    return 0;
}
