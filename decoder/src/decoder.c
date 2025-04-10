#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"

// Ejemplo usando cJSON (suponiendo que lo incluyas en tu proyecto)
#include "cJSON.h"

#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
extern int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);
extern int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);
extern int hash(void *data, size_t len, uint8_t *hash_out);
#endif

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

#define MAX_CHANNEL_COUNT 8
// Este define lo usabas para el "canal de emergencia". Aquí lo renombro a 0.
#define EMERGENCY_CHANNEL 0

#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF

#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32
#define CMAC_SIZE 16
#define ENCODER_ID_SIZE 8
#define NONCE_SIZE 8
#define HEADER_SIZE 16

#define FLASH_DEVICE_ID_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))
#define FLASH_STATUS_ADDR    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_KEYS_ADDR      ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

#pragma pack(push, 1)
typedef struct {
    channel_id_t channel;
    timestamp_t  timestamp;
    uint8_t      data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t  start_timestamp;
    timestamp_t  end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t  start;
    timestamp_t  end;
} channel_info_t;

typedef struct {
    uint32_t      n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

typedef struct {
    uint32_t seq_num;
    uint32_t channel;
    uint8_t  encoder_id[8];
    uint8_t  encrypted_data[];
} encoded_frame_t;

typedef struct {
    uint8_t master_key[KEY_SIZE];
    uint8_t signature_key[KEY_SIZE];
    uint8_t encoder_id[ENCODER_ID_SIZE];
} decoder_keys_t;
#pragma pack(pop)

typedef struct {
    bool         active;
    channel_id_t id;
    timestamp_t  start_timestamp;
    timestamp_t  end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t         first_boot;
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

// -------------------------------------------------------------
// Variables globales
// -------------------------------------------------------------
static flash_entry_t  decoder_status;
static decoder_keys_t decoder_keys;
static char           output_buf[128];

// Ejemplo de array para "channels" provenientes de secrets_1.bin
static uint32_t valid_channels_from_secrets[32];
static size_t   valid_channels_count = 0;

// Nombre de archivo JSON (en tu caso "secrets_1.bin", aunque contenga JSON)
static const char *SECRET_FILE_PATH = "secrets_1.bin";

#ifndef DECODER_ID
#define DECODER_ID 0xDEADBEEF
#endif

static decoder_id_t DEVICE_ID = DECODER_ID;

void boot_flag() {
    char flag_buf[64];
    sprintf(flag_buf, "boot flag: %p", boot_flag);
    print_debug(flag_buf);
}

void create_nonce_from_seq_channel(uint32_t seq_num, uint32_t channel_id, uint8_t *nonce) {
    memcpy(nonce, &seq_num, sizeof(uint32_t));
    memcpy(nonce + sizeof(uint32_t), &channel_id, sizeof(uint32_t));
}

/**
 * @brief Lee el archivo secrets_1.bin, parsea su contenido JSON y
 *        extrae el array "channels" para usarlo en el filtrado.
 *
 * @return true si tuvo éxito, false en caso de error.
 */
bool load_channels_from_secrets(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        print_error("No se pudo abrir secrets_1.bin");
        return false;
    }

    // Leer todo el contenido en memoria
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    rewind(fp);

    if (filesize <= 0) {
        fclose(fp);
        print_error("Tamaño inválido de secrets_1.bin");
        return false;
    }

    char *data = (char *)malloc(filesize + 1);
    if (!data) {
        fclose(fp);
        print_error("No hay memoria para leer secrets_1.bin");
        return false;
    }

    size_t read_count = fread(data, 1, filesize, fp);
    fclose(fp);

    if (read_count < (size_t)filesize) {
        free(data);
        print_error("Lectura incompleta de secrets_1.bin");
        return false;
    }
    data[filesize] = '\0';  // Aseguramos terminación en 0

    // Parsear JSON con cJSON (o la librería que dispongas)
    cJSON *root = cJSON_Parse(data);
    if (!root) {
        free(data);
        print_error("Error parseando el JSON de secrets_1.bin");
        return false;
    }

    cJSON *channels_array = cJSON_GetObjectItem(root, "channels");
    if (!channels_array || !cJSON_IsArray(channels_array)) {
        cJSON_Delete(root);
        free(data);
        print_error("No se encontró 'channels' o no es un array en secrets_1.bin");
        return false;
    }

    // Volcamos los canales al array global
    int array_size = cJSON_GetArraySize(channels_array);
    valid_channels_count = 0;
    for (int i = 0; i < array_size && i < 32; i++) {
        cJSON *item = cJSON_GetArrayItem(channels_array, i);
        if (cJSON_IsNumber(item)) {
            valid_channels_from_secrets[valid_channels_count++] = (uint32_t)item->valuedouble;
        }
    }

    cJSON_Delete(root);
    free(data);

    // Si quieres debug
    char dbg_buf[128];
    sprintf(dbg_buf, "Se leyeron %u canales del secrets_1.bin", (unsigned)valid_channels_count);
    print_debug(dbg_buf);

    return true;
}

/**
 * @brief Comprueba si el canal está en la lista proveniente del secrets_1.bin
 *        o si es el canal 0 (emergencia).
 */
bool channel_in_secrets(channel_id_t channel)
{
    // Si canal == 0 (emergencia) y quieres permitir siempre, descomenta:
    // if (channel == EMERGENCY_CHANNEL) {
    //     return true;
    // }

    for (size_t i = 0; i < valid_channels_count; i++) {
        if (valid_channels_from_secrets[i] == channel) {
            return true;
        }
    }
    return false;
}

// --------- is_subscribed se mantiene para el control de suscripciones --------
bool is_subscribed(channel_id_t channel)
{
    // En tu versión original, canal 0 es “emergencia” siempre visible:
    if (channel == EMERGENCY_CHANNEL) {
        return true;
    }

    time_t now = time(NULL);
    if (now < 0) {
        now = 0;
    }
    timestamp_t current_time = (timestamp_t) now;

    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active &&
            decoder_status.subscribed_channels[i].id == channel &&
            decoder_status.subscribed_channels[i].start_timestamp <= current_time &&
            decoder_status.subscribed_channels[i].end_timestamp   >= current_time)
        {
            return true;
        }
    }
    return false;
}

// Resto de funciones sin cambios...
// ---------------------------------------------------------------------

int find_free_channel_slot() {
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (!decoder_status.subscribed_channels[i].active) {
            return i;
        }
    }
    return -1;
}

void custom_print_hex(uint8_t *data, size_t len) {
    size_t pos = 0;
    for (size_t i = 0; i < len && pos < sizeof(output_buf)-3; i++) {
        pos += sprintf(output_buf + pos, "%02x", data[i]);
    }
    output_buf[pos] = '\0';
    print_debug(output_buf);
}

void list_channels() {
    list_response_t resp = {0};
    uint32_t channel_count = 0;
    char debug_buf[64];
    sprintf(debug_buf, "Listing channels...");
    print_debug(debug_buf);

    // Canal emergencia (0). Si quieres que aparezca como "1" a nivel de UI, ajusta aquí.
    resp.channel_info[channel_count].channel = EMERGENCY_CHANNEL;
    resp.channel_info[channel_count].start   = 0;
    resp.channel_info[channel_count].end     = 0xFFFFFFFFFFFFFFFF;
    channel_count++;

    // Suscripciones activas
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[channel_count].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[channel_count].start   = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[channel_count].end     = decoder_status.subscribed_channels[i].end_timestamp;
            channel_count++;
        }
    }
    resp.n_channels = channel_count;
    write_packet(LIST_MSG, &resp, sizeof(uint32_t) + channel_count * sizeof(channel_info_t));
}

int update_subscription(pkt_len_t pkt_len, uint8_t *raw_buf) {
    char debug_buf[64];
    // 1) leer encoder_id (8 bytes) - no se usa
    uint8_t encoder_id[8];
    memcpy(encoder_id, raw_buf, 8);

    subscription_update_packet_t *sub_ptr = (subscription_update_packet_t *)(raw_buf + 8);
    print_debug("Updating subscription");
    sprintf(debug_buf, "Subscription: Device ID=%u, Channel=%u",
            sub_ptr->decoder_id, sub_ptr->channel);
    print_debug(debug_buf);

    if (sub_ptr->decoder_id != DEVICE_ID) {
        print_error("Subscription not for this device");
        return -1;
    }

#ifdef CRYPTO_EXAMPLE
    size_t subscription_data_len = 8 + sizeof(subscription_update_packet_t); // 8+24 = 32
    if (pkt_len < (subscription_data_len + CMAC_SIZE)) {
        print_error("Invalid subscription packet length");
        return -1;
    }
    uint8_t *signature = raw_buf + subscription_data_len;
    if (verify_aes_cmac(decoder_keys.signature_key, raw_buf, subscription_data_len, signature) != 1) {
        print_error("Invalid subscription signature");
        return -1;
    }
#endif
    int slot = find_free_channel_slot();
    if (slot < 0) {
        print_error("No free subscription slots");
        return -1;
    }
    decoder_status.subscribed_channels[slot].active = true;
    decoder_status.subscribed_channels[slot].id     = sub_ptr->channel;
    decoder_status.subscribed_channels[slot].start_timestamp = sub_ptr->start_timestamp;
    decoder_status.subscribed_channels[slot].end_timestamp   = sub_ptr->end_timestamp;

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    print_debug("Subscription updated and saved");
    return 0;
}

int decode(pkt_len_t frame_len, frame_packet_t *new_frame) {
    char debug_buf[64];
    print_debug("Checking if channel is valid in secrets...");

    // -------- NUEVO: Comprobar si el canal está dentro de 'channels' del secrets_1.bin
    if (!channel_in_secrets(new_frame->channel)) {
        sprintf(debug_buf, "Canal %u NO está en la lista de secrets_1.bin. Se descarta.", new_frame->channel);
        print_error(debug_buf);
        return -1;
    }

    // -------- Comprobación normal de suscripción
    print_debug("Checking subscription");
    if (!is_subscribed(new_frame->channel)) {
        STATUS_LED_RED();
        sprintf(debug_buf, "Receiving unsubscribed channel data: %u", new_frame->channel);
        print_error(debug_buf);
        return -1;
    }
    print_debug("Subscription Valid");

#ifdef CRYPTO_EXAMPLE
    encoded_frame_t *encoded_frame = (encoded_frame_t *)new_frame;

    // Para canales normales, se verifica replay y encoder_id.
    if (new_frame->channel != EMERGENCY_CHANNEL) {
        if (encoded_frame->seq_num <= last_seq_num && last_seq_num > 0) {
            print_error("Possible replay attack detected");
            return -1;
        }
        last_seq_num = encoded_frame->seq_num;
        if (memcmp(encoded_frame->encoder_id, decoder_keys.encoder_id, ENCODER_ID_SIZE) != 0) {
            print_error("Invalid encoder ID");
            return -1;
        }
    }

    // Decidir qué clave usar
    uint8_t *key;
    if (new_frame->channel == EMERGENCY_CHANNEL) {
        key = decoder_keys.master_key;
    } else {
        // Ten cuidado si new_frame->channel es muy grande y no cabe en channel_keys[].
        // Este array era de tamaño MAX_CHANNEL_COUNT, indexado por i, no por el valor.
        // Si es un canal "grande" (por ej. 4294967295), necesitarías una tabla/dictionary real.
        // El ejemplo original no contemplaba canal > 7 en channel_keys.
        // Aquí simplemente supón que tienes otra forma de obtener la clave,
        // o has adaptado tu derive_key_from_master() en tiempo de arranque.
        key = channel_keys[0]; // <-- DEBES cambiar la forma de obtener la key real
    }

    uint8_t nonce[NONCE_SIZE];
    create_nonce_from_seq_channel(encoded_frame->seq_num, new_frame->channel, nonce);
    size_t encrypted_data_size = frame_len - HEADER_SIZE;
    if (encrypted_data_size < 12) {
        print_error("Frame too small");
        return -1;
    }
    uint8_t decrypted_data[FRAME_SIZE + 12];
    int result = aes_ctr_crypt(key,
                               encoded_frame->encrypted_data,
                               encrypted_data_size,
                               nonce,
                               decrypted_data);
    if (result != 0) {
        sprintf(debug_buf, "Decryption failed with error %d", result);
        print_error(debug_buf);
        return -1;
    }

    // ...
    // En ambos casos, se elimina el bloque final de 12 bytes (timestamp + seq_num)
    write_packet(DECODE_MSG, decrypted_data, encrypted_data_size - 12);
    (void)get_msg();
#endif
    return 0;
}

void init() {
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        print_debug("First boot. Setting flash...");
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        channel_status_t subscription[MAX_CHANNEL_COUNT];
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp   = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }
        flash_simple_erase_page(FLASH_DEVICE_ID_ADDR);
        flash_simple_write(FLASH_DEVICE_ID_ADDR, &DEVICE_ID, sizeof(decoder_id_t));
        memcpy(decoder_status.subscribed_channels, subscription, sizeof(subscription));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
#ifdef CRYPTO_EXAMPLE
        memset(decoder_keys.master_key,    0x42, KEY_SIZE);
        memset(decoder_keys.signature_key, 0x43, KEY_SIZE);
        memset(decoder_keys.encoder_id,    0x44, ENCODER_ID_SIZE);
        flash_simple_erase_page(FLASH_KEYS_ADDR);
        flash_simple_write(FLASH_KEYS_ADDR, &decoder_keys, sizeof(decoder_keys_t));
#endif
    } else {
        flash_simple_read(FLASH_KEYS_ADDR, &decoder_keys, sizeof(decoder_keys_t));
    }

    // -------- NUEVO: cargar el archivo secrets_1.bin y parsear 'channels' --------
    if (!load_channels_from_secrets(SECRET_FILE_PATH)) {
        print_error("No se pudieron cargar los canales de secrets_1.bin, algunos canales se bloquearán");
    }

    int ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        while (1);
    }
}

int main(void) {
    char     debug_buf[64];
    uint8_t  uart_buf[100];
    msg_type_t cmd;
    int      result;
    uint16_t pkt_len;

    init();
    print_debug("Decoder Booted!");

    while (1) {
        print_debug("Ready");
        STATUS_LED_GREEN();
        result = read_packet(&cmd, uart_buf, &pkt_len);
        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host");
            continue;
        }
        switch (cmd) {
            case LIST_MSG:
                STATUS_LED_CYAN();
#ifdef CRYPTO_EXAMPLE
                // ...
#endif
                boot_flag();
                list_channels();
                break;

            case DECODE_MSG:
                STATUS_LED_PURPLE();
                decode(pkt_len, (frame_packet_t *)uart_buf);
                break;

            case SUBSCRIBE_MSG:
                STATUS_LED_YELLOW();
                if (update_subscription(pkt_len, uart_buf) == 0) {
                    write_packet(SUBSCRIBE_MSG, NULL, 0);
                }
                break;

            default:
                STATUS_LED_ERROR();
                sprintf(debug_buf, "Invalid Command: %c", cmd);
                print_error(debug_buf);
                break;
        }
    }
}
