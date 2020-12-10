/* BSD Socket API Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <sys/param.h>
#include "driver/i2c.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/event_groups.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/err.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "sodium/crypto_auth_hmacsha256.h"

#include "bme680.h"
#include "bsec_datatypes.h"
#include "bsec_interface.h"
#include "bsec_integration.h"
#include "bsec_serialized_configurations_iaq.h"

#include "config.h"

#define BSEC_SAVE_INTERVAL_MEASUREMENTS (CONFIG_BSEC_SAVE_INTERVAL_SECONDS / 3)

#define STATUS_LED_GPIO_NUM 2
#define STATUS_LED_INVERTED 1

#define I2C_BME680_MASTER_NUM I2C_NUM_0
#define I2C_BME680_MASTER_SCL_IO 12
#define I2C_BME680_MASTER_SDA_IO 14

// BEACON PACKET STRUCTURE
//
// struct packet {
//      struct signed {
//          version             u8
//          bsec_status         u8
//          iaq_accuracy        u8
//          [padding]           u8
//          name                char[16]
//          counter             u64
//          iaq                 f32
//          temperature         f32
//          humidity            f32
//          pressure            f32
//          raw_temperature     f32
//          raw_humidity        f32
//          gas                 f32
//          static_iaq          f32
//          co2_equivalent      f32
//          breath_voc_equivalent f32
//      }
//      mac      u8[32]
// }
//
// version:     The protocol version. MUST be 0x02.
//
// name:        The identifier of the sending node, this SHOULD be a ascii encoded
//              string with the name/description of the node. This string must be
//              padded with zero bytes.
//              examples: "bedroom\0\0\0\0\0\0\0\0\0"/"feynman\0\0\0\0\0\0\0\0\0"
//
// counter:     A 64-bit sequence number. The receiver MUST keep a counter which
//              contains the last counter value it has seen from this identifier.
//              If an HMAC-authenticated packet contains a counter with a value
//              less than the saved counter, the reciever MUST silently drop the
//              beacon packet.
//
// bsec_status: The bsec status. 0 equals ok, other values indicate an error.
//
// iaq_accuracy:
//              The accuracy if the reported IAQ and values derived from that. These
//              values are really only accurate if this value is equal to 3.
//
// iaq          Indoor air quality value.  Use static_iaq when this device
//              is stationary.
//
// temperature: Floating point temperature value. [Celsius]
//
// humidity:    Humidity value. [percent]
//
// pressure:    Pressure value. [Pascal]
//
// raw_temperature:
//              Raw (uncompensated) temperature. [Celsius]
//
// raw_humidity:
//              Raw (uncompensated) humidity. [percent]
//
// gas:         Gas resistance measured. [Ohm]
//
// static_iaq:  Static indoor air quality metric.  The normal IAQ is avaraged
//              using previous measurements.  Bosch recommends using this
//              value when the device is in a static location.
//              Use the IAQ when the ESP8266 is a part of a carry-on device.
//
// co2_equivalent:
//              Amount of CO2 resulting from estimating using the static IAQ.
//              This value is *not* the actual CO2 in the air; it is only an
//              *estimate*. [ppm]
//
// breath_voc_equivalent:
//              Amount of volatile organic compounds (VOCs) in the air,
//              equivalent the static IAQ value.
//
// mac:     A 32-bit HMAC-SHA256 signature over the `signed` struct using the
//          node's pre-shared key. The receiver MUST NOT read any values of
//          the packet before verifying this value, with the exception of the
//          `version`, `name` values, which can be used to identify the key
//          that has been used.

typedef struct bme680_measurement
{
    int64_t timestamp;
    float iaq;
    uint8_t iaq_accuracy;
    float temperature;
    float humidity;
    float pressure;
    float raw_temperature;
    float raw_humidity;
    float gas;
    bsec_library_return_t bsec_status;
    float static_iaq;
    float co2_equivalent;
    float breath_voc_equivalent;
} bme680_measurement_t;

// Logging tag
static const char *TAG = "bme680_beacon";

// FreeRTOS event group to signal when we are connected & ready to make a request
static EventGroupHandle_t event_group_wifi;

// FreeRTOS event group to signal that a component has an error
static EventGroupHandle_t event_group_status_led;
static const uint32_t event_group_status_led_bme680_read_err = 1 << 0;
static const uint32_t event_group_status_led_udp_client_err = 1 << 1;

// FreeRTOS queue that will channel the bme680 measurements from the bme680
// manager task to the network sender task.
static QueueHandle_t queue_bme680_measurement;

// Packet counter.
static volatile uint64_t udp_client_packet_counter = 0;

const int IPV4_GOTIP_BIT = BIT0;

static int8_t bsec_driver_i2c_write(uint8_t dev_id, uint8_t reg_addr, uint8_t *data, uint16_t len)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (dev_id << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, reg_addr, true);
    i2c_master_write(cmd, data, len, true);
    i2c_master_stop(cmd);
    esp_err_t err = i2c_master_cmd_begin(I2C_BME680_MASTER_NUM, cmd, 1000 / CONFIG_FREERTOS_HZ);
    i2c_cmd_link_delete(cmd);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "i2c write failed: %d", err);
        return BME680_E_COM_FAIL;
    }
    return BME680_OK;
}

static int8_t bsec_driver_i2c_read(uint8_t dev_id, uint8_t reg_addr, uint8_t *data, uint16_t len)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (dev_id << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, reg_addr, true);
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (dev_id << 1) | I2C_MASTER_READ, true);
    for (uint16_t idx = 0; idx < len; idx++)
    {
        i2c_ack_type_t ack = idx == (len - 1) ? I2C_MASTER_NACK : I2C_MASTER_ACK;
        i2c_master_read_byte(cmd, &data[idx], ack);
    }
    i2c_master_stop(cmd);
    esp_err_t err = i2c_master_cmd_begin(I2C_BME680_MASTER_NUM, cmd, 10);
    i2c_cmd_link_delete(cmd);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "i2c read failed: %d", err);
        return BME680_E_COM_FAIL;
    }
    return BME680_OK;
}

static void bsec_driver_sleep_ms(uint32_t delay_ms)
{
    vTaskDelay(delay_ms * CONFIG_FREERTOS_HZ / 1000);
}

static uint32_t bsec_driver_state_load(uint8_t *state_buffer, uint32_t n_buffer_)
{
    nvs_handle nvs;
    esp_err_t err;
    uint32_t n_buffer = n_buffer_;

    const char *namespace = "app";
    const char *key = "bsec_state";

    ESP_LOGI(TAG, "nvs: loading bsec state");
    err = nvs_open("app", NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGW(TAG, "nvs: namespace '%s' does not exist", namespace);
        return 0;
    }
    else if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "nvs: failed to open '%s' namespace: errno 0x%x", namespace, err);
        return 0;
    }
    err = nvs_get_blob(nvs, key, state_buffer, &n_buffer);
    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGW(TAG, "nvs: '%s' key does not exist", key);
        nvs_close(nvs);
        return 0;
    }
    else if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "nvs: error reading '%s': errno 0x%x", key, err);
        nvs_close(nvs);
        return 0;
    }
    ESP_LOGI(TAG, "nvs: successfully read bsec state (length=%d)", n_buffer);
    nvs_close(nvs);
    return n_buffer;
}

static void bsec_driver_state_save(const uint8_t *state_buffer, uint32_t length)
{
    nvs_handle nvs;
    esp_err_t err;

    const char *namespace = "app";
    const char *key = "bsec_state";

    ESP_LOGI(TAG, "nvs: saving bsec state");
    err = nvs_open(namespace, NVS_READWRITE, &nvs);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "nvs: failed to open '%s' namespace: errno 0x%x", namespace, err);
        return;
    }
    err = nvs_erase_key(nvs, key);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "nvs: failed erasing %s: errno 0x%x", key, err);
    }
    err = nvs_set_blob(nvs, key, state_buffer, length);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "nvs: failed to save %s: errno %d", key, err);
        nvs_close(nvs);
        return;
    }
    err = nvs_commit(nvs);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "nvs: failed to commit changes: errno %d", err);
        nvs_close(nvs);
        return;
    }
    ESP_LOGI(TAG, "nvs: successfully saved %s (length=%d)", key, length);
    nvs_close(nvs);
}

static uint32_t bsec_driver_config_load(uint8_t *config_buffer, uint32_t n_buffer)
{
    memcpy(config_buffer, bsec_config_iaq, sizeof(bsec_config_iaq));
    return sizeof(bsec_config_iaq);
}

static int64_t bsec_driver_get_timestamp_us()
{
    struct timeval tv;
    struct timezone tz;
    if (gettimeofday(&tv, &tz) != 0)
    {
        ESP_LOGE(TAG, "gettimeofday failed");
        return 0;
    }
    return (1e6 * (int64_t)tv.tv_sec) + (int64_t)tv.tv_usec;
}

static void bsec_driver_output_ready(int64_t timestamp, float iaq, uint8_t iaq_accuracy, float temperature, float humidity,
                                     float pressure, float raw_temperature, float raw_humidity, float gas, bsec_library_return_t bsec_status,
                                     float static_iaq, float co2_equivalent, float breath_voc_equivalent)
{
    bme680_measurement_t m = {
        .timestamp = timestamp,
        .iaq = iaq,
        .iaq_accuracy = iaq_accuracy,
        .temperature = temperature,
        .humidity = humidity,
        .pressure = pressure,
        .raw_temperature = raw_temperature,
        .raw_humidity = raw_humidity,
        .gas = gas,
        .bsec_status = bsec_status,
        .static_iaq = static_iaq,
        .co2_equivalent = co2_equivalent,
        .breath_voc_equivalent = breath_voc_equivalent};
    if (bsec_status != BSEC_OK)
    {
        ESP_LOGW(TAG, "bsec status not ok: %d", bsec_status);
        xEventGroupSetBits(event_group_status_led, event_group_status_led_bme680_read_err);
    }
    else
    {
        xEventGroupClearBits(event_group_status_led, event_group_status_led_bme680_read_err);
    }
    ESP_LOGI(TAG, "bsec output ready: Temp: %.2f | rH: %.2f | Pres: %.2f | IAQ: %.2f/%.2f (%d)",
             temperature, humidity, pressure, iaq, static_iaq, iaq_accuracy);
    xQueueOverwrite(queue_bme680_measurement, (const void *)&m);
}

static void bme680_read_task(void *pvParameters)
{
    // Initialize BSEC library
    return_values_init rvi = bsec_iot_init(BSEC_SAMPLE_RATE_LP,
                                           CONFIG_BME680_TEMP_OFFSET,
                                           bsec_driver_i2c_write,
                                           bsec_driver_i2c_read,
                                           bsec_driver_sleep_ms,
                                           bsec_driver_state_load,
                                           bsec_driver_config_load);
    if (rvi.bme680_status != 0)
    {
        ESP_LOGE(TAG, "failed to initialize bme680: errno %d", rvi.bme680_status);
        vTaskDelete(NULL);
        return;
    }
    if (rvi.bsec_status != 0)
    {
        ESP_LOGE(TAG, "failed to initialize BSEC library: errno %d", rvi.bsec_status);
        vTaskDelete(NULL);
        return;
    }

    // Run the BSEC mainloop
    bsec_iot_loop(bsec_driver_sleep_ms,
                  bsec_driver_get_timestamp_us,
                  bsec_driver_output_ready,
                  bsec_driver_state_save,
                  BSEC_SAVE_INTERVAL_MEASUREMENTS);
    vTaskDelete(NULL);
}

static ip4_addr_t device_get_broadcast_ip4()
{
    tcpip_adapter_ip_info_t info = {};
    ip4_addr_t broadcast = {};

    ESP_ERROR_CHECK(tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &info));
    broadcast.addr = ~info.netmask.addr | info.ip.addr;
    return broadcast;
}

static bool wifi_wait_for_ip(TickType_t xTicksToWait)
{
    EventBits_t wait_bits = IPV4_GOTIP_BIT;
    EventBits_t bits = xEventGroupWaitBits(event_group_wifi, wait_bits, false, true, xTicksToWait);
    return (bits & wait_bits) != 0;
}

static esp_err_t udp_client_load_packet_counter(uint64_t *packet_counter)
{
    nvs_handle nvs;
    esp_err_t err = ESP_OK;

    const char *namespace = "app";
    const char *key = "packet_counter";

    ESP_LOGI(TAG, "nvs: loading packet counter");
    err = nvs_open(namespace, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGW(TAG, "nvs: namespace '%s' does not exist", namespace);
        return err;
    }
    else if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "nvs: failed to open '%s' namespace: errno 0x%x", namespace, err);
        return err;
    }
    err = nvs_get_u64(nvs, key, packet_counter);
    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGW(TAG, "nvs: '%s' key does not exist", key);
        nvs_close(nvs);
        return err;
    }
    else if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "nvs: error reading '%s': errno 0x%x", key, err);
        nvs_close(nvs);
        return err;
    }
    ESP_LOGI(TAG, "nvs: successfully read packet counter");
    nvs_close(nvs);
    return ESP_OK;
}

static esp_err_t udp_client_store_packet_counter(uint64_t packet_counter)
{
    nvs_handle nvs;
    esp_err_t err;

    const char *namespace = "app";
    const char *key = "packet_counter";
    ESP_LOGI(TAG, "nvs: saving packet counter");

    err = nvs_open(namespace, NVS_READWRITE, &nvs);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "nvs: failed to open '%s' namespace: errno 0x%x", namespace, err);
        return -1;
    }
    err = nvs_erase_key(nvs, key);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "nvs: failed erasing %s: errno 0x%x", key, err);
    }
    err = nvs_set_u64(nvs, key, packet_counter);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "nvs: failed to save %s: errno %d", key, err);
        nvs_close(nvs);
        return -1;
    }
    err = nvs_commit(nvs);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "nvs: failed to commit changes: errno %d", err);
        nvs_close(nvs);
        return -1;
    }
    ESP_LOGI(TAG, "nvs: successfully saved %s", key);
    nvs_close(nvs);
    return ESP_OK;
}

static uint32_t udp_client_make_packet(uint8_t *buf_begin, bme680_measurement_t *m)
{
    const uint8_t protocol_version = 2;
    const char room_name[16] = CONFIG_ROOM_NAME;
    const uint8_t hmac_key[32] = CONFIG_PACKET_AUTH_HMAC_KEY;

    if (udp_client_packet_counter == UINT64_MAX)
    {
        ESP_LOGE(TAG, "panic: packer counter overflow");
        abort();
    }
    uint64_t packet_counter = udp_client_packet_counter++;

    uint8_t *signed_begin = buf_begin;
    uint8_t *version = signed_begin;
    uint8_t *bsec_status = version + 1;
    uint8_t *iaq_accuracy = bsec_status + 1;
    uint8_t *name = iaq_accuracy + 2;
    uint8_t *ctr = name + 16;
    uint8_t *iaq = ctr + 8;
    uint8_t *temperature = iaq + 4;
    uint8_t *humidity = temperature + 4;
    uint8_t *pressure = humidity + 4;
    uint8_t *raw_temperature = pressure + 4;
    uint8_t *raw_humidity = raw_temperature + 4;
    uint8_t *gas = raw_humidity + 4;
    uint8_t *static_iaq = gas + 4;
    uint8_t *co2_equivalent = static_iaq + 4;
    uint8_t *breath_voc_equivalent = co2_equivalent + 4;
    uint8_t *signed_end = breath_voc_equivalent + 4;
    uint8_t *hmac = signed_end;
    uint8_t *buf_end = hmac + 32;

    memcpy(version, &protocol_version, sizeof(protocol_version));
    memcpy(bsec_status, &m->bsec_status, sizeof(m->bsec_status));
    memcpy(iaq_accuracy, &m->iaq_accuracy, sizeof(m->iaq_accuracy));
    memcpy(name, &room_name, sizeof(room_name));
    memcpy(ctr, &packet_counter, sizeof(packet_counter));
    memcpy(iaq, &m->iaq, sizeof(m->iaq));
    memcpy(temperature, &m->temperature, sizeof(m->temperature));
    memcpy(humidity, &m->humidity, sizeof(m->humidity));
    memcpy(pressure, &m->pressure, sizeof(m->pressure));
    memcpy(raw_temperature, &m->raw_temperature, sizeof(m->raw_temperature));
    memcpy(raw_humidity, &m->raw_humidity, sizeof(m->raw_humidity));
    memcpy(gas, &m->gas, sizeof(m->gas));
    memcpy(static_iaq, &m->static_iaq, sizeof(m->static_iaq));
    memcpy(co2_equivalent, &m->co2_equivalent, sizeof(m->co2_equivalent));
    memcpy(breath_voc_equivalent, &m->breath_voc_equivalent, sizeof(m->breath_voc_equivalent));

    // Sign the message
    crypto_auth_hmacsha256(hmac, signed_begin, signed_end - signed_begin, hmac_key);

    return buf_end - buf_begin;
}

static void udp_client_task(void *pvParameters)
{
    esp_err_t esp_err = ESP_OK;
    const uint64_t packet_counter_save_interval_bumps = CONFIG_PACKET_COUNTER_SAVE_INTERVAL_SECONDS / 3;
    uint64_t packet_counter = 0, last_saved_packet_counter = 0;

    ESP_LOGI(TAG, "starting 'udp_client' task");

    // Allocate a buffer for the packet.
    uint8_t *packet = calloc(sizeof(uint8_t), 4096);
    if (packet == NULL)
    {
        ESP_LOGE(TAG, "could not allocate packet buffer, aborting");
        abort();
        vTaskDelete(NULL);
        return;
    }

    // Read the packet_counter value from flash.
    esp_err = udp_client_load_packet_counter(&packet_counter);
    if (esp_err == ESP_ERR_NVS_NOT_FOUND)
    {
        // First boot
        packet_counter = 0;
    }
    else if (esp_err != ESP_OK)
    {
        ESP_LOGE(TAG, "error loading packet counter: %d", esp_err);
        abort();
    }
    // Add the maximum amount of counter bumps that could have occured without
    // saving the counter inbetween.
    last_saved_packet_counter = packet_counter;
    packet_counter += packet_counter_save_interval_bumps;
    udp_client_packet_counter = packet_counter;

    // Run the mainloop
    for (;;)
    {
        struct sockaddr_in destAddr;
        char addr_str[128];

        uint32_t wifi_connect_timeout_seconds = 40;
        bool ok = wifi_wait_for_ip(wifi_connect_timeout_seconds * CONFIG_FREERTOS_HZ);
        if (!ok)
        {
            // Set this task to error
            xEventGroupSetBits(event_group_status_led, event_group_status_led_udp_client_err);
            continue;
        }

        destAddr.sin_addr.s_addr = device_get_broadcast_ip4().addr;
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(CONFIG_BEACON_PORT);
        inet_ntoa_r(destAddr.sin_addr, addr_str, sizeof(addr_str) - 1);

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock != 0)
        {
            ESP_LOGE(TAG, "unable to create socket: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "socket created");

        for (;;)
        {
            bme680_measurement_t m;
            uint32_t bme680_timeout_seconds = 40;
            // Wait for a new measurement from the other thread.
            long prs = xQueueReceive(queue_bme680_measurement, &m, bme680_timeout_seconds * CONFIG_FREERTOS_HZ);
            if (prs == pdFALSE)
            {
                ESP_LOGE(TAG, "did not receive bme680 data for %d seconds, aborting", bme680_timeout_seconds);
                abort();
            }

            // Send a packet with the measurement data.
            size_t packet_len = udp_client_make_packet(packet, &m);
            int lwip_err = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&destAddr, sizeof(destAddr));
            if (lwip_err < 0)
            {
                ESP_LOGE(TAG, "error occured during sending: errno %d", errno);
                break;
            }

            // Backup the packet counter if it has been backed up too long ago.
            packet_counter = udp_client_packet_counter;
            if (last_saved_packet_counter + packet_counter_save_interval_bumps < udp_client_packet_counter)
            {
                esp_err = udp_client_store_packet_counter(packet_counter);
                if (esp_err != ESP_OK)
                {
                    ESP_LOGE(TAG, "error storing packet counter: %d", esp_err);
                    abort();
                }
                last_saved_packet_counter = packet_counter;
            }
            udp_client_packet_counter = packet_counter;

            // This task is working correctly.
            xEventGroupClearBits(event_group_status_led, event_group_status_led_udp_client_err);
        }

        if (sock != -1)
        {
            ESP_LOGE(TAG, "Shutting down socket and restarting...");
            shutdown(sock, 0);
            close(sock);
        }
    }
    vTaskDelete(NULL);
}

static void status_led_set_on(uint32_t on)
{
    gpio_set_level(STATUS_LED_GPIO_NUM, (on & 0x1) ^ STATUS_LED_INVERTED);
}

static void led_blink_task(void *pvParameters)
{
    status_led_set_on(0);
    for (;;)
    {
        const EventBits_t wait_bits = event_group_status_led_bme680_read_err | event_group_status_led_udp_client_err;
        const EventBits_t bits = xEventGroupWaitBits(event_group_status_led, wait_bits, pdFALSE, pdFALSE, portMAX_DELAY);
        if (bits == 0)
        {
            // No errors, carry on.
            continue;
        }

        const uint32_t blink_period_ms = 500;
        const uint32_t toggle_period_ticks = blink_period_ms / 2 * CONFIG_FREERTOS_HZ / 1000;

        status_led_set_on(1);
        vTaskDelay(toggle_period_ticks);
        status_led_set_on(0);
        vTaskDelay(toggle_period_ticks);
    }
    vTaskDelete(NULL);
}

static esp_err_t device_event_handler(void *ctx, system_event_t *event)
{
    char addr_str[128] = {};
    system_event_info_t *info = &event->event_info;

    switch (event->event_id)
    {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        ESP_LOGI(TAG, "wifi: station start");
        break;
    case SYSTEM_EVENT_STA_CONNECTED:
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        inet_ntoa_r(info->got_ip.ip_info.ip, addr_str, sizeof(addr_str) - 1);
        ESP_LOGI(TAG, "wifi: got ip: %s", addr_str);
        xEventGroupSetBits(event_group_wifi, IPV4_GOTIP_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        ESP_LOGE(TAG, "wifi: disconnected: errno %d", info->disconnected.reason);
        if (info->disconnected.reason == WIFI_REASON_BASIC_RATE_NOT_SUPPORT)
        {
            // Switch to 802.11 bgn mode
            esp_wifi_set_protocol(ESP_IF_WIFI_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
        }
        esp_wifi_connect();
        xEventGroupClearBits(event_group_wifi, IPV4_GOTIP_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void wifi_init(void)
{
    tcpip_adapter_init();
    event_group_wifi = xEventGroupCreate();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = CONFIG_WIFI_SSID,
            .password = CONFIG_WIFI_PASSWORD,
        },
    };
    ESP_LOGI(TAG, "setting WiFi configuration SSID to '%s'", wifi_config.sta.ssid);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static void gpio_init(void)
{
    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = 1 << STATUS_LED_GPIO_NUM,
        .pull_down_en = 0,
        .pull_up_en = 0,
    };
    gpio_config(&io_conf);
}

static void i2c_init(void)
{
    const i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = I2C_BME680_MASTER_SDA_IO,
        .sda_pullup_en = 1,
        .scl_io_num = I2C_BME680_MASTER_SCL_IO,
        .scl_pullup_en = 1,
        .clk_stretch_tick = 300, // 300 ticks, Clock stretch is about 210us, you can make changes according to the actual situation.
    };
    ESP_ERROR_CHECK(i2c_driver_install(I2C_BME680_MASTER_NUM, I2C_MODE_MASTER));
    ESP_ERROR_CHECK(i2c_param_config(I2C_BME680_MASTER_NUM, &conf));
}

static void storage_init(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
}

void app_main()
{
    ESP_ERROR_CHECK(esp_event_loop_init(device_event_handler, NULL));

    event_group_status_led = xEventGroupCreate();
    if (event_group_status_led == NULL)
    {
        ESP_LOGE(TAG, "could not allocate `event_group_status_led` event group");
        abort();
    }
    // Set the err bits in the status led event group. They will be cleared
    // when the tasks have correctly initialized.
    xEventGroupSetBits(event_group_status_led, event_group_status_led_bme680_read_err | event_group_status_led_udp_client_err);

    queue_bme680_measurement = xQueueCreate(1, sizeof(bme680_measurement_t));
    if (queue_bme680_measurement == NULL)
    {
        ESP_LOGE(TAG, "could not allocate `queue_bme680_measurement` queue");
        abort();
    }

    gpio_init();
    i2c_init();
    storage_init();
    wifi_init();

    ESP_LOGI(TAG, "starting tasks");
    xTaskCreate(led_blink_task, "led_blink", 4096, NULL, 5, NULL);
    xTaskCreate(bme680_read_task, "bme280_read", 4096, NULL, 5, NULL);
    xTaskCreate(udp_client_task, "udp_client", 4096, NULL, 5, NULL);
}
