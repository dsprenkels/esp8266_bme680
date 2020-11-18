#pragma once

// Wifi SSID.
#define CONFIG_WIFI_SSID "myssid"

// Wifi passphrase.
#define CONFIG_WIFI_PASSWORD "mypassword"

// UDP port on which to broadcast the BME680 measurements.
#define CONFIG_BEACON_PORT 21772

// Temperature compensation offset.
#define CONFIG_BME680_TEMP_OFFSET 0.28f

// Interval how often the BSEC state should be saved.
#define CONFIG_BSEC_SAVE_INTERVAL_SECONDS (24 * 3600)

// ID of this room
#define CONFIG_ROOM_NAME "bedroom"

// Secret authentication key of the broacast HMACs.
#define CONFIG_PACKET_AUTH_HMAC_KEY { /* Fill with 32 random bytes */ }

// Backup the packet counter to nvs every N seconds
#define CONFIG_PACKET_COUNTER_SAVE_INTERVAL_SECONDS (3600 * 24)