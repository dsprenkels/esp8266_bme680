# ESP8266 BME680 beacon

This beacon will read out a connected BMD680 device via I2C, and broadcast
its measurements over wifi.

## Connections

Connect your BME680 to your ESP8266 using these pin assignments:

| BME680 | ESP8266 |
|--------|---------|
| Vcc    | 3V3     |
| GND    | GND     |
| SDA    | D5      |
| SCK    | D6      |
| CS     | 3V3     |
| SDO    | GND     |

## Configuration

Run `make menuconfig`