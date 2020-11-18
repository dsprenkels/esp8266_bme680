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

Copy `main/config.example.h` to `main/config.h`.  Update the values that you
like to have different.

## Building and flashing

The build system depends on a couple of additional environment variables and
tools.  Run `source .env` to initialize the environment variables.  The tools
that are needed are documented by the ESP8266_RTOS_SDK `README.md` file.
In any case, you will need `esptool.py` and `miniterm`, both installable using
`pip3`.  Personally, I always use `python3 -m venv` to install these kinds of
tools locally.

After you have sorted your dependencies, run `make flash monitor`.  This will
take one or two minutes.  When the build is done, you should see the console.
After a couple of seconds, it should show you the measurements coming from the
BME680, or (hopefully) a useful error.
