This project emulates a U2F HID device and proxies the data to paired U2F
Bluetooth devices. We believe it works since all the Google/U2F provided tests
pass for the HID layer. However, this code does not implement a full U2F token.
Therefore, we can't guarantee that it works with your specific Bluetooth U2F
token. If it doesn't, please let us know!

# Getting Started

## Build and Install the Code

```bash
$ mkdir build
$ cd build
$ meson --prefix=/usr ..
$ ninja install
```

## Enable the Daemon

```bash
$ sudo systemctl enable --now u2fhid2bt.service
```

# How it Works

1. First, we register with Bluez to say that we are interested in Bluetooth Low
   Energy GATT devices with the U2F GATT Service.

2. When such a device appears, we create an emulated HID U2F device. All packets
   sent to this emulated device are proxied to the Bluetooth device. This makes
   it seem like the Bluetooth device is actually plugged into USB.

3. Applications which work with USB U2F devices should transparently work with
   Bluetooth U2F devices.

# License

This project is licensed under the Apache License, Version 2.0.
