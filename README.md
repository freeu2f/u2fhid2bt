This project emulates a U2F HID device and proxies the data to paired U2F
Bluetooth devices. It doesn't fully work yet. But we can at least detect
Bluetooth devices, make emulated U2F HID devices and handle some basic packets,
including the U2FHID_INIT command.
