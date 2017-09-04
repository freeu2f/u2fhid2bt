This project runs tests against Bluetooth U2F devices.

However, we do not currently run any tests. Currently, it monitors D-Bus for
U2F devices and creates an internal object which represents the state of U2F
services on a device. More or less, this code pretty must just prints which
U2F devices it finds over Bluetooth.

This code can also be extrapolated for use in a HID transport driver.
