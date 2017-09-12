/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>

#define sd_bus_auto \
    sd_bus __attribute__((cleanup(sd_bus_unrefp)))

#define sd_bus_message_auto \
    sd_bus_message __attribute__((cleanup(sd_bus_message_unrefp)))

#define sd_event_auto \
    sd_event __attribute__((cleanup(sd_event_unrefp)))

#define sd_event_source_auto \
    sd_event_source __attribute__((cleanup(sd_event_source_unrefp)))

#define load16(p) be16toh(*((uint16_t *) (p)))
#define load32(p) be32toh(*((uint32_t *) (p)))
#define load64(p) be64toh(*((uint64_t *) (p)))
#define save16(n) \
    (((n) >> 0x08) & 0xff), \
    (((n) >> 0x00) & 0xff)
#define save32(n) \
    (((n) >> 0x18) & 0xff), \
    (((n) >> 0x10) & 0xff), \
    save16(n)
#define save64(n) \
    (((n) >> 0x38) & 0xff), \
    (((n) >> 0x30) & 0xff), \
    (((n) >> 0x28) & 0xff), \
    (((n) >> 0x20) & 0xff), \
    save32(n)
