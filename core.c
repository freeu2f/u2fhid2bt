/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "core.h"
#undef u2f_chl_rep_buf
#undef u2f_chl_rep
#undef u2f_chl_err

#include <linux/uhid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#define HID_VEND 0
#define HID_PROD 0
#define HID_VERS 0
#define HID_CTRY 0

#define HID_FRME 64

void
u2f_pkt_free(u2f_pkt *pkt)
{
    free(pkt);
}

u2f_pkt *
u2f_pkt_new(const uint8_t *buf, size_t *len)
{
    uint16_t cnt = 0;
    u2f_pkt *pkt = NULL;

    if (*len < 3)
        return NULL;

    cnt = load16(&buf[1]);
    pkt = calloc(1, sizeof(*pkt) + cnt);
    if (!pkt)
        return NULL;

    *len -= 3;
    *len = *len < cnt ? *len : cnt;

    pkt->cmd = buf[0];
    pkt->cnt = cnt;
    memcpy(pkt->buf, &buf[3], *len);
    return pkt;
}

void
u2f_chl_free(u2f_chl *chl)
{
    if (!chl)
        return;

    u2f_pkt_free(chl->pkt);
    list_rem(&chl->lst);
    free(chl);
}

u2f_chl *
u2f_chl_new(uint32_t cid, const uint8_t *buf, size_t len)
{
    u2f_chl *chl = NULL;

    chl = calloc(1, sizeof(*chl));
    if (!chl)
        return NULL;

    list_new(&chl->lst);
    chl->cid = cid;

    if (buf) {
        chl->len = len;
        chl->pkt = u2f_pkt_new(buf, &chl->len);
        if (!chl->pkt) {
            free(chl);
            return NULL;
        }
    }

    return chl;
}

static int
call_write_value(u2f_svc *svc, const uint8_t *buf, size_t len)
{
    sd_bus_message_auto *msg = NULL;
    int r;

    r = sd_bus_message_new_method_call(svc->bus, &msg, "org.bluez",
                                       svc->chr[CHR_CONTROL_POINT],
                                       "org.bluez.GattCharacteristic1",
                                       "WriteValue");
    if (r < 0)
        return r;

    r = sd_bus_message_append_array(msg, 'y', buf, len);
    if (r < 0)
        return r;

    r = sd_bus_message_append(msg, "a{sv}", 0);
    if (r < 0)
        return r;

    return sd_bus_call(svc->bus, msg, 0, NULL, NULL);
}

int
u2f_chl_req(u2f_chl *chl)
{
    const int len = sizeof(*chl->pkt) + chl->pkt->cnt;
    int mtu = 0;
    int r = 0;

    mtu = u2f_svc_mtu(chl->svc);
    if (mtu < 0)
        return mtu;
    else if (mtu < 20)
        return -EINVAL;

    fprintf(stderr, ">");
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02hhx", chl->buf[i]);
    fprintf(stderr, "\n");

    r = call_write_value(chl->svc, chl->buf, mtu < len ? mtu : len);
    if (r < 0)
        return r;

    for (size_t i = 0, off = mtu; off < len; i++, off += mtu - 1) {
        size_t cnt = (len - off) < mtu ? len - off + 1 : mtu;
        uint8_t blk[mtu];

        blk[0] = i;
        memcpy(&blk[1], &chl->buf[off], cnt - 1);
        (void) call_write_value(chl->svc, blk, cnt);
    }

    return len;
}

int
u2f_chl_rep_buf(u2f_chl *chl, const uint8_t *buf, size_t len,
                const char *file, int line)
{
    int fd = sd_event_source_get_io_fd(chl->svc->hid);
    struct uhid_event ue = { .type = UHID_INPUT2 };

    fprintf(stderr, "reply@%s:%d\n", file, line);

    ue.u.input2.size = HID_FRME < len ? HID_FRME : len;
    memcpy(ue.u.input2.data, buf, ue.u.input2.size);
    if (write(fd, &ue, sizeof(ue)) < 0)
        return -errno;

    for (size_t i = 0, off = HID_FRME; off < len; i++, off += HID_FRME - 1) {
        ue.u.input2.size = (len - off) < HID_FRME ? len - off + 1 : HID_FRME;
        ue.u.input2.data[0] = i;
        memcpy(&ue.u.input2.data[1], &buf[off], ue.u.input2.size - 1);
        (void) write(fd, &ue, sizeof(ue));
    }

    return len;
}

int
u2f_chl_rep(u2f_chl *chl, const char *file, int line)
{
    const size_t len = sizeof(*chl->pkt) + chl->pkt->cnt;
    return u2f_chl_rep_buf(chl, chl->buf, len, file, line);
}

int
u2f_chl_err(u2f_chl *chl, u2f_err err, const char *file, int line)
{
    struct uhid_event ue = {
        .type = UHID_INPUT2,
        .u.input2 = {
            .size = 8,
            .data = {
                save32(chl->cid),
                U2F_CMD_ERROR,
                save16(1), /* Length */
                err
            }
        }
    };

    fprintf(stderr, "error@%s:%d\n", file, line);
    return write(sd_event_source_get_io_fd(chl->svc->hid), &ue, sizeof(ue));
}

void
u2f_svc_free(u2f_svc *svc)
{
    if (!svc)
        return;

    list_rem(&svc->lst);

    sd_bus_unref(svc->bus);
    free(svc->obj);

    for (u2f_chr p = 0; p < _CHR_TOTAL; p++)
        free(svc->chr[p]);

    sd_event_source_unref(svc->hid);

    while (svc->req.nxt != &svc->req)
        u2f_chl_free(list_itm(u2f_chl, lst, svc->req.nxt));

    while (svc->rep.nxt != &svc->rep)
        u2f_chl_free(list_itm(u2f_chl, lst, svc->rep.nxt));

    free(svc);
}

static int
uhid_io_cb(sd_event_source *es, int fd, uint32_t revents, void *userdata)
{
    struct uhid_event ue = {};
    u2f_svc *svc = userdata;

    if (read(fd, &ue, sizeof(ue)) != sizeof(ue))
        return -errno;

    if (ue.type != UHID_OUTPUT)
        return 0;

    /* Data layout:
     *   Report ID (1 byte); see USB HID 1.11 Section 5.6 (I think)
     *   Channel ID (4 bytes); see U2F HID Section 2.4
     *   ... */

    if (ue.u.output.size < 1)
        return 0; /* Input is so malformed we can't make an error. */

    (void) svc->fnc(svc, &ue.u.output.data[1], ue.u.output.size - 1);
    return 0;
}

u2f_svc *
u2f_svc_new(sd_bus *bus, u2f_uhid_io_t fnc, const char *dev, const char *obj)
{
    /* It would be much better if we could set the MTU of this device to match
     * the Bluetooth u2fControlPointLength. Unfortunately, the host
     * implementations seem to presume 64 bytes. So we will have to reframe. */
    struct uhid_event ue = {
        .type = UHID_CREATE2,
        .u.create2 = {
            .bus = BUS_BLUETOOTH, // https://github.com/signal11/hidapi/pull/355
            .vendor = HID_VEND,
            .product = HID_PROD,
            .version = HID_VERS,
            .country = HID_CTRY,
            .rd_size = 36,        // Number of bytes below (KEEP IN SYNC!)
            .rd_data = {
                0x06, 0xD0, 0xF1, // Usage Page (FIDO_USAGE_PAGE: 0xF1D0)
                0x09, 0x01,       // Usage (FIDO_USAGE_U2FHID: 1)
                0xA1, 0x01,       // Collection (Application)
                0x09, 0x20,       //   Usage (FIDO_USAGE_DATA_IN: 32)
                0x15, 0x00,       //   Logical Minimum (0)
                0x26, 0xFF, 0x00, //   Logical Maximum (255)
                0x75, 0x08,       //   Report Size (8)
                0x95, HID_FRME,   //   Report Count (64)
                0x81, 0x02,       //   Input (HID_Data | HID_Absolute | HID_Variable)
                0x09, 0x21,       //   Usage (FIDO_USAGE_DATA_OUT: 33)
                0x15, 0x00,       //   Logical Minimum (0)
                0x26, 0xFF, 0x00, //   Logical Maximum (255)
                0x75, 0x08,       //   Report Size (8)
                0x95, HID_FRME,   //   Report Count (64)
                0x91, 0x02,       //   Output (HID_Data | HID_Absolute | HID_Variable)
                0xC0,             // End Collection
            },
        }
    };

    sd_bus_message_auto *msg = NULL;
    sd_event_auto *event = NULL;
    const char *str = NULL;
    u2f_svc *svc = NULL;
    int hid = -1;
    int r;

    r = sd_bus_get_property(bus, "org.bluez", dev, "org.bluez.Device1",
                            "Name", NULL, &msg, "s");
    if (r < 0)
        return NULL;

    r = sd_bus_message_read(msg, "s", &str);
    if (r < 0)
        return NULL;

    strncpy((char *) ue.u.create2.name, str, sizeof(ue.u.create2.name) - 1);
    strncpy((char *) ue.u.create2.phys, dev, sizeof(ue.u.create2.phys) - 1);
    strncpy((char *) ue.u.create2.uniq, obj, sizeof(ue.u.create2.uniq) - 1);

    r = sd_event_default(&event);
    if (r < 0)
        return NULL;

    hid = open("/dev/uhid", O_RDWR);
    if (hid < 0)
        return NULL;

    if (write(hid, &ue, sizeof(ue)) != sizeof(ue)) {
        close(hid);
        return NULL;
    }

    while (ue.type != UHID_START) {
        if (read(hid, &ue, sizeof(ue)) != sizeof(ue)) {
            close(hid);
            return NULL;
        }
    }

    svc = calloc(1, sizeof(*svc));
    if(!svc) {
        close(hid);
        return NULL;
    }

    list_new(&svc->lst);
    list_new(&svc->req);
    list_new(&svc->rep);

    svc->fnc = fnc;
    svc->bus = sd_bus_ref(bus);
    svc->obj = strdup(obj);
    if (!svc->bus || !svc->obj) {
        u2f_svc_free(svc);
        close(hid);
        return NULL;
    }

    r = sd_event_add_io(event, &svc->hid, hid, EPOLLIN, uhid_io_cb, svc);
    if (r < 0) {
        u2f_svc_free(svc);
        close(hid);
        return NULL;
    }

    return svc;
}

int
u2f_svc_mtu(u2f_svc *svc)
{
    sd_bus_message_auto *msg = NULL;
    const uint8_t *bytes = NULL;
    const char *obj = NULL;
    size_t size = 0;
    int r;

    obj = svc->chr[CHR_CONTROL_POINT_LENGTH];
    if (!obj)
        return -ENOENT;

    r = sd_bus_call_method(svc->bus, "org.bluez", obj,
                           "org.bluez.GattCharacteristic1", "ReadValue",
                           NULL, &msg, "a{sv}", 0);
    if (r < 0)
        return r;

    r = sd_bus_message_read_array(msg, 'y', (const void **) &bytes, &size);
    if (r < 0)
        return r;

    if (size != 2)
        return -EMSGSIZE;

    return load16(bytes);
}
