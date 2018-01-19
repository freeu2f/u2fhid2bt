/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE

#include "gatt.h"
#include "uhid.h"
#include "list.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define CNT(v) (sizeof((v)) / sizeof(*(v)))

#define sd_bus_message_auto \
    sd_bus_message __attribute__((cleanup(sd_bus_message_unrefp)))

#define MATCH \
    "type='signal',sender='org.bluez',member='PropertiesChanged'," \
    "interface='org.freedesktop.DBus.Properties',path='%s'," \
    "arg0='org.bluez.GattCharacteristic1'"

static const struct {
    const char *uuid;
    const char *name;
} props[] = {
    { "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb", "u2fControlPoint" },
    { "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb", "u2fStatus" },
    { "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", "u2fControlPointLength" },
    { "00002a28-0000-1000-8000-00805f9b34fb", "u2fServiceRevision" },
    { "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb", "u2fServiceRevisionBitfield" },
};

struct u2f_gatt {
    char         *svc;             /* Service (D-Bus Object Path) */
    char         *chr[CNT(props)]; /* Characteristics (D-Bus Object Paths) */

    sd_bus       *bus;
    sd_bus_slot  *slt;

    u2f_gatt_cbk *cbk;
    void         *msc;

    u2f_frm      *frm;
    size_t        len;
    uint32_t      cid;
};

static int
write_chr(sd_bus *bus, const char *chr, const void *buf, size_t len)
{
    sd_bus_message_auto *msg = NULL;
    int r;

    r = sd_bus_message_new_method_call(bus, &msg, "org.bluez", chr,
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

    return sd_bus_call(bus, msg, 0, NULL, NULL);
}

static int
get_mtu(const u2f_gatt *gatt)
{
    sd_bus_message_auto *msg = NULL;
    const uint16_t *mtu = NULL;
    const char *chr = NULL;
    size_t size = 0;
    int r;

    chr = u2f_gatt_get(gatt, "u2fControlPointLength");
    if (!chr)
        return -ENOENT;

    r = sd_bus_call_method(gatt->bus, "org.bluez", chr,
                           "org.bluez.GattCharacteristic1", "ReadValue",
                           NULL, &msg, "a{sv}", 0);
    if (r < 0)
        return r;

    r = sd_bus_message_read_array(msg, 'y', (const void **) &mtu, &size);
    if (r < 0)
        return r;

    if (size != sizeof(*mtu))
        return -EMSGSIZE;

    return be16toh(*mtu);
}

static void
on_sts_bytes(u2f_gatt *gatt, const void *buf, size_t len)
{
    size_t off = offsetof(u2f_pkt, seq.buf);
    const uint8_t *src = buf;
    const u2f_pkt *pkt = buf;
    size_t rem;
    size_t tot;

    fprintf(stderr, ">G %08X ", gatt->cid);
    u2f_pkt_dump("", pkt, len);

    if (gatt->cid == U2F_CID_RESERVED || gatt->cid == U2F_CID_BROADCAST)
        return;

    if (pkt->cmd.cmd & U2F_CMD) {
        if (gatt->frm || len < sizeof(pkt->cmd))
            goto error;

        gatt->frm = calloc(1, sizeof(u2f_frm) + be16toh(pkt->cmd.len));
        if (!gatt->frm)
            goto error;

        gatt->frm->cid = gatt->cid;
        gatt->frm->pkt = *pkt;
        gatt->len = 0;

        off = offsetof(u2f_pkt, cmd.buf);
    } else if (!gatt->frm || len < sizeof(pkt->seq))
        goto error;

    rem = be16toh(gatt->frm->pkt.cmd.len) - gatt->len;
    tot = ((len - off) < rem) ? len - off : rem;

    memcpy(&gatt->frm->pkt.cmd.buf[gatt->len], &src[off], tot);
    gatt->len += tot;

    if (gatt->len == be16toh(gatt->frm->pkt.cmd.len)) {
        gatt->cbk(gatt->frm, gatt->msc);
        goto error;
    }

    return;

error:
    free(gatt->frm);
    gatt->frm = NULL;
    gatt->cid = U2F_CID_RESERVED;
}

static int
on_sts_notify(sd_bus_message *m, void *misc, sd_bus_error *ret_error)
{
    int r;

    r = sd_bus_message_skip(m, "s");
    if (r < 0)
        return r;

    r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r < 0)
        return r;

    while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
        const char *name = NULL;

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
            return r;

        if (strcmp(name, "Value") == 0) {
            const void *buf = NULL;
            size_t len = 0;

            r = sd_bus_message_enter_container(m, 'v', "ay");
            if (r < 0)
                return r;

            r = sd_bus_message_read_array(m, 'y', &buf, &len);
            if (r < 0)
                return r;

            r = sd_bus_message_exit_container(m);
            if (r < 0)
                return r;

            on_sts_bytes(misc, buf, len);
        } else {
            r = sd_bus_message_skip(m, "v");
            if (r < 0)
                return r;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
            return r;
    }

    r = sd_bus_message_exit_container(m);
    if (r < 0)
        return r;

    return 0;
}

void
u2f_gatt_free(u2f_gatt *gatt)
{
    if (!gatt)
        return;

    free(gatt->svc);

    for (size_t i = 0; i < CNT(props); i++)
        free(gatt->chr[i]);

    sd_bus_slot_unref(gatt->slt);
    sd_bus_unref(gatt->bus);
}

u2f_gatt *
u2f_gatt_new(sd_bus *bus, const char *svc, u2f_gatt_cbk *cbk, void *msc)
{
    u2f_gatt *gatt = NULL;

    gatt = calloc(1, sizeof(*gatt));
    if (!gatt)
        return NULL;

    gatt->svc = strdup(svc);
    if (!gatt->svc) {
        free(gatt);
        return NULL;
    }

    gatt->bus = sd_bus_ref(bus);
    gatt->msc = msc;
    gatt->cbk = cbk;
    return gatt;
}

const char *
u2f_gatt_svc(const u2f_gatt *gatt)
{
    return gatt->svc;
}

int
u2f_gatt_set(u2f_gatt *gatt, const char *id, const char *obj)
{
    for (size_t i = 0; i < CNT(props); i++) {
        if (strcmp(id, props[i].name) == 0 ||
            strcasecmp(id, props[i].uuid) == 0) {
            char *tmp = NULL;

            if (strcmp(props[i].name, "u2fStatus") == 0) {
                char *match = NULL;
                int r;

                r = asprintf(&match, MATCH, obj);
                if (r < 0)
                    return -errno;

                if (gatt->slt) {
                    sd_bus_slot_unref(gatt->slt);
                    gatt->slt = NULL;
                }

                r = sd_bus_add_match(gatt->bus, &gatt->slt, match,
                                     on_sts_notify, gatt);
                free(match);
                if (r < 0)
                    return r;
            }

            if (obj) {
                tmp = strdup(obj);
                if (!tmp)
                    return -ENOMEM;
            }

            free(gatt->chr[i]);
            gatt->chr[i] = tmp;
            return 0;
        }
    }

    return -ENOENT;
}

const char *
u2f_gatt_has(u2f_gatt *gatt, const char *obj)
{
    for (size_t i = 0; i < CNT(props); i++) {
        if (gatt->chr[i] && strcmp(gatt->chr[i], obj) == 0)
            return props[i].name;
    }

    return NULL;
}

const char *
u2f_gatt_get(const u2f_gatt *gatt, const char *id)
{
    for (size_t i = 0; i < CNT(props); i++) {
        if (strcmp(id, props[i].name) == 0 ||
            strcasecmp(id, props[i].uuid) == 0)
            return gatt->chr[i];
    }

    return NULL;
}

int
u2f_gatt_send(u2f_gatt *gatt, const u2f_frm *frm)
{
    const size_t len = sizeof(frm->pkt) + be16toh(frm->pkt.cmd.len);
    sd_bus_message_auto *msg = NULL;
    const char *pnt = NULL;
    const char *sts = NULL;
    u2f_seq *seq = NULL;
    int mtu = 0;
    int r = 0;

    pnt = u2f_gatt_get(gatt, "u2fControlPoint");
    if (!pnt)
        return -ENOENT;

    sts = u2f_gatt_get(gatt, "u2fStatus");
    if (!sts)
        return -ENOENT;

    mtu = get_mtu(gatt);
    fprintf(stderr, "MTU: %d\n", mtu);
    if (mtu < 0)
        return mtu;
    else if (mtu <= sizeof(*seq) || mtu > 4096)
        return -EMSGSIZE;

    r = sd_bus_message_new_method_call(gatt->bus, &msg, "org.bluez", sts,
                                       "org.bluez.GattCharacteristic1",
                                       "StartNotify");
    if (r < 0)
        return r;

    r = sd_bus_call(gatt->bus, msg, 0, NULL, NULL);
    if (r < 0)
        return r;

    fprintf(stderr, "<G %08u ", frm->cid);
    u2f_pkt_dump("", &frm->pkt, mtu < len ? mtu : len);

    r = write_chr(gatt->bus, pnt, &frm->pkt, mtu < len ? mtu : len);
    if (r < 0)
        return r;

    seq = alloca(mtu);
    seq->seq = 0;

    for (size_t off = mtu; off < len; seq->seq++, off += mtu - sizeof(*seq)) {
        size_t rem = len - off + sizeof(*seq);
        size_t cnt = rem < mtu ? rem : mtu;
        memcpy(seq->buf, &frm->pkt.cmd.buf[off - sizeof(frm->pkt)],
               cnt - sizeof(*seq));

        fprintf(stderr, "<G %08u ", frm->cid);
        u2f_seq_dump("", seq, cnt);

        r = write_chr(gatt->bus, pnt, seq, cnt);
        if (r < 0)
            return r;
    }

    gatt->cid = frm->cid;
    free(gatt->frm);
    gatt->frm = NULL;

    return len;
}
