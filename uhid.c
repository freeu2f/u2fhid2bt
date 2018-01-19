/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "uhid.h"
#include "list.h"

#include <linux/uhid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HID_VEND 0
#define HID_PROD 0
#define HID_VERS 0
#define HID_CTRY 0
#define HID_FRME 64

#define DEV_HID_VER 2
#define DEV_VER_MAJ 0
#define DEV_VER_MIN 0
#define DEV_VER_BLD 0

typedef struct __attribute__((packed)) {
    uint8_t rid; // Report ID (1 byte); See (I think): USB HID 1.11 Section 5.6
    u2f_frm frm;
} hid_frm;

typedef struct {
    u2f_list lst;
    uint8_t  seq;
    size_t   len;
    u2f_frm *frm;
} channel;

struct u2f_uhid {
    sd_event_source *src;
    u2f_uhid_cb *cb;
    u2f_list chls;
    uint32_t cid;
    void *misc;
};

static void
channel_free(channel *chl)
{
    if (!chl)
        return;

    u2f_list_rem(&chl->lst);
    free(chl->frm);
    free(chl);
}

static int
on_io(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    u2f_uhid *uhid = userdata;
    struct uhid_event ue = {};
    hid_frm *hid = (hid_frm *) ue.u.output.data;
    channel *chl = NULL;

    if (read(fd, &ue, sizeof(ue)) != sizeof(ue))
        return -errno;

    if (ue.type != UHID_OUTPUT)
        return 0;

    if (ue.u.output.size < sizeof(*hid) - sizeof(hid->frm.pkt.cmd.len))
        return 0;

    for (u2f_list *l = uhid->chls.nxt; l != &uhid->chls; l = l->nxt) {
        channel *c = u2f_list_itm(channel, lst, l);
        if (c->frm->cid == hid->frm.cid)
            chl = c;
    }

    if (hid->frm.pkt.cmd.cmd & U2F_CMD) {
        if (ue.u.output.size < sizeof(*hid)) {
            (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_INVALID_LEN);
            return 0;
        }

        if (chl) {
            (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_OTHER);
            channel_free(chl);
        }

        chl = calloc(1, sizeof(*chl));
        if (!chl) {
            (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_OTHER);
            channel_free(chl);
            return 0;
        }

        u2f_list_new(&chl->lst);

        chl->len = ue.u.output.size - sizeof(*hid);
        if (chl->len > be16toh(hid->frm.pkt.cmd.len))
            chl->len = be16toh(hid->frm.pkt.cmd.len);

        u2f_frm_dump(">U ", &hid->frm, sizeof(u2f_frm) + chl->len);

        chl->frm = calloc(1, sizeof(hid->frm) + be16toh(hid->frm.pkt.cmd.len));
        if (!chl->frm) {
            (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_OTHER);
            channel_free(chl);
            return 0;
        }

        memcpy(chl->frm, &hid->frm, sizeof(u2f_frm) + chl->len);
        u2f_list_app(&uhid->chls, &chl->lst);
    } else if (chl) {
        const uint16_t len = ue.u.output.size - offsetof(hid_frm, frm.pkt.seq.buf);
        const uint16_t rem = be16toh(chl->frm->pkt.cmd.len) - chl->len;
        const uint16_t tot = len < rem ? len : rem;

        u2f_frm_dump(">U ", &hid->frm, tot + offsetof(u2f_frm, pkt.seq.buf));

        if (hid->frm.pkt.seq.seq != chl->seq) {
            (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_INVALID_SEQ);
            channel_free(chl);
            return 0;
        }

        memcpy(&chl->frm->pkt.cmd.buf[chl->len], hid->frm.pkt.seq.buf, tot);
        chl->len += tot;
        chl->seq++;
    } else {
        (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_INVALID_CID);
        return 0;
    }

    // If the message is complete...
    if (chl->len == be16toh(chl->frm->pkt.cmd.len)) {
        // Handle INIT commands internally.
        if (chl->frm->cid == U2F_CID_BROADCAST) {
            u2f_frm *msg = alloca(sizeof(u2f_frm) + sizeof(u2f_cmd_rep_init));
            u2f_cmd_req_init *req = (u2f_cmd_req_init *) chl->frm->pkt.cmd.buf;
            u2f_cmd_rep_init *rep = (u2f_cmd_rep_init *) msg->pkt.cmd.buf;

            if (chl->frm->pkt.cmd.cmd != U2F_CMD_INIT) {
                (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_INVALID_CMD);
                channel_free(chl);
                return 0;
            }

            if (be16toh(chl->frm->pkt.cmd.len) != sizeof(u2f_cmd_req_init)) {
                (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_INVALID_LEN);
                channel_free(chl);
                return 0;
            }

            while (uhid->cid == U2F_CID_RESERVED ||
                   uhid->cid == U2F_CID_BROADCAST)
                uhid->cid++;

            msg->cid = U2F_CID_BROADCAST;
            msg->pkt.cmd.cmd = U2F_CMD_INIT;
            msg->pkt.cmd.len = htobe16(sizeof(u2f_cmd_rep_init));
            rep->non = req->non;
            rep->cid = uhid->cid;
            rep->ver = DEV_HID_VER;
            rep->maj = DEV_VER_MAJ;
            rep->min = DEV_VER_MIN;
            rep->bld = DEV_VER_BLD;
            rep->cap = 0x00;

            (void) u2f_uhid_send(uhid, msg);
            channel_free(chl);
            return 0;
        } else if (chl->frm->pkt.cmd.cmd == U2F_CMD_INIT) {
            (void) u2f_uhid_error(uhid, hid->frm.cid, U2F_ERR_INVALID_CMD);
            channel_free(chl);
            return 0;
        }

        uhid->cb(chl->frm, uhid->misc);
        channel_free(chl);
        return 0;
    }

    return 0;
}

void
u2f_uhid_free(u2f_uhid *uhid)
{
    if (!uhid)
        return;

    if (uhid->src) {
        close(sd_event_source_get_io_fd(uhid->src));
        sd_event_source_unref(uhid->src);
    }

    while (uhid->chls.nxt != &uhid->chls)
        channel_free(u2f_list_itm(channel, lst, &uhid->chls.nxt));

    free(uhid);
}

u2f_uhid *
u2f_uhid_new(const char *name, const char *phys, const char *uniq,
             u2f_uhid_cb *cb, void *misc)
{
    sd_event __attribute__((cleanup(sd_event_unrefp))) *evt = NULL;
    u2f_uhid *uhid = NULL;
    int fd = -1;

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

    strncpy((char *) ue.u.create2.name, name, sizeof(ue.u.create2.name) - 1);
    strncpy((char *) ue.u.create2.phys, phys, sizeof(ue.u.create2.phys) - 1);
    strncpy((char *) ue.u.create2.uniq, uniq, sizeof(ue.u.create2.uniq) - 1);

    if (sd_event_default(&evt) != 0)
        return NULL;

    uhid = calloc(1, sizeof(u2f_uhid));
    if (!uhid)
        return NULL;

    u2f_list_new(&uhid->chls);
    uhid->misc = misc;
    uhid->cb = cb;

    fd = open("/dev/uhid", O_RDWR);
    if (fd < 0)
        goto error;

    if (sd_event_add_io(evt, &uhid->src, fd, EPOLLIN, on_io, uhid) != 0) {
        close(fd);
        goto error;
    }

    if (write(fd, &ue, sizeof(ue)) != sizeof(ue))
        goto error;

    while (ue.type != UHID_START) {
        if (read(fd, &ue, sizeof(ue)) != sizeof(ue))
            goto error;
    }

    return uhid;

error:
    u2f_uhid_free(uhid);
    return NULL;
}

int
u2f_uhid_enable(u2f_uhid *uhid, bool enable)
{
    int arg = enable ? SD_EVENT_ON : SD_EVENT_OFF;
    return sd_event_source_set_enabled(uhid->src, arg);
}

int
#undef u2f_uhid_send
u2f_uhid_send(const u2f_uhid *uhid, const u2f_frm *frm,
              const char *file, int line)
{
    const size_t len = sizeof(*frm) + be16toh(frm->pkt.cmd.len);
    struct uhid_event ue = { .type = UHID_INPUT2 };
    int fd = sd_event_source_get_io_fd(uhid->src);
    u2f_frm *msg = (u2f_frm *) ue.u.input2.data;
    size_t off;

    off = ue.u.input2.size = len < HID_FRME ? len : HID_FRME;
    memcpy(ue.u.input2.data, frm, off);

    if (frm->pkt.cmd.cmd != U2F_CMD_KEEPALIVE)
        u2f_frm_dump("<U ", msg, ue.u.input2.size);

    if (write(fd, &ue, sizeof(ue)) != sizeof(ue))
        return -errno;

    for (msg->pkt.seq.seq = 0; off < len; msg->pkt.seq.seq++) {
        const size_t rem = len - off + offsetof(u2f_frm, pkt.seq.buf);
        const size_t src = off - offsetof(u2f_frm, pkt.cmd.buf);
        size_t cnt;

        ue.u.input2.size = rem < HID_FRME ? rem : HID_FRME;
        cnt = ue.u.input2.size - offsetof(u2f_frm, pkt.seq.buf);

        memcpy(msg->pkt.seq.buf, &frm->pkt.cmd.buf[src], cnt);
        off += cnt;

        if (frm->pkt.cmd.cmd != U2F_CMD_KEEPALIVE)
            u2f_frm_dump("<U ", msg, ue.u.input2.size);

        if (write(fd, &ue, sizeof(ue)) != sizeof(ue))
            return -errno;
    }

    return len;
}

int
#undef u2f_uhid_error
u2f_uhid_error(const u2f_uhid *uhid, uint32_t cid, uint8_t err,
               const char *file, int line)
{
    u2f_frm *frm = alloca(sizeof(*frm) + sizeof(err));

    frm->cid = cid;
    frm->pkt.cmd.cmd = U2F_CMD_ERROR;
    frm->pkt.cmd.len = 1;
    frm->pkt.cmd.buf[0] = err;

    return u2f_uhid_send(uhid, frm, file, line);
}
