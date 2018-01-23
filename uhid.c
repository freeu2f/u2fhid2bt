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

#include <linux/uhid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <systemd/sd-bus.h>

#define TIMEOUT 500000

#define HID_VEND 0
#define HID_PROD 0
#define HID_VERS 0
#define HID_CTRY 0
#define HID_FRME 64

#define DEV_HID_VER 2
#define DEV_VER_MAJ 0
#define DEV_VER_MIN 0
#define DEV_VER_BLD 0

#define MAX_LEN \
    (HID_FRME - offsetof(u2f_frm, pkt.cmd.buf) + (INT8_MAX + 1) * \
     (HID_FRME - offsetof(u2f_frm, pkt.seq.buf)))

typedef struct __attribute__((packed)) {
    uint8_t rid; // Report ID (1 byte); See (I think): USB HID 1.11 Section 5.6
    u2f_frm frm;
} hid_frm;

struct u2f_uhid {
    sd_event_source *src; /* File data event source */
    sd_event_source *out; /* Timeout event source */

    uint32_t         cid; /* Channel ID iterator (for INIT command) */

    u2f_uhid_cbk    *cbk; /* Callback for incoming request */
    void            *msc; /* Misc. data for callback */

    u2f_frm         *frm; /* Incoming request (in progress) */
    uint8_t          seq; /* Sequence counter */
    size_t           len; /* # bytes written in frm->pkt.cmd.buf */
};

static int
send_frm(int fd, uint32_t cid, u2f_pkt *pkt, size_t hdr,
         const uint8_t *buf, size_t len)
{
    struct uhid_event ue = { .type = UHID_INPUT2 };
    u2f_frm *frm = (u2f_frm *) ue.u.input2.data;

    if (len > HID_FRME - offsetof(u2f_frm, pkt) - hdr)
        len = HID_FRME - offsetof(u2f_frm, pkt) - hdr;

    frm->cid = cid;
    frm->pkt = *pkt;
    memcpy(&ue.u.input2.data[offsetof(u2f_frm, pkt) + hdr], buf, len);
    ue.u.input2.size = HID_FRME;

    u2f_frm_dump(frm, offsetof(u2f_frm, pkt) + hdr + len, "<U ");
    return write(fd, &ue, sizeof(ue)) == sizeof(ue) ? len : -errno;
}

static int
send_reply(int fd, uint32_t cid, const u2f_cmd *cmd)
{
    size_t len = be16toh(cmd->len);
    u2f_pkt pkt = {};
    int r;

    if (len > MAX_LEN)
        return send_reply(fd, cid, u2f_cmd_mkerr(U2F_ERR_OTHER));

    pkt.cmd = *cmd;
    r = send_frm(fd, cid, &pkt, offsetof(u2f_pkt, cmd.buf), cmd->buf, len);
    if (r < 0)
        return r;

    for (size_t off = r, seq = 0; off < len; off += r, seq++) {
        pkt.seq.seq = seq;
        r = send_frm(fd, cid, &pkt, offsetof(u2f_pkt, seq.buf),
                     &cmd->buf[off], len - off);
        if (r < 0)
            return r;
    }

    return 0;
}

static int
on_timeout(sd_event_source *s, uint64_t usec, void *userdata)
{
    u2f_uhid *uhid = userdata;

    sd_event_source_unref(uhid->out);
    uhid->out = NULL;

    (void) u2f_uhid_send(uhid, u2f_cmd_mkerr(U2F_ERR_MSG_TIMEOUT));
    return 0;
}

static void
on_init(u2f_uhid *uhid, uint32_t cid, const u2f_cmd *creq)
{
    u2f_cmd *crep = alloca(sizeof(u2f_cmd) + sizeof(u2f_cmd_rep_init));
    u2f_cmd_req_init *ireq = (u2f_cmd_req_init *) creq->buf;
    u2f_cmd_rep_init *irep = (u2f_cmd_rep_init *) crep->buf;

    if (be16toh(creq->len) != sizeof(u2f_cmd_req_init)) {
        (void) send_reply(sd_event_source_get_io_fd(uhid->src), cid,
                          u2f_cmd_mkerr(U2F_ERR_INVALID_LEN));
        return;
    }

    crep->cmd = U2F_CMD_INIT;
    crep->len = htobe16(sizeof(u2f_cmd_rep_init));
    irep->non = ireq->non;
    irep->cid = cid;
    irep->ver = DEV_HID_VER;
    irep->maj = DEV_VER_MAJ;
    irep->min = DEV_VER_MIN;
    irep->bld = DEV_VER_BLD;
    irep->cap = 0x00;

    while (irep->cid == U2F_CID_BROADCAST || irep->cid == U2F_CID_RESERVED)
        irep->cid = ++(uhid->cid);

    (void) send_reply(sd_event_source_get_io_fd(uhid->src), cid, crep);

    if (uhid->frm && uhid->frm->cid == cid) {
        free(uhid->frm);
        uhid->frm = NULL;
    }
}

static uint8_t
on_cmd(u2f_uhid *uhid, uint32_t cid, const u2f_cmd *cmd, size_t len)
{
    uint64_t now = 0;

    if (len < offsetof(hid_frm, frm.pkt.cmd.buf))
        return U2F_ERR_INVALID_LEN;

    if (be16toh(cmd->len) > MAX_LEN)
        return U2F_ERR_INVALID_LEN;

    if (len > be16toh(cmd->len))
        len = be16toh(cmd->len);

    switch (cid) {
    case U2F_CID_RESERVED:
        return U2F_ERR_INVALID_CID;

    case U2F_CID_BROADCAST:
        if (cmd->cmd == U2F_CMD_INIT)
            break;
        return U2F_ERR_INVALID_CID;
    }

    if (cmd->cmd == U2F_CMD_INIT) {
        on_init(uhid, cid, cmd);
        return U2F_ERR_SUCCESS;
    }

    if (uhid->frm) {
        if (cid != uhid->frm->cid)
            return U2F_ERR_CHANNEL_BUSY;

        free(uhid->frm);
        uhid->frm = NULL;
        return U2F_ERR_INVALID_SEQ;
    }

    if (sd_event_now(sd_event_source_get_event(uhid->src),
                     CLOCK_MONOTONIC, &now) < 0)
        return U2F_ERR_OTHER;

    uhid->seq = 0;
    uhid->len = len;
    uhid->frm = calloc(1, sizeof(u2f_frm) + be16toh(cmd->len));
    if (!uhid->frm)
        goto error;

    uhid->frm->cid = cid;
    uhid->frm->pkt.cmd = *cmd;
    memcpy(uhid->frm->pkt.cmd.buf, cmd->buf, len);

    if (sd_event_add_time(sd_event_source_get_event(uhid->src),
                          &uhid->out, CLOCK_MONOTONIC, now + TIMEOUT, 1,
                          on_timeout, uhid) < 0)
        goto error;

    return U2F_ERR_SUCCESS;

error:
    free(uhid->frm);
    uhid->frm = NULL;
    return U2F_ERR_OTHER;
}

static uint8_t
on_seq(u2f_uhid *uhid, uint32_t cid, const u2f_seq *seq, size_t len)
{
    if (!uhid->frm)
        return U2F_ERR_SUCCESS;

    if (len > be16toh(uhid->frm->pkt.cmd.len) - uhid->len)
        len = be16toh(uhid->frm->pkt.cmd.len) - uhid->len;

    if (cid != uhid->frm->cid)
        return U2F_ERR_SUCCESS;

    if (seq->seq != uhid->seq++) {
        free(uhid->frm);
        uhid->frm = NULL;
        return U2F_ERR_INVALID_SEQ;
    }

    memcpy(&uhid->frm->pkt.cmd.buf[uhid->len], seq->buf, len);
    uhid->len += len;

    return U2F_ERR_SUCCESS;
}

static int
on_io(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    uint8_t err = U2F_ERR_OTHER;
    u2f_uhid *uhid = userdata;
    struct uhid_event ue = {};
    hid_frm *hid = NULL;

    if (read(fd, &ue, sizeof(ue)) != sizeof(ue))
        return -errno;

    if (ue.type != UHID_OUTPUT)
        return 0;

    if (ue.u.output.size < offsetof(hid_frm, frm.pkt.seq.buf))
        return 0;

    hid = (hid_frm *) ue.u.output.data;
    u2f_frm_dump(&hid->frm, ue.u.output.size, ">U ");

    if (hid->frm.pkt.cmd.cmd & U2F_CMD)
        err = on_cmd(uhid, hid->frm.cid, &hid->frm.pkt.cmd,
                     ue.u.output.size - offsetof(hid_frm, frm.pkt.cmd.buf));
    else
        err = on_seq(uhid, hid->frm.cid, &hid->frm.pkt.seq,
                     ue.u.output.size - offsetof(hid_frm, frm.pkt.seq.buf));

    if (err != U2F_ERR_SUCCESS)
        return send_reply(sd_event_source_get_io_fd(s), hid->frm.cid,
                          u2f_cmd_mkerr(err));

    if (!uhid->frm || uhid->len < be16toh(uhid->frm->pkt.cmd.len))
        return 0;

    uhid->cbk(&uhid->frm->pkt.cmd, uhid->msc);
    sd_event_source_unref(uhid->out);
    uhid->out = NULL;
    return 0;
}

void
u2f_uhid_free(u2f_uhid *uhid)
{
    if (!uhid)
        return;

    if (uhid->src)
        close(sd_event_source_get_io_fd(uhid->src));

    sd_event_source_unref(uhid->src);
    sd_event_source_unref(uhid->out);
    free(uhid->frm);
    free(uhid);
}

u2f_uhid *
u2f_uhid_new(const char *name, const char *phys, const char *uniq,
             u2f_uhid_cbk *cbk, void *msc)
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

    uhid->msc = msc;
    uhid->cbk = cbk;

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
u2f_uhid_send(u2f_uhid *uhid, const u2f_cmd *cmd)
{
    int r;

    if (!uhid->frm)
        return -ENOENT;

    r = send_reply(sd_event_source_get_io_fd(uhid->src), uhid->frm->cid, cmd);
    free(uhid->frm);
    uhid->frm = NULL;
    return r;
}
