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

#define _GNU_SOURCE

#include "gatt.h"
#include "uhid.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <systemd/sd-bus.h>

#define GATT_CHARACTERISTIC "org.bluez.GattCharacteristic1"
#define TIMEOUT_SECONDS 5

#define CNT(v) (sizeof((v)) / sizeof(*(v)))

static const struct {
    const char *uuid;
    const char *name;
} chrs[] = {
    { "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb", "u2fControlPoint" },
    { "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb", "u2fStatus" },
    { "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", "u2fControlPointLength" },
    { "00002a28-0000-1000-8000-00805f9b34fb", "u2fServiceRevision" },
    { "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb", "u2fServiceRevisionBitfield" },
};

struct io {
    u2f_cmd *cmd; /* The incoming or outgoing command */
    size_t   len; /* Bytes of the frame already sent/received */
    uint8_t  seq; /* Sequence counter for continuations */
};

struct send {
    struct io        req; /* Outgoing request state */
    struct io        rep; /* Incoming request state */
    sd_bus_slot     *slt; /* Current outstanding method call */
    uint16_t         mtu; /* BT MTU (cached) */
    sd_event_source *out; /* Timeout event */
    sd_event_source *not; /* Event to catch incoming packets from BT */
};

struct u2f_gatt {
    char            *svc;            /* Service (D-Bus Object Path) */
    char            *chr[CNT(chrs)]; /* Characteristics (D-Bus Object Paths) */

    u2f_gatt_cbk    *cbk;            /* Response callback */
    void            *msc;            /* Misc. data */

    struct send      snd;            /* State for the current send operation */
};

static void
cleanup_send(u2f_gatt *gatt)
{
    if (gatt->snd.not)
        close(sd_event_source_get_io_fd(gatt->snd.not));

    sd_event_source_unref(gatt->snd.not);
    sd_event_source_unref(gatt->snd.out);
    sd_bus_slot_unref(gatt->snd.slt);
    free(gatt->snd.req.cmd);
    free(gatt->snd.rep.cmd);
    memset(&gatt->snd, 0, sizeof(gatt->snd));
}

static int
on_timeout(sd_event_source *s, uint64_t usec, void *userdata)
{
    u2f_gatt *gatt = userdata;
    if (gatt->snd.req.cmd)
        gatt->cbk(u2f_cmd_mkerr(U2F_ERR_MSG_TIMEOUT), gatt->msc);
    cleanup_send(gatt);
    return 0;
}

static sd_event_source *
start_timer(u2f_gatt *gatt)
{
    sd_event_source *out = NULL;
    uint64_t usec = 0;

    if (sd_event_now(SD_EVENT_DEFAULT, CLOCK_MONOTONIC, &usec) < 0)
        return NULL;

    usec += TIMEOUT_SECONDS * 1000000;
    if (sd_event_add_time(SD_EVENT_DEFAULT, &out, CLOCK_MONOTONIC, usec, 1,
                          on_timeout, gatt) < 0)
        return NULL;

    return out;
}

static void
on_bytes(u2f_gatt *gatt, const u2f_pkt *pkt, size_t len)
{
    size_t off = offsetof(u2f_pkt, seq.buf);
    struct io *rep = &gatt->snd.rep;

    if (!gatt->snd.req.cmd ||
        gatt->snd.req.len < be16toh(gatt->snd.req.cmd->len))
        return;

    u2f_pkt_dump(pkt, len, ">G ........ ");

    if (pkt->cmd.cmd & U2F_CMD) {
        if (rep->cmd || len < sizeof(u2f_cmd))
            goto error;

        rep->cmd = calloc(1, sizeof(u2f_cmd) + be16toh(pkt->cmd.len));
        if (!rep->cmd)
            goto error;

        *rep->cmd = pkt->cmd;
        rep->len = 0;

        off = offsetof(u2f_pkt, cmd.buf);
    } else if (!rep->cmd || len <= sizeof(u2f_seq) || pkt->seq.seq != rep->seq++)
        goto error;

    len -= off;
    if (len > be16toh(rep->cmd->len) - rep->len)
        len = be16toh(rep->cmd->len) - rep->len;

    memcpy(&rep->cmd->buf[rep->len], &((uint8_t *) pkt)[off], len);
    rep->len += len;

    if (rep->len < be16toh(rep->cmd->len))
        return;

    /* Ignore keepalive packets and reset timeout. */
    if (rep->cmd->cmd == U2F_CMD_KEEPALIVE) {
        sd_event_source *out = NULL;

        free(rep->cmd);
        memset(rep, 0, sizeof(*rep));

        out = start_timer(gatt);
        if (out) {
            sd_event_source_unref(gatt->snd.out);
            gatt->snd.out = out;
        }

        return;
    }

    gatt->cbk(rep->cmd, gatt->msc);
    cleanup_send(gatt);
    return;

error:
    u2f_gatt_cancel(gatt);
}

static int
on_pkt(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    u2f_gatt *gatt = userdata;
    u2f_pkt *pkt = NULL;
    ssize_t len;

    pkt = alloca(sizeof(*pkt) + gatt->snd.mtu);
    len = read(fd, pkt, sizeof(*pkt) + gatt->snd.mtu);
    if (len < 0)
        u2f_gatt_cancel(gatt);
    else if (len > offsetof(u2f_pkt, seq.buf))
        on_bytes(gatt, pkt, len);

    return 0;
}

static int
on_write(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    sd_bus_message *msg = NULL;
    u2f_gatt *gatt = userdata;
    const char *obj = NULL;
    u2f_seq *seq = NULL;
    size_t len = 0;

    sd_bus_slot_unref(gatt->snd.slt);
    gatt->snd.slt = NULL;

    if (sd_bus_error_is_set(ret_error))
        goto error;

    len = be16toh(gatt->snd.req.cmd->len) - gatt->snd.req.len;
    if (len > gatt->snd.mtu - sizeof(u2f_seq))
        len = gatt->snd.mtu - sizeof(u2f_seq);

    if (len == 0)
        return 0;

    obj = u2f_gatt_get(gatt, "u2fControlPoint");
    if (!obj)
        goto error;

    seq = alloca(sizeof(u2f_seq) + len);
    seq->seq = gatt->snd.req.seq++;
    memcpy(seq->buf, &gatt->snd.req.cmd->buf[gatt->snd.req.len], len);
    gatt->snd.req.len += len;

    u2f_seq_dump(seq, sizeof(u2f_seq) + len, "<G ........ ");

    if (sd_bus_message_new_method_call(sd_bus_message_get_bus(m), &msg,
                                       "org.bluez", obj, GATT_CHARACTERISTIC,
                                       "WriteValue") < 0)
        goto error;

    if (sd_bus_message_append_array(msg, 'y', seq, sizeof(u2f_seq) + len) < 0)
        goto error;

    if (sd_bus_message_append(msg, "a{sv}", 0) < 0)
        goto error;

    if (sd_bus_call_async(sd_bus_message_get_bus(m), &gatt->snd.slt, msg,
                          on_write, gatt, 0) < 0)
        goto error;

    sd_bus_message_unref(msg);
    return 0;

error:
    sd_bus_message_unref(msg);
    u2f_gatt_cancel(gatt);
    return 0;
}

static int
on_mtu(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    sd_bus_message *msg = NULL;
    const uint16_t *mtu = NULL;
    u2f_gatt *gatt = userdata;
    const char *obj = NULL;
    size_t size = 0;

    sd_bus_slot_unref(gatt->snd.slt);
    gatt->snd.slt = NULL;

    if (sd_bus_error_is_set(ret_error))
        goto error;

    if (sd_bus_message_read_array(m, 'y', (const void **) &mtu, &size) < 0)
        goto error;

    if (size != sizeof(*mtu))
        goto error;

    fprintf(stderr, "MTUs: %hu %hu\n", gatt->snd.mtu, be16toh(*mtu));
    if (gatt->snd.mtu > be16toh(*mtu))
        gatt->snd.mtu = be16toh(*mtu);

    if (gatt->snd.mtu <= sizeof(u2f_cmd) || gatt->snd.mtu > 4096)
        goto error;

    gatt->snd.req.len = be16toh(gatt->snd.req.cmd->len);
    if (gatt->snd.req.len > gatt->snd.mtu - sizeof(u2f_cmd))
        gatt->snd.req.len = gatt->snd.mtu - sizeof(u2f_cmd);

    obj = u2f_gatt_get(gatt, "u2fControlPoint");
    if (!obj)
        goto error;

    u2f_cmd_dump(gatt->snd.req.cmd, sizeof(u2f_cmd) + gatt->snd.req.len,
                 "<G ........ ");

    if (sd_bus_message_new_method_call(sd_bus_message_get_bus(m), &msg,
                                       "org.bluez", obj, GATT_CHARACTERISTIC,
                                       "WriteValue") < 0)
        goto error;

    if (sd_bus_message_append_array(msg, 'y', gatt->snd.req.cmd,
                                    sizeof(u2f_cmd) + gatt->snd.req.len) < 0)
        goto error;

    if (sd_bus_message_append(msg, "a{sv}", 0) < 0)
        goto error;

    if (sd_bus_call_async(sd_bus_message_get_bus(m), &gatt->snd.slt, msg,
                          on_write, gatt, 0) < 0)
        goto error;

    sd_bus_message_unref(msg);
    return 0;

error:
    sd_bus_message_unref(msg);
    u2f_gatt_cancel(gatt);
    return 0;
}

static int
on_notify(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    u2f_gatt *gatt = userdata;
    const char *obj = NULL;
    uint16_t mtu = 0;
    int fd = -1;

    sd_bus_slot_unref(gatt->snd.slt);
    gatt->snd.slt = NULL;

    if (sd_bus_error_is_set(ret_error))
        goto error;

    if (sd_bus_message_read(m, "hq", &fd, &mtu) < 0)
        goto error;

    fd = dup(fd);
    if (fd < 0)
        goto error;

    gatt->snd.mtu = mtu;
    if (sd_event_add_io(SD_EVENT_DEFAULT, &gatt->snd.not, fd,
                        EPOLLIN, on_pkt, gatt) < 0) {
        close(fd);
        goto error;
    }

    obj = u2f_gatt_get(gatt, "u2fControlPointLength");
    if (!obj)
        goto error;

    if (sd_bus_call_method_async(sd_bus_message_get_bus(m), &gatt->snd.slt,
                                 "org.bluez", obj, GATT_CHARACTERISTIC,
                                 "ReadValue", on_mtu, gatt, "a{sv}", 0) < 0)
        goto error;

    return 0;

error:
    u2f_gatt_cancel(gatt);
    return 0;
}

void
u2f_gatt_free(u2f_gatt *gatt)
{
    if (!gatt)
        return;

    u2f_gatt_cancel(gatt);

    free(gatt->svc);

    for (size_t i = 0; i < CNT(chrs); i++)
        free(gatt->chr[i]);

    cleanup_send(gatt);
    free(gatt);
}

u2f_gatt *
u2f_gatt_new(const char *svc, u2f_gatt_cbk *cbk, void *msc)
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
    for (size_t i = 0; i < CNT(chrs); i++) {
        char *tmp = NULL;

        if (strcmp(id, chrs[i].name) != 0 && strcasecmp(id, chrs[i].uuid) != 0)
            continue;

        u2f_gatt_cancel(gatt);

        if (obj) {
            tmp = strdup(obj);
            if (!tmp)
                return -ENOMEM;
        }

        free(gatt->chr[i]);
        gatt->chr[i] = tmp;
        return 0;
    }

    return -ENOENT;
}

const char *
u2f_gatt_has(u2f_gatt *gatt, const char *obj)
{
    for (size_t i = 0; i < CNT(chrs); i++) {
        if (gatt->chr[i] && strcmp(gatt->chr[i], obj) == 0)
            return chrs[i].name;
    }

    return NULL;
}

const char *
u2f_gatt_get(const u2f_gatt *gatt, const char *id)
{
    for (size_t i = 0; i < CNT(chrs); i++) {
        if (strcmp(id, chrs[i].name) == 0 || strcasecmp(id, chrs[i].uuid) == 0)
            return gatt->chr[i];
    }

    return NULL;
}

bool
u2f_gatt_ready(u2f_gatt *gatt)
{
    return u2f_gatt_get(gatt, "u2fControlPoint")
        && u2f_gatt_get(gatt, "u2fStatus")
        && u2f_gatt_get(gatt, "u2fControlPointLength");
}

void
u2f_gatt_cancel(u2f_gatt *gatt)
{
    if (gatt->snd.req.cmd)
        gatt->cbk(u2f_cmd_mkerr(U2F_ERR_OTHER), gatt->msc);

    cleanup_send(gatt);
}

void
u2f_gatt_send(u2f_gatt *gatt, const u2f_cmd *cmd)
{
    const char *obj = NULL;

    obj = u2f_gatt_get(gatt, "u2fStatus");
    if (!obj)
        goto error;

    u2f_gatt_cancel(gatt);

    gatt->snd.req.cmd = malloc(sizeof(u2f_cmd) + be16toh(cmd->len));
    if (!gatt->snd.req.cmd)
        goto error;

    memcpy(gatt->snd.req.cmd, cmd, sizeof(u2f_cmd) + be16toh(cmd->len));

    gatt->snd.out = start_timer(gatt);
    if (!gatt->snd.out)
        goto error;

    if (sd_bus_call_method_async(SD_BUS_DEFAULT, &gatt->snd.slt, "org.bluez",
                                 obj, GATT_CHARACTERISTIC, "AcquireNotify",
                                 on_notify, gatt, "a{sv}", 0) < 0)
        goto error;

    return;

error:
    gatt->cbk(u2f_cmd_mkerr(U2F_ERR_OTHER), gatt->msc);
    cleanup_send(gatt);
}
