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

#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "../u2f.h"

#define TIMEOUT 1000000

#define BUS_NAME "org.bluez"

#define MAN_PATH "/"
#define INT_PATH "/org/bluez/hci0"
#define DEV_PATH INT_PATH "/dev0"
#define SVC_PATH DEV_PATH "/svc0"

#define INT_FACE "org.bluez.GattManager1"
#define DEV_FACE "org.bluez.Device1"
#define SVC_FACE "org.bluez.GattService1"
#define CHR_FACE "org.bluez.GattCharacteristic1"

#define VER_U2F_1_1  (1 << 7)
#define VER_U2F_1_2  (1 << 6)
#define VER_FIDO_2_0 (1 << 5)

#define MTU 20
#define MAX \
    (MTU - offsetof(u2f_pkt, cmd.buf) + (INT8_MAX + 1) * \
     (MTU - offsetof(u2f_pkt, seq.buf)))

struct req {
    sd_event_source *out; /* Timeout event */
    uint8_t  seq;
    uint16_t len;
    u2f_cmd  cmd;
};

struct val {
    size_t len;
    uint8_t buf[MTU];
};

struct chr {
    sd_bus_message_handler_t write;
    struct val value;
    const char *uuid;
    const char *path;
};

static struct sd_event_source *notify = NULL;
static struct req *request = NULL;

static int
send_pkt(int fd, u2f_pkt *pkt, size_t hdr, const uint8_t *buf, size_t len)
{
    union {
        uint8_t buf[MTU];
        u2f_pkt pkt;
    } frm;
    int r;

    if (len > MTU - hdr)
        len = MTU - hdr;

    frm.pkt = *pkt;
    memcpy(&frm.buf[hdr], buf, len);

    u2f_pkt_dump(&frm.pkt, hdr + len, "< ");

    errno = 0;
    while (true) {
        r = write(fd, &frm.pkt, hdr + len);
        if (r >= hdr)
            return r - hdr;
        else if (r >= 0)
            return -EIO;
        else if (errno != EAGAIN)
            return -errno;
    }
}

static int
send_reply(const u2f_cmd *cmd)
{
    size_t len = be16toh(cmd->len);
    u2f_pkt pkt = {};
    int fd;
    int r;

    if (!notify)
        return 0;

    if (len > MAX)
        return send_reply(u2f_cmd_mkerr(U2F_ERR_OTHER));

    fd = sd_event_source_get_io_fd(notify);

    pkt.cmd = *cmd;
    r = send_pkt(fd, &pkt, offsetof(u2f_pkt, cmd.buf), cmd->buf, len);
    if (r < 0)
        return r;

    for (size_t off = r, seq = 0; off < len; off += r, seq++) {
        pkt.seq.seq = seq;
        r = send_pkt(fd, &pkt, offsetof(u2f_pkt, seq.buf), &cmd->buf[off], len - off);
        if (r < 0)
            return r;
    }

    return 0;
}

static int
on_timeout(sd_event_source *s, uint64_t usec, void *userdata)
{
    if (!request)
        return 0;

    send_reply(u2f_cmd_mkerr(U2F_ERR_MSG_TIMEOUT));
    sd_event_source_unref(request->out);
    free(request);
    request = NULL;
    return 0;
}

static uint8_t
on_cmd(const u2f_cmd *cmd, size_t len)
{
    __attribute__((cleanup(sd_event_unrefp))) sd_event *e = NULL;
    uint64_t now = 0;

    if (be16toh(cmd->len) > MAX)
        return U2F_ERR_INVALID_LEN;

    if (len > be16toh(cmd->len))
        len = be16toh(cmd->len);

    if (request) {
        sd_event_source_unref(request->out);
        free(request);
        request = NULL;
        return U2F_ERR_INVALID_SEQ;
    }

    if (sd_event_default(&e) < 0)
        return U2F_ERR_OTHER;

    if (sd_event_now(e, CLOCK_MONOTONIC, &now) < 0)
        return U2F_ERR_OTHER;

    request = calloc(1, sizeof(*request) + be16toh(cmd->len));
    if (!request)
        return U2F_ERR_OTHER;

    request->len = len;
    request->cmd = *cmd;
    memcpy(request->cmd.buf, cmd->buf, len);
    if (sd_event_add_time(e, &request->out, CLOCK_MONOTONIC, now + TIMEOUT, 1,
                          on_timeout, NULL) < 0) {
        free(request);
        request = NULL;
        return U2F_ERR_OTHER;
    }

    return U2F_ERR_SUCCESS;
}

static uint8_t
on_seq(const u2f_seq *seq, size_t len)
{
    if (!request)
        return U2F_ERR_SUCCESS;

    if (len > be16toh(request->cmd.len) - request->len)
        len = be16toh(request->cmd.len) - request->len;

    if (seq->seq != request->seq++) {
        sd_event_source_unref(request->out);
        free(request);
        request = NULL;
        return U2F_ERR_INVALID_SEQ;
    }

    memcpy(&request->cmd.buf[request->len], seq->buf, len);
    request->len += len;

    return U2F_ERR_SUCCESS;
}

static int
on_write(sd_bus_message *m, void *userdata, sd_bus_error *err)
{
    uint8_t e = U2F_ERR_SUCCESS;
    const u2f_pkt *pkt = NULL;
    size_t len = 0;
    int r;

    r = sd_bus_message_read_array(m, 'y', (const void **) &pkt, &len);
    if (r < 0)
        return r;

    if (len <= offsetof(u2f_pkt, seq.buf))
        return sd_bus_reply_method_return(m, "");

    u2f_pkt_dump(pkt, len, "> ");
    if (pkt->cmd.cmd & U2F_CMD) {
        if (len >= offsetof(u2f_pkt, cmd.buf)) {
            e = on_cmd(&pkt->cmd, len - offsetof(u2f_pkt, cmd.buf));
        } else {
            e = U2F_ERR_INVALID_LEN;
        }
    } else {
        e = on_seq(&pkt->seq, len - offsetof(u2f_pkt, seq.buf));
    }

    if (e == U2F_ERR_SUCCESS) {
        if (!request || request->len < be16toh(request->cmd.len))
            return sd_bus_reply_method_return(m, "");

        if (request->cmd.cmd != U2F_CMD_PING)
            e = U2F_ERR_INVALID_CMD;
    }

    send_reply(e == U2F_ERR_SUCCESS ? &request->cmd : u2f_cmd_mkerr(e));
    sd_event_source_unref(request->out);
    free(request);
    request = NULL;
    return sd_bus_reply_method_return(m, "");
}

static int
on_ver(sd_bus_message *m, void *userdata, sd_bus_error *err)
{
    return sd_bus_reply_method_return(m, "");
}

static const struct chr u2fControlPoint = {
    .path = SVC_PATH "/chr0",
    .uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb",
    .write = on_write,
};

static const struct chr u2fStatus = {
    .path = SVC_PATH "/chr1",
    .uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
};

static const struct chr u2fControlPointLength = {
    .path = SVC_PATH "/chr2",
    .uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb",
    .value = { 2, { 0, MTU } }
};

static const struct chr u2fServiceRevisionBitfield = {
    .path = SVC_PATH "/chr3",
    .uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb",
    .value = { 1, { VER_U2F_1_2 } },
    .write = on_ver
};

static int
int_meth(sd_bus_message *m, void *userdata, sd_bus_error *err)
{
    return sd_bus_reply_method_return(m, "");
}

static int
dev_prop(sd_bus *bus, const char *path, const char *interface,
         const char *property, sd_bus_message *reply, void *userdata,
         sd_bus_error *ret_error)
{
    if (strcmp(property, "Name") == 0)
        return sd_bus_message_append(reply, "s", "[NAME]");

    if (strcmp(property, "Adapter") == 0)
        return sd_bus_message_append(reply, "o", INT_PATH);

    return -ENOENT;
}

static int
svc_prop(sd_bus *bus, const char *path, const char *interface,
         const char *property, sd_bus_message *reply, void *userdata,
         sd_bus_error *ret_error)
{
    if (strcmp(property, "Includes") == 0)
        return sd_bus_message_append(reply, "ao", 0);

    if (strcmp(property, "Primary") == 0)
        return sd_bus_message_append(reply, "b", true);

    if (strcmp(property, "Device") == 0)
        return sd_bus_message_append(reply, "o", DEV_PATH);

    if (strcmp(property, "UUID") == 0)
        return sd_bus_message_append(reply, "s",
                                     "0000fffd-0000-1000-8000-00805f9b34fb");

    return -ENOENT;
}

static int
chr_prop(sd_bus *bus, const char *path, const char *interface,
         const char *property, sd_bus_message *reply, void *userdata,
         sd_bus_error *ret_error)
{
    struct chr *chr = userdata;
    int r;

    if (strcmp(property, "NotifyAcquired") == 0) {
        if (strcmp(path, u2fStatus.path) == 0)
            return sd_bus_message_append(reply, "b", !!notify);
        else
            return sd_bus_message_append(reply, "b", false);
    }

    if (strcmp(property, "WriteAcquired") == 0)
        return sd_bus_message_append(reply, "b", false);

    if (strcmp(property, "Notifying") == 0)
        return sd_bus_message_append(reply, "b", false);

    if (strcmp(property, "Service") == 0)
        return sd_bus_message_append(reply, "o", SVC_PATH);

    if (strcmp(property, "Value") == 0)
        return sd_bus_message_append(reply, "ay", 0);

    if (strcmp(property, "Flags") == 0) {
        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
            return r;

        if (chr->write && (r = sd_bus_message_append(reply, "s", "write")) < 0)
            return r;

        if (chr->value.len > 0 &&
            (r = sd_bus_message_append(reply, "s", "read")) < 0)
            return r;

        if (!chr->write && chr->value.len == 0 &&
            (r = sd_bus_message_append(reply, "s", "notify")) < 0)
            return r;

        return sd_bus_message_close_container(reply);
    }

    if (strcmp(property, "UUID") == 0)
        return sd_bus_message_append(reply, "s", chr->uuid);

    return -ENOENT;
}

static int
on_hup(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    __attribute__((cleanup(sd_bus_unrefp))) sd_bus *b = NULL;
    int r;

    sd_event_source_unref(notify);
    notify = NULL;
    close(fd);

    r = sd_bus_default(&b);
    if (r < 0)
        return r;

    return sd_bus_emit_properties_changed(b, u2fStatus.path, CHR_FACE,
                                          "NotifyAcquired", NULL);
}

static int
chr_meth(sd_bus_message *m, void *userdata, sd_bus_error *err)
{
    struct chr *chr = userdata;
    const char *name = NULL;
    int r;

    name = sd_bus_message_get_member(m);
    if (!name)
        return -ENOENT;

    if (strcmp(name, "AcquireNotify") == 0) {
        __attribute__((cleanup(sd_event_unrefp))) sd_event *e = NULL;
        int fd[2] = { -1, -1 };

        if (strcmp(sd_bus_message_get_path(m), u2fStatus.path) != 0)
            return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotSupported",
                                              "Operation is not supported (36)");

        if (notify)
            return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotPermitted",
                                              "Notify acquired (36)");

        r = sd_event_default(&e);
        if (r < 0)
            return r;

        if (pipe2(fd, O_DIRECT | O_NONBLOCK | O_CLOEXEC) < 0)
            return -errno;

        r = sd_event_add_io(e, &notify, fd[1], EPOLLHUP, on_hup, NULL);
        if (r < 0) {
            close(fd[0]);
            close(fd[1]);
            return r;
        }

        r = sd_bus_reply_method_return(m, "hq", fd[0], MTU);
        close(fd[0]);
        if (r < 0)
            return r;

        return sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                              chr->path, CHR_FACE,
                                              "NotifyAcquired", NULL);
    }

    if (strcmp(name, "AcquireWrite") == 0)
        return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotSupported",
                                          "Operation is not supported (36)");

    if (strcmp(name, "WriteValue") == 0) {
        if (!chr->write)
            return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotSupported",
                                              "Not supported");

        return chr->write(m, chr, err);
    }

    if (strcmp(name, "ReadValue") == 0) {
        __attribute__((cleanup(sd_bus_message_unrefp))) sd_bus_message *v = NULL;

        if (chr->value.len == 0)
            return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotSupported",
                                              "Operation is not supported (36)");

        r = sd_bus_message_new_method_return(m, &v);
        if (r < 0)
            return r;

        r = sd_bus_message_append_array(v, 'y', chr->value.buf, chr->value.len);
        if (r < 0)
            return r;

        return sd_bus_send(sd_bus_message_get_bus(m), v, NULL);
    }

    if (strcmp(name, "StartNotify") == 0) {
        if (strcmp(sd_bus_message_get_path(m), u2fStatus.path) == 0 && notify)
            return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotPermitted",
                                              "Notify acquired (36)");

        return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotSupported",
                                          "Operation is not supported (36)");
    }

    if (strcmp(name, "StopNotify") == 0)
        return sd_bus_reply_method_errorf(m, "org.bluez.Error.Failed",
                                          "No notify session started (36)");

    return -ENOENT;
}

static const sd_bus_vtable vint[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("RegisterApplication", "oa{sv}", NULL, int_meth, 0),
    SD_BUS_METHOD("UnegisterApplication", "o", NULL, int_meth, 0),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable vdev[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Adapter", "o", dev_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Name", "s", dev_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable vsvc[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Includes", "ao", svc_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Primary", "b", svc_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Device", "o", svc_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("UUID", "s", svc_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable vchr[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("NotifyAcquired", "b", chr_prop, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("WriteAcquired", "b", chr_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Notifying", "b", chr_prop, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Service", "o", chr_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Value", "ay", chr_prop, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Flags", "as", chr_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("UUID", "s", chr_prop, 0, SD_BUS_VTABLE_PROPERTY_CONST),

    SD_BUS_METHOD("AcquireNotify", "a{sv}", "hq", chr_meth, 0),
    SD_BUS_METHOD("AcquireWrite", "a{sv}", "hq", chr_meth, 0),
    SD_BUS_METHOD("WriteValue", "aya{sv}", "", chr_meth, 0),
    SD_BUS_METHOD("ReadValue", "a{sv}", "ay", chr_meth, 0),
    SD_BUS_METHOD("StartNotify", "", "", chr_meth, 0),
    SD_BUS_METHOD("StopNotify", "", "", chr_meth, 0),
    SD_BUS_VTABLE_END
};

static int
on_dbus(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    return sd_bus_process(userdata, NULL);
}

int
main(int argc, const char *argv[])
{
    static const struct chr *chrs[] = {
        &u2fControlPoint,
        &u2fStatus,
        &u2fControlPointLength,
        &u2fServiceRevisionBitfield,
        NULL
    };

    __attribute__((cleanup(sd_event_source_unrefp))) sd_event_source *s = NULL;
    __attribute__((cleanup(sd_event_unrefp))) sd_event *e = NULL;
    __attribute__((cleanup(sd_bus_unrefp))) sd_bus *b = NULL;
    sigset_t ss;
    int r;

    assert(sigemptyset(&ss) == 0);
    assert(sigaddset(&ss, SIGTERM) == 0);
    assert(sigaddset(&ss, SIGINT) == 0);
    assert(sigprocmask(SIG_BLOCK, &ss, NULL) == 0);

    assert(sd_event_default(&e) >= 0);
    assert(sd_bus_default(&b) >= 0);

    assert(sd_bus_request_name(b, BUS_NAME, 0) >= 0);

    assert(sd_event_add_signal(e, NULL, SIGINT, NULL, NULL) >= 0);
    assert(sd_event_add_signal(e, NULL, SIGTERM, NULL, NULL) >= 0);
    assert(sd_event_add_io(e, &s, sd_bus_get_fd(b), EPOLLIN, on_dbus, b) >= 0);
    assert(sd_event_source_set_priority(s, SD_EVENT_PRIORITY_IDLE) >= 0);

    assert(sd_bus_add_object_manager(b, NULL, MAN_PATH) >= 0);
    assert(sd_bus_add_object_vtable(b, NULL, INT_PATH, INT_FACE, vint, NULL) >= 0);
    assert(sd_bus_add_object_vtable(b, NULL, DEV_PATH, DEV_FACE, vdev, NULL) >= 0);
    assert(sd_bus_add_object_vtable(b, NULL, SVC_PATH, SVC_FACE, vsvc, NULL) >= 0);
    for (size_t i = 0; chrs[i]; i++)
        assert(sd_bus_add_object_vtable(b, NULL, chrs[i]->path, CHR_FACE,
                                        vchr, (void *) chrs[i]) >= 0);

    r = sd_event_loop(e);

    if (notify)
        close(sd_event_source_get_io_fd(notify));

    if (request)
        sd_event_source_unref(request->out);

    sd_event_source_unref(notify);
    free(request);

    return r;
}
