/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "core.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#define DEV_HID_VER 2
#define DEV_VER_MAJ 0
#define DEV_VER_MIN 0
#define DEV_VER_BLD 0

#define MAN_PATH "/"
#define PRF_PATH "/prf"
#define SVC_UUID "0000fffd-0000-1000-8000-00805f9b34fb"

#define ADD_MATCH \
    "type='signal',sender='org.bluez',path='/',member='InterfacesAdded'," \
    "interface='org.freedesktop.DBus.ObjectManager'"

#define REM_MATCH \
    "type='signal',sender='org.bluez',path='/',member='InterfacesRemoved'," \
    "interface='org.freedesktop.DBus.ObjectManager'"

#define VAL_MATCH \
    "type='signal',sender='org.bluez',member='PropertiesChanged'," \
    "interface='org.freedesktop.DBus.Properties'," \
    "arg0='org.bluez.GattCharacteristic1'"

static list svcs = { &svcs, &svcs };

static const struct {
    const char *name;
    const char *uuid;
} svc_props[] = { /* Index MUST match chr values! */
    { "u2fControlPoint", "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb" },
    { "u2fStatus", "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb" },
    { "u2fControlPointLength", "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb" },
    { "u2fServiceRevision", "00002a28-0000-1000-8000-00805f9b34fb" },
    { "u2fServiceRevisionBitfield", "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb" },
};

static u2f_chl *
find_chl_by_cid(const list *chls, uint32_t cid)
{
    for (list *l = chls->nxt; l != chls; l = l->nxt) {
        u2f_chl *chl = list_itm(u2f_chl, lst, l);
        if (chl->cid == cid)
            return chl;
    }

    return NULL;
}

static u2f_svc *
find_svc_by_obj(const char *obj)
{
    if (!obj)
        return NULL;

    for (list *l = svcs.nxt; l != &svcs; l = l->nxt) {
        u2f_svc *svc = list_itm(u2f_svc, lst, l);
        if (strcmp(svc->obj, obj) == 0)
            return svc;
    }

    return NULL;
}

static u2f_svc *
find_svc_by_chr(const char *obj, u2f_chr chr)
{
    if (!obj)
        return NULL;

    for (list *l = svcs.nxt; l != &svcs; l = l->nxt) {
        u2f_svc *svc = list_itm(u2f_svc, lst, l);
        if (svc->chr[chr] && strcmp(svc->chr[chr], obj) == 0)
            return svc;
    }

    return NULL;
}

static int
on_cmd_init(u2f_chl *chl)
{
    if (chl->cid != U2F_CID_BROADCAST)
        return u2f_chl_err(chl, U2F_ERR_INVALID_CID);

    if (chl->pkt->cnt != 8)
        return u2f_chl_err(chl, U2F_ERR_INVALID_LEN);

    if (u2f_svc_mtu(chl->svc) < 0) {
        fprintf(stderr, "Device is unreachable! %s\n", chl->svc->obj);
        return u2f_chl_err(chl, U2F_ERR_OTHER);
    }

    while (chl->svc->cid == U2F_CID_RESERVED ||
           chl->svc->cid == U2F_CID_BROADCAST)
        chl->svc->cid++;

    uint64_t nonce = load64(chl->pkt->buf);
    uint8_t msg[] = {
        save32(chl->cid),
        U2F_CMD_INIT,
        save16(17), /* Length */
        save64(nonce),
        save32(chl->svc->cid),
        DEV_HID_VER,
        DEV_VER_MAJ,
        DEV_VER_MIN,
        DEV_VER_BLD,
        0x00 /* Capabilities flags */
    };

    return u2f_chl_rep_buf(chl, msg, sizeof(msg));
}

static int
on_cmd(u2f_chl *chl)
{
    u2f_chl *tmp = NULL;
    int r;

    if (chl->pkt->cmd == U2F_CMD_INIT)
        return on_cmd_init(chl);

    if (chl->cid == U2F_CID_RESERVED || chl->cid == U2F_CID_BROADCAST)
        return u2f_chl_err(chl, U2F_ERR_INVALID_CID);

    tmp = u2f_chl_new(chl->cid, NULL, 0);
    if (!tmp)
        return u2f_chl_err(chl, U2F_ERR_OTHER);

    list_app(&chl->svc->rep, &tmp->lst);
    tmp->svc = chl->svc;

    r = u2f_chl_req(chl);
    if (r < 0) {
        u2f_chl_free(tmp);
        return u2f_chl_err(chl, U2F_ERR_OTHER);
    }

    return r;
}

static int
on_uhid_data(u2f_svc *svc, const uint8_t *buf, size_t len)
{
    if (len < 4)
        return 0; /* Input data is too malformed to make an error. */

    uint32_t cid = load32(buf);
    u2f_chl *chl = find_chl_by_cid(&svc->req, cid);
    u2f_chl tmp = { .cid = cid, .svc = svc };

    if (len < 5)
        return u2f_chl_err(&tmp, U2F_ERR_INVALID_LEN);

    /* Data layout: see U2F HID Section 2.4. Channel ID already removed. */

    if (buf[5] & U2F_CMD_BIT) {
        if (chl) {
            (void) u2f_chl_err(chl, U2F_ERR_CHANNEL_BUSY);
            u2f_chl_free(chl);
        }

        if (len < 3)
            return u2f_chl_err(&tmp, U2F_ERR_INVALID_LEN);

        chl = u2f_chl_new(cid, &buf[4], len - 4);
        if (!chl)
            return u2f_chl_err(&tmp, U2F_ERR_OTHER);

        list_app(&svc->req, &chl->lst);
    } else if (chl) {
        uint16_t rem = chl->pkt->cnt - chl->len;
        uint16_t cnt = (len - 5) < rem ? len - 5 : rem;

        if (buf[5] != chl->seq) {
            (void) u2f_chl_err(chl, U2F_ERR_INVALID_SEQ);
            u2f_chl_free(chl);
            return 0;
        }

        memcpy(&chl->pkt->buf[chl->len], &buf[5], cnt);
        chl->len += cnt;
        chl->seq++;
    } else {
        return u2f_chl_err(&tmp, U2F_ERR_INVALID_CID);
    }

    if (chl->len == chl->pkt->cnt) {
        (void) on_cmd(chl);
        u2f_chl_free(chl);
    }

    return 0;
}

static int
on_reply(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    if (sd_bus_error_is_set(ret_error))
        fprintf(stderr, "Error registering: %s: %s\n",
                ret_error->name, ret_error->message);

    return 0;
}

static int
on_svc_iface_add(sd_bus_message *m, void *misc, sd_bus_error *ret_error)
{
    sd_bus *bus = sd_bus_message_get_bus(m);
    const char *obj = NULL;
    int r;

    r = sd_bus_message_has_signature(m, "oa{sa{sv}}");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", &obj);
    if (r < 0)
        return r;

    r = sd_bus_message_enter_container(m, 'a', "{sa{sv}}");
    if (r < 0)
        return r;

    while ((r = sd_bus_message_enter_container(m, 'e', "sa{sv}")) > 0) {
        const char *parent = NULL;
        const char *iface = NULL;
        const char *uuid = NULL;

        r = sd_bus_message_read(m, "s", &iface);
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

            if (strcmp(name, "UUID") == 0) {
                r = sd_bus_message_read(m, "v", "s", &uuid);
                if (r < 0)
                    return r;
            } else if (strcmp(name, "Service") == 0 ||
                       strcmp(name, "Device") == 0) {
                r = sd_bus_message_read(m, "v", "o", &parent);
                if (r < 0)
                    return r;
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

        r = sd_bus_message_exit_container(m);
        if (r < 0)
            return r;

        if (strcmp(iface, "org.bluez.GattManager1") == 0) {
            r = sd_bus_call_method_async(bus, NULL, "org.bluez", obj, iface,
                                         "RegisterApplication", on_reply,
                                         NULL, "oa{sv}", MAN_PATH, 0);
            if (r < 0)
                return r;
        } else if (strcmp(iface, "org.bluez.GattService1") == 0 &&
                   uuid && strcasecmp(uuid, SVC_UUID) == 0) {
            u2f_svc *svc = find_svc_by_obj(obj);
            if (!svc) {
                svc = u2f_svc_new(bus, on_uhid_data, parent, obj);
                if (!svc)
                    return -ENOMEM;

                list_app(&svcs, &svc->lst);
                fprintf(stderr, "+%s\n", svc->obj);
            }
        } else if (strcmp(iface, "org.bluez.GattCharacteristic1") == 0) {
            u2f_svc *svc = find_svc_by_obj(parent);

            for (size_t i = 0; svc && i < _CHR_TOTAL; i++) {
                if (strcasecmp(svc_props[i].uuid, uuid) != 0)
                    continue;

                free(svc->chr[i]);
                svc->chr[i] = strdup(obj);
                if (!svc->chr[i])
                    return -ENOMEM;

                break;
            }
        }
    }
    if (r < 0)
        return r;

    r = sd_bus_message_exit_container(m);
    if (r < 0)
        return r;

    return 0;
}

static int
on_svc_iface_rem(sd_bus_message *m, void *misc, sd_bus_error *ret_error)
{
    const char *obj = NULL;
    int r;

    r = sd_bus_message_has_signature(m, "oas");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", &obj);
    if (r < 0)
        return r;

    r = sd_bus_message_enter_container(m, 'a', "s");
    if (r < 0)
        return r;

    while ((r = sd_bus_message_enter_container(m, 'e', "s")) > 0) {
        const char *iface = NULL;

        r = sd_bus_message_read(m, "s", &iface);
        if (r < 0)
            return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
            return r;

        if (strcmp(iface, "org.bluez.GattService1") == 0) {
            u2f_svc *svc = find_svc_by_obj(obj);
            if (svc) {
                fprintf(stderr, "-%s\n", svc->obj);
                u2f_svc_free(svc);
            }
        }
    }

    r = sd_bus_message_exit_container(m);
    if (r < 0)
        return r;

    return 0;
}

static int
on_svc_reply(const char *obj, const uint8_t *buf, size_t len)
{
    u2f_svc *svc = NULL;
    u2f_chl *chl = NULL;

    svc = find_svc_by_chr(obj, CHR_STATUS);
    if (!svc || len < 1 || svc->rep.nxt == &svc->rep)
        return 0;

    chl = list_itm(u2f_chl, lst, svc->rep.nxt);
    if (buf[0] & U2F_CMD_BIT) {
        if (len < 3)
            return 0;

        if (chl->pkt) {
            u2f_chl_err(chl, U2F_ERR_OTHER);
            u2f_chl_free(chl);
            return on_svc_reply(obj, buf, len);
        }

        chl->len = len;
        chl->pkt = u2f_pkt_new(buf, &chl->len);
        if (!chl->pkt)
            goto error;
    } else if (chl->pkt) {
        uint16_t rem = chl->pkt->cnt - chl->len;
        uint16_t cnt = (len - 1) < rem ? len - 1 : rem;

        if (buf[0] != chl->seq)
            goto error;

        memcpy(&chl->pkt->buf[chl->len], &buf[1], cnt);
        chl->len += cnt;
        chl->seq++;
    } else {
        goto error;
    }

    if (chl->len == chl->pkt->cnt) {
        if (u2f_chl_rep(chl) < 0)
            goto error;
    }

    u2f_chl_free(chl);
    return 0;

error:
    (void) u2f_chl_err(chl, U2F_ERR_OTHER);
    u2f_chl_free(chl);
    return 0;
}

static int
on_svc_gatt_chr_notify(sd_bus_message *m, void *misc, sd_bus_error *ret_error)
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
            union {
                const void *buf;
                const uint8_t *arr;
            } out = {};
            size_t len = 0;

            r = sd_bus_message_enter_container(m, 'v', "ay");
            if (r < 0)
                return r;

            r = sd_bus_message_read_array(m, 'y', &out.buf, &len);
            if (r < 0)
                return r;

            r = sd_bus_message_exit_container(m);
            if (r < 0)
                return r;

            (void) on_svc_reply(sd_bus_message_get_path(m), out.arr, len);
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

static void
setup_registration(sd_bus *bus)
{
    sd_bus_message_auto *msg = NULL;
    int r;

    r = sd_bus_add_match(bus, NULL, ADD_MATCH, on_svc_iface_add, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error registering for bluetooth interfaces");

    r = sd_bus_add_match(bus, NULL, REM_MATCH, on_svc_iface_rem, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error registering for bluetooth interfaces");

    r = sd_bus_add_match(bus, NULL, VAL_MATCH, on_svc_gatt_chr_notify, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error registering for bluetooth interfaces");

    r = sd_bus_call_method(bus, "org.bluez", "/",
                           "org.freedesktop.DBus.ObjectManager",
                           "GetManagedObjects", NULL, &msg, "");
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error calling bluez ObjectManager");

    r = sd_bus_message_enter_container(msg, 'a', "{oa{sa{sv}}}");
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error parsing bluez results");

    while ((r = sd_bus_message_enter_container(msg, 'e', "oa{sa{sv}}")) > 0) {
        r = on_svc_iface_add(msg, NULL, NULL);
        if (r < 0)
            error(EXIT_FAILURE, -r, "Error parsing bluez results");

        r = sd_bus_message_exit_container(msg);
        if (r < 0)
            error(EXIT_FAILURE, -r, "Error parsing bluez results");
    }
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error parsing bluez results");

    r = sd_bus_message_exit_container(msg);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error parsing bluez results");
}

static int
on_dbus_io(sd_event_source *es, int fd, uint32_t revents, void *userdata)
{
    return sd_bus_process(userdata, NULL);
}

static int
prf_release(sd_bus_message *m, void *misc, sd_bus_error *err)
{
    return sd_bus_reply_method_return(m, "");
}

static int
prf_props(sd_bus *bus, const char *path, const char *interface,
          const char *property, sd_bus_message *reply, void *userdata,
          sd_bus_error *ret_error)
{
    int r;

    if (strcmp(property, "UUIDs") != 0)
        return -ENOENT;

    r = sd_bus_message_open_container(reply, 'a', "s");
    if (r < 0)
        return r;

    r = sd_bus_message_append(reply, "s", SVC_UUID);
    if (r < 0)
        return r;

    return sd_bus_message_close_container(reply);
}

static const sd_bus_vtable prf_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Release", "", "", prf_release, 0),
    SD_BUS_PROPERTY("UUIDs", "as", prf_props, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END
};

int
main(int argc, char *argv[])
{
    sd_event_auto *event = NULL;
    sd_bus_auto *bus = NULL;
    sigset_t ss;
    int r;

    if (sigemptyset(&ss) < 0 ||
        sigaddset(&ss, SIGTERM) < 0 ||
        sigaddset(&ss, SIGINT) < 0 ||
        sigprocmask(SIG_BLOCK, &ss, NULL) < 0)
        error(EXIT_FAILURE, errno, "Error blocking signals");

    r = sd_event_default(&event);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error creating main loop");

    r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error creating signal event source");

    r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error creating signal event source");

    r = sd_bus_open_system(&bus);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error connecting to system bus");

    r = sd_event_add_io(event, NULL, sd_bus_get_fd(bus),
                        EPOLLIN, on_dbus_io, bus);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error creating dbus event source");

    r = sd_bus_add_object_manager(bus, NULL, MAN_PATH);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error adding object manager");

    r = sd_bus_add_object_vtable(bus, NULL, PRF_PATH,
                                 "org.bluez.GattProfile1",
                                 prf_vtable, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error creating profile");

    setup_registration(bus);

    r = sd_event_loop(event);

    while (svcs.nxt != &svcs)
        u2f_svc_free(list_itm(u2f_svc, lst, svcs.nxt));

    return r;
}
