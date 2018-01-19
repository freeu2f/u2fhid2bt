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
#include "gatt.h"
#include "list.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#define MAN_PATH "/"
#define PRF_PATH "/prf"
#define SVC_UUID "0000fffd-0000-1000-8000-00805f9b34fb"

#define ADD_MATCH \
    "type='signal',sender='org.bluez',path='/',member='InterfacesAdded'," \
    "interface='org.freedesktop.DBus.ObjectManager'"

#define REM_MATCH \
    "type='signal',sender='org.bluez',path='/',member='InterfacesRemoved'," \
    "interface='org.freedesktop.DBus.ObjectManager'"

#define sd_bus_auto \
    sd_bus __attribute__((cleanup(sd_bus_unrefp)))

#define sd_bus_message_auto \
    sd_bus_message __attribute__((cleanup(sd_bus_message_unrefp)))

#define sd_event_auto \
    sd_event __attribute__((cleanup(sd_event_unrefp)))

#define sd_event_source_auto \
    sd_event_source __attribute__((cleanup(sd_event_source_unrefp)))

static u2f_list vu2fs = { &vu2fs, &vu2fs };

typedef struct {
    u2f_list         list;
    u2f_gatt        *gatt;
    u2f_uhid        *uhid;
} vu2f;

static void
vu2f_free(vu2f *v)
{
    if (!v)
        return;

    u2f_list_rem(&v->list);
    u2f_uhid_free(v->uhid);
    u2f_gatt_free(v->gatt);
    free(v);
}

static void
uhid_cb(const u2f_frm *frm, void *misc)
{
    vu2f *v = misc;

    u2f_uhid_enable(v->uhid, false);
    u2f_gatt_send(v->gatt, frm);
}

static void
gatt_cb(const u2f_frm *frm, void *misc)
{
    vu2f *v = misc;

    u2f_uhid_enable(v->uhid, true);
    u2f_uhid_send(v->uhid, frm);
}

static vu2f *
vu2f_new(sd_bus *bus, const char *obj)
{
    vu2f *v = NULL;

    v = calloc(1, sizeof(*v));
    if (!v)
        return NULL;

    u2f_list_new(&v->list);

    v->uhid = u2f_uhid_new("name", "phys", "uniq", uhid_cb, v);
    if (!v->uhid)
        goto error;

    v->gatt = u2f_gatt_new(bus, obj, gatt_cb, v);
    if (!v->gatt)
        goto error;

    return v;

error:
    vu2f_free(v);
    return NULL;
}

static vu2f *
find_vu2f_by_svc(const char *svc)
{
    if (!svc)
        return NULL;

    for (u2f_list *l = vu2fs.nxt; l != &vu2fs; l = l->nxt) {
        vu2f *v = u2f_list_itm(vu2f, list, l);
        if (v->gatt && strcmp(u2f_gatt_svc(v->gatt), svc) == 0)
            return v;
    }

    return NULL;
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
            fprintf(stderr, "+%s\n", obj);
        } else if (strcmp(iface, "org.bluez.GattService1") == 0 &&
                   uuid && strcasecmp(uuid, SVC_UUID) == 0) {
            vu2f *v = find_vu2f_by_svc(obj);
            if (!v) {
                v = vu2f_new(bus, obj);
                if (!v)
                    return -ENOMEM;

                u2f_list_app(&vu2fs, &v->list);
                fprintf(stderr, "+%s\n", obj);
            }
        } else if (strcmp(iface, "org.bluez.GattCharacteristic1") == 0) {
            vu2f *v = find_vu2f_by_svc(parent);
            if (v) {
                u2f_gatt_set(v->gatt, uuid, obj);
                fprintf(stderr, "+%s\n", obj);
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
            fprintf(stderr, "-%s\n", obj);
            vu2f_free(find_vu2f_by_svc(obj));
        } else if (strcmp(iface, "org.bluez.GattCharacteristic1") == 0) {
            fprintf(stderr, "-%s\n", obj);

            for (u2f_list *l = vu2fs.nxt; l != &vu2fs; l = l->nxt) {
                vu2f *v = u2f_list_itm(vu2f, list, l);
                const char *id = NULL;

                if (!v->gatt)
                    continue;

                id = u2f_gatt_has(v->gatt, obj);
                if (id)
                    u2f_gatt_set(v->gatt, id, NULL);
            }
        }
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
    if (strcmp(property, "UUIDs") != 0)
        return -ENOENT;

    return sd_bus_message_append(reply, "as", 1, SVC_UUID);
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
        error(EXIT_FAILURE, -r, "Error creating SIGINT event source");

    r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error creating SIGTERM event source");

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

    while (vu2fs.nxt != &vu2fs) {
        vu2f *v = u2f_list_itm(vu2f, list, vu2fs.nxt);
        u2f_list_rem(&v->list);
        u2f_uhid_free(v->uhid);
        u2f_gatt_free(v->gatt);
        free(v);
    }

    return r;
}
