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

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include <systemd/sd-bus.h>

#define MAN_PATH "/"
#define PRF_PATH "/prf"
#define SVC_UUID "0000fffd-0000-1000-8000-00805f9b34fb"

#define ADD_MATCH \
    "type='signal',sender='org.bluez',path='/',member='InterfacesAdded'," \
    "interface='org.freedesktop.DBus.ObjectManager'"

#define REM_MATCH \
    "type='signal',sender='org.bluez',path='/',member='InterfacesRemoved'," \
    "interface='org.freedesktop.DBus.ObjectManager'"

struct dev;

struct svc {
    struct svc *prev;
    struct svc *next;

    u2f_gatt   *gatt;
    u2f_uhid   *uhid;
    struct dev *prnt;
};

struct dev {
    struct dev *prev;
    struct dev *next;

    struct svc  svcs;
    char       *path;
    char       *name;
};

static struct dev devs = { .prev = &devs, .next = &devs };

static void
on_uhid(const u2f_cmd *cmd, void *misc)
{
    struct svc *svc = misc;
    u2f_gatt_send(svc->gatt, cmd);
}

static void
on_gatt(const u2f_cmd *cmd, void *misc)
{
    struct svc *svc = misc;
    if (svc->uhid)
        u2f_uhid_send(svc->uhid, cmd);
}

static struct dev *
dev_find(const char *path)
{
    for (struct dev *d = devs.next; d != &devs; d = d->next) {
        if (strcmp(d->path, path) == 0)
            return d;
    }

    return NULL;
}

static struct svc *
svc_find(const char *path)
{
    for (struct dev *d = devs.next; d != &devs; d = d->next) {
        for (struct svc *s = d->svcs.next; s != &d->svcs; s = s->next) {
            if (strcmp(u2f_gatt_svc(s->gatt), path) == 0)
                return s;
        }
    }

    return NULL;
}

static void
svc_free(struct svc *svc)
{
    if (!svc)
        return;

    svc->next->prev = svc->prev;
    svc->prev->next = svc->next;
    u2f_gatt_free(svc->gatt);
    u2f_uhid_free(svc->uhid);
    free(svc);
}

static void
dev_free(struct dev *dev)
{
    if (!dev)
        return;

    while (dev->svcs.next != &dev->svcs)
        svc_free(dev->svcs.next);

    dev->next->prev = dev->prev;
    dev->prev->next = dev->next;
    free(dev->name);
    free(dev->path);
    free(dev);
}

static int
dev_add(const char *parent, const char *path, const char *info)
{
    struct dev *dev = NULL;

    if (dev_find(path))
        return 0;

    dev = calloc(1, sizeof(*dev));
    if (!dev)
        return -errno;

    dev->svcs.next = &dev->svcs;
    dev->svcs.prev = &dev->svcs;
    dev->path = strdup(path);
    dev->name = strdup(info);
    if (!dev->path || !dev->name) {
        dev_free(dev);
        return -ENOMEM;
    }

    fprintf(stderr, "+%s (%s)\n", path, info);
    devs.next->prev = dev;
    dev->prev = &devs;
    dev->next = devs.next;
    devs.next = dev;
    return 0;
}

static int
svc_add(const char *parent, const char *path, const char *info)
{
    struct dev *dev = dev_find(parent);
    struct svc *svc = svc_find(path);

    if (svc || !dev || !info || strcasecmp(info, SVC_UUID) != 0)
        return 0;

    svc = calloc(1, sizeof(*svc));
    if (!svc)
        return -errno;

    svc->prnt = dev;
    svc->gatt = u2f_gatt_new(path, on_gatt, svc);
    if (!svc->gatt) {
        free(svc);
        return -errno;
    }

    fprintf(stderr, "+%s\n", path);
    dev->svcs.next->prev = svc;
    svc->prev = &dev->svcs;
    svc->next = dev->svcs.next;
    dev->svcs.next = svc;
    return 0;
}

static int
chr_add(const char *parent, const char *path, const char *info)
{
    struct svc *svc = svc_find(parent);
    int r;

    if (!svc || !path || !info)
        return 0;

    fprintf(stderr, "+%s (%s)\n", path, info);
    r = u2f_gatt_set(svc->gatt, info, path);
    if (r < 0)
        return r;

    if (!svc->uhid && u2f_gatt_ready(svc->gatt)) {
        svc->uhid = u2f_uhid_new(svc->prnt->name, svc->prnt->name,
                                 u2f_gatt_svc(svc->gatt), on_uhid, svc);
        if (!svc->uhid)
            return -ENOMEM;
    }

    return 0;
}

static void
chr_rem(const char *path)
{
    for (struct dev *d = devs.next; d != &devs; d = d->next) {
        for (struct svc *s = d->svcs.next; s != &d->svcs; s = s->next) {
            const char *id = u2f_gatt_has(s->gatt, path);

            if (!id)
                continue;

            u2f_gatt_set(s->gatt, id, NULL);

            if (!u2f_gatt_ready(s->gatt)) {
                u2f_uhid_free(s->uhid);
                s->uhid = NULL;
            }

            return;
        }
    }
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
    const char *path = NULL;
    int r;

    r = sd_bus_message_has_signature(m, "oa{sa{sv}}");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", &path);
    if (r < 0)
        return r;

    r = sd_bus_message_enter_container(m, 'a', "{sa{sv}}");
    if (r < 0)
        return r;

    while (true) {
        const char *parent = NULL;
        const char *iface = NULL;
        const char *info = NULL;

        r = sd_bus_message_enter_container(m, 'e', "sa{sv}");
        if (r < 0)
            return r;
        else if (r == 0)
            break;

        r = sd_bus_message_read(m, "s", &iface);
        if (r < 0)
            return r;

        r = sd_bus_message_enter_container(m, 'a', "{sv}");
        if (r < 0)
            return r;

        while (true) {
            const char *prop = NULL;

            r = sd_bus_message_enter_container(m, 'e', "sv");
            if (r < 0)
                return r;
            else if (r == 0)
                break;

            r = sd_bus_message_read(m, "s", &prop);
            if (r < 0)
                return r;

            if (strcmp(prop, "Service") == 0 || strcmp(prop, "Device") == 0)
                r = sd_bus_message_read(m, "v", "o", &parent);
            else if (strcmp(prop, "UUID") == 0 || strcmp(prop, "Name") == 0)
                r = sd_bus_message_read(m, "v", "s", &info);
            else
                r = sd_bus_message_skip(m, "v");
            if (r < 0)
                return r;

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
            r = sd_bus_call_method_async(bus, NULL, "org.bluez", path, iface,
                                         "RegisterApplication", on_reply,
                                         NULL, "oa{sv}", MAN_PATH, 0);
            fprintf(stderr, "+%s\n", path);
        } else if (strcmp(iface, "org.bluez.Device1") == 0 && info) {
            r = dev_add(parent, path, info);
        } else if (strcmp(iface, "org.bluez.GattService1") == 0 && parent && info) {
            r = svc_add(parent, path, info);
        } else if (strcmp(iface, "org.bluez.GattCharacteristic1") == 0 && parent && info) {
            r = chr_add(parent, path, info);
        }
        if (r < 0)
            return r;
    }

    r = sd_bus_message_exit_container(m);
    if (r < 0)
        return r;

    return 0;
}

static int
on_svc_iface_rem(sd_bus_message *m, void *misc, sd_bus_error *ret_error)
{
    const char *path = NULL;
    int r;

    r = sd_bus_message_read(m, "o", &path);
    if (r < 0)
        return r;

    r = sd_bus_message_enter_container(m, 'a', "s");
    if (r < 0)
        return r;

    while (true) {
        const char *iface = NULL;

        r = sd_bus_message_read(m, "s", &iface);
        if (r < 0)
            return r;
        else if (r == 0)
            break;

        if (strcmp(iface, "org.bluez.GattManager1") == 0) {
            fprintf(stderr, "-%s\n", path);
        } else if (strcmp(iface, "org.bluez.Device1") == 0) {
            fprintf(stderr, "-%s\n", path);
            dev_free(dev_find(path));
        } else if (strcmp(iface, "org.bluez.GattService1") == 0) {
            fprintf(stderr, "-%s\n", path);
            svc_free(svc_find(path));
        } else if (strcmp(iface, "org.bluez.GattCharacteristic1") == 0) {
            fprintf(stderr, "-%s\n", path);
            chr_rem(path);
        }
    }

    return sd_bus_message_exit_container(m);
}

static void
setup_registration(sd_bus *bus)
{
    __attribute__((cleanup(sd_bus_message_unrefp))) sd_bus_message *msg = NULL;
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
    while (sd_bus_process(userdata, NULL) > 0)
        continue;

    return 0;
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
    __attribute__((cleanup(sd_event_unrefp))) sd_event *event = NULL;
    __attribute__((cleanup(sd_bus_unrefp))) sd_bus *bus = NULL;
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

    r = sd_bus_default(&bus);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error connecting to bus");

    r = sd_event_add_io(event, NULL, sd_bus_get_fd(bus),
                        EPOLLIN | EPOLLPRI | EPOLLET | EPOLLRDHUP,
                        on_dbus_io, bus);
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

    while (devs.next != &devs)
        dev_free(devs.next);

    return r;
}
