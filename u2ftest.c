/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <systemd/sd-bus.h>

#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

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

enum u2f_prop {
    U2F_CONTROL_POINT = 0,
    U2F_STATUS,
    U2F_CONTROL_POINT_LENGTH,
    U2F_SERVICE_REVISION,
    U2F_SERVICE_REVISION_BITFIELD,
    _U2F_PROP_TOTAL
};

struct {
    char *name;
    char *uuid;
} table[] = { /* Index MUST match enum u2f_prop values! */
    { "u2fControlPoint", "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb" },
    { "u2fStatus", "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb" },
    { "u2fControlPointLength", "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb" },
    { "u2fServiceRevision", "00002a28-0000-1000-8000-00805f9b34fb" },
    { "u2fServiceRevisionBitfield", "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb" },
};

struct u2f {
    struct u2f *prev;
    struct u2f *next;
    char *svc;
    char *prp[_U2F_PROP_TOTAL];
    bool old;
};

static struct u2f tokens = { &tokens, &tokens };

static void
u2f_free(struct u2f *u2f)
{
    free(u2f->svc);
    for (enum u2f_prop p = 0; p < _U2F_PROP_TOTAL; p++)
        free(u2f->prp[p]);
    free(u2f);
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
    SD_BUS_METHOD("Release", "", "", prf_release,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_PROPERTY("UUIDs", "as", prf_props, 0,
                    SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END
};

static int
on_reply(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    if (sd_bus_error_is_set(ret_error))
        fprintf(stderr, "Error registering: %s: %s\n",
                ret_error->name, ret_error->message);

    return 0;
}

struct u2f *
find_svc(const char *svc)
{
    if (!svc)
        return NULL;

    for (struct u2f *u = tokens.next; u != &tokens; u = u->next) {
        if (strcmp(u->svc, svc) == 0)
            return u;
    }

    return NULL;
}

static int
on_bt_iface_add(sd_bus_message *m, void *bus, sd_bus_error *ret_error)
{
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
        const char *iface = NULL;
        const char *uuid = NULL;
        const char *svc = NULL;

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
            } else if (strcmp(name, "Service") == 0) {
                r = sd_bus_message_read(m, "v", "o", &svc);
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
            struct u2f *u2f = find_svc(obj);

            if (!u2f) {
                u2f = calloc(1, sizeof(*u2f));
                if (!u2f)
                    return -ENOMEM;

                u2f->svc = strdup(obj);
                if (!u2f->svc) {
                    free(u2f);
                    return -ENOMEM;
                }

                u2f->next = tokens.next;
                u2f->prev = &tokens;
                tokens.next->prev = u2f;
                tokens.next = u2f;
            }
        } else if (strcmp(iface, "org.bluez.GattCharacteristic1") == 0) {
            struct u2f *u2f = find_svc(svc);

            for (size_t i = 0; u2f && i < _U2F_PROP_TOTAL; i++) {
                if (strcasecmp(table[i].uuid, uuid) != 0)
                    continue;

                u2f->old = false;
                free(u2f->prp[i]);
                u2f->prp[i] = strdup(obj);
                if (!u2f->prp[i])
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
on_bt_iface_rem(sd_bus_message *m, void *bus, sd_bus_error *ret_error)
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
            struct u2f *u2f = find_svc(obj);
            u2f->next->prev = u2f->prev;
            u2f->prev->next = u2f->next;
            u2f_free(u2f);
        } else if (strcmp(iface, "org.bluez.GattCharacteristic1") == 0) {
            for (struct u2f *u = tokens.next; u != &tokens; u = u->next) {
                for (enum u2f_prop p = 0; p < _U2F_PROP_TOTAL; p++) {
                    if (u->prp[p] && strcmp(obj, u->prp[p]) == 0) {
                        free(u->prp[p]);
                        u->prp[p] = NULL;
                        u->old = false;
                    }
                }
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

    r = sd_bus_add_match(bus, NULL, ADD_MATCH, on_bt_iface_add, bus);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error registering for bluetooth interfaces");

    r = sd_bus_add_match(bus, NULL, REM_MATCH, on_bt_iface_rem, bus);
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
        r = on_bt_iface_add(msg, bus, NULL);
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

static void
run_tests(struct u2f *u2f)
{
}

int
main(int argc, char *argv[])
{
    sd_bus_auto *bus = NULL;
    int r;

    r = sd_bus_open_system(&bus);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error connecting to system bus");

    r = sd_bus_add_object_manager(bus, NULL, MAN_PATH);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error adding object manager");

    r = sd_bus_add_object_vtable(bus, NULL, PRF_PATH,
                                 "org.bluez.GattProfile1",
                                 prf_vtable, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error creating profile");

    setup_registration(bus);

    while ((r = sd_bus_wait(bus, (uint64_t) -1)) >= 0) {
        while ((r = sd_bus_process(bus, NULL)) > 0)
            continue;
        if (r < 0)
            error(EXIT_FAILURE, -r, "Error processing bus");

        for (struct u2f *u = tokens.next; u != &tokens; u = u->next) {
            if (u->old)
                continue;

            fprintf(stderr, "%s:\n", u->svc);
            for (size_t i = 0; i < _U2F_PROP_TOTAL; i++)
                fprintf(stderr, "%30s: %s\n", table[i].name, u->prp[i]);

            run_tests(u);
            u->old = true;
        }
    }
    if (r < 0 && r != -EINTR)
        error(EXIT_FAILURE, -r, "Error waiting on bus");

    return EXIT_SUCCESS;
}
