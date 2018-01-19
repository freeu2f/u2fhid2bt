/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "u2f.h"

#include <stdbool.h>

#include <systemd/sd-bus.h>

typedef struct u2f_gatt u2f_gatt;
typedef void (u2f_gatt_cbk)(const u2f_frm *frm, void *msc);

void
u2f_gatt_free(u2f_gatt *gatt);

u2f_gatt *
u2f_gatt_new(sd_bus *bus, const char *svc, u2f_gatt_cbk *cbk, void *msc);

const char *
u2f_gatt_svc(const u2f_gatt *gatt);

int
u2f_gatt_set(u2f_gatt *gatt, const char *id, const char *obj);

const char *
u2f_gatt_has(u2f_gatt *gatt, const char *obj);

const char *
u2f_gatt_get(const u2f_gatt *gatt, const char *id);

int
u2f_gatt_send(u2f_gatt *gatt, const u2f_frm *frm);
