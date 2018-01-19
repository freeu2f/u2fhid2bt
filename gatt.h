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
