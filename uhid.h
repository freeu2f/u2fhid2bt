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

#pragma once

#include "u2f.h"

#include <stdbool.h>

typedef struct u2f_uhid u2f_uhid;
typedef void (u2f_uhid_cbk)(const u2f_cmd *cmd, void *msc);

void
u2f_uhid_free(u2f_uhid *uhid);

u2f_uhid *
u2f_uhid_new(const char *name, const char *phys, const char *uniq,
             u2f_uhid_cbk *cbk, void *msc);

int
u2f_uhid_send(u2f_uhid *uhid, const u2f_cmd *cmd);
