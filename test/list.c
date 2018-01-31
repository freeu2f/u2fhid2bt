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

#include <hidapi/hidapi.h>
#include "../uhid.h"
#include <stdio.h>

int
main(int argc, const char *argv[])
{
    struct hid_device_info *info = NULL;
    size_t cnt = 0;

    if (hid_init() != 0) {
        fprintf(stderr, "Error initializing HID API!\n");
        return 1;
    }

    info = hid_enumerate(UHID_VEND, UHID_PROD);
    if (!info) {
        fprintf(stderr, "Error enumerating HID devices!\n");
        return 1;
    }

    for (struct hid_device_info *i = info; i; i = i->next, cnt++)
        printf("%s\n", i->path);

    hid_free_enumeration(info);
    hid_exit();
    return cnt > 0 ? 0 : 1;
}
