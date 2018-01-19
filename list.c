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

#include "list.h"

void
u2f_list_app(u2f_list *lst, u2f_list *itm)
{
    itm->nxt = lst;
    itm->prv = lst->prv;
    lst->prv->nxt = itm;
    lst->prv = itm;
}

void
u2f_list_pre(u2f_list *lst, u2f_list *itm)
{
    itm->prv = lst;
    itm->nxt = lst->nxt;
    lst->nxt->prv = itm;
    lst->nxt = itm;
}

void
u2f_list_rem(u2f_list *itm)
{
    itm->nxt->prv = itm->prv;
    itm->prv->nxt = itm->nxt;
    itm->nxt = itm;
    itm->prv = itm;
}
