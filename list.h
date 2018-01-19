/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once
#include <stddef.h>

#define u2f_list_itm(type, memb, item) \
    ((type *) (((char *) item) - offsetof(type, memb)))

#define u2f_list_new(lst) \
    *(lst) = (u2f_list) { (lst), (lst) }

typedef struct u2f_list u2f_list;
struct u2f_list {
    u2f_list *prv;
    u2f_list *nxt;
};

void
u2f_list_app(u2f_list *lst, u2f_list *itm);

void
u2f_list_pre(u2f_list *lst, u2f_list *itm);

void
u2f_list_rem(u2f_list *itm);
