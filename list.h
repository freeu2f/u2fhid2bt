/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once
#include <stddef.h>

#define list_itm(type, meth, item) \
    ((type *) (((char *) item) - offsetof(type, meth)))

#define list_new(lst) \
    *(lst) = (list) { (lst), (lst) }

typedef struct list list;
struct list {
    list *prv;
    list *nxt;
};

void
list_app(list *lst, list *itm);

void
list_pre(list *lst, list *itm);

void
list_rem(list *itm);
