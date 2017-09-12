/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "list.h"

void
list_app(list *lst, list *itm)
{
    itm->nxt = lst;
    itm->prv = lst->prv;
    lst->prv->nxt = itm;
    lst->prv = itm;
}

void
list_pre(list *lst, list *itm)
{
    itm->prv = lst;
    itm->nxt = lst->nxt;
    lst->nxt->prv = itm;
    lst->nxt = itm;
}

void
list_rem(list *itm)
{
    itm->nxt->prv = itm->prv;
    itm->prv->nxt = itm->nxt;
    itm->nxt = itm;
    itm->prv = itm;
}
