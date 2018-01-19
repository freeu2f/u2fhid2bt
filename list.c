/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

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
