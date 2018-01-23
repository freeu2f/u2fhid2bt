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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

static void
dump(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02X", buf[i]);
    fprintf(stderr, "\n");
}

void
u2f_cmd_dump(const u2f_cmd *cmd, size_t len, const char *prfx, ...)
{
    va_list ap;
    char c;

    va_start(ap, prfx);
    vfprintf(stderr, prfx, ap);
    va_end(ap);

    switch (cmd->cmd) {
    case U2F_CMD_PING:      c = 'P'; break;
    case U2F_CMD_KEEPALIVE: c = 'K'; break;
    case U2F_CMD_MSG:       c = 'M'; break;
    case U2F_CMD_LOCK:      c = 'L'; break;
    case U2F_CMD_INIT:      c = 'I'; break;
    case U2F_CMD_WINK:      c = 'W'; break;
    case U2F_CMD_SYNC:      c = 'S'; break;
    case U2F_CMD_ERROR:     c = 'E'; break;
    default:                c = 'U'; break;
    }

    fprintf(stderr, "%c(%04hu): ", c, be16toh(cmd->len));
    dump(cmd->buf, len - offsetof(u2f_cmd, buf));
}

void
u2f_seq_dump(const u2f_seq *seq, size_t len, const char *prfx, ...)
{
    va_list ap;

    va_start(ap, prfx);
    vfprintf(stderr, prfx, ap);
    va_end(ap);

    fprintf(stderr, "Q(%04hhu): ", seq->seq);
    dump(seq->buf, len - offsetof(u2f_seq, buf));
}

void
u2f_pkt_dump(const u2f_pkt *pkt, size_t len, const char *prfx, ...)
{
    va_list ap;

    va_start(ap, prfx);
    vfprintf(stderr, prfx, ap);
    va_end(ap);

    if (pkt->cmd.cmd & U2F_CMD)
        u2f_cmd_dump(&pkt->cmd, len - offsetof(u2f_pkt, cmd), "");
    else
        u2f_seq_dump(&pkt->seq, len - offsetof(u2f_pkt, seq), "");
}

void
u2f_frm_dump(const u2f_frm *frm, size_t len, const char *prfx, ...)
{
    va_list ap;

    va_start(ap, prfx);
    vfprintf(stderr, prfx, ap);
    va_end(ap);

    u2f_pkt_dump(&frm->pkt, len - offsetof(u2f_frm, pkt), "%08X ", frm->cid);
}

u2f_cmd *
#undef u2f_cmd_mkerr
u2f_cmd_mkerr(u2f_cmd *cmd, uint8_t err)
{
    cmd->cmd = U2F_CMD_ERROR;
    cmd->len = htobe16(1);
    cmd->buf[0] = err;
    return cmd;
}
