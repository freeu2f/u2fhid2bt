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
#include <endian.h>

static void
dump(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02X", buf[i]);
    fprintf(stderr, "\n");
}

void
u2f_cmd_dump(const char *prfx, const u2f_cmd *cmd, size_t len)
{
    char c;

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

    fprintf(stderr, "%s%c(%04hu): ", prfx, c, be16toh(cmd->len));
    dump(cmd->buf, len - sizeof(*cmd));
}

void
u2f_seq_dump(const char *prfx, const u2f_seq *seq, size_t len)
{
    fprintf(stderr, "%sQ(%04hhu): ", prfx, seq->seq);
    dump(seq->buf, len - sizeof(*seq));
}

void
u2f_pkt_dump(const char *prfx, const u2f_pkt *pkt, size_t len)
{
    fprintf(stderr, "%s", prfx);
    if (pkt->cmd.cmd & U2F_CMD)
        u2f_cmd_dump("", &pkt->cmd, len);
    else
        u2f_seq_dump("", &pkt->seq, len);
}

void
u2f_frm_dump(const char *prfx, const u2f_frm *frm, size_t len)
{
    fprintf(stderr, "%s%08X ", prfx, frm->cid);
    u2f_pkt_dump("", &frm->pkt, len - offsetof(u2f_frm, pkt));
}
