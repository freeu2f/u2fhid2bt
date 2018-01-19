/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define U2F_KEEPALIVE_MILLIS 500

#define U2F_CID_RESERVED  0x00000000UL
#define U2F_CID_BROADCAST 0xffffffffUL

#define U2F_CMD           ((uint8_t) (1 << 7))
#define U2F_CMD_PING      (U2F_CMD | 0x01)
#define U2F_CMD_KEEPALIVE (U2F_CMD | 0x02)
#define U2F_CMD_MSG       (U2F_CMD | 0x03)
#define U2F_CMD_LOCK      (U2F_CMD | 0x04)
#define U2F_CMD_INIT      (U2F_CMD | 0x06)
#define U2F_CMD_WINK      (U2F_CMD | 0x08)
#define U2F_CMD_SYNC      (U2F_CMD | 0x3c)
#define U2F_CMD_ERROR     (U2F_CMD | 0x3f)

#define U2F_KA_PROCESSING 0x01
#define U2F_KA_TUP_NEEDED 0x02

#define U2F_ERR_SUCCESS       0x00
#define U2F_ERR_INVALID_CMD   0x01
#define U2F_ERR_INVALID_PAR   0x02
#define U2F_ERR_INVALID_LEN   0x03
#define U2F_ERR_INVALID_SEQ   0x04
#define U2F_ERR_MSG_TIMEOUT   0x05
#define U2F_ERR_CHANNEL_BUSY  0x06
#define U2F_ERR_LOCK_REQUIRED 0x0a
#define U2F_ERR_INVALID_CID   0x0b
#define U2F_ERR_OTHER         0x7f

typedef struct __attribute__((packed)) {
    uint8_t  cmd;
    uint16_t len;
    uint8_t  buf[];
} u2f_cmd;

typedef struct __attribute__((packed)) {
    uint8_t  seq;
    uint8_t  buf[];
} u2f_seq;

typedef union __attribute__((packed)) {
    u2f_cmd cmd;
    u2f_seq seq;
} u2f_pkt;

typedef struct __attribute__((packed)) {
    uint32_t cid;
    u2f_pkt  pkt;
} u2f_frm;

typedef struct __attribute__((packed)) {
    uint64_t non;
} u2f_cmd_req_init;

typedef struct __attribute__((packed)) {
    uint64_t non;
    uint32_t cid;
    uint8_t  ver;
    uint8_t  maj;
    uint8_t  min;
    uint8_t  bld;
    uint8_t  cap;
} u2f_cmd_rep_init;

void
u2f_cmd_dump(const char *prfx, const u2f_cmd *cmd, size_t len);

void
u2f_seq_dump(const char *prfx, const u2f_seq *seq, size_t len);

void
u2f_pkt_dump(const char *prfx, const u2f_pkt *pkt, size_t len);

void
u2f_frm_dump(const char *prfx, const u2f_frm *frm, size_t len);
