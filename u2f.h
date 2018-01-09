#pragma once

#define U2F_CMD_BIT       (1 << 7)

typedef enum {
    U2F_CMD_PING      = (U2F_CMD_BIT | 0x01),
    U2F_CMD_KEEPALIVE = (U2F_CMD_BIT | 0x02),
    U2F_CMD_MSG       = (U2F_CMD_BIT | 0x03),
    U2F_CMD_LOCK      = (U2F_CMD_BIT | 0x04),
    U2F_CMD_INIT      = (U2F_CMD_BIT | 0x06),
    U2F_CMD_WINK      = (U2F_CMD_BIT | 0x08),
    U2F_CMD_SYNC      = (U2F_CMD_BIT | 0x3c),
    U2F_CMD_ERROR     = (U2F_CMD_BIT | 0x3f),
} u2f_cmd;

typedef enum {
    U2F_KA_PROCESSING = 0x01,
    U2F_KA_TUP_NEEDED = 0x02,
} u2f_ka;

typedef enum {
    U2F_ERR_SUCCESS       = 0x00,
    U2F_ERR_INVALID_CMD   = 0x01,
    U2F_ERR_INVALID_PAR   = 0x02,
    U2F_ERR_INVALID_LEN   = 0x03,
    U2F_ERR_INVALID_SEQ   = 0x04,
    U2F_ERR_MSG_TIMEOUT   = 0x05,
    U2F_ERR_CHANNEL_BUSY  = 0x06,
    U2F_ERR_LOCK_REQUIRED = 0x0a,
    U2F_ERR_INVALID_CID   = 0x0b,
    U2F_ERR_OTHER         = 0x7f,
} u2f_err;

typedef enum {
    U2F_CID_RESERVED  = 0x00000000,
    U2F_CID_BROADCAST = 0xffffffff,
} u2f_cid;
