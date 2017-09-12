/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "u2f.h"
#include "list.h"
#include "misc.h"

typedef struct u2f_pkt u2f_pkt;
typedef struct u2f_chl u2f_chl;
typedef struct u2f_svc u2f_svc;

typedef int (*u2f_uhid_io_t)(u2f_svc *svc, const uint8_t *buf, size_t len);

typedef enum {
    CHR_CONTROL_POINT = 0,
    CHR_STATUS,
    CHR_CONTROL_POINT_LENGTH,
    CHR_SERVICE_REVISION,
    CHR_SERVICE_REVISION_BITFIELD,
    _CHR_TOTAL
} u2f_chr;

struct u2f_pkt {
    uint8_t  cmd;
    uint16_t cnt;
    uint8_t  buf[];
} __attribute__((packed));

struct u2f_chl {
    list     lst;
    u2f_svc *svc;

    uint32_t cid;
    uint8_t  seq;
    size_t   len;

    union {
        u2f_pkt *pkt;
        uint8_t *buf;
    };
};

struct u2f_svc {
    list lst;

    sd_bus *bus;             /* D-Bus Bus Reference */
    char   *obj;             /* Service (D-Bus Object Path) */
    char   *chr[_CHR_TOTAL]; /* Charactaristics (D-Bus Object Paths) */

    u2f_uhid_io_t    fnc;    /* Callback for UHID input */
    sd_event_source *hid;    /* IO Event for UHID */
    uint32_t         cid;    /* Per-Device Channel ID Iterator */
    list             req;    /* Request Channels */
    list             rep;    /* Reply Channels */
};

void
u2f_pkt_free(u2f_pkt *pkt);

u2f_pkt *
u2f_pkt_new(const uint8_t *buf, size_t *len);

void
u2f_chl_free(u2f_chl *chl);

u2f_chl *
u2f_chl_new(uint32_t cid, const uint8_t *buf, size_t len);

/* Sends the accumulated packet in the channel to the bluetooth device. */
int
u2f_chl_req(u2f_chl *chl);

/* Sends the specified data to the uhid virtual device. */
int
u2f_chl_rep_buf(u2f_chl *chl, const uint8_t *buf, size_t len,
                const char *file, int line);
#define u2f_chl_rep_buf(chl, buf, len) \
    u2f_chl_rep_buf(chl, buf, len, __FILE__, __LINE__)

/* Sends the accumulated packet in the channel to the uhid virtual device. */
int
u2f_chl_rep(u2f_chl *chl, const char *file, int line);
#define u2f_chl_rep(chl) \
    u2f_chl_rep(chl, __FILE__, __LINE__)

/* Sends the specified error to the uhid virtual device. */
int
u2f_chl_err(u2f_chl *chl, u2f_err err, const char *file, int line);
#define u2f_chl_err(chl, err) \
    u2f_chl_err(chl, err, __FILE__, __LINE__)

void
u2f_svc_free(u2f_svc *svc);

u2f_svc *
u2f_svc_new(sd_bus *bus, u2f_uhid_io_t fnc, const char *dev, const char *svc);

/* Fetches the MTU (u2fControlPointLength) from the bluetooth device. */
int
u2f_svc_mtu(u2f_svc *svc);
