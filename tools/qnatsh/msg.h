/*
 * QNAT is a software NAT based on DPDK and DPVS.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _MSG_H_
#define _MSG_H_

#define OAM_FLAGS_RECONNECT 0x1

enum req_type {
    REQ_GET = 0,
    REQ_SET,
    REQ_MAX,
};

struct nsh_sock_msg {
    unsigned int version;
    unsigned int id;
    enum req_type type;
    size_t len;
    char data[0];
};

struct nsh_sock_msg_reply {
    unsigned int version;
    unsigned int id;
    enum req_type type;
    int errcode;
    char errstr[64];
    size_t len;
    char data[0];
};

#endif
