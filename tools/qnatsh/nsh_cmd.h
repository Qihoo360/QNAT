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

#ifndef _NSH_CMD_H_
#define _NSH_CMD_H_

#define uint64_t u_int64_t
#define uint32_t u_int32_t
#define uint16_t u_int16_t
#define uint8_t u_int8_t

enum{
    NAT_SO_SET_FLUSH = 200,
    NAT_SO_SET_ZERO,
    NAT_SO_SET_ADD,
    NAT_SO_SET_EDIT,
    NAT_SO_SET_DEL,
    NAT_SO_SET_ADDDEST,
    NAT_SO_SET_EDITDEST,
    NAT_SO_SET_DELDEST,
    NAT_SO_SET_GRATARP,
};

enum{
    NAT_SO_GET_VERSION = 200,
    NAT_SO_GET_INFO,
    NAT_SO_GET_SERVICES,
    NAT_SO_GET_SERVICE,
    NAT_SO_GET_DESTS,
};

enum {
    /* set */
    NAT_SET_ROUTE_ADD   = 300,
    NAT_SET_ROUTE_DEL,
    NAT_SET_ROUTE_SET,
    NAT_SET_ROUTE_FLUSH,

    /* get */
    NAT_GET_ROUTE_SHOW,
};

enum {
    /* set */
    NAT_SET_IFADDR_ADD  = 400,
    NAT_SET_IFADDR_DEL,
    NAT_SET_IFADDR_SET,
    NAT_SET_IFADDR_FLUSH,

    /* get */
    NAT_GET_IFADDR_SHOW,
};

enum {
    /* get */
    SOCKOPT_NETIF_GET_LCORE_MASK = 500,
    SOCKOPT_NETIF_GET_LCORE_BASIC,
    SOCKOPT_NETIF_GET_LCORE_STATS,
    SOCKOPT_NETIF_GET_PORT_NUM,
    SOCKOPT_NETIF_GET_PORT_BASIC,
    SOCKOPT_NETIF_GET_PORT_DEV_INFO,
    SOCKOPT_NETIF_GET_PORT_STATS,
    SOCKOPT_NETIF_GET_PORT_QUEUE,
    SOCKOPT_NETIF_GET_PORT_MBUFPOOL,
    SOCKOPT_NETIF_GET_BOND_STATUS,
    SOCKOPT_NETIF_GET_MC_ADDRS,
    SOCKOPT_NETIF_GET_MAX,
    /* set */
    SOCKOPT_NETIF_SET_LCORE = 500,
    SOCKOPT_NETIF_SET_PORT,
    SOCKOPT_NETIF_SET_BOND,
    SOCKOPT_NETIF_SET_MAX,
};

enum {
    /* get */
    SOCKOPT_GET_NEIGH_SHOW = 600,

    /* set */
    SOCKOPT_SET_NEIGH_ADD,
    SOCKOPT_SET_NEIGH_DEL,
};

struct nat_service_ipc
{
    unsigned short    proto;
    unsigned int    addr;
    unsigned short    port;
    unsigned int    fwmark;
    
    char        sched_name[16];
    unsigned    flags;
    unsigned    timeout;
    unsigned    conn_timeout;
    unsigned int    netmask;
    unsigned    bps;
    unsigned    limit_proportion;

    char        srange[256];
    char        drange[256];
    char        iifname[16];
    char        oifname[16];
};

struct nat_getinfo_ipc
{
    unsigned int version;
    unsigned int size;
    unsigned int num_services;
};

struct nat_service_stats {
    unsigned long            conns;
    unsigned long            inpkts;
    unsigned long            inbytes;
    unsigned long            outpkts;
    unsigned long            outbytes;

    unsigned int cps;
    unsigned int inpps;
    unsigned int inbps;
    unsigned int outpps;
    unsigned int outbps;
};

struct nat_service_entry {
    unsigned short            proto;
    unsigned int            addr;
    unsigned short            port;
    unsigned int            fwmark;

    char                sched_name[16];
    unsigned            flags;
    unsigned            timeout;
    unsigned            conn_timeout;
    unsigned int            netmask;
    unsigned            bps;
    unsigned            limit_proportion;

    unsigned int        num_dests;
    unsigned int        num_laddrs;

    struct nat_service_stats  stats;

    char                srange[256];
    char                drange[256];
    char                iifname[16];
    char                oifname[16];
};

struct nat_get_services {
    unsigned int        num_services;
    struct nat_service_entry entrytable[0];
};

struct nat_dest_entry {
    unsigned int addr;        /* destination address */
    unsigned short port;
    unsigned conn_flags;    /* connection flags */
    int weight;     /* destination weight */

    unsigned int max_conn;  /* upper threshold */
    unsigned int min_conn;  /* lower threshold */

    unsigned int actconns;  /* active connections */
    unsigned int inactconns;   /* inactive connections */
    unsigned int persistconns; /* persistent connections */

    /* statistics */
    struct nat_service_stats stats;
};

struct nat_get_dests {
    /* which service: user fills in these */
    unsigned short    proto;
    unsigned int    addr;        /* virtual address */
    unsigned short    port;
    unsigned int    fwmark;       /* firwall mark of service */

    /* number of real servers */
    unsigned int num_dests;

    char        srange[256];
    char        drange[256];
    char        iifname[16];
    char        oifname[16];

    /* the real servers */
    struct nat_dest_entry entrytable[0];
};

struct nat_realserver_ipc{
    unsigned int addr;
    unsigned short port;

    unsigned int conn_flags;
    int weight;

    unsigned int max_conn;
    unsigned int min_conn;
};

union inet_addr {
    struct in_addr      in;
    struct in6_addr     in6;
};

struct inet_addr_ipc {
    int                 af;
    char                ifname[16];
    union inet_addr     addr;
    unsigned char             plen;
    union inet_addr     bcast;
    unsigned int            valid_lft;
    unsigned int            prefered_lft;
    unsigned char             scope;
    unsigned int            flags;

    unsigned int            sa_used;
    unsigned int            sa_free;
    unsigned int            sa_miss;
} __attribute__((__packed__));

struct inet_addr_param_array {
    int                 naddr;
    struct inet_addr_ipc addrs[0];
};

struct nat_route_ipc {
    int             af;
    union inet_addr dst;    /* all-zero for default */
    unsigned char         plen;   /* prefix length */
    union inet_addr via;
    union inet_addr src;
    char            ifname[16];
    unsigned int        mtu;
    unsigned char         tos;
    unsigned char         scope;
    unsigned char         metric;
    unsigned char         proto;  /* routing protocol */
    unsigned int        flags;
} __attribute__((__packed__));

struct nat_route_conf_array {
    int                 nroute;
    struct nat_route_ipc   routes[0];
} __attribute__((__packed__));

struct netif_nic_num_get
{
    uint8_t nic_num;
    uint8_t phy_pid_base;
    uint8_t phy_pid_end;
    uint8_t bond_pid_base;
    uint8_t bond_pid_end;
    char pid_name_map[64][32];
};

struct netif_nic_mbufpool {
    uint32_t available;
    uint32_t inuse;
};

struct netif_nic_basic_get
{
    uint8_t port_id;
    char name[32];
    uint16_t flags; /* NETIF_PORT_FLAG_ */
    uint8_t nrxq;
    uint8_t ntxq;
    char addr[32];
    uint8_t socket_id;
    uint16_t mtu;
    uint32_t link_speed; /* ETH_SPEED_NUM_ */
    uint16_t link_duplex:1; /* ETH_LINK_[HALF/FULL]_DUPLEX */
    uint16_t link_autoneg:1; /* ETH_LINK_SPEED_[AUTONEG/FIXED] */
    uint16_t link_status:1; /* ETH_LINK_[DOWN/UP] */
    uint16_t promisc:1; /* promiscuous mode */
    uint16_t tc_egress:1;
    uint16_t tc_ingress:1;
};

struct netif_nic_stats_get {
    uint8_t port_id;
	uint64_t ipackets;  /* Total number of successfully received packets. */
	uint64_t opackets;  /* Total number of successfully transmitted packets.*/
	uint64_t ibytes;    /* Total number of successfully received bytes. */
	uint64_t obytes;    /* Total number of successfully transmitted bytes. */
	uint64_t imissed;
	/* Total of RX packets dropped by the HW,
     * because there are no available mbufs (i.e. RX queues are full). */
	uint64_t ierrors;   /* Total number of erroneous received packets. */
	uint64_t oerrors;   /* Total number of failed transmitted packets. */
	uint64_t rx_nombuf; /* Total number of RX mbuf allocation failures. */
	uint64_t q_ipackets[16];
	/* Total number of queue RX packets. */
	uint64_t q_opackets[16];
	/* Total number of queue TX packets. */
	uint64_t q_ibytes[16];
	/* Total number of successfully received queue bytes. */
	uint64_t q_obytes[16];
	/* Total number of successfully transmitted queue bytes. */
	uint64_t q_errors[16];
	/* Total number of queue packets received that are dropped. */
};

void nsh_init_cmd(void);

#endif
