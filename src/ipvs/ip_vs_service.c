/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
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
#include <arpa/inet.h>
#include <netinet/in.h>
#include "inet.h"
#include "ipv4.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/blklst.h"
#include "ctrl.h"
#include "route.h"
#include "netif.h"
#include "assert.h"
#include "neigh.h"

static int dp_vs_num_services = 0;

/**
 * hash table for svc
 */
#define DP_VS_SVC_TAB_BITS 8
#define DP_VS_SVC_TAB_SIZE (1 << DP_VS_SVC_TAB_BITS)
#define DP_VS_SVC_TAB_MASK (DP_VS_SVC_TAB_SIZE - 1)

static struct list_head dp_vs_svc_table[DP_VS_SVC_TAB_SIZE];

static struct list_head dp_vs_svc_fwm_table[DP_VS_SVC_TAB_SIZE];

#ifdef CONFIG_NETOPS_ACL_RANGE
static struct list_head dp_vs_svc_match_table[DP_VS_SVC_TAB_SIZE];

static int dp_vs_svc_match_range_masklen[4] = {0, 18, 21, 24};

static struct list_head dp_vs_svc_match_range_table[4][DP_VS_SVC_TAB_SIZE];
#endif

static struct list_head dp_vs_svc_match_list;

static inline unsigned dp_vs_svc_hashkey(int af, unsigned proto, const union inet_addr *addr)
{
    /* now IPv4 only */
    uint32_t addr_fold = addr->in.s_addr;
    return (proto ^ rte_be_to_cpu_32(addr_fold)) & DP_VS_SVC_TAB_MASK;
}

static inline unsigned dp_vs_svc_fwm_hashkey(uint32_t fwmark)
{
    return fwmark & DP_VS_SVC_TAB_MASK;
}

static int dp_vs_svc_hash(struct dp_vs_service *svc)
{
	unsigned hash;
#ifdef CONFIG_NETOPS_ACL_RANGE
	unsigned int mask = 0;
	int idx = 0;
#endif
    if (svc->flags & DP_VS_SVC_F_HASHED){
        RTE_LOG(DEBUG, SERVICE, "%s: request for already hashed.\n", __func__);
        return EDPVS_EXIST;
    }

    if (svc->fwmark) {
        hash = dp_vs_svc_fwm_hashkey(svc->fwmark);
        list_add(&svc->f_list, &dp_vs_svc_fwm_table[hash]);
    } else if (svc->match) {
#ifdef CONFIG_NETOPS_ACL_RANGE
		if(svc->match->srange.min_addr.in.s_addr != svc->match->srange.max_addr.in.s_addr)
        {
#endif
        	list_add(&svc->m_list, &dp_vs_svc_match_list);
#ifdef CONFIG_NETOPS_ACL_RANGE
			rte_atomic32_inc(&svc->refcnt);
			mask = svc->match->srange.min_addr.in.s_addr ^ svc->match->srange.max_addr.in.s_addr;
			if(mask == 0xffffc0000)
				idx = 1;
			else if(mask == 0xfffff800)
				idx = 2;
			else if(mask == 0xffffff00)
				idx = 3;
			else
				idx = 0;
			hash = dp_vs_svc_hashkey(svc->af, svc->proto, &svc->match->srange.min_addr);
			list_add(&svc->mr_list, &dp_vs_svc_match_range_table[idx][hash]);
		}
		else
		{
			hash = dp_vs_svc_hashkey(svc->af, svc->proto, &svc->match->srange.min_addr);
        	list_add(&svc->m_list, &dp_vs_svc_match_table[hash]);
		}
#endif
    } else {
        /*
         *  Hash it by <protocol,addr,port> in dp_vs_svc_table
         */
        hash = dp_vs_svc_hashkey(svc->af, svc->proto, &svc->addr);
        list_add(&svc->s_list, &dp_vs_svc_table[hash]);
    }

    svc->flags |= DP_VS_SVC_F_HASHED;
    rte_atomic32_inc(&svc->refcnt);
    return EDPVS_OK;
}

static int dp_vs_svc_unhash(struct dp_vs_service *svc)
{
    if (!(svc->flags & DP_VS_SVC_F_HASHED)) {
        RTE_LOG(DEBUG, SERVICE, "%s: request for unhashed flag.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    if (svc->fwmark)
        list_del(&svc->f_list);
    else if (svc->match)
        list_del(&svc->m_list);
    else
        list_del(&svc->s_list);

    svc->flags &= ~DP_VS_SVC_F_HASHED;
    rte_atomic32_dec(&svc->refcnt);
    return EDPVS_OK;
}

struct dp_vs_service *__dp_vs_service_get(int af, uint16_t protocol, 
                                          const union inet_addr *vaddr, uint16_t vport)
{
    unsigned hash;
    struct dp_vs_service *svc;

    hash = dp_vs_svc_hashkey(af, protocol, vaddr);
    list_for_each_entry(svc, &dp_vs_svc_table[hash], s_list){
        if ((svc->af == af)
            && inet_addr_equal(af, &svc->addr, vaddr)
            && (svc->port == vport)
            && (svc->proto == protocol)) {
                rte_atomic32_inc(&svc->usecnt);
                return svc;
            }
    }

    return NULL;
}

struct dp_vs_service *__dp_vs_svc_fwm_get(int af, uint32_t fwmark)
{
    unsigned hash;
    struct dp_vs_service *svc;

    /* Check for fwmark addressed entries */
    hash = dp_vs_svc_fwm_hashkey(fwmark);

    list_for_each_entry(svc, &dp_vs_svc_fwm_table[hash], f_list) {
        if (svc->fwmark == fwmark && svc->af == af) {
            /* HIT */
            rte_atomic32_inc(&svc->usecnt);
            return svc;
        }
    }

    return NULL;
}

static inline bool __svc_in_range(int af,
                                  const union inet_addr *addr, __be16 port,
                                  const struct inet_addr_range *range)
{
    if (unlikely(af != AF_INET))
        return false;

    if (unlikely(ntohl(range->min_addr.in.s_addr) > \
        ntohl(range->max_addr.in.s_addr)))
        return false;

    if (unlikely(ntohs(range->min_port) > ntohs(range->max_port)))
        return false;

    /* if both min/max are zero, means need not check. */
    if (range->max_addr.in.s_addr != htonl(INADDR_ANY)) {
        if (ntohl(addr->in.s_addr) < ntohl(range->min_addr.in.s_addr) ||
            ntohl(addr->in.s_addr) > ntohl(range->max_addr.in.s_addr))
            return false;
    }

    if (range->max_port != 0) {
        if (ntohs(port) < ntohs(range->min_port) ||
            ntohs(port) > ntohs(range->max_port))
            return false;
    }

    return true;
}

#ifdef CONFIG_NETOPS_ACL_RANGE
static void masklen2ip (const int masklen, struct in_addr *netmask)
{
	/* left shift is only defined for less than the size of the type.
	* we unconditionally use long long in case the target platform
	* has defined behaviour for << 32 (or has a 64-bit left shift) */

	if (sizeof(unsigned long long) > 4)
		netmask->s_addr = htonl(0xffffffffULL << (32 - masklen));
	else
		netmask->s_addr = htonl(masklen ? 0xffffffffU << (32 - masklen) : 0);
}
#endif

static struct dp_vs_service *
__dp_vs_svc_match_get(int af, const struct rte_mbuf *mbuf)
{
    struct route_entry *rt = mbuf->userdata;
    struct ipv4_hdr *iph = ip4_hdr(mbuf); /* ipv4 only */
    struct dp_vs_service *svc;
    union inet_addr saddr, daddr;

    __be16 _ports[2], *ports;
    portid_t oif = NETIF_PORT_ID_ALL;
#ifdef CONFIG_NETOPS_ACL_RANGE
	unsigned hash;
	int idx = 0;
	union inet_addr tmpsaddr;
	union inet_addr maskip;
#endif

    saddr.in.s_addr = iph->src_addr;
    daddr.in.s_addr = iph->dst_addr;
    ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
    if (!ports)
        return NULL;

#ifdef CONFIG_NETOPS_ACL_RANGE
    hash = dp_vs_svc_hashkey(af, iph->next_proto_id, &saddr);
    list_for_each_entry(svc, &dp_vs_svc_match_table[hash], m_list){
        struct dp_vs_match *m = svc->match;
        struct netif_port *idev, *odev;
        assert(m);

        /* snat is handled at pre-routing to check if oif
         * is match perform route here. */
        if (strlen(m->oifname)) {
            if (!rt) {
                rt = route4_input(mbuf, &daddr.in, &saddr.in,
                                  iph->type_of_service,
                                  netif_port_get(mbuf->port));
                if (!rt)
                    return NULL;

                /* set mbuf->userdata to @rt as side-effect is not good!
                 * although route will done again when out-xmit. */
                oif = rt->port->id;
                route4_put(rt);
            } else {
                oif = rt->port->id;
            }
        }

        idev = netif_port_get_by_name(m->iifname);
        odev = netif_port_get_by_name(m->oifname);

        if (svc->af == af && svc->proto == iph->next_proto_id &&
            __svc_in_range(af, &saddr, ports[0], &m->srange) &&
            __svc_in_range(af, &daddr, ports[1], &m->drange) &&
            (!idev || idev->id == mbuf->port) &&
            (!odev || odev->id == oif)
           ) {
            rte_atomic32_inc(&svc->usecnt);
            return svc;
        }
    }

	for(idx = 3; idx >= 0; idx--)
	{
		masklen2ip(dp_vs_svc_match_range_masklen[idx], &(maskip.in));
		tmpsaddr.in.s_addr = saddr.in.s_addr & maskip.in.s_addr;
		hash = dp_vs_svc_hashkey(af, iph->next_proto_id, &tmpsaddr);
	    list_for_each_entry(svc, &dp_vs_svc_match_range_table[idx][hash], mr_list){
	        struct dp_vs_match *m = svc->match;
	        struct netif_port *idev, *odev;
	        assert(m);

	        /* snat is handled at pre-routing to check if oif
	         * is match perform route here. */
	        if (strlen(m->oifname)) {
	            if (!rt) {
	                rt = route4_input(mbuf, &daddr.in, &saddr.in,
	                                  iph->type_of_service,
	                                  netif_port_get(mbuf->port));
	                if (!rt)
	                    return NULL;

	                /* set mbuf->userdata to @rt as side-effect is not good!
	                 * although route will done again when out-xmit. */
	                oif = rt->port->id;
	                route4_put(rt);
	            } else {
	                oif = rt->port->id;
	            }
	        }

	        idev = netif_port_get_by_name(m->iifname);
	        odev = netif_port_get_by_name(m->oifname);

	        if (svc->af == af && svc->proto == iph->next_proto_id &&
	            __svc_in_range(af, &saddr, ports[0], &m->srange) &&
	            __svc_in_range(af, &daddr, ports[1], &m->drange) &&
	            (!idev || idev->id == mbuf->port) &&
	            (!odev || odev->id == oif)
	           ) {
	            rte_atomic32_inc(&svc->usecnt);
	            return svc;
	        }
	    }
	}
#endif

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        struct dp_vs_match *m = svc->match;
        struct netif_port *idev, *odev;
        assert(m);

        /* snat is handled at pre-routing to check if oif
         * is match perform route here. */
        if (strlen(m->oifname)) {
            if (!rt) {
                rt = route4_input(mbuf, &daddr.in, &saddr.in,
                                  iph->type_of_service,
                                  netif_port_get(mbuf->port));
                if (!rt)
                    return NULL;

                /* set mbuf->userdata to @rt as side-effect is not good!
                 * although route will done again when out-xmit. */
                oif = rt->port->id;
                route4_put(rt);
            } else {
                oif = rt->port->id;
            }
        }

        idev = netif_port_get_by_name(m->iifname);
        odev = netif_port_get_by_name(m->oifname);

        if (svc->af == af && svc->proto == iph->next_proto_id &&
            __svc_in_range(af, &saddr, ports[0], &m->srange) &&
            __svc_in_range(af, &daddr, ports[1], &m->drange) &&
            (!idev || idev->id == mbuf->port) &&
            (!odev || odev->id == oif)
           ) {
            rte_atomic32_inc(&svc->usecnt);
            return svc;
        }
    }

    return NULL;
}

int dp_vs_match_parse(int af, const char *srange, const char *drange,
                      const char *iifname, const char *oifname,
                      struct dp_vs_match *match)
{
    int err;

    memset(match, 0, sizeof(*match));

    if (srange && strlen(srange)) {
        err = inet_addr_range_parse(AF_INET, srange, &match->srange);
        if (err != EDPVS_OK)
            return err;
    }

    if (drange && strlen(drange)) {
        err = inet_addr_range_parse(AF_INET, drange, &match->drange);
        if (err != EDPVS_OK)
            return err;
    }

    snprintf(match->iifname, IFNAMSIZ, "%s", iifname ? : "");
    snprintf(match->oifname, IFNAMSIZ, "%s", oifname ? : "");

    return EDPVS_OK;
}

static struct dp_vs_service *
__dp_vs_svc_match_find(int af, uint8_t proto, const struct dp_vs_match *match)
{
    struct dp_vs_service *svc;
#ifdef CONFIG_NETOPS_ACL_RANGE
	unsigned hash;
	int idx = 0;
	union inet_addr tmpsaddr;
	union inet_addr maskip;
#endif

    if (!match || is_empty_match(match))
        return NULL;

#ifdef CONFIG_NETOPS_ACL_RANGE
	if(match->srange.min_addr.in.s_addr == match->srange.max_addr.in.s_addr)
	{
		hash = dp_vs_svc_hashkey(af, proto, &match->srange.min_addr);
	    list_for_each_entry(svc, &dp_vs_svc_match_table[hash], m_list){
	        assert(svc->match);
	        if (af == svc->af && proto == svc->proto &&
	            memcmp(match, svc->match, sizeof(struct dp_vs_match)) == 0)
	        {
	            rte_atomic32_inc(&svc->usecnt);
	            return svc;
	        }
	    }
	}
	else
	{
		for(idx = 3; idx >= 0; idx--)
		{
			masklen2ip(dp_vs_svc_match_range_masklen[idx], &(maskip.in));
			tmpsaddr.in.s_addr = match->srange.min_addr.in.s_addr & maskip.in.s_addr;
			hash = dp_vs_svc_hashkey(af, proto, &tmpsaddr);
		    list_for_each_entry(svc, &dp_vs_svc_match_range_table[idx][hash], mr_list){
		        assert(svc->match);
		        if (af == svc->af && proto == svc->proto &&
		            memcmp(match, svc->match, sizeof(struct dp_vs_match)) == 0)
		        {
		            rte_atomic32_inc(&svc->usecnt);
		            return svc;
		        }
		    }
		}
	    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
	        assert(svc->match);
	        if (af == svc->af && proto == svc->proto &&
	            memcmp(match, svc->match, sizeof(struct dp_vs_match)) == 0)
	        {
	            rte_atomic32_inc(&svc->usecnt);
	            return svc;
	        }
	    }
	}
#else
    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        assert(svc->match);
        if (af == svc->af && proto == svc->proto &&
            memcmp(match, svc->match, sizeof(struct dp_vs_match)) == 0)
        {
            rte_atomic32_inc(&svc->usecnt);
            return svc;
        }
    }
#endif
    return NULL;
}

#ifdef CONFIG_NETOPS_BYPASS_ROUTING
struct bypass_conn
{
    int af;
    struct conn_tuple_hash  tuplehash;
    rte_atomic32_t          refcnt;
    struct dpvs_timer       timer;
    struct timeval          timeout;
    lcoreid_t               lcore;

    struct netif_port       *out_dev;   /* outside */
    struct ether_addr       out_dmac;
};

struct direct_bypass
{
	struct netif_port       *out_dev;   /* outside */
    struct ether_addr       out_dmac;
};

RTE_DEFINE_PER_LCORE(int, hit_dir_bypass);
#define this_hit_dir_bypass    RTE_PER_LCORE(hit_dir_bypass)

RTE_DEFINE_PER_LCORE(struct direct_bypass, direct_bypass_cache);
#define this_direct_bypass_cache    RTE_PER_LCORE(direct_bypass_cache)

RTE_DEFINE_PER_LCORE(uint32_t, self_addr);
#define this_self_addr    RTE_PER_LCORE(self_addr)

static int direct_bypass_xmit(struct rte_mbuf *mbuf)
{
	struct ether_hdr *eth;
	uint16_t pkt_type;

	if(likely(this_direct_bypass_cache.out_dev != NULL))
	{
		eth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct ether_hdr));
		ether_addr_copy(&this_direct_bypass_cache.out_dmac, &eth->d_addr);
		ether_addr_copy(&this_direct_bypass_cache.out_dev->addr, &eth->s_addr);
		pkt_type = (uint16_t)mbuf->packet_type;
		eth->ether_type = rte_cpu_to_be_16(pkt_type);
		netif_xmit(mbuf, this_direct_bypass_cache.out_dev);
		return INET_STOLEN;
	}
	else
		return INET_ACCEPT;
}

static inline int miss_direct_bypass_addr(const union inet_addr *saddr)
{
	char *addr = (char *)&(saddr->in.s_addr);
	/*private address*/
	if(addr[0] == 0xa) //10.x.x.x
		return 1;
	if(addr[0] == 0xc0 && addr[1] == 0xa8) //192.168.x.x
		return 3;
	if(addr[0] == 0xac && (addr[1] >= 0x10 && addr[1] <= 0x1f)) //172.16.x.x ~ 172.31.x.x
		return 2;
	return 0;
}

inline bool is_local_pkt(uint32_t daddr);

inline bool is_local_pkt(uint32_t daddr)
{
	char *addr = (char *)&daddr;
	char *selfaddr = (char *)&this_self_addr;

	return (addr[0] == selfaddr[0] && addr[1] == selfaddr[1] &&
		addr[2] == selfaddr[2] && (addr[3] == selfaddr[3] || addr[3] == selfaddr[3] + 1));
}

int direct_bypass_routing(const union inet_addr *saddr, struct rte_mbuf *mbuf);

int direct_bypass_routing(const union inet_addr *saddr, struct rte_mbuf *mbuf)
{	
	if(!miss_direct_bypass_addr(saddr))
	{
		this_hit_dir_bypass = 1;
		return direct_bypass_xmit(mbuf);
	}

	this_hit_dir_bypass = 0;
	return INET_ACCEPT;
}

#define DPVS_CONN_TAB_BITS      20
#define DPVS_CONN_TAB_SIZE      (1 << DPVS_CONN_TAB_BITS)
#define DPVS_CONN_TAB_MASK      (DPVS_CONN_TAB_SIZE - 1)

#define DPVS_CONN_POOL_SIZE_DEF     2097152
#define DPVS_CONN_POOL_SIZE_MIN     65536
static int conn_pool_size = DPVS_CONN_POOL_SIZE_DEF;
#define DPVS_CONN_CACHE_SIZE_DEF    256
static int conn_pool_cache = DPVS_CONN_CACHE_SIZE_DEF;

#define DPVS_CONN_INIT_TIMEOUT_DEF  30   /* sec */
int bp_conn_init_timeout = DPVS_CONN_INIT_TIMEOUT_DEF;

static uint32_t dp_vs_conn_rnd;

static RTE_DEFINE_PER_LCORE(struct list_head *, bypass_conn_tab);
#define this_bypass_conn_tab           (RTE_PER_LCORE(bypass_conn_tab))
static struct rte_mempool *bypass_conn_cache[DPVS_MAX_SOCKET];
#define this_bypass_conn_cache         (bypass_conn_cache[rte_socket_id()])

int bypass_conn_init(void *);
struct bypass_conn * bypass_conn_new(int af, uint16_t proto, const struct rte_mbuf *mbuf);
struct bypass_conn *bypass_conn_get(int af, uint16_t proto, const union inet_addr *saddr, uint16_t sport);
void bypass_conn_put(struct bypass_conn *conn);

static inline void bconn_dump(const char *msg, uint16_t proto, const union inet_addr *srcaddr, uint16_t sport)
{
    char sbuf[64];
    const char *saddr;

    saddr = inet_ntop(AF_INET, srcaddr, sbuf, sizeof(sbuf)) ? sbuf : "::";

    RTE_LOG(INFO, IPVS, "%s [%d] %s %s:%u\n",
            msg ? msg : "", rte_lcore_id(), inet_proto_name(proto),
            saddr, ntohs(sport));
}

int bypass_conn_init(void *arg)
{
	int i;
	
	this_bypass_conn_tab = rte_malloc_socket(NULL,
                        sizeof(struct list_head) * DPVS_CONN_TAB_SIZE,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!this_bypass_conn_tab)
        return EDPVS_NOMEM;

    for (i = 0; i < DPVS_CONN_TAB_SIZE; i++)
        INIT_LIST_HEAD(&this_bypass_conn_tab[i]);

	dp_vs_conn_rnd = (uint32_t)random();

	this_direct_bypass_cache.out_dev = NULL;
	this_self_addr = 0;
	
	return EDPVS_OK;
}

static inline struct bypass_conn *
tuplehash_to_conn(const struct conn_tuple_hash *thash)
{
    return container_of(thash, struct bypass_conn, tuplehash);
}

static inline uint32_t bp_conn_hashkey(int af,
                                const union inet_addr *saddr, uint16_t sport)
{
    return rte_jhash_3words((uint32_t)saddr->in.s_addr,
            0,
            ((uint32_t)sport) << 16 | 0,
            dp_vs_conn_rnd)
        & DPVS_CONN_TAB_MASK;
}

static inline int __bp_conn_hash(struct bypass_conn *conn, uint32_t ihash)
{
    list_add(&conn->tuplehash.list, &this_bypass_conn_tab[ihash]);

    rte_atomic32_inc(&conn->refcnt);

    return EDPVS_OK;
}

static inline int bp_conn_hash(struct bypass_conn *conn)
{
    uint32_t ihash;
    int err;

    ihash = bp_conn_hashkey(conn->af,
                &conn->tuplehash.saddr, conn->tuplehash.sport);

    err = __bp_conn_hash(conn, ihash);

    return err;
}

static inline int bp_conn_unhash(struct bypass_conn *conn)
{
    int err;

    if (rte_atomic32_read(&conn->refcnt) != 2) {
        err = EDPVS_BUSY;
    } else {
        list_del(&conn->tuplehash.list);
        rte_atomic32_dec(&conn->refcnt);
        err = EDPVS_OK;
    }

#ifdef CONFIG_DPVS_IPVS_DEBUG
    if (unlikely(err == EDPVS_BUSY))
        RTE_LOG(DEBUG, IPVS, "%s: connection is busy: conn->refcnt = %d.\n",
                __func__, rte_atomic32_read(&conn->refcnt));
    else if (unlikely(err == EDPVS_NOTEXIST))
        RTE_LOG(DEBUG, IPVS, "%s: connection not hashed.\n", __func__);
#endif

    return err;
}

struct bypass_conn *bypass_conn_get(int af, uint16_t proto, const union inet_addr *saddr, uint16_t sport)
{
    uint32_t hash;
    struct conn_tuple_hash *tuphash;
    struct bypass_conn *conn = NULL;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char sbuf[64], dbuf[64];
#endif
	bconn_dump("find bypass", proto, saddr, sport);

    hash = bp_conn_hashkey(af, saddr, sport);

    list_for_each_entry(tuphash, &this_bypass_conn_tab[hash], list) {
        if (tuphash->sport == sport
                && inet_addr_equal(af, &tuphash->saddr, saddr)
                && tuphash->proto == proto
                && tuphash->af == af) {
            /* hit */
            conn = tuplehash_to_conn(tuphash);
			bconn_dump("finded bypass", proto, saddr, sport);
            rte_atomic32_inc(&conn->refcnt);
            break;
        }
    }

    return conn;
}

void bypass_conn_put(struct bypass_conn *conn)
{
    rte_atomic32_dec(&conn->refcnt);
}

static void bconn_expire(void *priv)
{
	struct bypass_conn *conn = (struct bypass_conn *)priv;

	/* unhash it then no further user can get it,
		 * even we cannot del it now. */
	bp_conn_unhash(conn);

	/* refcnt == 1 means we are the only referer.
     * no one is using the conn and it's timed out. */
    if (rte_atomic32_read(&conn->refcnt) == 1) {
        dpvs_timer_cancel(&conn->timer, false);
        rte_atomic32_dec(&conn->refcnt);
        rte_mempool_put(this_bypass_conn_cache, conn);

        return;
    }
}

struct bypass_conn * bypass_conn_new(int af, uint16_t proto, const struct rte_mbuf *mbuf)
{
    struct bypass_conn *new;
    struct conn_tuple_hash *t;
    uint16_t rport;
    __be16 _ports[2], *ports;
    int err;

    assert(mbuf);

    if (unlikely(rte_mempool_get(this_bypass_conn_cache, (void **)&new) != 0)) {
        RTE_LOG(WARNING, IPVS, "%s: no memory\n", __func__);
        return NULL;
    }
 	ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
    if (unlikely(!ports)) {
        RTE_LOG(WARNING, IPVS, "%s: no memory\n", __func__);
        return NULL;
    }
    rport = ports[0];
    memset(new, 0, sizeof(struct bypass_conn));
    /* init outbound conn tuple hash */
    t = &new->tuplehash;
    t->direct   = DPVS_CONN_DIR_OUTBOUND;
    t->af       = af;
    t->proto    = proto;
    t->saddr.in.s_addr = ip4_hdr(mbuf)->src_addr;
    t->sport    = rport;
    INIT_LIST_HEAD(&t->list);
    new->af = af;
    new->out_dev = NULL;
    /* caller will use it right after created,
     * just like dp_vs_conn_get(). */
    rte_atomic32_set(&new->refcnt, 1);
    if ((err = bp_conn_hash(new)) != EDPVS_OK)
        goto errout;

    /* timer */
    new->timeout.tv_sec = bp_conn_init_timeout;
    new->timeout.tv_usec = 0;
    
    /* schedule conn timer */
    dpvs_time_rand_delay(&new->timeout, 1000000);
    dpvs_timer_sched(&new->timer, &new->timeout, bconn_expire, new, false);
	bconn_dump("new bypass", new->tuplehash.proto, &new->tuplehash.saddr, new->tuplehash.sport);
    return new;
errout:
    rte_mempool_put(this_bypass_conn_cache, new);
    return NULL;
}

int bypass_xmit(struct bypass_conn *bc, struct rte_mbuf *mbuf);

int bypass_xmit(struct bypass_conn *bc, struct rte_mbuf *mbuf)
{
	struct ether_hdr *eth;
    uint16_t pkt_type;

	if(bc->out_dev)
	{
	    eth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct ether_hdr));
	    ether_addr_copy(&bc->out_dmac,&eth->d_addr);
	    ether_addr_copy(&bc->out_dev->addr,&eth->s_addr);
	    pkt_type = (uint16_t)mbuf->packet_type;
	    eth->ether_type = rte_cpu_to_be_16(pkt_type);
		netif_xmit(mbuf, bc->out_dev);
		return INET_STOLEN;
	}
	else
		return INET_ACCEPT;
}

int bypass_routing(int af, uint16_t proto, struct rte_mbuf *mbuf);

int bypass_routing(int af, uint16_t proto, struct rte_mbuf *mbuf)
{
	struct bypass_conn *bc;
	int ret;
	uint16_t sport;
	__be16 _ports[2], *ports;
	union inet_addr     saddr;

	ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
	if (unlikely(!ports)) {
		RTE_LOG(WARNING, IPVS, "%s: no memory\n", __func__);
		return INET_ACCEPT;
	}
	sport = ports[0];
	saddr.in.s_addr = ip4_hdr(mbuf)->src_addr;

	bc = bypass_conn_get(af, proto, &saddr, sport);
	if(bc)
	{
		ret = bypass_xmit(bc, mbuf);
		bypass_conn_put(bc);
		if(ret == INET_STOLEN)
			return INET_STOLEN;
		return INET_ACCEPT;
	}
	return INET_ACCEPT;
}
#endif

struct dp_vs_service *dp_vs_service_lookup(int af, uint16_t protocol,
                                        const union inet_addr *vaddr, 
                                        uint16_t vport, uint32_t fwmark,
                                        const struct rte_mbuf *mbuf,
                                        const struct dp_vs_match *match)
{
    struct dp_vs_service *svc = NULL;

    rte_rwlock_read_lock(&__dp_vs_svc_lock);

    if (fwmark && (svc = __dp_vs_svc_fwm_get(af, fwmark)))
        goto out;

    if ((svc = __dp_vs_service_get(af, protocol, vaddr, vport)))
        goto out;

    if (match && !is_empty_match(match))
        if ((svc = __dp_vs_svc_match_find(af, protocol, match)))
            goto out;

    if (mbuf) /* lowest priority */
#ifdef CONFIG_NETOPS_BYPASS_ROUTING
    {
    	svc = __dp_vs_svc_match_get(af, mbuf);
		if(NULL == svc)
		{
			struct bypass_conn *bc;
		        uint16_t sport;
		        __be16 _ports[2], *ports;
		        union inet_addr     saddr;

		        ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
		        if (unlikely(!ports)) {
                		RTE_LOG(WARNING, IPVS, "%s: no memory\n", __func__);
		                return NULL;
		        }
		        sport = ports[0];
		        saddr.in.s_addr = ip4_hdr(mbuf)->src_addr;

		        bc = bypass_conn_get(af, protocol, &saddr, sport);
		        if(NULL == bc)
				bc = bypass_conn_new(af, protocol, mbuf);
		}
    }
#else
        svc = __dp_vs_svc_match_get(af, mbuf);
#endif

out:
    rte_rwlock_read_unlock(&__dp_vs_svc_lock);
    return svc;
}


struct dp_vs_service *dp_vs_lookup_vip(int af, uint16_t protocol,
                       const union inet_addr *vaddr)
{
    struct dp_vs_service *svc;
    unsigned hash;

    rte_rwlock_read_lock(&__dp_vs_svc_lock);

    hash = dp_vs_svc_hashkey(af, protocol, vaddr);
    list_for_each_entry(svc, &dp_vs_svc_table[hash], s_list) {
        if ((svc->af == af)
            && inet_addr_equal(af, &svc->addr, vaddr)
            && (svc->proto == protocol)) {
            /* HIT */
            rte_rwlock_read_unlock(&__dp_vs_svc_lock);
            return svc;
        }
    }

    rte_rwlock_read_unlock(&__dp_vs_svc_lock);
    return NULL;
}

void
__dp_vs_bind_svc(struct dp_vs_dest *dest, struct dp_vs_service *svc)
{
    rte_atomic32_inc(&svc->refcnt);
    dest->svc = svc;
}

void __dp_vs_unbind_svc(struct dp_vs_dest *dest)
{
    struct dp_vs_service *svc = dest->svc;

    dest->svc = NULL;
    if (rte_atomic32_dec_and_test(&svc->refcnt)) {
        dp_vs_del_stats(svc->stats);
        if (svc->match)
            rte_free(svc->match);
        rte_free(svc);
    }
}

int dp_vs_add_service(struct dp_vs_service_conf *u, 
                             struct dp_vs_service **svc_p)
{
    int ret = 0;
    int size;
    struct dp_vs_scheduler *sched = NULL;
    struct dp_vs_service *svc = NULL;

    if (!u->fwmark && !u->addr.in.s_addr && !u->port &&
            is_empty_match(&u->match)) {
        RTE_LOG(ERR, SERVICE, "%s: adding empty servive\n", __func__);
        return EDPVS_INVAL;
    }

    sched = dp_vs_scheduler_get(u->sched_name);
    if(sched == NULL) {
        RTE_LOG(DEBUG, SERVICE, "%s: scheduler not found.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct dp_vs_service));
    svc = rte_zmalloc("dp_vs_service", size, RTE_CACHE_LINE_SIZE);
    if(svc == NULL){
        RTE_LOG(DEBUG, SERVICE, "%s: no memory.\n", __func__);
        return EDPVS_NOMEM;
    }
    rte_atomic32_set(&svc->usecnt, 1);
    rte_atomic32_set(&svc->refcnt, 0);

    svc->af = u->af;
    svc->proto = u->protocol;
    svc->addr = u->addr;
    svc->port = u->port;
    svc->fwmark = u->fwmark;
    svc->flags = u->flags;
    svc->timeout = u->timeout;
    svc->conn_timeout = u->conn_timeout;
    svc->bps = u->bps;
    svc->limit_proportion = u->limit_proportion;
    svc->netmask = u->netmask;
    if (!is_empty_match(&u->match)) {
        svc->match = rte_zmalloc(NULL, sizeof(struct dp_vs_match),
                                 RTE_CACHE_LINE_SIZE);
        if (!svc->match) {
            ret = EDPVS_NOMEM;
            goto out_err;
        }

        *(svc->match) = u->match;
    }

    rte_rwlock_init(&svc->laddr_lock);
    INIT_LIST_HEAD(&svc->laddr_list);
    svc->num_laddrs = 0;
    svc->laddr_curr = &svc->laddr_list;

    INIT_LIST_HEAD(&svc->dests);
    rte_rwlock_init(&svc->sched_lock);

    ret = dp_vs_bind_scheduler(svc, sched);
    if (ret)
        goto out_err;
    sched = NULL;

    ret = dp_vs_new_stats(&(svc->stats));
    if(ret)
        goto out_err;
    if(svc->af == AF_INET)
        dp_vs_num_services++;

    rte_rwlock_write_lock(&__dp_vs_svc_lock);
    dp_vs_svc_hash(svc);
    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    *svc_p = svc;
    return EDPVS_OK;

out_err:
    if(svc != NULL) {
        if (svc->scheduler)
            dp_vs_unbind_scheduler(svc);
        dp_vs_del_stats(svc->stats);
        if (svc->match)
            rte_free(svc->match);
        rte_free(svc);
    }
    return ret;
}

int
dp_vs_edit_service(struct dp_vs_service *svc, struct dp_vs_service_conf *u)
{
    struct dp_vs_scheduler *sched, *old_sched;
    int ret = 0;

    /*
     * Lookup the scheduler, by 'u->sched_name'
     */
    sched = dp_vs_scheduler_get(u->sched_name);
    if (sched == NULL) {
        RTE_LOG(DEBUG, SERVICE, "Scheduler dp_vs_%s not found\n", u->sched_name);
        return EDPVS_NOTEXIST;
    }
    old_sched = sched;

#ifdef CONFIG_IP_VS_IPV6
    if (u->af == AF_INET6 && (u->netmask < 1 || u->netmask > 128)) {
        ret = -EINVAL;
        goto out;
    }
#endif

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    /*
     * Wait until all other svc users go away.
     */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    /*
     * Set the flags and timeout value
     */
    svc->flags = u->flags | DP_VS_SVC_F_HASHED;
    svc->timeout = u->timeout;
    svc->conn_timeout = u->conn_timeout;
    svc->netmask = u->netmask;
    svc->bps = u->bps;
    svc->limit_proportion = u->limit_proportion;

    old_sched = svc->scheduler;
    if (sched != old_sched) {
        /*
         * Unbind the old scheduler
         */
        if ((ret = dp_vs_unbind_scheduler(svc))) {
            old_sched = sched;
            goto out_unlock;
        }

        /*
         * Bind the new scheduler
         */
        if ((ret = dp_vs_bind_scheduler(svc, sched))) {
            /*
             * If ip_vs_bind_scheduler fails, restore the old
             * scheduler.
             * The main reason of failure is out of memory.
             *
             * The question is if the old scheduler can be
             * restored all the time. TODO: if it cannot be
             * restored some time, we must delete the service,
             * otherwise the system may crash.
             */
            dp_vs_bind_scheduler(svc, old_sched);
            old_sched = sched;
            goto out_unlock;
        }
    }

      out_unlock:
    rte_rwlock_write_unlock(&__dp_vs_svc_lock);
#ifdef CONFIG_IP_VS_IPV6
      out:
#endif

    return ret;
}


static void __dp_vs_del_service(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest, *nxt;

    /* Count only IPv4 services for old get/setsockopt interface */
    if (svc->af == AF_INET)
        dp_vs_num_services--;

    /* Unbind scheduler */
    dp_vs_unbind_scheduler(svc);

    dp_vs_laddr_flush(svc);

    dp_vs_blklst_flush(svc);

    /*
     *    Unlink the whole destination list
     */
    list_for_each_entry_safe(dest, nxt, &svc->dests, n_list) {
        DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);
        __dp_vs_unlink_dest(svc, dest, 0);
        __dp_vs_del_dest(dest);
    }

    /*
     *    Free the service if nobody refers to it
     */
    if (rte_atomic32_read(&svc->refcnt) == 0) {
        dp_vs_del_stats(svc->stats);
        if (svc->match)
            rte_free(svc->match);
        rte_free(svc);
    }
}

int dp_vs_del_service(struct dp_vs_service *svc)
{
    if (svc == NULL)
        return EDPVS_NOTEXIST;

    /*
     * Unhash it from the service table
     */
    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    dp_vs_svc_unhash(svc);

    /*
     * Wait until all the svc users go away.
     */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    __dp_vs_del_service(svc);

    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    return EDPVS_OK;
}

static int
dp_vs_copy_service(struct dp_vs_service_entry *dst, struct dp_vs_service *src)
{
    int err = 0;
    struct dp_vs_match *m;

    memset(dst, 0, sizeof(*dst));
    dst->proto = src->proto;
    dst->addr = src->addr.in.s_addr;
    dst->port = src->port;
    dst->fwmark = src->fwmark;
    snprintf(dst->sched_name, sizeof(dst->sched_name),
             "%s", src->scheduler->name);
    dst->flags = src->flags;
    dst->timeout = src->timeout;
    dst->conn_timeout = src->conn_timeout;
    dst->netmask = src->netmask;
    dst->num_dests = src->num_dests;
    dst->num_laddrs = src->num_laddrs;

    err = dp_vs_copy_stats(&dst->stats, src->stats);

    m = src->match;
    if (!m)
        return err;

    inet_addr_range_dump(AF_INET, &m->srange, dst->srange, sizeof(dst->srange));
    inet_addr_range_dump(AF_INET, &m->drange, dst->drange, sizeof(dst->drange));

    snprintf(dst->iifname, sizeof(dst->iifname), "%s", m->iifname);
    snprintf(dst->oifname, sizeof(dst->oifname), "%s", m->oifname);

    return err;
}

int dp_vs_get_service_entries(const struct dp_vs_get_services *get, 
                              struct dp_vs_get_services *uptr)
{
    int idx, count = 0;
    struct dp_vs_service *svc;
    int ret = 0;

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_table[idx], s_list){
            if (svc->af != AF_INET)
                continue;
            if (count >= get->num_services)
                goto out;
            ret = dp_vs_copy_service(&uptr->entrytable[count], svc);
            if (ret != EDPVS_OK)
                goto out;
            count++;
        }
    }

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_fwm_table[idx], f_list) {
            /* Only expose IPv4 entries to old interface */
            if (svc->af != AF_INET)
                continue;
            if (count >= get->num_services)
                goto out;
            ret = dp_vs_copy_service(&uptr->entrytable[count], svc);
            if (ret != EDPVS_OK)
                goto out;
            count++;
        }
    }

#ifdef CONFIG_NETOPS_ACL_RANGE
	for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_match_table[idx], m_list) {
            if (svc->af != AF_INET)
	            continue;
	        if (count >= get->num_services)
	            goto out;
	        ret = dp_vs_copy_service(&uptr->entrytable[count], svc);
	        if (ret != EDPVS_OK)
	            goto out;
	        count++;
        }
    }
#endif

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        if (svc->af != AF_INET)
            continue;
        if (count >= get->num_services)
            goto out;
        ret = dp_vs_copy_service(&uptr->entrytable[count], svc);
        if (ret != EDPVS_OK)
            goto out;
        count++;
    }

out:
    return ret;
}


unsigned dp_vs_get_conn_timeout(struct dp_vs_conn *conn)
{
    unsigned conn_timeout;
    if (conn->dest) {
        conn_timeout = conn->dest->conn_timeout;
        return conn_timeout;
    }
    return 90;
}

int dp_vs_flush(void)
{
#ifdef CONFIG_NETOPS_ACL_RANGE
    int i, idx;
#else
	int idx;
#endif
    struct dp_vs_service *svc, *nxt;

    /*
     * Flush the service table hashed by <protocol,addr,port>
     */
    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry_safe(svc, nxt, &dp_vs_svc_table[idx],
                     s_list) {
            rte_rwlock_write_lock(&__dp_vs_svc_lock);
            dp_vs_svc_unhash(svc);
            /*
             * Wait until all the svc users go away.
             */
            DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 0);
            __dp_vs_del_service(svc);
            rte_rwlock_write_unlock(&__dp_vs_svc_lock);
        }
    }

    /*
     * Flush the service table hashed by fwmark
     */
    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry_safe(svc, nxt,
                     &dp_vs_svc_fwm_table[idx], f_list) {
            rte_rwlock_write_lock(&__dp_vs_svc_lock);
            dp_vs_svc_unhash(svc);
            /*
             * Wait until all the svc users go away.
             */
            DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 0);
            __dp_vs_del_service(svc);
            rte_rwlock_write_unlock(&__dp_vs_svc_lock);
        }
    }
	
#ifdef CONFIG_NETOPS_ACL_RANGE
	for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry_safe(svc, nxt,
                     &dp_vs_svc_match_table[idx], m_list) {
	        rte_rwlock_write_lock(&__dp_vs_svc_lock);
	        dp_vs_svc_unhash(svc);
	        /*
	         * Wait until all the svc users go away.
	         */
	        DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 0);
	        __dp_vs_del_service(svc);
	        rte_rwlock_write_unlock(&__dp_vs_svc_lock);
	    }
    }

	for(i = 0; i < 4; i++) {
		for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
			list_for_each_entry_safe(svc, nxt,
						 &dp_vs_svc_match_range_table[i][idx], mr_list) {
				rte_rwlock_write_lock(&__dp_vs_svc_lock);
				dp_vs_svc_unhash(svc);
				/*
				 * Wait until all the svc users go away.
				 */
				DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 0);
				__dp_vs_del_service(svc);
				rte_rwlock_write_unlock(&__dp_vs_svc_lock);
			}
		}
	}
#endif

    list_for_each_entry_safe(svc, nxt,
                    &dp_vs_svc_match_list, m_list) {
        rte_rwlock_write_lock(&__dp_vs_svc_lock);
        dp_vs_svc_unhash(svc);
        /*
         * Wait until all the svc users go away.
         */
        DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 0);
        __dp_vs_del_service(svc);
        rte_rwlock_write_unlock(&__dp_vs_svc_lock);
    }

    return EDPVS_OK;
}

int dp_vs_zero_service(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest;

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    list_for_each_entry(dest, &svc->dests, n_list) {
        dp_svc_stats_clear(dest->stats);
    }
    dp_svc_stats_clear(svc->stats);
    rte_rwlock_write_unlock(&__dp_vs_svc_lock);
    return EDPVS_OK;
}

int dp_vs_zero_all(void)
{
#ifdef CONFIG_NETOPS_ACL_RANGE
    int i, idx;
#else
	int idx;
#endif
    struct dp_vs_service *svc;

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_table[idx], s_list) {
            dp_vs_zero_service(svc);
        }
    }

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_fwm_table[idx], f_list) {
            dp_vs_zero_service(svc);
        }
    }
	
#ifdef CONFIG_NETOPS_ACL_RANGE
	for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_match_table[idx], m_list) {
            dp_vs_zero_service(svc);
        }
    }

	for(i = 0; i < 4; i++) {
		for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
			list_for_each_entry(svc, &dp_vs_svc_match_range_table[i][idx], mr_list) {
				dp_vs_zero_service(svc);
			}
		}
	}
#endif

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        dp_vs_zero_service(svc);
    }

    dp_vs_stats_clear();
    return EDPVS_OK;
}


/*CONTROL PLANE*/
static int dp_vs_copy_usvc_compat(struct dp_vs_service_conf *conf,
                                   struct dp_vs_service_user *user)
{
    conf->af = AF_INET;
    conf->protocol = user->proto;
    conf->addr.in.s_addr = user->addr;
    conf->port = user->port;
    conf->fwmark = user->fwmark;

    /* Deep copy of sched_name is not needed here */
    conf->sched_name = user->sched_name;

    conf->flags = user->flags;
    conf->timeout = user->timeout;
    conf->conn_timeout = user->conn_timeout;
    conf->netmask = user->netmask;
    conf->bps = user->bps;
    conf->limit_proportion = user->limit_proportion;

    return dp_vs_match_parse(AF_INET, user->srange, user->drange,
                             user->iifname, user->oifname, &conf->match);
}

static void dp_vs_copy_udest_compat(struct dp_vs_dest_conf *udest,
                                    struct dp_vs_dest_user *udest_compat)
{
    udest->addr.in.s_addr = udest_compat->addr;
    udest->port = udest_compat->port;
    udest->fwdmode = udest_compat->conn_flags;//make sure fwdmode and conn_flags are the same
    udest->conn_flags = udest_compat->conn_flags; 
    udest->weight = udest_compat->weight;
    udest->max_conn = udest_compat->max_conn;
    udest->min_conn = udest_compat->min_conn;
}

static int gratuitous_arp_send_vip(struct in_addr *vip)
{
    struct route_entry *local_route;
    local_route = route_out_local_lookup(vip->s_addr);

    if(local_route){
        neigh_gratuitous_arp(&local_route->dest, local_route->port);
        route4_put(local_route);
        return EDPVS_OK;
    }
    return EDPVS_NOTEXIST;
}

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
static int dp_vs_set_svc(sockoptid_t opt, const void *user, size_t len)
{
    int ret;
    unsigned char arg[MAX_ARG_LEN];
    struct dp_vs_service_user *usvc_compat;
    struct dp_vs_service_conf usvc;
    struct dp_vs_service *svc = NULL;
    struct dp_vs_dest_user *udest_compat;
    struct dp_vs_dest_conf udest;
    struct in_addr *vip;

    if (opt == DPVS_SO_SET_GRATARP){
        vip = (struct in_addr *)user;
        return gratuitous_arp_send_vip(vip);
    }
    if (opt == DPVS_SO_SET_FLUSH)
        return dp_vs_flush();
    memcpy(arg, user, len);

    usvc_compat = (struct dp_vs_service_user *)arg;
    udest_compat = (struct dp_vs_dest_user *)(usvc_compat + 1);
 
    ret = dp_vs_copy_usvc_compat(&usvc, usvc_compat);
    if (ret != EDPVS_OK)
        return ret;
    
    if (opt == DPVS_SO_SET_ZERO) {
        if(!usvc.fwmark && !usvc.addr.in.s_addr && !usvc.port &&
           is_empty_match(&usvc.match)
          ) {
            return dp_vs_zero_all();
        }
    }

    if (usvc.protocol != IPPROTO_TCP && usvc.protocol != IPPROTO_UDP &&
        usvc.protocol != IPPROTO_ICMP) {
        RTE_LOG(ERR, SERVICE, "%s: protocol not support.\n", __func__);
        return EDPVS_INVAL;
    }

    if (usvc.addr.in.s_addr || usvc.port)
        svc = __dp_vs_service_get(usvc.af, usvc.protocol, 
                                  &usvc.addr, usvc.port);
    else if (usvc.fwmark)
        svc = __dp_vs_svc_fwm_get(usvc.af, usvc.fwmark);
    else if (!is_empty_match(&usvc.match))
        svc = __dp_vs_svc_match_find(usvc.af, usvc.protocol, &usvc.match);
    else {
        RTE_LOG(ERR, SERVICE, "%s: empty service.\n", __func__);
        return EDPVS_INVAL;
    }

    if(opt != DPVS_SO_SET_ADD && 
            (svc == NULL || svc->proto != usvc.protocol)){
        if (svc)
            dp_vs_service_put(svc);
        return EDPVS_INVAL;
    }

    switch(opt){
        case DPVS_SO_SET_ADD:
            if(svc != NULL)
                ret = EDPVS_EXIST;
            else 
                ret = dp_vs_add_service(&usvc, &svc);
            break;
        case DPVS_SO_SET_EDIT:
            ret = dp_vs_edit_service(svc, &usvc);
            break;
        case DPVS_SO_SET_DEL:
            ret = dp_vs_del_service(svc);
            break;
        case DPVS_SO_SET_ZERO:
            ret = dp_vs_zero_service(svc);
            break;
        case DPVS_SO_SET_ADDDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_add_dest(svc, &udest);
            break;
        case DPVS_SO_SET_EDITDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_edit_dest(svc, &udest);
            break;
        case DPVS_SO_SET_DELDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_del_dest(svc, &udest);
            break;
        default:
            ret = EDPVS_INVAL;
    }

    if(svc)
        dp_vs_service_put(svc);
    return ret;
}

static int dp_vs_get_svc(sockoptid_t opt, const void *user, size_t len, void **out, size_t *outlen)
{
    int ret = 0;
    switch (opt){
        case DPVS_SO_GET_VERSION:
            {
                char *buf = rte_zmalloc("info",64,0);
                sprintf(buf,"DPDK-FULLNAT Server version 1.1.4 (size=0)");
                *out = buf;
                *outlen = 64;
                break;
            }
        case DPVS_SO_GET_INFO:
            {
                struct dp_vs_getinfo *info;
                info = rte_zmalloc("info", sizeof(struct dp_vs_getinfo), 0);
                info->version = 0;
                info->size = 0;
                info->num_services = dp_vs_num_services;
                *out = info;
                *outlen = sizeof(struct dp_vs_getinfo);
                break;
            }
        case DPVS_SO_GET_SERVICES:
            {
                struct dp_vs_get_services *get, *output;
                int size;
                get = (struct dp_vs_get_services*)user;
                size = sizeof(*get) + \
                       sizeof(struct dp_vs_service_entry) * (get->num_services);
                //memcpy(&get, user, size);
                if(len != size){
                    *outlen = 0; 
                    return EDPVS_INVAL;
                }
                output = rte_zmalloc("get_services", len, 0);
                memcpy(output, get, size);
                ret = dp_vs_get_service_entries(get, output);
                *out = output;
                *outlen = size;
            }
            break;
        case DPVS_SO_GET_SERVICE:
            {
                struct dp_vs_service_entry *entry, *output;
                struct dp_vs_service *svc = NULL;
                union inet_addr addr;

                entry = (struct dp_vs_service_entry *)user;
                addr.in.s_addr = entry->addr;
                if(entry->fwmark)
                    svc = __dp_vs_svc_fwm_get(AF_INET, entry->fwmark);
                else if (entry->addr || entry->port)
                    svc = __dp_vs_service_get(AF_INET, entry->proto,
                                              &addr, entry->port);
                else {
                    struct dp_vs_match match;

                    ret = dp_vs_match_parse(AF_INET, entry->srange,
                                            entry->drange, entry->iifname,
                                            entry->oifname, &match);
                    if (ret != EDPVS_OK)
                        return ret;

                    if (!is_empty_match(&match)) {
                        svc = __dp_vs_svc_match_find(AF_INET, entry->proto,
                                                     &match);
                    }
                }

                output = rte_zmalloc("get_service",
                                     sizeof(struct dp_vs_service_entry), 0);
                memcpy(output, entry, sizeof(struct dp_vs_service_entry));
                if(svc) {
                    ret = dp_vs_copy_service(output, svc);
                    dp_vs_service_put(svc);
                    *out = output;
                    *outlen = sizeof(struct dp_vs_service_entry);
                }else{
                    *outlen = 0;
                    ret = EDPVS_NOTEXIST;
                }
            }
            break;
        case DPVS_SO_GET_DESTS:
            {
                struct dp_vs_service *svc = NULL;
                union inet_addr addr;
                struct dp_vs_get_dests *get, *output;
                int size;
                get = (struct dp_vs_get_dests *)user;
                size = sizeof(*get) + sizeof(struct dp_vs_dest_entry) * get->num_dests;
                if(len != size){
                    *outlen = 0;
                    return EDPVS_INVAL;
                }
                addr.in.s_addr = get->addr;
                output = rte_zmalloc("get_services", size, 0);
                memcpy(output, get, size);

                if(get->fwmark)
                    svc = __dp_vs_svc_fwm_get(AF_INET, get->fwmark);
                else if (addr.in.s_addr || get->port)
                    svc = __dp_vs_service_get(AF_INET, get->proto, &addr,
                                              get->port);
                else {
                    struct dp_vs_match match;

                    ret = dp_vs_match_parse(AF_INET, get->srange,
                                            get->drange, get->iifname,
                                            get->oifname, &match);
                    if (ret != EDPVS_OK)
                        return ret;

                    if (!is_empty_match(&match)) {
                        svc = __dp_vs_svc_match_find(AF_INET, get->proto,
                                                     &match);
                    }
                }

                if (!svc)
                    ret = EDPVS_NOTEXIST;
                else {
                    ret = dp_vs_get_dest_entries(svc, get, output);
                    dp_vs_service_put(svc);
                }
                *out = output;
                *outlen = size;
            }
            break;
        default:
            return EDPVS_INVAL;
    }

    return ret; 
}

struct dpvs_sockopts sockopts_svc = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SVC_BASE,
    .set_opt_max    = SOCKOPT_SVC_SET_CMD_MAX,
    .set            = dp_vs_set_svc,
    .get_opt_min    = SOCKOPT_SVC_BASE,
    .get_opt_max    = SOCKOPT_SVC_GET_CMD_MAX,
    .get            = dp_vs_get_svc,
};

#ifdef CONFIG_NETOPS_BYPASS_ROUTING

#include <netinet/tcp.h>

void fill_bypass_dest(struct ether_addr *eth_addr, struct netif_port *port, struct rte_mbuf *mbuf);

void fill_bypass_dest(struct ether_addr *eth_addr, struct netif_port *port, struct rte_mbuf *mbuf)
{
	struct ipv4_hdr *ip4h = ip4_hdr(mbuf);
	uint16_t proto  = ip4h->next_proto_id;
	uint16_t sport = 0;
	struct tcphdr *th, _tcph;
	struct udp_hdr *uh, _udph;
	struct bypass_conn *bc; 
	union inet_addr saddr;
	struct netif_port *p;

	if(proto == IPPROTO_UDP)
	{
		uh = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_udph), &_udph);
		if(!uh)
			return ;
		sport = uh->src_port;
	}
	else if(proto == IPPROTO_TCP)
	{
		th = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_tcph), &_tcph);
		if(!th)
                        return ;
		sport = th->source;
	}
	saddr.in.s_addr = ip4h->src_addr;
	bc = bypass_conn_get(AF_INET, proto, &saddr, sport);
	if(bc)
	{
		memcpy(&bc->out_dmac, eth_addr, sizeof(struct ether_addr));
		bc->out_dev = port;
		bypass_conn_put(bc);
		if(this_hit_dir_bypass)
        {
        	struct inet_ifaddr *ifaddr;
            memcpy(&this_direct_bypass_cache.out_dmac, eth_addr, sizeof(struct ether_addr));
            this_direct_bypass_cache.out_dev = port;
			p = netif_port_get_by_name("dpdk0");
			ifaddr = list_entry(p->in_ptr->ifa_list.next, struct inet_ifaddr, d_list);
			this_self_addr = ifaddr->addr.in.s_addr;
        } 
	}
}

#endif

int dp_vs_service_init(void)
{
	int idx;
#ifdef CONFIG_NETOPS_ACL_RANGE
    int i;
#endif
#ifdef CONFIG_NETOPS_BYPASS_ROUTING
	lcoreid_t lcore;
    int err;
	char poolname[32];
	int core_num = 0;

    rte_eal_mp_remote_launch(bypass_conn_init, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
	core_num++;
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, IPVS, "%s: lcore %d: %s.\n",
                    __func__, lcore, dpvs_strerror(err));
        }
    }

	/* connection cache on each NUMA socket */
	for (idx = 0; idx < DPVS_MAX_SOCKET; idx++) {
		snprintf(poolname, sizeof(poolname), "bypass_conn_%d", idx);
		bypass_conn_cache[idx] = rte_mempool_create(poolname,
									conn_pool_size * core_num,
									sizeof(struct bypass_conn),
									conn_pool_cache,
									0, NULL, NULL, NULL, NULL,
									idx, 0);
		if (!bypass_conn_cache[idx]) {
			return EDPVS_NOMEM;
		}
	}
#endif

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        INIT_LIST_HEAD(&dp_vs_svc_table[idx]);
        INIT_LIST_HEAD(&dp_vs_svc_fwm_table[idx]);
#ifdef CONFIG_NETOPS_ACL_RANGE
		INIT_LIST_HEAD(&dp_vs_svc_match_table[idx]);
    }
	for(i = 0; i < 4; i++) {
		for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
			INIT_LIST_HEAD(&dp_vs_svc_match_range_table[i][idx]);
	    }
#endif
	}
    INIT_LIST_HEAD(&dp_vs_svc_match_list);
    rte_rwlock_init(&__dp_vs_svc_lock);
    dp_vs_dest_init();
    sockopt_register(&sockopts_svc);
    return EDPVS_OK;
}

int dp_vs_service_term(void)
{
    dp_vs_flush();
    dp_vs_dest_term();
    return EDPVS_OK;
}
