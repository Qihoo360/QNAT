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
#include <assert.h>
#include "common.h"
#include "netif.h"
#include "list.h"
#include "ctrl.h"
#include "ipvs/conn.h"
#include "ipvs/dest.h"
#include "ipvs/service.h"
#include "ipvs/stats.h"

#define this_dpvs_stats             (dpvs_stats[rte_lcore_id()])
#define this_dpvs_estats            (dpvs_estats[rte_lcore_id()])

static struct dp_vs_stats dpvs_stats[NETIF_MAX_LCORES];
static struct dp_vs_estats dpvs_estats[NETIF_MAX_LCORES];

static void __dp_vs_stats_clear(struct dp_vs_stats *stats)
{
    stats->conns    = 0;
    stats->inpkts   = 0;
    stats->inbytes  = 0;
    stats->outpkts  = 0;
    stats->outbytes = 0;
}

void dp_vs_stats_clear(void)
{
    uint8_t nlcore, i;
    uint64_t lcore_mask;

    /* get configured data-plane lcores */
    netif_get_slave_lcores(&nlcore, &lcore_mask);

    for (i = 0; i < NETIF_MAX_LCORES; i++) {
        if (!(lcore_mask & (1L<<i)))
            continue; /* unused */

        __dp_vs_stats_clear(&dpvs_stats[i]);
    }

    return;
}

/*add this code for per core stats*/
void dp_svc_stats_clear(struct dp_vs_stats *stats)
{
    uint8_t nlcore, i;
    uint64_t lcore_mask;

    netif_get_slave_lcores(&nlcore, &lcore_mask);

    for (i = 0; i < NETIF_MAX_LCORES; i++) {
        if (!(lcore_mask & (1L<<i)))
            continue;
        __dp_vs_stats_clear(&stats[i]);
    }
}


static struct dp_vs_stats* alloc_percpu_stats(void)
{
    uint8_t nlcore, i;
    uint64_t lcore_mask;
    struct dp_vs_stats* svc_stats;

    netif_get_slave_lcores(&nlcore, &lcore_mask);
    svc_stats = rte_malloc_socket(NULL, sizeof(struct dp_vs_stats) * NETIF_MAX_LCORES,
                                   RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!svc_stats)
        return NULL;

    for (i = 0; i < NETIF_MAX_LCORES; i++) {
        if (!(lcore_mask & (1L<<i)))
            continue;
        __dp_vs_stats_clear(&svc_stats[i]);
    } 
    
    return svc_stats;
}

int dp_vs_new_stats(struct dp_vs_stats **p)
{
    *p = alloc_percpu_stats();
    if (NULL == *p) {
        RTE_LOG(WARNING, SERVICE, "%s: no memory!\n", __func__);
        return EDPVS_NOMEM;
    }
    return EDPVS_OK;
}

void dp_vs_del_stats(struct dp_vs_stats *p)
{
    if (p)
        rte_free(p);
}

void dp_vs_zero_stats(struct dp_vs_stats* stats)
{
    uint8_t nlcore, i;
    uint64_t lcore_mask;
    
    netif_get_slave_lcores(&nlcore,&lcore_mask);

    for (i = 0; i < NETIF_MAX_LCORES; i++) {
        if (!(lcore_mask & (1L<<i)))
            continue;
        __dp_vs_stats_clear(&stats[i]);
    } 
    return;
}

static int get_stats_uc_cb(struct dpvs_msg *msg)
{
    struct dp_vs_stats **src;
    lcoreid_t cid;
    assert(msg);
    cid = rte_lcore_id();
    if (msg->len != sizeof(struct dp_vs_stats *)) {
        RTE_LOG(ERR, SERVICE, "%s: bad message.\n", __func__);
        return EDPVS_INVAL;
    }
    src = (struct dp_vs_stats **)msg->data;
    char *reply = rte_malloc(NULL, sizeof(struct dp_vs_stats), RTE_CACHE_LINE_SIZE);
    memcpy(reply, &((*src)[cid]), sizeof(struct dp_vs_stats));
    msg->reply.len = sizeof(struct dp_vs_stats);
    msg->reply.data = (void *)reply;
    return EDPVS_OK;
}

int dp_vs_copy_stats(struct dp_vs_stats* dst, struct dp_vs_stats* src)
{
    struct dpvs_msg *msg;
    struct dpvs_multicast_queue *reply=NULL;
    struct dpvs_msg *cur;
    struct dp_vs_stats *per_stats;
    int err;

    if (!src)
        return EDPVS_INVAL;

    msg = msg_make(MSG_TYPE_STATS_GET, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
			sizeof(struct dp_vs_stats *), &src);
    if (!msg) {   
        return EDPVS_NOMEM;
    }
    err = multicast_msg_send(msg, 0, &reply);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
        return err;
    }
    list_for_each_entry(cur, &reply->mq, mq_node) {
        per_stats = (struct dp_vs_stats *)(cur->data);
        dst->conns += per_stats->conns;
        dst->inpkts += per_stats->inpkts;
        dst->inbytes += per_stats->inbytes;
        dst->outbytes += per_stats->outbytes;
        dst->outpkts += per_stats->outpkts;
    }
    msg_destroy(&msg);
    return EDPVS_OK;
}

static void register_stats_cb(void)
{
    struct dpvs_msg_type mt;
    memset(&mt, 0 ,sizeof(mt));
    mt.type = MSG_TYPE_STATS_GET;
    mt.unicast_msg_cb = get_stats_uc_cb;
    mt.multicast_msg_cb = NULL;
    assert(msg_type_mc_register(&mt) == 0);
}

static void unregister_stats_cb(void)
{
    struct dpvs_msg_type mt;
    memset(&mt, 0, sizeof(mt));
    mt.type = MSG_TYPE_STATS_GET;
    mt.unicast_msg_cb = get_stats_uc_cb;
    mt.multicast_msg_cb = NULL;
    assert(msg_type_mc_unregister(&mt) == 0);
}

int dp_vs_stats_in(struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    assert(conn && mbuf);
    struct dp_vs_dest *dest = conn->dest;
    lcoreid_t cid;   
    cid = rte_lcore_id();

    if (dest && (dest->flags & DPVS_DEST_F_AVAILABLE)) {
        /*limit rate*/
        if ((dest->limit_proportion < 100) &&
            (dest->limit_proportion > 0)) {
            return (rand()%100) > dest->limit_proportion 
                        ? EDPVS_OVERLOAD : EDPVS_OK;
        }

        dest->stats[cid].inpkts++;
        dest->stats[cid].inbytes += mbuf->pkt_len;
    }

    this_dpvs_stats.inpkts++;
    this_dpvs_stats.inbytes += mbuf->pkt_len;
    return EDPVS_OK;
}

int dp_vs_stats_out(struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    assert(conn && mbuf);
    struct dp_vs_dest *dest = conn->dest;
    lcoreid_t cid;
    cid = rte_lcore_id();

    if (dest && (dest->flags & DPVS_DEST_F_AVAILABLE)) {
        /*limit rate*/
        if ((dest->limit_proportion < 100) && 
            (dest->limit_proportion > 0)) {
            return (rand()%100) > dest->limit_proportion 
			? EDPVS_OVERLOAD : EDPVS_OK; 
        }

        dest->stats[cid].outpkts++;
        dest->stats[cid].outbytes += mbuf->pkt_len;
    }

    this_dpvs_stats.outpkts++;
    this_dpvs_stats.outbytes += mbuf->pkt_len;
    return EDPVS_OK;
}

void dp_vs_stats_conn(struct dp_vs_conn *conn)
{
    assert(conn && conn->dest);
    lcoreid_t cid;

    cid = rte_lcore_id();   
    conn->dest->stats[cid].conns++;
    this_dpvs_stats.conns++;
}

void dp_vs_estats_inc(enum dp_vs_estats_type field)
{
    this_dpvs_estats.mibs[field]++;
}

void dp_vs_estats_clear(void)
{
    memset(&dpvs_estats[0], 0, sizeof(dpvs_estats));
}

uint64_t dp_vs_estats_get(enum dp_vs_estats_type field)
{
    return this_dpvs_estats.mibs[field];
}

#ifdef CONFIG_NETOPS_CONN_THRESH
void ns_state_sip_init(void);
#endif

int dp_vs_stats_init(void)
{
    dp_vs_stats_clear();
    srand(rte_rdtsc());
    register_stats_cb();
#ifdef CONFIG_NETOPS_CONN_THRESH
	ns_state_sip_init();
#endif
    return EDPVS_OK;
}

int dp_vs_stats_term(void)
{
    unregister_stats_cb();
    return EDPVS_OK;
}

#ifdef CONFIG_NETOPS_CONN_THRESH
struct ns_sip_stat_node
{
	struct list_head list;
	unsigned int ip;
	int allowed;
	rte_atomic64_t conns;
};

struct ns_sip_thresh_conf
{
	struct list_head list;
	unsigned int ip;
	unsigned int threshhold;
};

struct ns_stat_bucket
{
	struct list_head list;
};

#define STAT_HASH_SIZE 4096
#define THRESH_CONF_NAME    "/etc/qnat/qnat_blk.conf"

struct ns_stat_bucket *ns_stat_sip_hash[RTE_MAX_LCORE] = {NULL};
struct ns_stat_bucket *ns_stat_sip_threshhold_hash = NULL;
unsigned int g_default_thresh = 10000;

static unsigned int ip_stat_hash(unsigned int ip)
{
	return (ip + ((ip >> 16) & 0xFFFF)) % STAT_HASH_SIZE;
}

static void init_thresh_conf(void)
{
	FILE *fp;
	char line[64] = {0};
	char *ipstr = NULL;
	char *token = NULL;
	uint32_t thval = 0;
	struct ns_sip_thresh_conf *conf;
	uint32_t sip;
	unsigned int sip_hash;
	struct list_head *pos,*tmp;

	fp = fopen(THRESH_CONF_NAME, "r");
	if(fp)
	{
		while(fgets(line, 64, fp))
		{
			sscanf(line, "%s=%u", ipstr, &thval);
			token = strtok(line, "=");
			ipstr = token;
			token = strtok(NULL, "=");
			thval = atoi(token);
			if (strncmp(ipstr, "255.255.255.255", strlen("255.255.255.255")) == 0)
				g_default_thresh = thval;
			else
			{
				sip = inet_addr(ipstr);
				sip_hash = ip_stat_hash(sip);
				conf = NULL;
				list_for_each_safe(pos, tmp, &ns_stat_sip_threshhold_hash[sip_hash].list)
				{
					conf = (struct ns_sip_thresh_conf *)pos;
					if(conf->ip == sip)
					{
						break;
					}
				}
				if(!conf)
				{
					conf = (struct ns_sip_thresh_conf *)rte_malloc("SIP_THRESH_CONF", sizeof(struct ns_sip_thresh_conf), RTE_CACHE_LINE_SIZE);
					if(!conf)
					{
						return ;
					}
				}
				memset(conf, 0, sizeof(struct ns_sip_thresh_conf));
				INIT_LIST_HEAD(&conf->list);
				list_add_tail(&conf->list, &ns_stat_sip_threshhold_hash[sip_hash].list);
				conf->ip = sip;
				conf->threshhold = thval;
			}
		}
		fclose(fp);
		return ;
	}
	printf("Can not find thresh info, use default: %u\n", g_default_thresh);
}

void ns_state_sip_init(void)
{
	int i, j;
	for(i = 0; i < RTE_MAX_LCORE; i++)
	{
		ns_stat_sip_hash[i] = (struct ns_stat_bucket *)rte_malloc("SIP_HASH", sizeof(struct ns_stat_bucket) * STAT_HASH_SIZE, RTE_CACHE_LINE_SIZE);
		if(!ns_stat_sip_hash[i])
		{
			printf ("ns_stat_sip_hash alloc failed!\r\n");
			return ;
		}
		for (j = 0; j < STAT_HASH_SIZE; j++)
		{	
			INIT_LIST_HEAD(&ns_stat_sip_hash[i][j].list);
		}
	}
	
	ns_stat_sip_threshhold_hash = (struct ns_stat_bucket *)rte_malloc("SIP_THRESH_HASH", sizeof(struct ns_stat_bucket) * STAT_HASH_SIZE, RTE_CACHE_LINE_SIZE);
	for (j = 0; j < STAT_HASH_SIZE; j++)
	{	
		INIT_LIST_HEAD(&ns_stat_sip_threshhold_hash[j].list);
	}
	init_thresh_conf();
}

static uint32_t ns_get_sip_thresh(uint32_t sip)
{
	struct ns_sip_thresh_conf *conf;
	unsigned int sip_hash = ip_stat_hash(sip);
	struct list_head *pos,*tmp;
	conf = NULL;
	list_for_each_safe(pos, tmp, &ns_stat_sip_threshhold_hash[sip_hash].list)
	{
		conf = (struct ns_sip_thresh_conf *)pos;
		if(conf->ip == sip)
		{
			break;
		}
	}
	if(!conf)
		return g_default_thresh;
	return conf->threshhold;
}

static inline void inc_stat_cplsesson_count(struct ns_sip_stat_node *snode)
{
	rte_atomic64_inc(&snode->conns);
	if(rte_atomic64_read(&snode->conns) >= ns_get_sip_thresh(snode->ip))
		snode->allowed = 0;
}

static inline void dec_stat_cplsesson_count(struct ns_sip_stat_node *snode)
{
	rte_atomic64_dec(&snode->conns);
	if(rte_atomic64_read(&snode->conns) < ns_get_sip_thresh(snode->ip))
		snode->allowed = 1;
}

static struct ns_sip_stat_node *ns_sip_stat_find_get_node(struct ns_stat_bucket *b, uint32_t sip)
{
	unsigned int found=0;
	struct list_head *pos,*tmp;
	struct ns_sip_stat_node *node;
	unsigned int sip_hash = ip_stat_hash(sip);

	list_for_each_safe(pos, tmp, &b[sip_hash].list){
		node = (struct ns_sip_stat_node *)pos;
		if(node->ip == sip){
			found = 1;
			break;
		}
	}
	if(!found){
		node = (struct ns_sip_stat_node *)rte_malloc("SIP_STAT", sizeof(struct ns_sip_stat_node), RTE_CACHE_LINE_SIZE);
		if(!node){
			return NULL;
		}
		memset(node,0,sizeof(struct ns_sip_stat_node));
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, &b[sip_hash].list);
		node->allowed = 1;
		node->ip = sip;
	}

	return node;		
}

void *ns_con_inc(uint32_t sip);
void ns_con_dec(void *snode);
int ns_conn_allowed(uint32_t sip);

void *ns_con_inc(uint32_t sip)
{
	struct ns_sip_stat_node *snode = NULL;

	snode = ns_sip_stat_find_get_node(ns_stat_sip_hash[rte_lcore_id()], sip);

	inc_stat_cplsesson_count(snode);
	return (void *)snode;
}

void ns_con_dec(void *snode)
{
	dec_stat_cplsesson_count((struct ns_sip_stat_node *)snode);
}

int ns_conn_allowed(uint32_t sip)
{
	struct ns_sip_stat_node *snode = NULL;

  	snode = ns_sip_stat_find_get_node(ns_stat_sip_hash[rte_lcore_id()], sip);
	return snode->allowed;
}

#endif

