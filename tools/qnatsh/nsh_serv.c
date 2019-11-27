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

#include <zebra.h>
#include "memory.h"
#include "memtypes.h"
#include "list.h"
#include "nsh_serv.h"

struct list_head g_poollist;
struct list_head g_servlist;

struct serv_info_st *get_serv_info(struct nat_service_ipc *servinfo)
{
	struct serv_info_st *serv = NULL;
	struct nat_service_ipc *info = servinfo;
	list_for_each_entry(serv, &g_servlist, serv_list)
	{
		struct nat_service_ipc *tmp = serv->servinfo;
		if ((info->proto == tmp->proto) && (strcmp(info->srange, tmp->srange) == 0) &&
			(strcmp(info->drange, tmp->drange) == 0) && (strcmp(info->oifname, tmp->oifname) == 0) &&
			(strcmp(info->iifname, tmp->iifname) == 0))
			return serv;
	}

	return NULL;
}

struct nat_service_ipc * add_serv_to_list(struct nat_service_ipc *servinfo)
{
	struct serv_info_st *serv;

	serv = XMALLOC(MTYPE_TMP, sizeof(struct serv_info_st));
	serv->servinfo = XMALLOC(MTYPE_TMP, sizeof(struct nat_service_ipc));
	memcpy(serv->servinfo, servinfo, sizeof(struct nat_service_ipc));
	INIT_LIST_HEAD(&serv->serv_list);
	INIT_LIST_HEAD(&serv->pools);
	list_add_tail(&serv->serv_list, &g_servlist);
	return serv->servinfo;
}

void remove_serv_from_list(struct serv_info_st *serv)
{
	XFREE(MTYPE_TMP, serv->servinfo);
	list_del(&serv->serv_list);
}

struct pool_info_st *get_pool_by_name(char *name)
{
	struct pool_info_st *pool = NULL;
	list_for_each_entry(pool, &g_poollist, pool_list)
	{
		if (strcmp (pool->poolname, name) == 0)
			return pool;
	}
	return NULL;
}

struct pool_info_st *create_pool_by_name(char *name)
{
	struct pool_info_st *pool = XMALLOC(MTYPE_LINK_NODE, sizeof(struct pool_info_st));
	if(pool)
	{
		strncpy(pool->poolname, name, 63);
		INIT_LIST_HEAD(&pool->members);
		list_add_tail(&pool->pool_list, &g_poollist);
	}
	return pool;
}

void remove_pool(struct pool_info_st *pool)
{
	list_del(&pool->pool_list);
	XFREE(MTYPE_LINK_NODE, pool);
}

struct member_info_st *get_member_by_ip(struct pool_info_st *pool, unsigned int minip, unsigned int maxip)
{
	struct member_info_st *member = NULL;
	list_for_each_entry(member, &pool->members, member_list)
	{
		if (member->min_ip == minip && member->max_ip == maxip)
			return member;
	}
	return NULL;
}

struct member_info_st *create_member(struct pool_info_st *pool, unsigned int minip, unsigned int maxip)
{
	struct member_info_st *member = XMALLOC(MTYPE_LINK_NODE, sizeof(struct member_info_st));
	if(member)
	{
		member->min_ip = minip;
		member->max_ip = maxip;
		INIT_LIST_HEAD(&member->member_list);
		list_add_tail(&member->member_list, &pool->members);
	}
	return member;
}

void remove_member(struct member_info_st *member)
{
	list_del(&member->member_list);
	XFREE(MTYPE_LINK_NODE, member);
}

int get_member_count(char *poolname)
{
	struct pool_info_st *pool = NULL;
	struct member_info_st *member = NULL;
	int count = 0;

	list_for_each_entry(pool, &g_poollist, pool_list)
	{
		if(pool->poolname != poolname)
			continue ;
		list_for_each_entry(member, &pool->members, member_list)
		{
			if(member->max_ip == member->min_ip)
				count++;
			else
				count += (ntohl(member->max_ip) - ntohl(member->min_ip) + 1);
		}
	}
	return count;
}

int is_ip_in_pool(struct pool_info_st *pool, unsigned int ip)
{
	struct member_info_st *member = NULL;

	list_for_each_entry(member, &pool->members, member_list)
	{
		if(member->max_ip == member->min_ip)
		{
			if(ip == member->min_ip)
				return 1;
		}
		else
		{
			if(ntohl(ip) >= ntohl(member->min_ip) && ntohl(ip) <= ntohl(member->max_ip))
				return 1;
		}
	}
	return 0;
}

void clear_serv_config(void)
{
	struct serv_info_st *serv = NULL, *next;
	list_for_each_entry_safe(serv, next, &g_servlist, serv_list)
	{
		XFREE(MTYPE_TMP, serv->servinfo);
		list_del(&serv->serv_list);
		XFREE(MTYPE_TMP, serv);
	}
}

void clear_pool_config(void)
{
	struct pool_info_st *pool = NULL, *np;
	struct member_info_st *member = NULL, *nm;

	list_for_each_entry_safe(pool, np, &g_poollist, pool_list)
	{
		list_for_each_entry_safe(member, nm, &pool->members, member_list)
		{
			list_del(&member->member_list);
			XFREE(MTYPE_LINK_NODE, member);
		}
		list_del(&pool->pool_list);
		XFREE(MTYPE_LINK_NODE, pool);
	}
}

void init_nat_serv(void)
{
	INIT_LIST_HEAD(&g_poollist);
	INIT_LIST_HEAD(&g_servlist);
}

