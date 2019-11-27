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

#ifndef _NSH_SERV_H__20190605__FL_
#define _NSH_SERV_H__20190605__FL_

#include "nsh_cmd.h"

struct poolnames_st
{
	struct list_head pool_list;
	char poolname[64];
};

struct serv_info_st
{
	struct list_head serv_list;
	struct nat_service_ipc *servinfo;
	struct list_head pools;
};

struct member_info_st
{
	struct list_head member_list;
	unsigned int min_ip;
	unsigned int max_ip;
	unsigned int masklen;
};

struct pool_info_st
{
	struct list_head pool_list;
	struct list_head members;
	char poolname[64];
};

struct serv_info_st *get_serv_info(struct nat_service_ipc *servinfo);
struct nat_service_ipc * add_serv_to_list(struct nat_service_ipc *servinfo);
void remove_serv_from_list(struct serv_info_st *serv);
struct pool_info_st *get_pool_by_name(char *name);
struct pool_info_st *create_pool_by_name(char *name);
void remove_pool(struct pool_info_st *pool);
struct member_info_st *get_member_by_ip(struct pool_info_st *pool, unsigned int minip, unsigned int maxip);
struct member_info_st *create_member(struct pool_info_st *pool, unsigned int minip, unsigned int maxip);
void remove_member(struct member_info_st *member);
int get_member_count(char *poolname);
int is_ip_in_pool(struct pool_info_st *pool, unsigned int ip);
void clear_serv_config(void);
void clear_pool_config(void);
void init_nat_serv(void);

#endif

