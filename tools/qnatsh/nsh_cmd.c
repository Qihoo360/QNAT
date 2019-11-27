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
#include <termios.h>
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "list.h"
#include "vector.h"
#include "nsh_cmd.h"
#include "nsh_serv.h"
#include "nsh.h"
#include "msg.h"

#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

struct ret_code_str
{
	int ret_code;
	char str[128];
};

struct ret_code_str ret_str[] = 
{
	{0, "OK"},
	{1, "Invalid parameter"},
	{2, "No memory"},
	{3, "Already exist"},
	{4, "Not exist"},
	{5, "Invalid packet"},
	{6, "Packet dropped"},
	{7, "No protocol"},
	{8, "No route"},
	{9, "Defragment error"},
	{10, "Fragment error"},
	{11, "DPDK error"},
	{12, "Nothing to do"},
	{13, "Resource busy"},
	{14, "Not support"},
	{15, "No resource"},
	{16, "Overloaded"}, 
	{17, "No service"},
	{18, "Disabled"}, 
	{19, "No room"},
	{20, "Non-eal thread lcore"},
	{21, "Callbacks fail"},
	{22, "I/O error"},
	{23, "Msg callback failed"},
	{24, "Msg callback dropped"},
	{25, "Stolen packet"},
	{26, "System call failed"},
	{27, "No such device"}
};

/* When '^Z' is received from vty, move down to the enable mode. */
int
vtysh_end (void)
{
  switch (vty->node)
    {
    case VIEW_NODE:
    case ENABLE_NODE:
      /* Nothing to do. */
      break;
    default:
      vty->node = ENABLE_NODE;
      break;
    }
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_end_all,
	 vtysh_end_all_cmd,
	 "end",
	 "End current mode and change to enable mode\n")
{
  return vtysh_end ();
}

/* TODO Implement "no interface command in isisd. */
DEFSH (VTYSH_ZEBRA|VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_OSPFD|VTYSH_OSPF6D,
       vtysh_no_interface_cmd,
       "no interface IFNAME",
       NO_STR
       "Delete a pseudo interface's configuration\n"
       "Interface's name\n")

/* TODO Implement interface description commands in ripngd, ospf6d
 * and isisd. */
DEFSH (VTYSH_ZEBRA|VTYSH_RIPD|VTYSH_OSPFD,
       interface_desc_cmd,
       "description .LINE",
       "Interface specific description\n"
       "Characters describing this interface\n")
       
DEFSH (VTYSH_ZEBRA|VTYSH_RIPD|VTYSH_OSPFD,
       no_interface_desc_cmd,
       "no description",
       NO_STR
       "Interface specific description\n")

DEFUNSH (VTYSH_INTERFACE,
	 vtysh_exit_interface,
	 vtysh_exit_interface_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

ALIAS (vtysh_exit_interface,
       vtysh_quit_interface_cmd,
       "quit",
       "Exit current mode and down to previous mode\n")

DEFUN (diagnose,
       diagnose_cmd,
       "diagnose",
       "Check into diagnose mode\n")
{
	vty->node = AUTH_NODE;
	
	return CMD_SUCCESS;
}

DEFUN (test,
       test_cmd,
       "test",
       "Check into test node for debug\n")
{
	vty->node = TEST_AUTH_NODE;
  return CMD_SUCCESS;
}

DEFUN (reboot,
	reboot_cmd,
	"reboot",
	"System reboot\n")
{
	char ch;
	printf("System will be reboot, are you sure?(y/n)");
	ch = getchar();
	if(ch == 'y')
	{
		while((ch = getchar()) != '\n');
		system("reboot");
	}
	while((ch = getchar()) != '\n');

	return CMD_SUCCESS;
}

DEFUN (poweroff,
	poweroff_cmd,
	"poweroff",
	"System shutdown\n")
{
	char ch;
	printf("System will be shutdown, are you sure?(y/n)");
	ch = getchar();
	if(ch == 'y')
	{
		while((ch = getchar()) != '\n');
		system("poweroff");
	}
	while((ch = getchar()) != '\n');

	return CMD_SUCCESS;
}

#ifndef IFA_F_SAPOOL
#define IFA_F_SAPOOL        0x10000
#endif

#define MAIN_ROUTING    "qnat &"
extern char config_default[];

DEFUN (startup,
        startup_cmd,
        "ip nat start",
        "IP protocol\n"
        "NAT service config\n"
        "Service start\n")
{
    system(MAIN_ROUTING);
    sleep(25);
    system("ifconfig dpdk0.kni up");
    system("ifconfig dpdk1.kni up");
    return CMD_SUCCESS;
}

DEFUN (load_config,
        load_config_cmd,
        "load config",
        "Load operation\n"
        "NAT service startup config\n")
{
	system("ifconfig dpdk0.kni up");
	system("ifconfig dpdk1.kni up");
    vtysh_read_config(config_default);
    return CMD_SUCCESS;
}

DEFUN (stop,
	stop_cmd,
	"ip nat stop",
	"IP protocol\n"
	"NAT service config\n"
	"Service stop\n")
{
	system("killall qnat");
	clear_serv_config();
	clear_serv_config();
	return CMD_SUCCESS;
}

#define DEFAULT_WEIGHT    100

extern int nat_request_set(int cmd, char * buff, int datalen, int bufferlen, int flags);
extern int nat_request_get(int cmd, char * buff, int datalen, int bufferlen, int flags);
extern struct list_head g_servlist;

char g_inside_if[16] = "dpdk0";
char g_outside_if[16] = "dpdk1";

int nsh_realserver_ops(struct nat_service_ipc *service, int cmd, unsigned int ip, unsigned int port, int weight)
{
	struct {
		struct nat_service_ipc svc;
		struct nat_realserver_ipc dest;
	} buf;
	int ret;

	memset(&buf, 0, sizeof buf);
	memcpy(&buf.svc, service, sizeof(buf.svc));

	buf.dest.addr = ip;
	buf.dest.port = port;
	buf.dest.weight = weight;
	buf.dest.conn_flags = 0x0006;

repeat:
	ret = nat_request_set(cmd, (char *)&buf, sizeof(buf), sizeof(buf), 0);
	if(ret)
	{
		if(ret == -3)
		{
			cmd = NAT_SO_SET_EDITDEST;
			goto repeat;
		}
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
	}
	return ret;
}

DEFUN(
		nat_ifconf,
		nat_ifconf_cmd,
		"(inside|outside) interface IFNAME",
		"In-going interface specified\n"
		"Out-going interface specified\n"
		"Interface config\n"
		"Name of interface, 15 charactors at the most, truncated if overflows\n")
{
	if(argv[0][0] == 'i')
		strncpy(g_inside_if, argv[1], 15);
	else
		strncpy(g_outside_if, argv[1], 15);
	return CMD_SUCCESS;
}

int config_local_address(int cmd, struct prefix_ipv4 *p, char *ifname, int flags)
{
	struct inet_addr_ipc addr;
	int ret;
	
	memset(&addr, 0, sizeof addr);
	memcpy(addr.ifname, ifname, 16);
	addr.af = AF_INET;
	addr.addr.in.s_addr = p->prefix.s_addr;
	addr.plen = p->prefixlen;
	addr.flags = flags;

	ret = nat_request_set(cmd, (char *)&addr, sizeof(addr), sizeof(addr), 0);
	
	return ret;
}

DEFUN(
		nat_service_add,
		nat_service_add_cmd,
		"ip nat source A.B.C.D A.B.C.D",
		"IP protocol\n"
		"NAT service config\n"
		"Match source IP\n"
		"Range begin ip\n"
		"Range end ip\n")
{
	struct nat_service_ipc buf;
	int i, ret;
	int cmd = NAT_SO_SET_ADD;
	struct in_addr start_ip;
	struct in_addr end_ip;
	int proto[3] = {6, 17, 1};

	memset(&buf, 0, sizeof buf);
	strncpy(buf.sched_name, "rr", strlen("rr"));
	if (!inet_aton (argv[0], &start_ip))
	{
		vty_out(vty, "IP address [%s] format invalid\n", argv[0]);
		return CMD_WARNING;
	}

	if (!inet_aton (argv[1], &end_ip))
	{
		vty_out(vty, "IP address [%s] format invalid\n", argv[1]);
		return CMD_WARNING;
	}

	if (start_ip.s_addr > end_ip.s_addr)
	{
		vty_out(vty, "IP range start ip [%s] can not greater than end ip [%s]\n", argv[0], argv[1]);
		return CMD_WARNING;
	}
	sprintf(buf.srange, "%s-%s", argv[0], argv[1]);
	strncpy(buf.oifname, g_outside_if, strlen(g_outside_if));

repeat:
	for(i = 0; i < 3; i++)
	{
		buf.proto = proto[i];
		ret = nat_request_set(cmd, (char *)&buf, sizeof(buf), sizeof(buf), 0);
		if(ret)
		{
			if(ret == -3)
			{
				cmd = NAT_SO_SET_EDIT;
				goto repeat;
			}
			vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
			return CMD_SUCCESS;
		}
	}

	if(vty->index != NULL)
		vty->index = NULL;
	buf.proto = 0;
	vty->index = get_serv_info(&buf);
	if(vty->index == NULL)
		vty->index = add_serv_to_list(&buf);
	vty->node = NAT_SERVICE_NODE;
	return CMD_SUCCESS;
}

DEFUN(
		nat_service_del,
		nat_service_del_cmd,
		"no ip nat source A.B.C.D A.B.C.D",
		NO_STR
		"IP protocol\n"
		"NAT service config\n"
		"Match source IP\n"
		"Range begin ip\n"
		"Range end ip\n")
{
	struct nat_service_ipc buf;
	int i, ret;
	struct in_addr start_ip;
	struct in_addr end_ip;
	int proto[3] = {6, 17, 1};
	
	memset(&buf, 0, sizeof buf);
	strncpy(buf.sched_name, "rr", strlen("rr"));
	if (!inet_aton (argv[0], &start_ip))
	{
		vty_out(vty, "IP address [%s] format invalid\n", argv[0]);
		return CMD_WARNING;
	}

	if (!inet_aton (argv[1], &end_ip))
	{
		vty_out(vty, "IP address [%s] format invalid\n", argv[1]);
		return CMD_WARNING;
	}

	if (start_ip.s_addr > end_ip.s_addr)
	{
		vty_out(vty, "IP range start ip [%s] can not greater than end ip [%s]\n", argv[0], argv[1]);
		return CMD_WARNING;
	}
	sprintf(buf.srange, "%s-%s", argv[0], argv[1]);
	strncpy(buf.oifname, g_outside_if, strlen(g_outside_if));

	for(i = 0; i < 3; i++)
	{
		buf.proto = proto[i];
		ret = nat_request_set(NAT_SO_SET_DEL, (char *)&buf, sizeof(buf), sizeof(buf), 0);
		if(ret)
		{
			vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
			return CMD_SUCCESS;
		}
	}

	struct serv_info_st *serv = NULL;
	serv = get_serv_info(&buf);
	if(serv != NULL)
	{
		struct poolnames_st *pool = NULL, *next;
		remove_serv_from_list(serv);
		list_for_each_entry_safe(pool, next, &serv->pools, pool_list)
		{
			XFREE(MTYPE_TMP, pool);
		}
		XFREE(MTYPE_TMP, serv);
	}
	return CMD_SUCCESS;
}

DEFUN(
		nat_dest,
		nat_dest_cmd,
		"dest A.B.C.D/M",
		"NAT service destination config\n"
		"Server address\n")
{
	struct prefix_ipv4 p;
	unsigned int i, ret;
	struct nat_service_ipc *service = vty->index;
	int proto[3] = {6, 17, 1};

	ret = str2prefix_ipv4 (argv[0], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	ret = config_local_address(NAT_SET_IFADDR_ADD, &p, g_outside_if, IFA_F_SAPOOL);
	for(i = 0; i < 3; i++)
	{
		service->proto = proto[i];
		ret = nsh_realserver_ops(vty->index, NAT_SO_SET_ADDDEST, p.prefix.s_addr, 0, DEFAULT_WEIGHT);
	}
	service->proto = 0;
	return ret;
}

DEFUN(
		no_nat_dest,
		no_nat_dest_cmd,
		"no dest A.B.C.D/M",
		NO_STR
		"NAT service real server config\n"
		"Server address\n")
{
	unsigned int i, ret;
	struct prefix_ipv4 p;
	struct nat_service_ipc *service = vty->index;
	int proto[3] = {6, 17, 1};

	ret = str2prefix_ipv4 (argv[0], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	for(i = 0; i < 3; i++)
	{
		service->proto = proto[i];
		ret = nsh_realserver_ops(vty->index, NAT_SO_SET_DELDEST, p.prefix.s_addr, 0, DEFAULT_WEIGHT);
	}
	ret = config_local_address(NAT_SET_IFADDR_DEL, &p, g_outside_if, IFA_F_SAPOOL);
	service->proto = 0;
	return ret;
}

DEFUN(
		nat_dest_pool,
		nat_dest_pool_cmd,
		"dest pool NAME",
		"NAT service destination config\n"
		"Set service destination pool by name\n"
		"Pool name\n")
{
	struct pool_info_st *pool = NULL;
	struct member_info_st *member = NULL;
	struct serv_info_st *serv = get_serv_info((struct nat_service_ipc *)vty->index);
	struct poolnames_st *poolname = NULL;
	unsigned int i, ip;
	struct nat_service_ipc *service = vty->index;
	int proto[3] = {6, 17, 1};
	if(serv == NULL)
	{
		vty_out(vty, "Get service failed!\n");
		return CMD_SUCCESS;
	}
	pool = get_pool_by_name((char *)argv[0]);
	if(pool)
	{
		for(i = 0; i < 3; i++)
		{
			service->proto = proto[i];
			list_for_each_entry(member, &pool->members, member_list)
			{
				if(member->min_ip == member->max_ip)
				{
					if(i == 0)
					{
						struct prefix_ipv4 p;
						p.prefix.s_addr = member->min_ip;
						p.prefixlen = member->masklen;
						int ret = config_local_address(NAT_SET_IFADDR_ADD, &p, g_outside_if, IFA_F_SAPOOL);
					}
					nsh_realserver_ops(service, NAT_SO_SET_ADDDEST, member->min_ip, 0, DEFAULT_WEIGHT);
				}
				else
				{
					for(ip = ntohl(member->min_ip); ip <= ntohl(member->max_ip); ip++)
					{
						if(i == 0)
						{
							struct prefix_ipv4 p;
							p.prefix.s_addr = htonl(ip);
							p.prefixlen = member->masklen;
							int ret = config_local_address(NAT_SET_IFADDR_ADD, &p, g_outside_if, IFA_F_SAPOOL);
						}
						nsh_realserver_ops(service, NAT_SO_SET_ADDDEST, htonl(ip), 0, DEFAULT_WEIGHT);
					}
				}
			}
		}
		service->proto = 0;
		poolname = XMALLOC(MTYPE_TMP, sizeof(struct poolnames_st));
		memset(poolname, 0, sizeof(struct poolnames_st));
		strncpy(poolname->poolname, pool->poolname, strlen(pool->poolname));
		list_add_tail(&poolname->pool_list, &serv->pools);
	}
	else
	{
		vty_out(vty, "Pool [%s] not found\n", argv[0]);
		return CMD_WARNING;
	}
	
	return CMD_SUCCESS;
}

DEFUN(
		no_nat_dest_pool,
		no_nat_dest_pool_cmd,
		"no dest pool NAME",
		NO_STR
		"NAT service destination config\n"
		"Set service destination pool by name\n"
		"Pool name\n"
		"Set weight\n"
		"Weight number\n")
{
	struct pool_info_st *pool = NULL;
	struct member_info_st *member = NULL;
	struct serv_info_st *serv = get_serv_info((struct nat_service_ipc *)vty->index);
	struct poolnames_st *poolname = NULL, *next;
	unsigned int i, ip;
	struct nat_service_ipc *service = vty->index;
	int proto[3] = {6, 17, 1};
	struct prefix_ipv4 p;
	
	pool = get_pool_by_name((char *)argv[0]);
	if(pool)
	{
		list_for_each_entry(member, &pool->members, member_list)
		{
			if(member->min_ip == member->max_ip)
			{
				for(i = 0; i < 3; i++)
				{
					service->proto = proto[i];
					nsh_realserver_ops(service, NAT_SO_SET_DELDEST, member->min_ip, 0, atoi(argv[1]));
				}
				p.prefix.s_addr = member->min_ip;
				p.prefixlen = member->masklen;
				config_local_address(NAT_SET_IFADDR_DEL, &p, g_outside_if, IFA_F_SAPOOL);
			}
			else
			{
				for(ip = ntohl(member->min_ip); ip <= ntohl(member->max_ip); ip++)
				{
					for(i = 0; i < 3; i++)
					{
						service->proto = proto[i];
						nsh_realserver_ops(service, NAT_SO_SET_DELDEST, htonl(ip), 0, atoi(argv[1]));
					}
					p.prefix.s_addr = htonl(ip);
					p.prefixlen = member->masklen;
					config_local_address(NAT_SET_IFADDR_DEL, &p, g_outside_if, IFA_F_SAPOOL);
				}
			}
		}
		service->proto = 0;
		list_for_each_entry_safe(poolname, next, &serv->pools, pool_list)
		{
			if(strcmp(poolname->poolname, pool->poolname) == 0)
			{
				list_del(&poolname->pool_list);
				XFREE(MTYPE_TMP, poolname);
			}
		}
	}
	else
	{
		vty_out(vty, "Pool [%s] not found\n", argv[0]);
		return CMD_WARNING;
	}
	
	return CMD_SUCCESS;
}

DEFUN(
		local_ip,
		local_ip_cmd,
		"local ip A.B.C.D/M",
		"Set local config\n"
		"Local IP\n"
		"IP address with masklen, e.g. x.x.x.x/x\n")
{
	int ret;
	struct prefix_ipv4 p;
	
	ret = str2prefix_ipv4 (argv[0], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}

	ret = config_local_address(NAT_SET_IFADDR_ADD, &p, g_inside_if, 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
	}
	
	return CMD_SUCCESS;
}


DEFUN(
		no_local_ip,
		no_local_ip_cmd,
		"no local ip A.B.C.D/M",
		NO_STR
		"Set local config\n"
		"Local IP\n"
		"IP address with masklen, e.g. x.x.x.x/x\n")
{
	int ret;
	struct prefix_ipv4 p;
	
	ret = str2prefix_ipv4 (argv[0], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}

	ret = config_local_address(NAT_SET_IFADDR_DEL, &p, g_inside_if, 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
	}
	
	return CMD_SUCCESS;
}

DEFUN(
		route_via,
		route_via_cmd,
		"ip route A.B.C.D/M via A.B.C.D dev (inside|outside)",
		"Set ip config\n"
		"Set route\n"
		"Destination IP address with masklen, e.g. x.x.x.x/x\n"
		"Specify gateway address\n"
		"Gateway IP address without masklen, e.g. x.x.x.x\n"
		"Output device\n"
		"Inside device\n"
		"Outside device\n")
{
	struct nat_route_ipc route;
	int ret;
	struct prefix_ipv4 p;

	memset(&route, 0, sizeof route);
	if(argv[2][0] == 'i')
		memcpy(route.ifname, g_inside_if, 16);
	else
		memcpy(route.ifname, g_outside_if, 16);
	ret = str2prefix_ipv4 (argv[0], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	route.af = AF_INET;
	route.dst.in.s_addr = p.prefix.s_addr;
	route.plen = p.prefixlen;
	ret = str2prefix_ipv4 (argv[1], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[1]);
		return CMD_WARNING;
	}
	route.via.in.s_addr = p.prefix.s_addr;

	ret = nat_request_set(NAT_SET_ROUTE_ADD, (char *)&route, sizeof(route), sizeof(route), 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
	}
	
	return CMD_SUCCESS;
}

DEFUN(
		route_dev,
		route_dev_cmd,
		"ip route A.B.C.D/M dev (inside|outside) [kni_host]",
		"Set ip config\n"
		"Set route\n"
		"Destination IP address with masklen, e.g. x.x.x.x/x\n"
		"Output device\n"
		"Inside device\n"
		"Outside device\n"
		"Specify scope to kni_host\n")
{
	struct nat_route_ipc route;
	int ret;
	struct prefix_ipv4 p;

	memset(&route, 0, sizeof route);
	if(argv[1][0] == 'i')
		memcpy(route.ifname, g_inside_if, 16);
	else
		memcpy(route.ifname, g_outside_if, 16);
	ret = str2prefix_ipv4 (argv[0], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	route.af = AF_INET;
	route.dst.in.s_addr = p.prefix.s_addr;
	route.plen = p.prefixlen;
	if(argc > 2)
		route.scope = 2;

	ret = nat_request_set(NAT_SET_ROUTE_ADD, (char *)&route, sizeof(route), sizeof(route), 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
	}
	
	return CMD_SUCCESS;
}

DEFUN(
		no_route_via,
		no_route_via_cmd,
		"no ip route A.B.C.D/M via A.B.C.D dev (inside|outside)",
		NO_STR
		"Set ip config\n"
		"Set route\n"
		"Destination IP address with masklen, e.g. x.x.x.x/x\n"
		"Specify gateway address\n"
		"Gateway IP address without masklen, e.g. x.x.x.x\n"
		"Output device\n"
		"Inside device\n"
		"Outside device\n")
{
	struct nat_route_ipc route;
	int ret;
	struct prefix_ipv4 p;

	memset(&route, 0, sizeof route);
	if(argv[2][0] == 'i')
		memcpy(route.ifname, g_inside_if, 16);
	else
		memcpy(route.ifname, g_outside_if, 16);
	ret = str2prefix_ipv4 (argv[0], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	route.af = AF_INET;
	route.dst.in.s_addr = p.prefix.s_addr;
	route.plen = p.prefixlen;
	ret = str2prefix_ipv4 (argv[1], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[1]);
		return CMD_WARNING;
	}
	route.via.in.s_addr = p.prefix.s_addr;

	ret = nat_request_set(NAT_SET_ROUTE_DEL, (char *)&route, sizeof(route), sizeof(route), 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
	}
	
	return CMD_SUCCESS;
}

DEFUN(
		no_route_dev,
		no_route_dev_cmd,
		"no ip route A.B.C.D/M dev (inside|outside) [kni_host]",
		"Set ip config\n"
		"Set route\n"
		"Destination IP address with masklen, e.g. x.x.x.x/x\n"
		"Output device\n"
		"Inside device\n"
		"Outside device\n"
		"Specify scope to kni_host\n")
{
	struct nat_route_ipc route;
	int ret;
	struct prefix_ipv4 p;

	memset(&route, 0, sizeof route);
	if(argv[1][0] == 'i')
		memcpy(route.ifname, g_inside_if, 16);
	else
		memcpy(route.ifname, g_outside_if, 16);
	ret = str2prefix_ipv4 (argv[0], &p);
	if (ret <= 0)
	{
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	route.af = AF_INET;
	route.dst.in.s_addr = p.prefix.s_addr;
	route.plen = p.prefixlen;
	if(argc > 2)
		route.scope = 2;

	ret = nat_request_set(NAT_SET_ROUTE_DEL, (char *)&route, sizeof(route), sizeof(route), 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
	}
	
	return CMD_SUCCESS;
}

DEFUN(pool,
		pool_cmd,
		"ip nat pool NAME",
		"IP protocol\n"
		"Nat service\n"
		"define a pool name\n"
		"set the name of a pool\n")
{
	struct pool_info_st *pool;

	pool = get_pool_by_name((char *)argv[0]);
	if (NULL == pool)
	{
		pool = create_pool_by_name((char *)argv[0]);
		if(!pool)
		{
			vty_out(vty, "Operation failed: Not enough memory\n");
			return CMD_SUCCESS;
		}
	}
	if(vty->index != NULL)
		XFREE(MTYPE_TMP, vty->index);
	vty->index = XMALLOC(MTYPE_TMP, 64);
	memcpy(vty->index, pool->poolname, 64);
	vty->node = POOL_NODE;
	
	return CMD_SUCCESS;
}

DEFUN(no_pool,
		no_pool_cmd,
		"no ip nat pool NAME",
		NO_STR
		"IP protocol\n"
		"Nat service\n"
		"define a pool name\n"
		"set the name of a pool\n")
{
	struct pool_info_st *pool;

	pool = get_pool_by_name((char *)argv[0]);
	if (NULL == pool)
	{
		vty_out(vty, "pool %s not found\n", (char *)argv[0]);
		return CMD_SUCCESS;
	}
	if(list_empty(&pool->members))
		remove_pool(pool);
	else
		vty_out(vty, "operation failed: pool %s has members, remove all members first and retry\n", (char *)argv[0]);
	
	return CMD_SUCCESS;
}

DEFUN(member,
		member_cmd,
		"member ip A.B.C.D/M",
		"Define a member ip port\n"
		"Set member ip address\n"
		"Ip address\n")
{
	struct pool_info_st *pool_info = NULL;
	struct member_info_st *member_info;
	int ret;
	struct prefix_ipv4 cp;
	
	ret = str2prefix_ipv4 (argv[0], &cp);
	if (ret <= 0) {
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	pool_info = get_pool_by_name(vty->index);
	member_info = get_member_by_ip(pool_info, cp.prefix.s_addr, cp.prefix.s_addr);
	if (NULL == member_info)
	{
		member_info = create_member(pool_info, cp.prefix.s_addr, cp.prefix.s_addr);
		if(!member_info)
			vty_out(vty, "Operation failed: Not enough memory\n");
		else
			member_info->masklen = cp.prefixlen;
	}
	
	return CMD_SUCCESS;
}

DEFUN(no_member,
		no_member_cmd,
		"no member ip A.B.C.D/M",
		NO_STR
		"Define a member ip port\n"
		"Set member ip address\n"
		"Ip address\n")
{
	struct pool_info_st *pool_info = NULL;
	struct member_info_st *member_info;
	struct serv_info_st *serv;
	struct poolnames_st *poolname;
	int i, ret;
	unsigned short oldproto;
	struct prefix_ipv4 cp;
	int proto[3] = {6, 17, 1};
	struct prefix_ipv4 p;
	
	ret = str2prefix_ipv4 (argv[0], &cp);
	if (ret <= 0) {
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	pool_info = get_pool_by_name(vty->index);
	member_info = get_member_by_ip(pool_info, cp.prefix.s_addr, cp.prefix.s_addr);
	if (NULL == member_info)
	{
		vty_out(vty, "member %s not found\n", (char *)argv[0]);
		return CMD_SUCCESS;
	}
	member_info->masklen = cp.prefixlen;
	list_for_each_entry(serv, &g_servlist, serv_list)
	{
		list_for_each_entry(poolname, &serv->pools, pool_list)
		{
			if(strcmp(poolname->poolname, vty->index) == 0)
			{
				oldproto = serv->servinfo->proto;
				for(i = 0; i < 3; i++)
				{
					serv->servinfo->proto = proto[i];
					nsh_realserver_ops(serv->servinfo, NAT_SO_SET_DELDEST, cp.prefix.s_addr, 0, 0);
				}
				serv->servinfo->proto = oldproto;
				p.prefix.s_addr = cp.prefix.s_addr;
				p.prefixlen = cp.prefixlen;
				config_local_address(NAT_SET_IFADDR_DEL, &p, g_outside_if, IFA_F_SAPOOL);
			}
		}
	}
	remove_member(member_info);
	
	return CMD_SUCCESS;
}

DEFUN(member_range,
		member_range_cmd,
		"member range A.B.C.D A.B.C.D masklen <0-32>",
		"Define a member ip port\n"
		"Set member ip address range\n"
		"Ip address range min\n"
		"Ip address range max\n"
		"Netmask length\n"
		"Mask length from 0 to 32\n")
{
	struct pool_info_st *pool_info = NULL;
	struct member_info_st *member_info;
	struct serv_info_st *serv;
	struct poolnames_st *poolname;
	int i, ret;
	unsigned short oldproto;
	struct prefix_ipv4 cp1, cp2, p;
	unsigned int ip;
	int proto[3] = {6, 17, 1};
	
	ret = str2prefix_ipv4 (argv[0], &cp1);
	if (ret <= 0) {
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	ret = str2prefix_ipv4 (argv[1], &cp2);
	if (ret <= 0) {
		vty_out(vty, "IP address [%s] is malformed\n", argv[1]);
		return CMD_WARNING;
	}
	if(cp1.prefix.s_addr > cp2.prefix.s_addr) {
		vty_out(vty, "IP address max [%s] must be greater than min [%s]\n", argv[1], argv[0]);
		return CMD_WARNING;
	}
	pool_info = get_pool_by_name(vty->index);
	member_info = get_member_by_ip(pool_info, cp1.prefix.s_addr, cp2.prefix.s_addr);
	if (NULL == member_info)
	{
		member_info = create_member(pool_info, cp1.prefix.s_addr, cp2.prefix.s_addr);
		if(NULL == member_info)
		{
			vty_out(vty, "Not enough memory\n");
			return CMD_SUCCESS;
		}
	}
	member_info->masklen = atoi(argv[2]);
	list_for_each_entry(serv, &g_servlist, serv_list)
	{
		list_for_each_entry(poolname, &serv->pools, pool_list)
		{
			if(strcmp(poolname->poolname, vty->index) == 0)
			{
				for(ip = ntohl(cp1.prefix.s_addr); ip < ntohl(cp2.prefix.s_addr); ip++)
				{
					oldproto = serv->servinfo->proto;
					p.prefix.s_addr = htonl(ip);
					p.prefixlen = member_info->masklen;
					config_local_address(NAT_SET_IFADDR_ADD, &p, g_outside_if, IFA_F_SAPOOL);
					for(i = 0; i < 3; i++)
					{
						serv->servinfo->proto = proto[i];
						nsh_realserver_ops(serv->servinfo, NAT_SO_SET_ADDDEST, htonl(ip), 0, 0);
					}
					serv->servinfo->proto = oldproto;
					
				}
			}
		}
	}
	
	return CMD_SUCCESS;
}

DEFUN(no_member_range,
		no_member_range_cmd,
		"no member range A.B.C.D A.B.C.D",
		NO_STR
		"Define a member ip port\n"
		"Set member ip address range\n"
		"Ip address range min\n"
		"Ip address range max\n")
{
	struct pool_info_st *pool_info = NULL;
	struct member_info_st *member_info;
	struct serv_info_st *serv;
	struct poolnames_st *poolname;
	int i, ret;
	struct prefix_ipv4 cp1, cp2, p;
	unsigned int ip;
	unsigned short oldproto;
	int proto[3] = {6, 17, 1};
	
	ret = str2prefix_ipv4 (argv[0], &cp1);
	if (ret <= 0) {
		vty_out(vty, "IP address [%s] is malformed\n", argv[0]);
		return CMD_WARNING;
	}
	ret = str2prefix_ipv4 (argv[1], &cp2);
	if (ret <= 0) {
		vty_out(vty, "IP address [%s] is malformed\n", argv[1]);
		return CMD_WARNING;
	}
	if(cp1.prefix.s_addr > cp2.prefix.s_addr) {
		vty_out(vty, "IP address max [%s] must be greater than min [%s]\n", argv[1], argv[0]);
		return CMD_WARNING;
	}
	pool_info = get_pool_by_name(vty->index);
	member_info = get_member_by_ip(pool_info, cp1.prefix.s_addr, cp2.prefix.s_addr);
	if (NULL == member_info)
	{
		vty_out(vty, "member range %s %s not found\n", (char *)argv[0], (char *)argv[1]);
		return CMD_SUCCESS;
	}
	list_for_each_entry(serv, &g_servlist, serv_list)
	{
		list_for_each_entry(poolname, &serv->pools, pool_list)
		{
			if(strcmp(poolname->poolname, vty->index) == 0)
			{
				for(ip = ntohl(cp1.prefix.s_addr); ip < ntohl(cp2.prefix.s_addr); ip++)
				{
					oldproto = serv->servinfo->proto;
					for(i = 0; i < 3; i++)
					{
						serv->servinfo->proto = proto[i];
						nsh_realserver_ops(serv->servinfo, NAT_SO_SET_DELDEST, htonl(ip), 0, 0);
					}
					serv->servinfo->proto = oldproto;
					p.prefix.s_addr = htonl(ip);
					p.prefixlen = member_info->masklen;
					config_local_address(NAT_SET_IFADDR_DEL, &p, g_outside_if, IFA_F_SAPOOL);
				}
			}
		}
	}
	remove_member(member_info);
	
	return CMD_SUCCESS;
}

extern int nsh_service_config_write (struct vty *vty);

DEFUN(show_nat_service,
		nat_service_show_cmd,
		"show nat",
		SHOW_STR
		"NAT service config\n")
{
	nsh_service_config_write(vty);
	return CMD_SUCCESS;
}

extern struct list_head g_poollist;

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

int nsh_localip_config_write (struct vty *vty)
{
	struct inet_addr_param_array *info;
	int ret;
	int i, len;

	len = sizeof(struct inet_addr_param_array) + 64 * sizeof(struct inet_addr_param_array);
	info = (struct inet_addr_param_array *)XMALLOC(MTYPE_TMP, len);
	memset(info, 0, len);
	ret = nat_request_get(NAT_GET_IFADDR_SHOW, (char *)info, len, len, 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
		return CMD_SUCCESS;
	}
	for(i = 0; i < info->naddr; i++)
	{
		if(strcmp(info->addrs[i].ifname, g_inside_if) == 0)
			vty_out(vty, "local ip "NIPQUAD_FMT"/%d\r\n",
				NIPQUAD(info->addrs[i].addr.in.s_addr), info->addrs[i].plen);
	}
	return CMD_SUCCESS;
}

int get_ospf_ifaddr(struct vty *vty)
{
	char cmd[64] = {0};
	char *ipaddr, *mask;
	struct prefix_ipv4 cp1;
	FILE *fp = popen("ifconfig dpdk0.kni | grep inet | awk -F ' ' '{print $2,$4}'", "r");
	fgets(cmd, 64, fp);
	if(strlen(cmd) > 1)
	{
		ipaddr = mask = cmd;
		while(*mask != ' ')
			mask++;
		*mask = '\0';
		mask++;
		str2prefix_ipv4 (mask, &cp1);
		vty_out(vty, "ip addr %s/%d dev dpdk0.kni\n", ipaddr, ip_masklen(cp1.prefix));
	}
	pclose(fp);
	memset(cmd, 0, 64);
	fp = popen("ifconfig dpdk1.kni | grep inet | awk -F ' ' '{print $2,$4}'", "r");
	fgets(cmd, 64, fp);
	if(strlen(cmd) > 1)
	{
		ipaddr = mask = cmd;
		while(*mask != ' ')
			mask++;
		*mask = '\0';
		mask++;
		str2prefix_ipv4 (mask, &cp1);
		vty_out(vty, "ip addr %s/%d dev dpdk1.kni\n", ipaddr, ip_masklen(cp1.prefix));
	}
	pclose(fp);
	return 0;
}

int nsh_route_need_write(struct nat_route_ipc *rt)
{
	int ret = 0;
	if(0 == rt->dst.in.s_addr)//default route
		ret = 1;
	if(2 == rt->scope)//route for kni device
		ret = 1;
	if(rt->via.in.s_addr != 0)//default route & route for back to intranet
		ret = 1;
	return ret;
}

int nsh_route_config_write (struct vty *vty, int write_file)
{
	struct nat_route_conf_array *info;
	int ret;
	int i, len;

	if(write_file)
		get_ospf_ifaddr(vty);

	len = sizeof(struct nat_route_conf_array) + 256 * sizeof(struct nat_route_ipc);
	info = (struct nat_route_conf_array *)XMALLOC(MTYPE_TMP, len);
	memset(info, 0, len);
	ret = nat_request_get(NAT_GET_ROUTE_SHOW, (char *)info, len, len, 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
		return CMD_SUCCESS;
	}
	for(i = 0; i < info->nroute; i++)
	{
		if(!nsh_route_need_write(&(info->routes[i])))
			continue;
		if(2 == info->routes[i].scope || 0 == info->routes[i].via.in.s_addr)
		{
			vty_out(vty, "ip route "NIPQUAD_FMT"/%d dev %s %s\r\n",
				NIPQUAD(info->routes[i].dst.in.s_addr), info->routes[i].plen,
				strcmp(info->routes[i].ifname, g_inside_if) ? "outside" : "inside", 2 == info->routes[i].scope ? "kni_host" : "");
		}
		else
		{
			vty_out(vty, "ip route "NIPQUAD_FMT"/%d via "NIPQUAD_FMT" dev %s\r\n",
				NIPQUAD(info->routes[i].dst.in.s_addr), info->routes[i].plen,
				NIPQUAD(info->routes[i].via.in.s_addr), strcmp(info->routes[i].ifname, g_inside_if) ? "outside" : "inside");
		}
	}
	return CMD_SUCCESS;
}

DEFUN(show_local_ip,
		show_local_ip_cmd,
		"show local-ip",
		SHOW_STR
		"Local ip address config\n")
{
	nsh_localip_config_write(vty);
	return CMD_SUCCESS;
}

DEFUN(show_ip_route,
		show_ip_route_cmd,
		"show route",
		SHOW_STR
		"NAT route config\n")
{
	nsh_route_config_write(vty, 0);
	return CMD_SUCCESS;
}

int nsh_network_config_write (struct vty *vty)
{
	if(strcmp(g_inside_if, "dpdk0"))
		vty_out(vty, "inside interface %s\n", g_inside_if);
	if(strcmp(g_outside_if, "dpdk1"))
		vty_out(vty, "outside interface %s\n", g_outside_if);
	nsh_localip_config_write(vty);
	nsh_route_config_write(vty, 1);
	return CMD_SUCCESS;
}

extern struct host host;

int nsh_pool_config_write (struct vty *vty)
{
	struct pool_info_st *pool = NULL;
	struct member_info_st *member = NULL;

	if (host.name)
		vty_out(vty, "hostname %s%s", host.name, VTY_NEWLINE);

	list_for_each_entry(pool, &g_poollist, pool_list)
	{
		vty_out(vty, "ip nat pool %s\n", pool->poolname);
		
		list_for_each_entry(member, &pool->members, member_list)
		{
			if(member->min_ip == member->max_ip)
				vty_out(vty, "    member ip "NIPQUAD_FMT"/%d\n", NIPQUAD(member->min_ip), member->masklen);
			else
				vty_out(vty, "    member range "NIPQUAD_FMT" "NIPQUAD_FMT" masklen %d\n",
					NIPQUAD(member->min_ip), NIPQUAD(member->max_ip), member->masklen);
		}
		vty_out(vty, "exit\n");
	}
	return CMD_SUCCESS;
}

DEFUN(show_nat_pool,
		nat_pool_show_cmd,
		"show ip nat pool",
		SHOW_STR
		"IP protocol\n"
		"Nat service\n"
		"NAT pool config\n")
{
	nsh_pool_config_write(vty);
	return CMD_SUCCESS;
}

char *get_dest_poolname(struct nat_get_dests *dest)
{
	int i = 0, mcount = 0;
	struct pool_info_st *pool = NULL;

	list_for_each_entry(pool, &g_poollist, pool_list)
	{
		mcount = 0;
		if(get_member_count(pool->poolname) == dest->num_dests)
		{
			for(i = 0; i < dest->num_dests; i++)
				if(is_ip_in_pool(pool, dest->entrytable[i].addr))
					mcount++;
		}
		if(mcount && mcount == get_member_count(pool->poolname))
			return pool->poolname;
	}
	
	return NULL;
}

struct service_cmd_str
{
	struct list_head list;
	char serv_cmd[64];
	char *dest_cmd;
};

int nsh_service_config_write (struct vty *vty)
{
	struct nat_getinfo_ipc info;
	struct nat_get_services *servs = NULL;
	int ret;
	int i, j, len;
	char *poolname = NULL;
	struct list_head cmdlist;
	struct service_cmd_str *cmdstr, *exist_cmd;

	INIT_LIST_HEAD(&cmdlist);

	memset(&info, 0, sizeof(info));
	ret = nat_request_get(NAT_SO_GET_INFO, (char *)&info, sizeof(info), sizeof(info), 0);
	if(ret)
	{
		printf("Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
		return CMD_SUCCESS;
	}
	if(info.num_services > 0)
	{
		len = sizeof(struct nat_get_services) + info.num_services * sizeof(struct nat_service_entry);
		servs = XMALLOC(MTYPE_TMP, len);
		memset(servs, 0, len);
		servs->num_services = info.num_services;
		ret = nat_request_get(NAT_SO_GET_SERVICES, (char *)servs, len, len, 0);
		if(ret)
		{
			printf("Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
			XFREE(MTYPE_TMP, servs);
			return CMD_SUCCESS;
		}
		for (i = info.num_services - 1; i >= 0; i--)
		{
			struct nat_service_entry *entry = &(servs->entrytable[i]);
			char *min = NULL, *max = NULL, *tmp;
			char range[256] = {0};
			cmdstr = XMALLOC(MTYPE_TMP, sizeof(struct service_cmd_str));
			memset(cmdstr, 0, sizeof(struct service_cmd_str));
			memcpy(range, entry->srange, strlen(entry->srange));
			tmp = min = &range[0];
			while(*tmp != '-')
				tmp++;
			*tmp = '\0';
			tmp++;
			max = tmp;
			while(*tmp != ':')
				tmp++;
			*tmp = '\0';
			
			sprintf(cmdstr->serv_cmd, "ip nat source %s %s", min, max);
			
			if(entry->num_dests)
			{
				struct nat_get_dests *dest;
				len = sizeof(struct nat_get_dests) + entry->num_dests * sizeof(struct nat_dest_entry);
				dest = XMALLOC(MTYPE_TMP, len);
				memset(dest, 0, len);
				dest->proto = entry->proto;
				dest->addr = entry->addr;
				dest->port = entry->port;
				dest->fwmark = entry->fwmark;
				dest->num_dests = entry->num_dests;
				strncpy(dest->srange, entry->srange, strlen(entry->srange));
				strncpy(dest->drange, entry->drange, strlen(entry->drange));
				strncpy(dest->iifname, entry->iifname, strlen(entry->iifname));
				strncpy(dest->oifname, entry->oifname, strlen(entry->oifname));
				ret = nat_request_get(NAT_SO_GET_DESTS, (char *)dest, len, len, 0);
				if(ret)
				{
					printf("Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
					XFREE(MTYPE_TMP, servs);
					XFREE(MTYPE_TMP, dest);
					goto failed;
				}
				poolname = get_dest_poolname(dest);
				if(poolname) {
					cmdstr->dest_cmd = XMALLOC(MTYPE_TMP, strlen(poolname) + 16);
					memset(cmdstr->dest_cmd, 0, strlen(poolname) + 16);
					sprintf(cmdstr->dest_cmd, "    dest pool %s\n", poolname);
				} else {
					cmdstr->dest_cmd = XMALLOC(MTYPE_TMP, dest->num_dests * 32);
					memset(cmdstr->dest_cmd, 0, dest->num_dests * 32);
					for(j = 0; j < dest->num_dests; j++)
					{
						char destcmd[32] = {0};
						struct inet_addr_param_array *info;
						int ret;
						int i, len;

						len = sizeof(struct inet_addr_param_array) + 64 * sizeof(struct inet_addr_param_array);
						info = (struct inet_addr_param_array *)XMALLOC(MTYPE_TMP, len);
						memset(info, 0, len);
						ret = nat_request_get(NAT_GET_IFADDR_SHOW, (char *)info, len, len, 0);
						if(ret)
						{
							vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
							return CMD_SUCCESS;
						}
						for(i = 0; i < info->naddr; i++)
						{
							if((strcmp(info->addrs[i].ifname, g_outside_if) == 0) && (dest->entrytable[j].addr == info->addrs[i].addr.in.s_addr))
							{
								sprintf(destcmd, "    dest "NIPQUAD_FMT"/%d\n", NIPQUAD(info->addrs[i].addr.in.s_addr), info->addrs[i].plen);
								strcat(cmdstr->dest_cmd, destcmd);
							}
						}
					}
				}
			}
			list_for_each_entry(exist_cmd, &cmdlist, list)
			{
				if((strcmp(exist_cmd->dest_cmd?exist_cmd->dest_cmd:"", cmdstr->dest_cmd?cmdstr->dest_cmd:"") == 0 &&
					strcmp(exist_cmd->serv_cmd?exist_cmd->serv_cmd:"", cmdstr->serv_cmd?cmdstr->serv_cmd:"") == 0))
				{
					if(cmdstr->dest_cmd)
						XFREE(MTYPE_TMP, cmdstr->dest_cmd);
					XFREE(MTYPE_TMP, cmdstr);
					cmdstr = NULL;
					break;
				}
			}
			if(cmdstr)
				list_add_tail(&cmdstr->list, &cmdlist);
		}
	}
	list_for_each_entry_safe(cmdstr, exist_cmd, &cmdlist, list)
	{
		vty_out(vty, "%s\n", cmdstr->serv_cmd);
		if(cmdstr->dest_cmd)
			vty_out(vty, "%s", cmdstr->dest_cmd);
		vty_out(vty, "exit\n");
		if(cmdstr->dest_cmd)
			XFREE(MTYPE_TMP, cmdstr->dest_cmd);
		XFREE(MTYPE_TMP, cmdstr);
	}
	XFREE(MTYPE_TMP, servs);
	return CMD_SUCCESS;
failed:
	list_for_each_entry_safe(cmdstr, exist_cmd, &cmdlist, list)
	{
		if(cmdstr->dest_cmd)
			XFREE(MTYPE_TMP, cmdstr->dest_cmd);
		XFREE(MTYPE_TMP, cmdstr);
	}
	XFREE(MTYPE_TMP, servs);
	return CMD_SUCCESS;
}

extern vector cmdvec;

DEFUN (vtysh_save_config,
		vtysh_save_config_cmd,
		"write file",
		"Write running configuration to file terminal\n"
		"Write configuration to the file\n")
{
	struct vty *vtyfs;
	int i;
	struct cmd_node *node;

	vtyfs = vty_new ();
	vtyfs->fd = open( VTYSH_DEFAULT_CONFIG, O_WRONLY|O_CREAT|O_TRUNC);
	if(vtyfs->fd <= 0)
	{
		vty_out(vty, "Write error\n\r");
		vty_close(vtyfs);
		return CMD_SUCCESS;
	}
	vtyfs->type = VTY_SHELL_SERV;
	
	nsh_network_config_write(vtyfs);

	vty_out (vty, "Building configuration...%s", VTY_NEWLINE);
	vty_out (vty, "%sCurrent configuration:%s", VTY_NEWLINE, VTY_NEWLINE);

	for ( i = 0; i < vector_active( cmdvec ); i++ )
		if ( ( node = vector_slot ( cmdvec, i ) ) && ( node->func ) )
		{
			( *node->func ) ( vtyfs );
		}

	vty_close(vtyfs);
	system("chmod 755 "VTYSH_DEFAULT_CONFIG);

	//unlink("/tmp/qnatcfg.conf");	
	system("sync");
	return CMD_SUCCESS;
}

DEFUN (vtysh_show_run,
		vtysh_show_run_cmd,
		"show running-config",
		SHOW_STR
		"Running configuration\n")
{
	struct vty *vtyfs;
	int i;
	struct cmd_node *node;

	vtyfs = vty_new ();
	vtyfs->fd = open("/tmp/running_config", O_WRONLY|O_CREAT|O_TRUNC);
	if(vtyfs->fd <= 0)
	{
		vty_out(vty, "Write error\n\r");
		vty_close(vtyfs);
		return CMD_SUCCESS;
	}
	vtyfs->type = VTY_SHELL_SERV;

	//vty_out (vty, "Building configuration...%s", VTY_NEWLINE);
	//vty_out (vty, "%sCurrent configuration:%s", VTY_NEWLINE, VTY_NEWLINE);
	nsh_network_config_write(vtyfs);

	for ( i = 0; i < vector_active( cmdvec ); i++ )
		if ( ( node = vector_slot ( cmdvec, i ) ) && ( node->func ) )
		{
			( *node->func ) ( vtyfs );
		}

	vty_close(vtyfs);
	system("more /tmp/running_config");
	unlink("/tmp/running_config");

	return CMD_SUCCESS;
}

DEFUN (vtysh_show_conf,
		vtysh_show_conf_cmd,
		"show startup-config",
		SHOW_STR
		"Startup configuration\n")
{
	system("more /etc/qnat/qnatcfg.conf");
	return CMD_SUCCESS;
}

char *get_port_flag_str(uint16_t flags)
{
	return "";
}

/* show stats */
DEFUN(show_nat_link,
	nat_link_show_cmd,
	"show link stats",
	SHOW_STR
	"NAT link info"
	"Stats infomation\n")
{
	struct netif_nic_num_get nicnum;
	int i, ret;
	struct netif_nic_mbufpool mbufstat;
	struct netif_nic_stats_get nicstat;
	struct netif_nic_basic_get nicinfo;
	
	ret = nat_request_get(SOCKOPT_NETIF_GET_PORT_NUM, (char *)&nicnum, sizeof(nicnum), sizeof(nicnum), 0);
	if(ret)
	{
		vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
		return CMD_SUCCESS;
	}
	for(i = 0; i < nicnum.nic_num; i++)
	{
		nicinfo.port_id = i;
		ret = nat_request_get(SOCKOPT_NETIF_GET_PORT_BASIC, (char *)&nicinfo, 1, 1, 0);
		if(ret)
		{
			vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
			return CMD_SUCCESS;
		}
		nicstat.port_id = i;
		ret = nat_request_get(SOCKOPT_NETIF_GET_PORT_STATS, (char *)&nicstat, 1, 1, 0);
		if(ret)
		{
			vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
			return CMD_SUCCESS;
		}
		mbufstat.available = i;
		ret = nat_request_get(SOCKOPT_NETIF_GET_PORT_MBUFPOOL, (char *)&mbufstat, 1, 1, 0);
		if(ret)
		{
			vty_out(vty, "Operation failed: code = %d[%s]\n", ret, ret_str[-ret].str);
			return CMD_SUCCESS;
		}
		vty_out(vty, "%s: socket %d mtu %u rx-queue %u tx-queue %u\n", nicinfo.name, nicinfo.socket_id,
			nicinfo.mtu, nicinfo.nrxq, nicinfo.ntxq);
		vty_out(vty, "\t%s %u Mbps %s %s\n", nicinfo.link_status ? "UP" : "DOWN",
			nicinfo.link_speed, nicinfo.link_duplex ? "full-duplex" : "half-duplex",
			nicinfo.link_autoneg ? "auto-nego" : "fixed-nego");
		vty_out(vty, "\taddr %s %s %s\n", nicinfo.addr, nicinfo.promisc ? "PROMISC" : "",
			get_port_flag_str(nicinfo.flags));
		vty_out(vty, "\tipackets %lu  ibytes %lu  ierrors %lu  imissed %lu  rx_nombuf %lu\n", nicstat.ipackets,
			nicstat.ibytes, nicstat.ierrors, nicstat.imissed, nicstat.rx_nombuf);
		vty_out(vty, "\topackets %lu  obytes %lu  oerrors %lu\n", nicstat.opackets, nicstat.obytes, nicstat.oerrors);
		vty_out(vty, "\tmbuf-avail %u  mbuf-inuse %u\n\n", mbufstat.available, mbufstat.inuse);
	}
	
	return CMD_SUCCESS;
}

DEFUN(show_ospf_if,
	ospf_if_show_cmd,
	"show ospf interface",
	SHOW_STR
	"OSPF\n"
	"Interfaces for ospf\n")
{
	system("ifconfig -a");
	return CMD_SUCCESS;
}

DEFUN(ip_addr,
	ip_addr_cmd,
	"ip addr A.B.C.D/M dev (dpdk0.kni|dpdk1.kni)",
	"IP protocol\n"
	"IP address\n"
	"IP address with mask length\n"
	"Device name for ip address configure(For ospf)\n"
	"Interface dpdk0.kni\n"
	"Interface dpdk1.kni\n")
{
	char cmd[64] = {0};
	sprintf(cmd, "ip addr add %s dev %s", argv[0], argv[1]);
	system(cmd);
	return CMD_SUCCESS;
}

DEFUN(no_ip_addr,
	no_ip_addr_cmd,
	"no ip addr A.B.C.D/M dev (dpdk0.kni|dpdk1.kni)",
	NO_STR
	"IP protocol\n"
	"IP address\n"
	"IP address with mask length\n"
	"Device name for ip address configure(For ospf)\n"
	"Interface dpdk0.kni\n"
	"Interface dpdk1.kni\n")
{
	char cmd[64] = {0};
	sprintf(cmd, "ip addr del %s dev %s", argv[0], argv[1]);
	system(cmd);
	return CMD_SUCCESS;
}

void nsh_init_cmd(void)
{
	init_nat_serv();
	install_element (ENABLE_NODE, &vtysh_save_config_cmd);
  	install_element (CONFIG_NODE, &vtysh_save_config_cmd);
	install_element (ENABLE_NODE, &vtysh_show_run_cmd);
	install_element (ENABLE_NODE, &vtysh_show_conf_cmd);
	/* "end" command. */
	install_element (CONFIG_NODE, &vtysh_end_all_cmd);
	install_element (ENABLE_NODE, &vtysh_end_all_cmd);
	install_element (VTY_NODE, &vtysh_end_all_cmd);

	install_element (ENABLE_NODE, &diagnose_cmd);
	install_element (ENABLE_NODE, &test_cmd);

	install_default (POOL_NODE);
	install_default (NAT_SERVICE_NODE);

	install_element (CONFIG_NODE, &nat_ifconf_cmd);
	install_element (CONFIG_NODE, &nat_service_add_cmd);
	install_element (CONFIG_NODE, &nat_service_del_cmd);
	install_element (NAT_SERVICE_NODE, &nat_dest_cmd);
	install_element (NAT_SERVICE_NODE, &nat_dest_pool_cmd);
	install_element (NAT_SERVICE_NODE, &no_nat_dest_cmd);
	install_element (NAT_SERVICE_NODE, &no_nat_dest_pool_cmd);
	install_element (ENABLE_NODE, &nat_service_show_cmd);
	install_element (ENABLE_NODE, &nat_pool_show_cmd);
	install_element (CONFIG_NODE, &local_ip_cmd);
	install_element (CONFIG_NODE, &route_via_cmd);
	install_element (CONFIG_NODE, &route_dev_cmd);
	install_element (CONFIG_NODE, &pool_cmd);
	install_element (CONFIG_NODE, &no_local_ip_cmd);
	install_element (CONFIG_NODE, &no_route_via_cmd);
	install_element (CONFIG_NODE, &no_route_dev_cmd);
	install_element (CONFIG_NODE, &no_pool_cmd);
	install_element (ENABLE_NODE, &show_local_ip_cmd);
	install_element (ENABLE_NODE, &show_ip_route_cmd);
	install_element (POOL_NODE, &member_cmd);
	install_element (POOL_NODE, &member_range_cmd);
	install_element (POOL_NODE, &no_member_cmd);
	install_element (POOL_NODE, &no_member_range_cmd);
	
	/* show stats */
	install_element (ENABLE_NODE, &nat_link_show_cmd);
	install_element (ENABLE_NODE, &startup_cmd);
	install_element (ENABLE_NODE, &load_config_cmd);
	install_element (ENABLE_NODE, &stop_cmd);

	/* ospf interface configure */
	install_element (CONFIG_NODE, &ip_addr_cmd);
	install_element (CONFIG_NODE, &no_ip_addr_cmd);
	install_element (ENABLE_NODE, &ospf_if_show_cmd);
}

