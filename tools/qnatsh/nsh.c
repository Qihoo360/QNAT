/* Virtual terminal interface shell.
 * Copyright (C) 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "command.h"
#include "memory.h"
#include "nsh.h"
#include "log.h"
#include "msg.h"
#define MTYPE_TMP 1

/* Struct VTY. */
struct vty *vty;

/* VTY shell pager name. */
char *vtysh_pager_name = NULL;

/* VTY shell client structure. */
struct vtysh_client
{
  int fd;
  char path[128];
} vtysh_client[] =
{
  { .fd = -1, .path = APP_MAIN_PATH},
};

/* We need direct access to ripd to implement vtysh_exit_ripd_only. */
static struct vtysh_client *ripd_client = NULL;
 

/* Using integrated config from Quagga.conf. Default is no. */
int vtysh_writeconfig_integrated = 0;

extern char config_default[];

/* Execute command in child process. */
int
execute_command (const char *command, int argc, const char *arg1,
		 const char *arg2, const char *arg3, const char *arg4)
{
  int ret;
  pid_t pid;
  int status;

	if (argc > 4)
		return system(command);
	
  /* Call fork(). */
  pid = fork ();

  if (pid < 0)
    {
      /* Failure of fork(). */
      fprintf (stderr, "Can't fork: %s\n", safe_strerror (errno));
      exit (1);
    }
  else if (pid == 0)
    {
      /* This is child process. */
      switch (argc)
	{
	case 0:
	  ret = execlp (command, command, (const char *)NULL);
	  break;
	case 1:
	  ret = execlp (command, command, arg1, (const char *)NULL);
	  break;
	case 2:
	  ret = execlp (command, command, arg1, arg2, (const char *)NULL);
	case 3:
	  ret = execlp (command, command, arg1, arg2, arg3, (const char *)NULL);
	  break;
	case 4:
	  ret = execlp (command, command, arg1, arg2, arg3, arg4, (const char *)NULL);
	  break;
	}

      /* When execlp suceed, this part is not executed. */
      fprintf (stderr, "Can't execute %s: %s\n", command, safe_strerror (errno));
      exit (1);
    }
  else
    {
      /* This is parent. */
      execute_flag = 1;
      ret = wait4 (pid, &status, 0, NULL);
      execute_flag = 0;
    }
  return 0;
}

static void
vclient_close (struct vtysh_client *vclient)
{
  if (vclient->fd >= 0)
    {
      close (vclient->fd);
      vclient->fd = -1;
    }
}

/* Following filled with debug code to trace a problematic condition
 * under load - it SHOULD handle it. */
#define ERR_WHERE_STRING "vtysh(): vtysh_client_config(): "
static int
vtysh_client_config (struct vtysh_client *vclient, char *line)
{
  int ret;
  char *buf;
  size_t bufsz;
  char *pbuf;
  size_t left;
  char *eoln;
  int nbytes;
  int i;
  int readln;

  if (vclient->fd < 0)
    return CMD_SUCCESS;

  ret = write (vclient->fd, line, strlen (line) + 1);
  if (ret <= 0)
    {
      vclient_close (vclient);
      return CMD_SUCCESS;
    }
	
  /* Allow enough room for buffer to read more than a few pages from socket. */
  bufsz = 5 * getpagesize() + 1;
  buf = XMALLOC(MTYPE_TMP, bufsz);
  memset(buf, 0, bufsz);
  pbuf = buf;

  while (1)
    {
      if (pbuf >= ((buf + bufsz) -1))
	{
	  fprintf (stderr, ERR_WHERE_STRING \
		   "warning - pbuf beyond buffer end.\n");
	  return CMD_WARNING;
	}

      readln = (buf + bufsz) - pbuf - 1;
      nbytes = read (vclient->fd, pbuf, readln);

      if (nbytes <= 0)
	{

	  if (errno == EINTR)
	    continue;

	  fprintf(stderr, ERR_WHERE_STRING "(%u)", errno);
	  perror("");

	  if (errno == EAGAIN || errno == EIO)
	    continue;

	  vclient_close (vclient);
	  XFREE(MTYPE_TMP, buf);
	  return CMD_SUCCESS;
	}

      pbuf[nbytes] = '\0';

      if (nbytes >= 4)
	{
	  i = nbytes - 4;
	  if (pbuf[i] == '\0' && pbuf[i + 1] == '\0' && pbuf[i + 2] == '\0')
	    {
	      ret = pbuf[i + 3];
	      break;
	    }
	}
      pbuf += nbytes;

      /* See if a line exists in buffer, if so parse and consume it, and
       * reset read position. */
      if ((eoln = strrchr(buf, '\n')) == NULL)
	continue;

      if (eoln >= ((buf + bufsz) - 1))
	{
	  fprintf (stderr, ERR_WHERE_STRING \
		   "warning - eoln beyond buffer end.\n");
	}
      vtysh_config_parse(buf);

      eoln++;
      left = (size_t)(buf + bufsz - eoln);
      memmove(buf, eoln, left);
      buf[bufsz-1] = '\0';
      pbuf = buf + strlen(buf);
    }

  /* Parse anything left in the buffer. */

  vtysh_config_parse (buf);

  XFREE(MTYPE_TMP, buf);
  return ret;
}

static int
vtysh_client_execute (struct vtysh_client *vclient, const char *line, FILE *fp)
{
  int ret;
  char buf[1001];
  int nbytes;
  int i; 
  int numnulls = 0;

  if (vclient->fd < 0)
    return CMD_SUCCESS;

  ret = write (vclient->fd, line, strlen (line) + 1);
  if (ret <= 0)
    {
      vclient_close (vclient);
      return CMD_SUCCESS;
    }
	
  while (1)
    {
      nbytes = read (vclient->fd, buf, sizeof(buf)-1);

      if (nbytes <= 0 && errno != EINTR)
	{
	  vclient_close (vclient);
	  return CMD_SUCCESS;
	}

      if (nbytes > 0)
	{
	  if ((numnulls == 3) && (nbytes == 1))
	    return buf[0];

	  buf[nbytes] = '\0';
	  fputs (buf, fp);
	  fflush (fp);
	  
	  /* check for trailling \0\0\0<ret code>, 
	   * even if split across reads 
	   * (see lib/vty.c::vtysh_read)
	   */
          if (nbytes >= 4) 
            {
              i = nbytes-4;
              numnulls = 0;
            }
          else
            i = 0;
          
          while (i < nbytes && numnulls < 3)
            {
              if (buf[i++] == '\0')
                numnulls++;
              else
                numnulls = 0;
            }

          /* got 3 or more trailing NULs? */
          if ((numnulls >= 3) && (i < nbytes))
            return (buf[nbytes-1]);
	}
    }
}

void
vtysh_exit_ripd_only (void)
{
  if (ripd_client)
    vtysh_client_execute (ripd_client, "exit", stdout);
}


void
vtysh_pager_init (void)
{
  char *pager_defined;

  pager_defined = getenv ("VTYSH_PAGER");

  if (pager_defined)
    vtysh_pager_name = strdup (pager_defined);
  else
    vtysh_pager_name = strdup ("more");
}

void set_hostname(void)
{
	char cmd[64] = {0};

	if(host.name)
	{
		sprintf(cmd, "echo '%s' > %s", host.name, HOSTNAME_PATH);
		execute_command(cmd, 5, NULL, NULL, NULL, NULL);
	}
}

extern char *dia_passwd;

/* Command execution over the vty interface. */
static int
vtysh_execute_func (const char *line, int pager)
{
  int ret, cmd_stat;
  u_int i;
  vector vline;
  struct cmd_element *cmd;
  FILE *fp = NULL;
  char *input_pwd;
  char tmp[24] = {0};
  int closepager = 0;
  int tried = 0;
  int saved_ret, saved_node;

	if(vty->node == AUTH_NODE)
	{
		vty->node = ENABLE_NODE;
		strncpy(tmp, line, strlen(line));
		input_pwd = tmp;
		if(strcmp(dia_passwd, input_pwd))
		{
			fprintf(stdout, "diagnose password error!%s", VTY_NEWLINE);
		}
		else
		{
			execute_command ("/bin/bash", 0, NULL, NULL, NULL, NULL);
		}
		return 0;
	}
	else if(vty->node == TEST_AUTH_NODE)
	{
		vty->node = ENABLE_NODE;
		if( strcmp("ntops.nat.test",line))
		{
			fprintf(stdout, "test password error!%s", VTY_NEWLINE);
		}
		else
		{
			vty->node = TEST_NODE;
		}
		return 0;
	}
  /* Split readline string up into the vector. */
  vline = cmd_make_strvec (line);

  if (vline == NULL)
    return CMD_SUCCESS;

  saved_ret = ret = cmd_execute_command (vline, vty, &cmd, 1);
  saved_node = vty->node;

  /* If command doesn't succeeded in current node, try to walk up in node tree.
   * Changing vty->node is enough to try it just out without actual walkup in
   * the vtysh. */
  while (ret != CMD_SUCCESS && ret != CMD_SUCCESS_DAEMON && ret != CMD_WARNING
	 && vty->node > CONFIG_NODE)
    {
      vty->node = node_parent(vty->node);
      ret = cmd_execute_command (vline, vty, &cmd, 1);
      tried++;
    }

  vty->node = saved_node;

  /* If command succeeded in any other node than current (tried > 0) we have
   * to move into node in the vtysh where it succeeded. */
  if (ret == CMD_SUCCESS || ret == CMD_SUCCESS_DAEMON || ret == CMD_WARNING)
    {
      if ((saved_node == BGP_VPNV4_NODE || saved_node == BGP_IPV4_NODE
	   || saved_node == BGP_IPV6_NODE || saved_node == BGP_IPV4M_NODE
	   || saved_node == BGP_IPV6M_NODE)
	  && (tried == 1))
	{
	  vtysh_execute("exit-address-family");
	}
      else if ((saved_node == KEYCHAIN_KEY_NODE) && (tried == 1))
	{
	  vtysh_execute("exit");
	}
      else if (tried)
	{
	  vtysh_execute ("end");
	  vtysh_execute ("configure terminal");
	}
    }
  /* If command didn't succeed in any node, continue with return value from
   * first try. */
  else if (tried)
    {
      ret = saved_ret;
    }

  cmd_free_strvec (vline);

	if((vty->node == CONFIG_NODE) && (line[0] == 'h') && (ret == 0))
	{
		set_hostname();
	}

  cmd_stat = ret;
  switch (ret)
    {
    case CMD_WARNING:
      if (vty->type == VTY_FILE)
	fprintf (stdout,"Warning...\n");
      break;
    case CMD_ERR_AMBIGUOUS:
      fprintf (stdout,"%% Ambiguous command.\n");
      break;
    case CMD_ERR_NO_MATCH:
      fprintf (stdout,"%% Unknown command.\n");
      break;
    case CMD_ERR_INCOMPLETE:
      fprintf (stdout,"%% Command incomplete.\n");
      break;
    case CMD_SUCCESS_DAEMON:
      {
	/* FIXME: Don't open pager for exit commands. popen() causes problems
	 * if exited from vtysh at all. This hack shouldn't cause any problem
	 * but is really ugly. */
	if (pager && vtysh_pager_name && (strncmp(line, "exit", 4) != 0))
	  {
	    fp = popen (vtysh_pager_name, "w");
	    if (fp == NULL)
	      {
		perror ("popen failed for pager");
		fp = stdout;
	      }
	    else
	      closepager=1;
	  }
	else
	  fp = stdout;

	if (! strcmp(cmd->string,"configure terminal"))
	  {
		cmd_stat = CMD_SUCCESS;
	    if (cmd_stat)
	      {
		line = "end";
		vline = cmd_make_strvec (line);

		if (vline == NULL)
		  {
		    if (pager && vtysh_pager_name && fp && closepager)
		      {
			if (pclose (fp) == -1)
			  {
			    perror ("pclose failed for pager");
			  }
			fp = NULL;
		      }
		    return CMD_SUCCESS;
		  }

		ret = cmd_execute_command (vline, vty, &cmd, 1);
		cmd_free_strvec (vline);
		if (ret != CMD_SUCCESS_DAEMON)
		  break;
	      }
	    else
	      if (cmd->func)
		{
		  (*cmd->func) (cmd, vty, 0, NULL);
		  break;
		}
	  }

	cmd_stat = CMD_SUCCESS;
	if (cmd_stat != CMD_SUCCESS)
	  break;

	if (cmd->func)
	  (*cmd->func) (cmd, vty, 0, NULL);
      }
    }
  if (pager && vtysh_pager_name && fp && closepager)
    {
      if (pclose (fp) == -1)
	{
	  perror ("pclose failed for pager");
	}
      fp = NULL;
    }
  return cmd_stat;
}

int
vtysh_execute_no_pager (const char *line)
{
  return vtysh_execute_func (line, 0);
}

int
vtysh_execute (const char *line)
{
  return vtysh_execute_func (line, 1);
}

/* Configration make from file. */
int
vtysh_config_from_file (struct vty *vty, FILE *fp)
{
  int ret;
  vector vline;
  struct cmd_element *cmd;

  while (fgets (vty->buf, VTY_BUFSIZ, fp))
    {
      if (vty->buf[0] == '!' || vty->buf[1] == '#')
	continue;

      vline = cmd_make_strvec (vty->buf);

      /* In case of comment line. */
      if (vline == NULL)
	continue;

      /* Execute configuration command : this is strict match. */
      ret = cmd_execute_command_strict (vline, vty, &cmd);

      /* Try again with setting node to CONFIG_NODE. */
      if (ret != CMD_SUCCESS 
	  && ret != CMD_SUCCESS_DAEMON
	  && ret != CMD_WARNING)
	{
	  if (vty->node == KEYCHAIN_KEY_NODE)
	    {
	      vty->node = KEYCHAIN_NODE;
	      vtysh_exit_ripd_only ();
	      ret = cmd_execute_command_strict (vline, vty, &cmd);

	      if (ret != CMD_SUCCESS 
		  && ret != CMD_SUCCESS_DAEMON 
		  && ret != CMD_WARNING)
		{
		  vtysh_exit_ripd_only ();
		  vty->node = CONFIG_NODE;
		  ret = cmd_execute_command_strict (vline, vty, &cmd);
		}
	    }
	  else
	    {
	      vtysh_execute ("end");
	      vtysh_execute ("configure terminal");
	      vty->node = CONFIG_NODE;
	      ret = cmd_execute_command_strict (vline, vty, &cmd);
	    }
	}	  

      cmd_free_strvec (vline);

      switch (ret)
	{
	case CMD_WARNING:
	  if (vty->type == VTY_FILE)
	    fprintf (stdout,"Warning...\n");
	  break;
	case CMD_ERR_AMBIGUOUS:
	  fprintf (stdout,"%% Ambiguous command.\n");
	  break;
	case CMD_ERR_NO_MATCH:
	  fprintf (stdout,"%% Unknown command: %s", vty->buf);
	  break;
	case CMD_ERR_INCOMPLETE:
	  fprintf (stdout,"%% Command incomplete.\n");
	  break;
	case CMD_SUCCESS_DAEMON:
	  {
	    u_int i;
	    int cmd_stat = CMD_SUCCESS;

	    for (i = 0; i < VTYSH_INDEX_MAX; i++)
	      {
		  {
		    cmd_stat = vtysh_client_execute (&vtysh_client[i],
						     vty->buf, stdout);
		    if (cmd_stat != CMD_SUCCESS)
		      break;
		  }
	      }
	    if (cmd_stat != CMD_SUCCESS)
	      break;

	    if (cmd->func)
	      (*cmd->func) (cmd, vty, 0, NULL);
	  }
	}
    }
  return CMD_SUCCESS;
}

/* We don't care about the point of the cursor when '?' is typed. */
int
vtysh_rl_describe (void)
{
  int ret;
  unsigned int i;
  vector vline;
  vector describe;
  int width;
  struct desc *desc;

  vline = cmd_make_strvec (rl_line_buffer);

  /* In case of '> ?'. */
  if (vline == NULL)
    {
      vline = vector_init (1);
      vector_set (vline, '\0');
    }
  else 
    if (rl_end && isspace ((int) rl_line_buffer[rl_end - 1]))
      vector_set (vline, '\0');

  describe = cmd_describe_command (vline, vty, &ret);

  fprintf (stdout,"\n");

  /* Ambiguous and no match error. */
  switch (ret)
    {
    case CMD_ERR_AMBIGUOUS:
      cmd_free_strvec (vline);
      fprintf (stdout,"%% Ambiguous command.\n");
      rl_on_new_line ();
      return 0;
      break;
    case CMD_ERR_NO_MATCH:
      cmd_free_strvec (vline);
      fprintf (stdout,"%% There is no matched command.\n");
      rl_on_new_line ();
      return 0;
      break;
    }  

  /* Get width of command string. */
  width = 0;
  for (i = 0; i < vector_active (describe); i++)
    if ((desc = vector_slot (describe, i)) != NULL)
      {
	int len;

	if (desc->cmd[0] == '\0')
	  continue;

	len = strlen (desc->cmd);
	if (desc->cmd[0] == '.')
	  len--;

	if (width < len)
	  width = len;
      }

  for (i = 0; i < vector_active (describe); i++)
    if ((desc = vector_slot (describe, i)) != NULL)
      {
	if (desc->cmd[0] == '\0')
	  continue;

	if ((desc->cmd[0] == '_') && (desc->cmd[1] == '_'))
	  continue;

	if (! desc->str)
	  fprintf (stdout,"  %-s\n",
		   desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd);
	else
	  fprintf (stdout,"  %-*s  %s\n",
		   width,
		   desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
		   desc->str);
      }

  cmd_free_strvec (vline);
  vector_free (describe);

  rl_on_new_line();

  return 0;
}

/* Result of cmd_complete_command() call will be stored here
 * and used in new_completion() in order to put the space in
 * correct places only. */
int complete_status;

static char *
command_generator (const char *text, int state)
{
  vector vline;
  static char **matched = NULL;
  static int index = 0;

  /* First call. */
  if (! state)
    {
      index = 0;

      if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
	return NULL;

      vline = cmd_make_strvec (rl_line_buffer);
      if (vline == NULL)
	return NULL;

      if (rl_end && isspace ((int) rl_line_buffer[rl_end - 1]))
	vector_set (vline, '\0');

      matched = cmd_complete_command (vline, vty, &complete_status);
    }

  if (matched && matched[index])
    return matched[index++];

  return NULL;
}

static char **
new_completion (char *text, int start, int end)
{
  char **matches;

  matches = rl_completion_matches (text, command_generator);

  if (matches)
    {
      rl_point = rl_end;
      if (complete_status == CMD_COMPLETE_FULL_MATCH)
	rl_pending_input = ' ';
    }

  return matches;
}

void show_completion_status(char **matches)
{
	int i = 0;
	printf("\nbuffer :%s, point:%d,end:%d,status:%d\n",&rl_line_buffer[0],rl_point,rl_end,complete_status);
	while(matches && matches[i])
	{
		printf("matches[%d] :%s     ",i,matches[i]);
		i++;
	}
	printf("\n");
}

int
vtysh_new_completion (void)
{
  	char **matches;
	int i;
  	int index = 0;
  	char *tmp_char;
	struct winsize size;
	int maxlen;

  	if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
    	return 0;

 	 matches = rl_completion_matches (rl_line_buffer, (rl_compentry_func_t *)command_generator);
//	 show_completion_status(matches);
	
  	if (matches)
    {
      	rl_point = rl_end;
    	if (complete_status == CMD_COMPLETE_FULL_MATCH)
		{
			int tmp_len;
			if((matches[index][0] == '_') && (matches[index][1] == '_'))
				return 0;

			rl_extend_line_buffer(256);
			tmp_char = strrchr(rl_line_buffer, ' ');
			if (tmp_char)
			{
				tmp_char ++;
				tmp_len = strlen(tmp_char);
//  				printf("\r\n%s%s", vtysh_prompt(),rl_line_buffer);
				strcat(rl_line_buffer, matches[0]+tmp_len);
				rl_point += strlen(matches[0]+tmp_len);
				rl_end = rl_point;
			}
			else
			{
//  				printf("\r\n%s%s", vtysh_prompt(),  rl_line_buffer);
				tmp_len = strlen(rl_line_buffer);
				strcat(rl_line_buffer, matches[0]+tmp_len);
				rl_point += strlen(matches[0]+tmp_len);
				rl_end = rl_point;
			}
			strcat(rl_line_buffer, " ");
			rl_point++;
			rl_end++;
			
			return 0;
		}
		else if(complete_status == CMD_COMPLETE_MATCH)
		{
			if((matches[index][0] == '_') && (matches[index][1] == '_'))
				return 0;

			while(rl_point && (rl_line_buffer[rl_point] != ' '))
				rl_point--;
//			printf("\r\n%s%s", vtysh_prompt(),rl_line_buffer);
			if(rl_point)
			{
				strncpy(&rl_line_buffer[rl_point + 1], matches[0], strlen(matches[0]));
				rl_point += (strlen(matches[0]) + 1);
				rl_end = rl_point;
			}
			else
			{
				strncpy(rl_line_buffer, matches[0], strlen(matches[0]));
				rl_point += strlen(matches[0]);
				rl_end = rl_point;
			}

			return 0;
		}
		else
		{
			printf("\r\n");
			if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &size)<0)
			{
				perror("ioctl TIOCGWINSZ error");
			}
			
			maxlen = 0;
			while(matches[index])
			{
				if (strlen(matches[index]) > maxlen)
					maxlen = strlen(matches[index]);
				index++;
			}
			

			index = 0;
			while(matches[index])
			{
				if (index)
				{
					if((matches[index][0] == '_') && (matches[index][1] == '_'))
					{
						index++;
						continue;
					}
					printf("%s", matches[index]);
					for(i = 0; i < maxlen + 2 - strlen(matches[index]); i++)
						printf("%s"," ");
					if (0 == index%((size.ws_col / (maxlen - 2 ? maxlen - 2 : 1)) ? (size.ws_col / (maxlen - 2 ? maxlen - 2 : 1)) : 1))
						printf("\r\n");
				}
				index++;
			}
  			printf("\r\n%s%s", vtysh_prompt(),  rl_line_buffer);
		}
    }
//    else
//   {
//		printf("\r\n");
//   }
  
//  printf("%s%s", vtysh_prompt(),  rl_line_buffer);

  return 0;
}

#if 0
/* This function is not actually being used. */
static char **
vtysh_completion (char *text, int start, int end)
{
  int ret;
  vector vline;
  char **matched = NULL;

  if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
    return NULL;

  vline = cmd_make_strvec (rl_line_buffer);
  if (vline == NULL)
    return NULL;

  /* In case of 'help \t'. */
  if (rl_end && isspace ((int) rl_line_buffer[rl_end - 1]))
    vector_set (vline, '\0');

  matched = cmd_complete_command (vline, vty, &ret);

  cmd_free_strvec (vline);

  return (char **) matched;
}
#endif

/* Vty node structures. */
static struct cmd_node bgp_node =
{
  BGP_NODE,
  "%s(config-router)# ",
};

static struct cmd_node rip_node =
{
  RIP_NODE,
  "%s(config-router)# ",
};

static struct cmd_node isis_node =
{
  ISIS_NODE,
  "%s(config-router)# ",
};

static struct cmd_node diagnose_auth_node =
{
	AUTH_NODE,
	"Password: ",
	0,
	NULL,
};

static struct cmd_node test_auth_node =
{
	TEST_AUTH_NODE,
	"Password: ",
	0,
	NULL,
};

static struct cmd_node test_node =
{
  TEST_NODE,
  "%s(test)# ",
};

static struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

static struct cmd_node nat_service_node =
{
  NAT_SERVICE_NODE,
  "%s(config-nat-service)# ",
  1
};

static struct cmd_node nat_pool_node =
{
  POOL_NODE,
  "%s(config-nat-pool)# ",
  1
};

static struct cmd_node rmap_node =
{
  RMAP_NODE,
  "%s(config-route-map)# "
};

static struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# "
};

static struct cmd_node bgp_vpnv4_node =
{
  BGP_VPNV4_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_ipv4_node =
{
  BGP_IPV4_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_ipv4m_node =
{
  BGP_IPV4M_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_ipv6_node =
{
  BGP_IPV6_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node bgp_ipv6m_node =
{
  BGP_IPV6M_NODE,
  "%s(config-router-af)# "
};

static struct cmd_node ospf_node =
{
  OSPF_NODE,
  "%s(config-router)# "
};

static struct cmd_node ripng_node =
{
  RIPNG_NODE,
  "%s(config-router)# "
};

static struct cmd_node ospf6_node =
{
  OSPF6_NODE,
  "%s(config-ospf6)# "
};

static struct cmd_node keychain_node =
{
  KEYCHAIN_NODE,
  "%s(config-keychain)# "
};

static struct cmd_node keychain_key_node =
{
  KEYCHAIN_KEY_NODE,
  "%s(config-keychain-key)# "
};

/* Defined in lib/vty.c */
extern struct cmd_node vty_node;

DEFUNSH (VTYSH_ALL,
	 vtysh_line_vty,
	 vtysh_line_vty_cmd,
	 "line vty",
	 "Configure a terminal line\n"
	 "Virtual terminal\n")
{
  vty->node = VTY_NODE;
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_enable, 
	 vtysh_enable_cmd,
	 "enable",
	 "Turn on privileged mode command\n")
{
  vty->node = ENABLE_NODE;
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_disable, 
	 vtysh_disable_cmd,
	 "disable",
	 "Turn off privileged mode command\n")
{
  if (vty->node == ENABLE_NODE)
    vty->node = VIEW_NODE;
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_config_terminal,
	 vtysh_config_terminal_cmd,
	 "configure terminal",
	 "Configuration from vty interface\n"
	 "Configuration terminal\n")
{
  vty->node = CONFIG_NODE;
  return CMD_SUCCESS;
}

int
vtysh_exit (struct vty *vty)
{
  switch (vty->node)
    {
    case VIEW_NODE:
    case ENABLE_NODE:
      exit (0);
      break;
    case CONFIG_NODE:
    case TEST_NODE:
      vty->node = ENABLE_NODE;
      break;
    case INTERFACE_NODE:
	case NAT_SERVICE_NODE:
	case POOL_NODE:
    case ZEBRA_NODE:
    case BGP_NODE:
    case RIP_NODE:
    case RIPNG_NODE:
    case OSPF_NODE:
    case OSPF6_NODE:
    case ISIS_NODE:
    case MASC_NODE:
    case RMAP_NODE:
    case VTY_NODE:
    case KEYCHAIN_NODE:
      vtysh_execute("end");
      vtysh_execute("configure terminal");
      vty->node = CONFIG_NODE;
      break;
    case BGP_VPNV4_NODE:
    case BGP_IPV4_NODE:
    case BGP_IPV4M_NODE:
    case BGP_IPV6_NODE:
    case BGP_IPV6M_NODE:
      vty->node = BGP_NODE;
      break;
    case KEYCHAIN_KEY_NODE:
      vty->node = KEYCHAIN_NODE;
      break;
    default:
      break;
    }
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_exit_all,
	 vtysh_exit_all_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

ALIAS (vtysh_exit_all,
       vtysh_quit_all_cmd,
       "quit",
       "Exit current mode and down to previous mode\n")

DEFUNSH (VTYSH_ZEBRA,
	 vtysh_exit_zebra,
	 vtysh_exit_zebra_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

ALIAS (vtysh_exit_zebra,
       vtysh_quit_zebra_cmd,
       "quit",
       "Exit current mode and down to previous mode\n")


DEFUNSH (VTYSH_ALL,
         vtysh_exit_line_vty,
         vtysh_exit_line_vty_cmd,
         "exit",
         "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

ALIAS (vtysh_exit_line_vty,
       vtysh_quit_line_vty_cmd,
       "quit",
       "Exit current mode and down to previous mode\n")

/* Memory */
DEFUN (vtysh_show_memory,
       vtysh_show_memory_cmd,
       "show memory",
       SHOW_STR
       "Memory statistics\n")
{
  unsigned int i;
  int ret = CMD_SUCCESS;
  char line[] = "show memory\n";
  
  for (i = 0; i < VTYSH_INDEX_MAX; i++)
    if ( vtysh_client[i].fd >= 0 )
      {
        ret = vtysh_client_execute (&vtysh_client[i], line, stdout);
        fprintf (stdout,"\n");
      }
  
  return ret;
}

/* Logging commands. */
DEFUN (vtysh_show_logging,
       vtysh_show_logging_cmd,
       "show logging",
       SHOW_STR
       "Show current logging configuration\n")
{
  unsigned int i;
  int ret = CMD_SUCCESS;
  char line[] = "show logging\n";
  
  for (i = 0; i < VTYSH_INDEX_MAX; i++)
    if ( vtysh_client[i].fd >= 0 )
      {
        ret = vtysh_client_execute (&vtysh_client[i], line, stdout);
        fprintf (stdout,"\n");
      }
  
  return ret;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_stdout,
	 vtysh_log_stdout_cmd,
	 "log stdout",
	 "Logging control\n"
	 "Set stdout logging level\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_stdout_level,
	 vtysh_log_stdout_level_cmd,
	 "log stdout "LOG_LEVELS,
	 "Logging control\n"
	 "Set stdout logging level\n"
	 LOG_LEVEL_DESC)
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_log_stdout,
	 no_vtysh_log_stdout_cmd,
	 "no log stdout [LEVEL]",
	 NO_STR
	 "Logging control\n"
	 "Cancel logging to stdout\n"
	 "Logging level\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_file,
	 vtysh_log_file_cmd,
	 "log file FILENAME",
	 "Logging control\n"
	 "Logging to file\n"
	 "Logging filename\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_file_level,
	 vtysh_log_file_level_cmd,
	 "log file FILENAME "LOG_LEVELS,
	 "Logging control\n"
	 "Logging to file\n"
	 "Logging filename\n"
	 LOG_LEVEL_DESC)
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_log_file,
	 no_vtysh_log_file_cmd,
	 "no log file [FILENAME]",
	 NO_STR
	 "Logging control\n"
	 "Cancel logging to file\n"
	 "Logging file name\n")
{
  return CMD_SUCCESS;
}

ALIAS_SH (VTYSH_ALL,
	  no_vtysh_log_file,
	  no_vtysh_log_file_level_cmd,
	  "no log file FILENAME LEVEL",
	  NO_STR
	  "Logging control\n"
	  "Cancel logging to file\n"
	  "Logging file name\n"
	  "Logging level\n")

DEFUNSH (VTYSH_ALL,
	 vtysh_log_monitor,
	 vtysh_log_monitor_cmd,
	 "log monitor",
	 "Logging control\n"
	 "Set terminal line (monitor) logging level\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_monitor_level,
	 vtysh_log_monitor_level_cmd,
	 "log monitor "LOG_LEVELS,
	 "Logging control\n"
	 "Set terminal line (monitor) logging level\n"
	 LOG_LEVEL_DESC)
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_log_monitor,
	 no_vtysh_log_monitor_cmd,
	 "no log monitor [LEVEL]",
	 NO_STR
	 "Logging control\n"
	 "Disable terminal line (monitor) logging\n"
	 "Logging level\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_syslog,
	 vtysh_log_syslog_cmd,
	 "log syslog",
	 "Logging control\n"
	 "Set syslog logging level\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_syslog_level,
	 vtysh_log_syslog_level_cmd,
	 "log syslog "LOG_LEVELS,
	 "Logging control\n"
	 "Set syslog logging level\n"
	 LOG_LEVEL_DESC)
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_log_syslog,
	 no_vtysh_log_syslog_cmd,
	 "no log syslog [LEVEL]",
	 NO_STR
	 "Logging control\n"
	 "Cancel logging to syslog\n"
	 "Logging level\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_facility,
	 vtysh_log_facility_cmd,
	 "log facility "LOG_FACILITIES,
	 "Logging control\n"
	 "Facility parameter for syslog messages\n"
	 LOG_FACILITY_DESC)

{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_log_facility,
	 no_vtysh_log_facility_cmd,
	 "no log facility [FACILITY]",
	 NO_STR
	 "Logging control\n"
	 "Reset syslog facility to default (daemon)\n"
	 "Syslog facility\n")

{
  return CMD_SUCCESS;
}

DEFUNSH_DEPRECATED (VTYSH_ALL,
		    vtysh_log_trap,
		    vtysh_log_trap_cmd,
		    "log trap "LOG_LEVELS,
		    "Logging control\n"
		    "(Deprecated) Set logging level and default for all destinations\n"
		    LOG_LEVEL_DESC)

{
  return CMD_SUCCESS;
}

DEFUNSH_DEPRECATED (VTYSH_ALL,
		    no_vtysh_log_trap,
		    no_vtysh_log_trap_cmd,
		    "no log trap [LEVEL]",
		    NO_STR
		    "Logging control\n"
		    "Permit all logging information\n"
		    "Logging level\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_record_priority,
	 vtysh_log_record_priority_cmd,
	 "log record-priority",
	 "Logging control\n"
	 "Log the priority of the message within the message\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_log_record_priority,
	 no_vtysh_log_record_priority_cmd,
	 "no log record-priority",
	 NO_STR
	 "Logging control\n"
	 "Do not log the priority of the message within the message\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_log_timestamp_precision,
	 vtysh_log_timestamp_precision_cmd,
	 "log timestamp precision <0-6>",
	 "Logging control\n"
	 "Timestamp configuration\n"
	 "Set the timestamp precision\n"
	 "Number of subsecond digits\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_log_timestamp_precision,
	 no_vtysh_log_timestamp_precision_cmd,
	 "no log timestamp precision",
	 NO_STR
	 "Logging control\n"
	 "Timestamp configuration\n"
	 "Reset the timestamp precision to the default value of 0\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_service_password_encrypt,
	 vtysh_service_password_encrypt_cmd,
	 "service password-encryption",
	 "Set up miscellaneous service\n"
	 "Enable encrypted passwords\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_service_password_encrypt,
	 no_vtysh_service_password_encrypt_cmd,
	 "no service password-encryption",
	 NO_STR
	 "Set up miscellaneous service\n"
	 "Enable encrypted passwords\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_config_password,
	 vtysh_password_cmd,
	 "password (8|) WORD",
	 "Assign the terminal connection password\n"
	 "Specifies a HIDDEN password will follow\n"
	 "dummy string \n"
	 "The HIDDEN line password string\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_password_text,
	 vtysh_password_text_cmd,
	 "password LINE",
	 "Assign the terminal connection password\n"
	 "The UNENCRYPTED (cleartext) line password\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_config_enable_password,
	 vtysh_enable_password_cmd,
	 "enable password (8|) WORD",
	 "Modify enable password parameters\n"
	 "Assign the privileged level password\n"
	 "Specifies a HIDDEN password will follow\n"
	 "dummy string \n"
	 "The HIDDEN 'enable' password string\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_enable_password_text,
	 vtysh_enable_password_text_cmd,
	 "enable password LINE",
	 "Modify enable password parameters\n"
	 "Assign the privileged level password\n"
	 "The UNENCRYPTED (cleartext) 'enable' password\n")
{
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 no_vtysh_config_enable_password,
	 no_vtysh_enable_password_cmd,
	 "no enable password",
	 NO_STR
	 "Modify enable password parameters\n"
	 "Assign the privileged level password\n")
{
  return CMD_SUCCESS;
}

DEFUN (vtysh_write_terminal,
       vtysh_write_terminal_cmd,
       "write terminal",
       "Write running configuration to memory, network, or terminal\n"
       "Write to terminal\n")
{
  u_int i;
  int ret;
  char line[] = "write terminal\n";
  FILE *fp = NULL;

  if (vtysh_pager_name)
    {
      fp = popen (vtysh_pager_name, "w");
      if (fp == NULL)
	{
	  perror ("popen");
	  exit (1);
	}
    }
  else
    fp = stdout;

  vty_out (vty, "Building configuration...%s", VTY_NEWLINE);
  vty_out (vty, "%sCurrent configuration:%s", VTY_NEWLINE,
	   VTY_NEWLINE);
  vty_out (vty, "!%s", VTY_NEWLINE);

  for (i = 0; i < VTYSH_INDEX_MAX; i++)
    ret = vtysh_client_config (&vtysh_client[i], line);

  /* Integrate vtysh specific configuration. */
  vtysh_config_write ();

  vtysh_config_dump (fp);

  if (vtysh_pager_name && fp)
    {
      fflush (fp);
      if (pclose (fp) == -1)
	{
	  perror ("pclose");
	  exit (1);
	}
      fp = NULL;
    }

  vty_out (vty, "end%s", VTY_NEWLINE);
  
  return CMD_SUCCESS;
}

DEFUN (vtysh_integrated_config,
       vtysh_integrated_config_cmd,
       "service integrated-vtysh-config",
       "Set up miscellaneous service\n"
       "Write configuration into integrated file\n")
{
  vtysh_writeconfig_integrated = 1;
  return CMD_SUCCESS;
}

DEFUN (no_vtysh_integrated_config,
       no_vtysh_integrated_config_cmd,
       "no service integrated-vtysh-config",
       NO_STR
       "Set up miscellaneous service\n"
       "Write configuration into integrated file\n")
{
  vtysh_writeconfig_integrated = 0;
  return CMD_SUCCESS;
}

static int
write_config_integrated(void)
{
  u_int i;
  int ret;
  char line[] = "write terminal\n";
  FILE *fp;
  char *integrate_sav = NULL;

  integrate_sav = malloc (strlen (integrate_default) +
			  strlen (CONF_BACKUP_EXT) + 1);
  strcpy (integrate_sav, integrate_default);
  strcat (integrate_sav, CONF_BACKUP_EXT);

  fprintf (stdout,"Building Configuration...\n");

  /* Move current configuration file to backup config file. */
  unlink (integrate_sav);
  rename (integrate_default, integrate_sav);
  free (integrate_sav);
 
  fp = fopen (integrate_default, "w");
  if (fp == NULL)
    {
      fprintf (stdout,"%% Can't open configuration file %s.\n",
	       integrate_default);
      return CMD_SUCCESS;
    }

  for (i = 0; i < VTYSH_INDEX_MAX; i++)
    ret = vtysh_client_config (&vtysh_client[i], line);

  vtysh_config_dump (fp);

  fclose (fp);

  if (chmod (integrate_default, CONFIGFILE_MASK) != 0)
    {
      fprintf (stdout,"%% Can't chmod configuration file %s: %s (%d)\n", 
	integrate_default, safe_strerror(errno), errno);
      return CMD_WARNING;
    }

  fprintf(stdout,"Integrated configuration saved to %s\n",integrate_default);

  fprintf (stdout,"[OK]\n");

  return CMD_SUCCESS;
}

DEFUN (vtysh_write_memory,
       vtysh_write_memory_cmd,
       "write memory",
       "Write running configuration to memory, network, or terminal\n"
       "Write configuration to the file (same as write file)\n")
{
  int ret = CMD_SUCCESS;
  char line[] = "write memory\n";
  u_int i;
  
  /* If integrated Quagga.conf explicitely set. */
  if (vtysh_writeconfig_integrated)
    return write_config_integrated();

  fprintf (stdout,"Building Configuration...\n");
	  
  for (i = 0; i < VTYSH_INDEX_MAX; i++)
    ret = vtysh_client_execute (&vtysh_client[i], line, stdout);
  
  fprintf (stdout,"[OK]\n");

  return ret;
}

ALIAS (vtysh_write_memory,
       vtysh_copy_runningconfig_startupconfig_cmd,
       "copy running-config startup-config",  
       "Copy from one file to another\n"
       "Copy from current system configuration\n"
       "Copy to startup configuration\n")

ALIAS (vtysh_write_memory,
       vtysh_write_file_cmd,
       "write file",
       "Write running configuration to memory, network, or terminal\n"
       "Write configuration to the file (same as write memory)\n")

ALIAS (vtysh_write_memory,
       vtysh_write_cmd,
       "write",
       "Write running configuration to memory, network, or terminal\n")

ALIAS (vtysh_write_terminal,
       vtysh_show_running_config_cmd,
       "show running-config",
       SHOW_STR
       "Current operating configuration\n")

DEFUN (vtysh_terminal_length,
       vtysh_terminal_length_cmd,
       "terminal length <0-512>",
       "Set terminal line parameters\n"
       "Set number of lines on a screen\n"
       "Number of lines on screen (0 for no pausing)\n")
{
  int lines;
  char *endptr = NULL;
  char default_pager[10];

  lines = strtol (argv[0], &endptr, 10);
  if (lines < 0 || lines > 512 || *endptr != '\0')
    {
      vty_out (vty, "length is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (vtysh_pager_name)
    {
      free (vtysh_pager_name);
      vtysh_pager_name = NULL;
    }

  if (lines != 0)
    {
      snprintf(default_pager, 10, "more -%i", lines);
      vtysh_pager_name = strdup (default_pager);
    }

  return CMD_SUCCESS;
}

DEFUN (vtysh_terminal_no_length,
       vtysh_terminal_no_length_cmd,
       "terminal no length",
       "Set terminal line parameters\n"
       NO_STR
       "Set number of lines on a screen\n")
{
  if (vtysh_pager_name)
    {
      free (vtysh_pager_name);
      vtysh_pager_name = NULL;
    }

  vtysh_pager_init();
  return CMD_SUCCESS;
}

DEFUN (vtysh_show_daemons,
       vtysh_show_daemons_cmd,
       "show daemons",
       SHOW_STR
       "Show list of running daemons\n")
{
  u_int i;

  for (i = 0; i < VTYSH_INDEX_MAX; i++)
    if ( vtysh_client[i].fd >= 0 )
      vty_out(vty, " %s", vtysh_client[i].path);
  vty_out(vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (vtysh_ping,
       vtysh_ping_cmd,
       "ping WORD",
       "Send echo messages\n"
       "Ping destination address or hostname\n")
{
  execute_command ("ping", 1, argv[0], NULL, NULL, NULL);
  return CMD_SUCCESS;
}

ALIAS (vtysh_ping,
       vtysh_ping_ip_cmd,
       "ping ip WORD",
       "Send echo messages\n"
       "IP echo\n"
       "Ping destination address or hostname\n")

DEFUN (vtysh_traceroute,
       vtysh_traceroute_cmd,
       "traceroute WORD",
       "Trace route to destination\n"
       "Trace route to destination address or hostname\n")
{
  execute_command ("traceroute", 1, argv[0], NULL, NULL, NULL);
  return CMD_SUCCESS;
}

ALIAS (vtysh_traceroute,
       vtysh_traceroute_ip_cmd,
       "traceroute ip WORD",
       "Trace route to destination\n"
       "IP trace\n"
       "Trace route to destination address or hostname\n")

#ifdef HAVE_IPV6
DEFUN (vtysh_ping6,
       vtysh_ping6_cmd,
       "ping ipv6 WORD",
       "Send echo messages\n"
       "IPv6 echo\n"
       "Ping destination address or hostname\n")
{
  execute_command ("ping6", 1, argv[0], NULL, NULL, NULL);
  return CMD_SUCCESS;
}

DEFUN (vtysh_traceroute6,
       vtysh_traceroute6_cmd,
       "traceroute ipv6 WORD",
       "Trace route to destination\n"
       "IPv6 trace\n"
       "Trace route to destination address or hostname\n")
{
  execute_command ("traceroute6", 1, argv[0], NULL, NULL, NULL);
  return CMD_SUCCESS;
}
#endif

DEFUN (vtysh_telnet,
       vtysh_telnet_cmd,
       "telnet WORD",
       "Open a telnet connection\n"
       "IP address or hostname of a remote system\n")
{
  execute_command ("telnet", 1, argv[0], NULL, NULL, NULL);
  return CMD_SUCCESS;
}

DEFUN (vtysh_telnet_port,
       vtysh_telnet_port_cmd,
       "telnet WORD PORT",
       "Open a telnet connection\n"
       "IP address or hostname of a remote system\n"
       "TCP Port number\n")
{
  execute_command ("telnet", 2, argv[0], argv[1], NULL, NULL);
  return CMD_SUCCESS;
}

int ssh_address_allowed(char *addr_str)
{
    int ret = 1;
    char *addr = NULL;

    if((addr = strstr(addr_str, "@")) == NULL)
    {
        return 0;
    }
    if (addr)
    {
        addr = addr_str;
        if((addr[0] == 'r') && (addr[1] == 'o') && (addr[2] == 'o') && (addr[3] == 't') && (addr[4] == '@'))
            ret = 0;
    }
    return ret;
}

DEFUN (vtysh_ssh,
       vtysh_ssh_cmd,
       "ssh WORD",
       "Open an ssh connection\n"
       "[user@]host\n")
{
  if (!ssh_address_allowed((char *)argv[0])) {
    fprintf(stdout, "Access is not allowed!\n");
    return CMD_SUCCESS;
  }
  execute_command ("ssh", 1, argv[0], NULL, NULL, NULL);
  return CMD_SUCCESS;
}

DEFUN (vtysh_start_shell,
       vtysh_start_shell_cmd,
       "start-shell",
       "Start UNIX shell\n")
{
  execute_command ("sh", 0, NULL, NULL, NULL, NULL);
  return CMD_SUCCESS;
}

DEFUN (vtysh_start_bash,
       vtysh_start_bash_cmd,
       "start-shell bash",
       "Start UNIX shell\n"
       "Start bash\n")
{
  execute_command ("bash", 0, NULL, NULL, NULL, NULL);
  return CMD_SUCCESS;
}

DEFUN (vtysh_start_zsh,
       vtysh_start_zsh_cmd,
       "start-shell zsh",
       "Start UNIX shell\n"
       "Start Z shell\n")
{
  execute_command ("zsh", 0, NULL, NULL, NULL, NULL);
  return CMD_SUCCESS;
}

static void
vtysh_install_default (enum node_type node)
{
  install_element (node, &config_list_cmd);
}

/* Making connection to protocol daemon. */
	int
vtysh_connect (struct vtysh_client *vclient, char *path)
{
	int ret;
	int sock, len;
	struct sockaddr_un addr;
	struct stat s_stat;
	uid_t euid;
	gid_t egid;

	memset (vclient, 0, sizeof (struct vtysh_client));
	strncpy(vclient->path,path ,123);
	vclient->fd = -1;

	/* Stat socket to see if we have permission to access it. */
	euid = geteuid();
	egid = getegid();
	ret = stat (path, &s_stat);
	if (ret < 0 && errno != ENOENT)
	{
		fprintf  (stderr, "vtysh_connect(%s): stat = %s\n", 
				path, strerror(errno)); 
		exit(1);
	}

	if (ret >= 0)
	{
		if (! S_ISSOCK(s_stat.st_mode))
		{
			fprintf (stderr, "vtysh_connect(%s): Not a socket\n",
					path);
			exit (1);
		}

		if (euid != s_stat.st_uid 
				|| !(s_stat.st_mode & S_IWUSR)
				|| !(s_stat.st_mode & S_IRUSR))
		{
			fprintf (stderr, "vtysh_connect(%s): No permission to access socket\n",
					path);
			exit (1);
		}
	}

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
#ifdef DEBUG
		fprintf(stderr, "vtysh_connect(%s): socket = %s\n", path, strerror(errno));
#endif /* DEBUG */
		return -1;
	}

	memset (&addr, 0, sizeof (struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, path, strlen (path));
#ifdef HAVE_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof (addr.sun_family) + strlen (addr.sun_path);
#endif /* HAVE_SUN_LEN */

	ret = connect (sock, (struct sockaddr *) &addr, len);
	if (ret < 0)
	{
#ifdef DEBUG
		fprintf(stderr, "vtysh_connect(%s): connect = %s\n", path, strerror(errno));
#endif /* DEBUG */
		close (sock);
		return -1;
	}
	vclient->fd = sock;
	struct timeval timeout = {180,0}; 
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));	
		return 0;

	return 0;
}

int
vtysh_connect_all()
{
//  vtysh_connect (&vtysh_client[VTYSH_INDEX_APP], APP_MAIN_PATH);
  return 0;
}


#define OAM_MAX_DATA_LEN    102400

int user_connect(struct vtysh_client *vclient, char *path)
{
	int ret;
	int sock, len;
	struct sockaddr_un addr;
	struct stat s_stat;
	uid_t euid;
	gid_t egid;

	//memset (vclient, 0, sizeof (struct vtysh_client));
	strncpy(vclient->path,path ,123);
	vclient->fd = -1;

	/* Stat socket to see if we have permission to access it. */
	euid = geteuid();
	egid = getegid();
	ret = stat (path, &s_stat);
	if (ret < 0 && errno != ENOENT)
	{
		fprintf  (stderr, "vtysh_connect(%s): stat = %s\n", 
				path, strerror(errno)); 
		exit(1);
	}

	if (ret >= 0)
	{
		if (! S_ISSOCK(s_stat.st_mode))
		{
			fprintf (stderr, "vtysh_connect(%s): Not a socket\n",
					path);
			exit (1);
		}

		if (euid != s_stat.st_uid 
				|| !(s_stat.st_mode & S_IWUSR)
				|| !(s_stat.st_mode & S_IRUSR))
		{
			fprintf (stderr, "vtysh_connect(%s): No permission to access socket\n",
					path);
			exit (1);
		}
	}

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
#ifdef DEBUG
		fprintf(stderr, "vtysh_connect(%s): socket = %s\n", path, strerror(errno));
#endif /* DEBUG */
		return -1;
	}

	memset (&addr, 0, sizeof (struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, path, strlen (path));
#ifdef HAVE_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof (addr.sun_family) + strlen (addr.sun_path);
#endif /* HAVE_SUN_LEN */

	ret = connect (sock, (struct sockaddr *) &addr, len);
	if (ret < 0)
	{
#ifdef DEBUG
		fprintf(stderr, "vtysh_connect(%s): connect = %s\n", path, strerror(errno));
#endif /* DEBUG */
		close (sock);
		return -1;
	}
	vclient->fd = sock;
	struct timeval timeout = {180,0}; 
		setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));	
		return 0;

	return 0;
}

int user_request_set( struct vtysh_client  * client,int type, char * buff, int datalen, int bufferlen, int flags)
{
	int rsize = 0;
	struct 
	{
		struct nsh_sock_msg oh;
		char buf[OAM_MAX_DATA_LEN];
	}  cmd;

	if(bufferlen < datalen)
	{
		printf("uipc  message response buffer len %d  must	be greater than request buffer len %d  type:%d\r\n",
					bufferlen,datalen,type);
		return -1;
	}
	if(bufferlen > OAM_MAX_DATA_LEN){
		printf("uipc  message len is too long! request:%d,limit:%d; type:%d\r\n",
					bufferlen,OAM_MAX_DATA_LEN,type);
		return -1;
	}

	memset(&cmd, 0, sizeof cmd);
	cmd.oh.version = 65536;
	cmd.oh.id = type;
	cmd.oh.type = REQ_SET;
	cmd.oh.len = bufferlen;

	if(buff)
		memcpy(cmd.buf, buff, bufferlen);

	if(write(client->fd, &cmd, 
			sizeof cmd - OAM_MAX_DATA_LEN + bufferlen) == -1 ){
		if (errno == EBADF 
			|| errno == EPIPE) {
			user_connect (client, client->path);
			if(write(client->fd, &cmd, 
					sizeof cmd - OAM_MAX_DATA_LEN + bufferlen) == -1){
				return 0;
			}
		}
		else{
			return 0;
		}
	}
	while (1)
	{
		int nbytes;
		struct nsh_sock_msg_reply cmd;

		memset(&cmd, 0, sizeof cmd);
		nbytes = read (client->fd, &cmd, sizeof(cmd));

		if (nbytes <= 0 && errno != EINTR)
		{
			return 0;
		}
		if (nbytes > 0)
		{

			if(cmd.len > 0){
				memcpy(buff,cmd.data,cmd.len);
			}
			
			if(cmd.errcode != 0) // keep  compatible
			{
				return cmd.errcode;
			}
			
			break;
		}
	}
	return 0;
}

int user_request_get( struct vtysh_client  * client,int type, char * buff, int datalen, int bufferlen, int flags)
{
	int rsize = 0;
	struct 
	{
		struct nsh_sock_msg oh;
		char buf[OAM_MAX_DATA_LEN];
	}  cmd;

	if(bufferlen < datalen)
	{
		printf("uipc  message response buffer len %d  must	be greater than request buffer len %d  type:%d\r\n",
					bufferlen,datalen,type);
		return -1;
	}
	if(bufferlen > OAM_MAX_DATA_LEN){
		printf("uipc  message len is too long! request:%d,limit:%d; type:%d\r\n",
					bufferlen,OAM_MAX_DATA_LEN,type);
		return -1;
	}

	memset(&cmd, 0, sizeof cmd);
	cmd.oh.version = 65536;
	cmd.oh.id = type;
	cmd.oh.type = REQ_GET;
	cmd.oh.len = bufferlen;

	if(buff)
		memcpy(cmd.buf, buff, bufferlen);

	if(write(client->fd, &cmd, 
			sizeof cmd - OAM_MAX_DATA_LEN + bufferlen) == -1 ){
		if (errno == EBADF 
			|| errno == EPIPE) {
			user_connect (client, client->path);
			if(write(client->fd, &cmd, 
					sizeof cmd - OAM_MAX_DATA_LEN + bufferlen) == -1){
				return 0;
			}
		}
		else{
			return 0;
		}
	}
	while (1)
	{
		int nbytes;
		struct nsh_sock_msg_reply cmd;
		char buf[OAM_MAX_DATA_LEN];

		memset(&cmd, 0, sizeof cmd);
		nbytes = read (client->fd, &cmd, sizeof(cmd));

		if (nbytes <= 0 && errno != EINTR)
		{
			return 0;
		}
		if (nbytes > 0)
		{

			if(cmd.len > 0){
				nbytes = read (client->fd, &buf, cmd.len);
				memcpy(buff, buf, cmd.len);
			}
			
			if(cmd.errcode != 0) // keep  compatible
			{
				return cmd.errcode;
			}
			
			break;
		}
	}
	
	return 0;
}

int nat_request_set(int cmd, char *buff, int datalen, int bufferlen, int flags)
{
	int ret = 0;
	user_connect (&vtysh_client[VTYSH_INDEX_APP], vtysh_client[VTYSH_INDEX_APP].path);
	ret = user_request_set(&vtysh_client[VTYSH_INDEX_APP], cmd, buff ,datalen, bufferlen, flags|OAM_FLAGS_RECONNECT);
	close(vtysh_client[VTYSH_INDEX_APP].fd);
	vtysh_client[VTYSH_INDEX_APP].fd = -1;
	return ret;
}

int nat_request_get(int cmd, char *buff, int datalen, int bufferlen, int flags)
{
	int ret = 0;
	user_connect (&vtysh_client[VTYSH_INDEX_APP], vtysh_client[VTYSH_INDEX_APP].path);
	ret = user_request_get(&vtysh_client[VTYSH_INDEX_APP], cmd, buff ,datalen, bufferlen, flags|OAM_FLAGS_RECONNECT);
	close(vtysh_client[VTYSH_INDEX_APP].fd);
	vtysh_client[VTYSH_INDEX_APP].fd = -1;
	return ret;
}

/* To disable readline's filename completion. */
static char *
vtysh_completion_entry_function (const char *ignore, int invoking_key)
{
  return NULL;
}

void
vtysh_readline_init (void)
{
  /* readline related settings. */
  rl_bind_key ('?', (Function *) vtysh_rl_describe);
  rl_completion_entry_function = vtysh_completion_entry_function;
//  rl_attempted_completion_function = (CPPFunction *)new_completion;
  /* do not append space after completion. It will be appended
   * in new_completion() function explicitly. */
   rl_bind_key ('\t', (Function *)vtysh_new_completion);
  rl_completion_append_character = '\0';
}

char *
vtysh_prompt (void)
{
  static struct utsname names;
  static char buf[100];
  const char*hostname;
  extern struct host host;

  hostname = host.name;

  if (!hostname)
    {
/*      if (!names.nodename[0])
	uname (&names);
      hostname = names.nodename;*/
      snprintf (buf, sizeof buf, cmd_prompt (vty->node), "nathost");
    }
  else
  	  snprintf (buf, sizeof buf, cmd_prompt (vty->node), hostname);

  return buf;
}

extern int nsh_pool_config_write(struct vty * vty);
extern int nsh_service_config_write(struct vty * vty);

void
vtysh_init_vty (void)
{
  /* Make vty structure. */
  vty = vty_new ();
  vty->type = VTY_SHELL;
  vty->node = ENABLE_NODE;

  /* Initialize commands. */
  cmd_init (0);

  /* Install nodes. */
  install_node (&interface_node, NULL);
  install_node (&zebra_node, NULL);
  install_node (&vty_node, NULL);
  install_node (&diagnose_auth_node, NULL);
  install_node (&test_auth_node, NULL);
  install_node (&test_node, NULL);
  install_node (&nat_service_node, nsh_service_config_write);
  install_node (&nat_pool_node, nsh_pool_config_write);

  vtysh_install_default (VIEW_NODE);
  vtysh_install_default (ENABLE_NODE);
  vtysh_install_default (CONFIG_NODE);
  vtysh_install_default (INTERFACE_NODE);
  vtysh_install_default (TEST_NODE);
  vtysh_install_default (ZEBRA_NODE);
  vtysh_install_default (VTY_NODE);

  install_element (VIEW_NODE, &vtysh_enable_cmd);
  install_element (ENABLE_NODE, &vtysh_config_terminal_cmd);
//  install_element (ENABLE_NODE, &vtysh_disable_cmd);

  /* "exit" command. */
  install_element (VIEW_NODE, &vtysh_exit_all_cmd);
//  install_element (VIEW_NODE, &vtysh_quit_all_cmd);
  install_element (CONFIG_NODE, &vtysh_exit_all_cmd);
  /* install_element (CONFIG_NODE, &vtysh_quit_all_cmd); */
  install_element (ENABLE_NODE, &vtysh_exit_all_cmd);
//  install_element (ENABLE_NODE, &vtysh_quit_all_cmd);
  install_element (VTY_NODE, &vtysh_exit_line_vty_cmd);
//  install_element (VTY_NODE, &vtysh_quit_line_vty_cmd);

//  install_element (CONFIG_NODE, &vtysh_line_vty_cmd);
//  install_element (ENABLE_NODE, &vtysh_show_running_config_cmd);
//  install_element (ENABLE_NODE, &vtysh_copy_runningconfig_startupconfig_cmd);
//  install_element (ENABLE_NODE, &vtysh_write_file_cmd);
//  install_element (ENABLE_NODE, &vtysh_write_cmd);

  /* "write terminal" command. */
//  install_element (ENABLE_NODE, &vtysh_write_terminal_cmd);
 
//  install_element (CONFIG_NODE, &vtysh_integrated_config_cmd);
//  install_element (CONFIG_NODE, &no_vtysh_integrated_config_cmd);

  /* "write memory" command. */
//  install_element (ENABLE_NODE, &vtysh_write_memory_cmd);

//  install_element (VIEW_NODE, &vtysh_terminal_length_cmd);
//  install_element (ENABLE_NODE, &vtysh_terminal_length_cmd);
//  install_element (VIEW_NODE, &vtysh_terminal_no_length_cmd);
//  install_element (ENABLE_NODE, &vtysh_terminal_no_length_cmd);
//  install_element (VIEW_NODE, &vtysh_show_daemons_cmd);
//  install_element (ENABLE_NODE, &vtysh_show_daemons_cmd);

  install_element (VIEW_NODE, &vtysh_ping_cmd);
  install_element (VIEW_NODE, &vtysh_ping_ip_cmd);
  install_element (VIEW_NODE, &vtysh_traceroute_cmd);
  install_element (VIEW_NODE, &vtysh_traceroute_ip_cmd);
#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &vtysh_ping6_cmd);
  install_element (VIEW_NODE, &vtysh_traceroute6_cmd);
#endif
  install_element (VIEW_NODE, &vtysh_telnet_cmd);
  install_element (VIEW_NODE, &vtysh_telnet_port_cmd);
  install_element (VIEW_NODE, &vtysh_ssh_cmd);
  install_element (ENABLE_NODE, &vtysh_ping_cmd);
  install_element (ENABLE_NODE, &vtysh_ping_ip_cmd);
  install_element (ENABLE_NODE, &vtysh_traceroute_cmd);
  install_element (ENABLE_NODE, &vtysh_traceroute_ip_cmd);
#ifdef HAVE_IPV6
  install_element (ENABLE_NODE, &vtysh_ping6_cmd);
  install_element (ENABLE_NODE, &vtysh_traceroute6_cmd);
#endif
  install_element (ENABLE_NODE, &vtysh_telnet_cmd);
  install_element (ENABLE_NODE, &vtysh_telnet_port_cmd);
  install_element (ENABLE_NODE, &vtysh_ssh_cmd);
//  install_element (ENABLE_NODE, &vtysh_start_shell_cmd);
//  install_element (ENABLE_NODE, &vtysh_start_bash_cmd);
//  install_element (ENABLE_NODE, &vtysh_start_zsh_cmd);
  
//  install_element (VIEW_NODE, &vtysh_show_memory_cmd);
//  install_element (ENABLE_NODE, &vtysh_show_memory_cmd);

  /* Logging 
  install_element (ENABLE_NODE, &vtysh_show_logging_cmd);
  install_element (VIEW_NODE, &vtysh_show_logging_cmd);
  install_element (CONFIG_NODE, &vtysh_log_stdout_cmd);
  install_element (CONFIG_NODE, &vtysh_log_stdout_level_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_stdout_cmd);
  install_element (CONFIG_NODE, &vtysh_log_file_cmd);
  install_element (CONFIG_NODE, &vtysh_log_file_level_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_file_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_file_level_cmd);
  install_element (CONFIG_NODE, &vtysh_log_monitor_cmd);
  install_element (CONFIG_NODE, &vtysh_log_monitor_level_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_monitor_cmd);
  install_element (CONFIG_NODE, &vtysh_log_syslog_cmd);
  install_element (CONFIG_NODE, &vtysh_log_syslog_level_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_syslog_cmd);
  install_element (CONFIG_NODE, &vtysh_log_trap_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_trap_cmd);
  install_element (CONFIG_NODE, &vtysh_log_facility_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_facility_cmd);
  install_element (CONFIG_NODE, &vtysh_log_record_priority_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_record_priority_cmd);
  install_element (CONFIG_NODE, &vtysh_log_timestamp_precision_cmd);
  install_element (CONFIG_NODE, &no_vtysh_log_timestamp_precision_cmd);*/
/*
  install_element (CONFIG_NODE, &vtysh_service_password_encrypt_cmd);
  install_element (CONFIG_NODE, &no_vtysh_service_password_encrypt_cmd);

  install_element (CONFIG_NODE, &vtysh_password_cmd);
  install_element (CONFIG_NODE, &vtysh_password_text_cmd);
  install_element (CONFIG_NODE, &vtysh_enable_password_cmd);
  install_element (CONFIG_NODE, &vtysh_enable_password_text_cmd);
  install_element (CONFIG_NODE, &no_vtysh_enable_password_cmd);
*/

}
