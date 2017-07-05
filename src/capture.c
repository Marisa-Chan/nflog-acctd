/*
  nflog-acctd --- a network accounting daemon for Linux
  Copyright (C) 2002, 2003 Hilko Bengen (original ulog-acctd)
  Copyright (C) 2017 Iartsev Anton

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


  Packet capture module, Based on capture-linux.c from net-acctd
  
  $Id: capture.c,v 1.17 2003/08/22 16:52:30 bengen Exp $
*/

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "process.h"
#include "debug.h"
#include "config.h"
#include "daemon.h"
#include "capture.h"
#include "utils.h"

#include <unistd.h>
#include <malloc.h>
#include <sys/socket.h>
#include <asm/types.h>

#include <fcntl.h>

#include <syslog.h>

/* For parsing netlink headers */
#include <linux/netlink.h>

/* For parsing nflog packets */
#include <net/if.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>

struct nflog_handle *nful_h = NULL;
struct nflog_g_handle* nful_gh[CFG_MAX_GROUPS];
int nful_fd = -1;
size_t recvbufsiz = 0;
size_t nlbufsiz = 0;
size_t nlmaxbufsiz = 0;
unsigned char *nfulog_buf = NULL;

int nful_overrun_warned = 0;

extern struct statistics* stats;

unsigned char nullmac[8] = {0, 0, 0, 0, 0, 0, 0, 0};

static int setnlbufsiz(int size)
{
	if (size < nlmaxbufsiz) {
		nlbufsiz = nfnl_rcvbufsiz(nflog_nfnlh(nful_h), size);
		DEBUG(DBG_MISC, my_sprintf("NFLOG socket buffer size has been "
					"set to %d (%d requested)", nlbufsiz, size));
		return 1;
	}

	DEBUG(DBG_ERR, my_sprintf("Maximum buffer size (%d) in NFLOG has been "
				"reached. Please, consider rising "
				"`netlink_socket_buffer_size` and "
				"`netlink_socket_buffer_maxsize` "
				"clauses.: %m", nlbufsiz));
	return 0;
}

static int msg_cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *data)
{
  char indev[IF_NAMESIZE];
  char outdev[IF_NAMESIZE];
  char *payload;
  int payload_len = nflog_get_payload(nfa, &payload);

  uint32_t i_indev = nflog_get_indev(nfa);
  uint32_t i_outdev = nflog_get_outdev(nfa);

  char *prefix = nflog_get_prefix(nfa);

  struct nfulnl_msg_packet_hw *hw = nflog_get_packet_hw(nfa);

  indev[0] = ' ';
  indev[1] = 0;
  outdev[0] = ' ';
  outdev[1] = 0;

  if (i_indev)
    if_indextoname(i_indev, indev);

  if (i_outdev)
    if_indextoname(i_outdev, outdev);

  if (hw)
    register_packet((struct iphdr*) payload, 
			payload_len,
			indev, 
			outdev, 
			prefix,
			hw->hw_addrlen,
			hw->hw_addr);
  else
    register_packet((struct iphdr*) payload, 
			payload_len,
			indev, 
			outdev, 
			prefix,
			0,
			nullmac);
  return 0;
}

void init_capture()
{
  /* open nflog */
  nful_h = nflog_open();

  if (!nful_h)
    {
      DEBUG(DBG_ERR, my_sprintf("can't open nflog: %m"));
      daemon_stop(0);
    }
    
    
  /* bind to NFLOG target group */
  
  int i;
  for (i = 0; i < CFG_MAX_GROUPS; i++)
    {
      nful_gh[i] = NULL;
      
      if (cfg->mcast_group[i] >= 0)
        {
          nful_gh[i] = nflog_bind_group(nful_h, cfg->mcast_group[i]);
          if (!nful_gh[i]) 
            {
	      DEBUG(DBG_ERR, my_sprintf("can't bind to group %d: %m",cfg->mcast_group[i]));
            }

          nflog_set_mode(nful_gh[i], NFULNL_COPY_PACKET, 0xffff);
          nflog_callback_register(nful_gh[i], &msg_cb, NULL);
	}
    }

  /* Set receive buffer size if requested. */
  if (cfg->buffsz) 
    {
      recvbufsiz = cfg->buffsz;
    }
    else
    {
      recvbufsiz = NFLOG_BUFSIZE_DEFAULT;
    }
  
  nfulog_buf = malloc(recvbufsiz);
  
  nlmaxbufsiz = cfg->so_rcvbuf_max;
  
  if (cfg->so_rcvbuf)
    {
      setnlbufsiz(cfg->so_rcvbuf);
    }
  
  nful_fd = nflog_fd(nful_h);
  
  int flags;

  /* make FD nonblocking */
  flags = fcntl(nful_fd, F_GETFL);
  
  if (flags >= 0)
    {
      flags |= O_NONBLOCK;
      flags = fcntl(nful_fd, F_SETFL, flags);
    }
}

void exit_capture(void)
{
  nful_fd = -1;
  
  int i;
  for (i = 0; i < CFG_MAX_GROUPS; i++)
    {
      nful_gh[i] = NULL;
      
      if (nful_gh[i])
        {
	  nflog_unbind_group(nful_gh[i]);
          nful_gh[i] = NULL;
	}
    }
  
  if (nful_h)
    {
      nflog_close(nful_h);
      nful_h = NULL;
    }
  
  if (nfulog_buf)
    {
      free(nfulog_buf);
      nfulog_buf = NULL;
    }
}

void packet_loop()
{
  int ret;
  fd_set readfds;

  while (running)
    {
      /* process signals */
      if( sigflag_reopen_files )
	{
	  DEBUG(DBG_STATE, "re-opening accounting file");
	  close(acct_file);
	  acct_file = open(cfg->acct_file, O_WRONLY|O_CREAT|O_APPEND, 0666);
	  if(acct_file==-1)
	    {
	      syslog(LOG_ERR, "error opening accounting file: %m");
	      syslog(LOG_INFO, "net accounting daemon aborting");
	      exit(1);
	    }
	  if( dbg_file!=STDERR_FILENO )
	    {
	      DEBUG(DBG_STATE, "re-opening debug file");
	      close(dbg_file);
	      dbg_file = open(cfg->dbg_file, O_WRONLY|O_CREAT|O_APPEND, 0666);
	      if(dbg_file==-1)
		{
		  syslog(LOG_ERR, "error opening debug file: %m");
		  syslog(LOG_INFO, "net accounting daemon aborting");
		  exit(1);
		}
	    }

	  if (sigflag_reopen_files != 1)
	    {
	      DEBUG(DBG_ERR, my_sprintf("signal_reopen_files = %d.", 
					sigflag_reopen_files));
	    }
	  sigflag_reopen_files--;
	  sigflag_may_write = 1;
	}

      if( sigflag_write_log )
	{
	      if( write_log(0) == 0)
		{
	          if (sigflag_write_log != 1)
		    {
		       DEBUG(DBG_ERR, my_sprintf("signal_write_log = %d.", 
						 sigflag_write_log));
		    }
		  sigflag_write_log--;
	        }
	      else
	        {
		  DEBUG(DBG_ERR, "Could not write accounting data.");
	        }
	}

      if( sigflag_reread_config )
	{
	  DEBUG(DBG_STATE, "re-reading config");
	  exit_capture();
	  if(cfg) {
	    free(cfg->acct_file);
	    free(cfg->dump_file);
	    free(cfg->dbg_file);
	    free(cfg->pid_file);
	    free(cfg);
	  }
	  cfg = read_config(fname);
      
	  write_log(1);
	
	  init_capture();
	  if (--sigflag_reread_config)
	    {
	      DEBUG(DBG_ERR, "sigflag_reread_config > 1");
	    }
	}

      if( sigflag_reopen_socket )
	{
	  DEBUG(DBG_STATE, "re-opening socket");
	  write_log(1);
	  reopen_socket();


	  if (sigflag_reopen_socket != 1)
	    {
	      DEBUG(DBG_ERR, my_sprintf("signal_reopen_socket = %d.", 
					sigflag_reopen_socket));
	    }
	  sigflag_reopen_socket--;
	}

      if (sigflag_child_finished)
	wait_children();
	
      /* Wait until data is available */
      FD_ZERO(&readfds);
      FD_SET(nful_fd,&readfds);
      
      ret=select(nful_fd + 1,&readfds,NULL,NULL,NULL);
      
	if (ret<0)
	  {
	    if (errno!=EINTR) 
	      {
	        DEBUG(DBG_ERR, my_sprintf("select(): %m"));
	      }
	  }
	else if (ret>0)
	  {
	    int len;
	    
	    len = recv(nful_fd, nfulog_buf, recvbufsiz, 0);
	    
	    if (len < 0) 
	      {
	        if (errno == ENOBUFS && !nful_overrun_warned) 
		  {
		    if (nlmaxbufsiz)
		      {
		        int newsize = nlbufsiz * 2;
			if (setnlbufsiz(newsize))
			  {
			    DEBUG(DBG_MISC, my_sprintf(
			        "We are losing events, "
				"increasing buffer size "
				"to %d", nlbufsiz));
			  }
			else
			  {
			    DEBUG(DBG_ERR, my_sprintf(
				"Maximal socket buffer size reached. "
				"We are losing events.: %m"));
			    nful_overrun_warned = 1;
			  }
		      }
		    else
		      {
		        DEBUG(DBG_ERR, my_sprintf(
				"We are losing events. Please, "
				"consider using the clauses "
				"`netlink_socket_buffer_size' and "
				"`netlink_socket_buffer_maxsize': %m"));
			nful_overrun_warned = 1;
		      }
		  }
	      }
	    else
	      nflog_handle_packet(nful_h, (char *)nfulog_buf, len);
	  }
    }
}
