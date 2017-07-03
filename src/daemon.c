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


  Utilities for a daemon process.
  
  $Id: daemon.c,v 1.5 2003/04/01 21:53:08 bengen Exp $
*/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/param.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <syslog.h>

#include "process.h"
#include "debug.h"
#include "config.h"
#include "capture.h"
#include "daemon.h"

char *rcs_revision_daemon_c = "$Revision: 1.5 $";

int daemon_start(void)
{
    int i;
    pid_t pid;
    
    if( (pid = fork()) < 0)
        return(-1);
    else if (pid!=0)
        exit(0);

    closelog();

    for(i=0; i<FD_SETSIZE; i++)
        close(i);

    setsid();

    return 0;
}

void daemon_stop(int sig)
{
  DEBUG(DBG_STATE,"entering daemon_stop");

  if( write_log(1) == 0 )
    {
      DEBUG(DBG_STATE, "wrote final log");
    }
  else
    {
      DEBUG(DBG_STATE, "writing final log unsuccessful");
    };
  
  unlink(cfg->pid_file);

  DEBUG(DBG_STATE, "unlinked PID_FILE");

  syslog(LOG_INFO, "net accounting daemon terminating (%d)",sig);

  DEBUG(DBG_STATE, "did syslog message");
    
  exit_capture();

  DEBUG(DBG_STATE, "cleaned up capture");

  closelog();

  DEBUG(DBG_STATE, "closed syslog");

  close(dbg_file);
  
  exit(1);
}







