/*
  nflog-acctd

  (C) 2002 Hilko Bengen (original ulog-acctd)
  (C) 2017 Iarcev Anton

  $Id: debug.h,v 1.5 2003/03/02 21:40:25 bengen Exp $
*/

#include <stdio.h>
#include <time.h>

/* parsing of config file */
#define DBG_CONFIG     0
#define DBG_STATE      1
#define DBG_SYSCALL    2
#define DBG_MISC       3
#define DBG_STATISTICS 4
#define DBG_SIGNAL     5
#define DBG_ERR	       6
#define DBG_ANNOYING   7
#define DBG_ERR_PKT    8

static char *DBG_TYPE_STRING[9] = 
  {"CONFIG",
   "STATE",
   "SYSCALL",
   "MISC",
   "STATISTICS",
   "SIGNAL",
   "ERROR",
   "ANNOY",
   "ERROR-PACKET"};

#define DEBUG(level,msg)\
  if((1 << level) & cfg->debug)\
    {\
      char tmptimestr[255];\
      char buf[1024];\
      time_t tmptime=time(NULL);\
      strftime(tmptimestr,255,"%b %d %H:%M:%S",localtime(&tmptime));\
      snprintf(buf,1023, "%s [%s] %s\n",tmptimestr,DBG_TYPE_STRING[level],msg);\
      write(dbg_file, buf, strlen(buf));\
    }
