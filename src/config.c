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


  Configuration module 

  $Id: config.c,v 1.17 2005/02/03 09:25:52 bengen Exp $
 */

#include <syslog.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>

#include "config.h"
#include "process.h"
#include "debug.h"

/* HOST_NAME_MAX is the maximum size for gethostname(2) */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

struct config *read_config(char *fname)
{
  char buff[1024];
  char acct_format[1024];
  char*key=NULL;
  char*value=NULL;
  char*tmpc=NULL;

  FILE *f;
  int line=0;
  unsigned int i;

  struct config *cfg = malloc(sizeof(struct config));
  if(cfg == NULL) return cfg;
  
  cfg->acct_file = NULL;
  cfg->dump_file = NULL;
  cfg->dbg_file = NULL;
  cfg->pid_file = NULL;
  cfg->acct_format = NULL;
  cfg->date_format = strdup(DEFAULT_DATEFORMAT);
  cfg->flush = DEFAULT_FLUSH;
  cfg->fdelay = DEFAULT_FDELAY;
  cfg->err_delay = DEFAULT_ERR_DELAY;
  cfg->mcast_group = 0;
  cfg->debug = 0;
  cfg->so_rcvbuf = 65536;
  cfg->hash_table_size = 65536; cfg->hash_mask = 0xffff; cfg->hash_initval = 0;
  cfg->logger_nice_value = 0;
  *(cfg->empty_iface) = '\0';
  *(cfg->empty_prefix) = '\0';
  
  f=fopen(fname,"r");
  if(f == NULL) 
    {
      syslog(LOG_ERR,"config: Error opening %s.",fname);
      return NULL;
    }
  
  while(fgets(buff,sizeof(buff),f))
    {
      line++;
      key=buff;
      /* remove leading whitespace of line (key) */
      while(isspace(*key))
	key++;
      /* ignore comments */
      if(*key=='#') continue;
      /* remove trailing newline, whitespace of line (value) */
      tmpc=strchr(key,'\n');
      while(tmpc>=key && isspace(*tmpc))
	*tmpc--='\0';
      /* barf if no '=' is in the line */
      tmpc = value = strchr(key,'=');
      if(value++)
	/* remove leading whitespace of value */
	while(isspace(*value)) value++;
      else
	{
	  /* syntax error */
	  continue;
	}
      *tmpc = ' ';
      /* remove trailing whitespace of key */
      while(tmpc>=key && isspace(*tmpc))
	*tmpc--='\0';

      /* processing starts here */
      if(strcasecmp(key, "accounting file")==0)
	{
	  cfg->acct_file=strdup(value);
	  syslog(LOG_DEBUG,"config: set accounting file to %s",cfg->acct_file);
	}
      else if(strcasecmp(key, "accounting format")==0)
	{
	  tmpc=acct_format;
	  while (*value)
	    {
	      switch(*value)
		{
		case '%':
		  switch(*++value)
		    {
		    case 'x':
		      cfg->output|=(1<<OUT_SINCE);
		      strcpy(tmpc,"%1$u");
		      tmpc+=4;
		      break;
		    case 't':
		      cfg->output|=(1<<OUT_TIMESTAMP);
		      strcpy(tmpc,"%2$u");
		      tmpc+=4;
		      break;
		    case 'p':
		      cfg->output|=(1<<OUT_PROTO);
		      strcpy(tmpc,"%3$u");
		      tmpc+=4;
		      break;
		    case 's':
		      cfg->output|=(1<<OUT_SRC);
		      strcpy(tmpc,"%4$s");
		      tmpc+=4;
		      break;
		    case 'S':
		      cfg->output|=(1<<OUT_SRCPORT);
		      strcpy(tmpc,"%5$hu");
		      tmpc+=5;
		      break;
		    case 'd':
		      cfg->output|=(1<<OUT_DST);
		      strcpy(tmpc,"%6$s");
		      tmpc+=4;
		      break;
		    case 'D':
		      cfg->output|=(1<<OUT_DSTPORT);
		      strcpy(tmpc,"%7$hu");
		      tmpc+=5;
		      break;
		    case 'P':
		      cfg->output|=(1<<OUT_PACKETS);
		      strcpy(tmpc,"%8$u");
		      tmpc+=4;
		      break;
		    case 'b':
		      cfg->output|=(1<<OUT_BYTES);
		      strcpy(tmpc,"%9$lu");
		      tmpc+=5;
		      break;
		    case 'i':
		      cfg->output|=(1<<OUT_INDEV);
		      strcpy(tmpc,"%10$s");
		      tmpc+=5;
		      break;
		    case 'o':
		      cfg->output|=(1<<OUT_OUTDEV);
		      strcpy(tmpc,"%11$s");
		      tmpc+=5;
		      break;
		    case 'f':
		      cfg->output|=(1<<OUT_PREFIX);
		      strcpy(tmpc,"%12$s");
		      tmpc+=5;
		      break;
		    case 'u':
		      cfg->output|=(1<<OUT_LOCAL_UID);
		      strcpy(tmpc,"%13$d");
		      syslog(LOG_DEBUG,"config: includeing LOCAL_UID");
		      tmpc+=5;
		      break;
		    case 'X':
		      cfg->output|=(1<<OUT_TIMESTRING_SINCE);
		      strcpy(tmpc,"%14$s");
		      tmpc+=5;
		      break;
		    case 'Z':
		      cfg->output|=(1<<OUT_TIMESTRING);
		      strcpy(tmpc,"%15$s");
		      tmpc+=5;
		      break;
		    case 'h':
		      gethostname(tmpc,HOST_NAME_MAX);
		      tmpc=strchr(tmpc,'\0');
		      break;
		    case 'm':
		      cfg->output|=(1<<OUT_MAC);
		      strcpy(tmpc,"%16$s");
		      tmpc+=5;
		      break;
		    case '%': strcpy(tmpc,"%%"); tmpc+=2; break;
		    default: *tmpc++=*value; break;
		    }
		  value++;
		  break;
		case '\\':
		  switch(*++value)
		    {
		    case 't': *tmpc++='\t'; break;
		    case 'n': *tmpc++='\n'; break;
		    case 'r': *tmpc++='\r'; break;
		    case 'f': *tmpc++='\f'; break;
		    case 'e': *tmpc++='\e'; break;
		    case '%': strcpy(tmpc,"%%"); tmpc+=2; break;
		    default: *tmpc++=*value; break;
		    }
		  value++;
		  break;
		case '"': value++; break;
		default: *tmpc++=*value++; break;
		}
	    }
	  *tmpc='\0';
	  cfg->acct_format=strdup(acct_format);
	  syslog(LOG_DEBUG,"config: set output format to %s",cfg->acct_format);
	}
      else if(strcasecmp(key, "date format")==0)
	{
	  cfg->date_format=strdup(value);
	  syslog(LOG_DEBUG,"config: set date format to %s",cfg->date_format);
	}
      else if(strcasecmp(key, "debug file")==0)
	{
	  cfg->dbg_file=strdup(value);
	  syslog(LOG_DEBUG,"config: set debug file to %s",cfg->dbg_file);
	}
      else if(strcasecmp(key, "debug")==0)
	{
	  tmpc=value;
	  while((value=strtok(tmpc,",")))
	    {
	      while (isspace(*value))
		value++;
	      tmpc=strchr(value,'\0')-1;
	      while (isspace(*tmpc))
		*tmpc--='\0';
	      if(strcasecmp(value,"config") == 0)
		cfg->debug|=(1<<DBG_CONFIG);
	      else if(strcasecmp(value,"state") == 0)
		cfg->debug|=(1<<DBG_STATE);
	      else if(strcasecmp(value,"syscall") == 0)
		cfg->debug|=(1<<DBG_SYSCALL);
	      else if(strcasecmp(value,"misc") == 0)
		cfg->debug|=(1<<DBG_MISC);
	      else if(strcasecmp(value,"statistics") == 0)
		cfg->debug|=(1<<DBG_STATISTICS);
	      else if(strcasecmp(value,"signal") == 0)
		cfg->debug|=(1<<DBG_SIGNAL);
	      else if(strcasecmp(value,"error") == 0)
		cfg->debug|=(1<<DBG_ERR);
	      else if(strcasecmp(value,"annoying") == 0)
		cfg->debug|=(1<<DBG_ANNOYING);
	      else if(strcasecmp(value,"error-packet") == 0)
		cfg->debug|=(1<<DBG_ERR_PKT);
	      else
		{
		  syslog(LOG_ERR,"config: Invalid debug category: \"%s\"",value);
		  tmpc=NULL;
		  continue;
		}
	      syslog(LOG_DEBUG,"config: Adding debug category \"%s\"",value);
	      tmpc=NULL;
	    }
	  syslog(LOG_DEBUG,"config: debug set to: %i",cfg->debug);
	}
      else if(strcasecmp(key, "dump file")==0)
	{
	  cfg->dump_file=strdup(value);
	  syslog(LOG_DEBUG,"config: set dump file to %s",cfg->dump_file);
	}
      else if(strcasecmp(key, "pid file")==0)
	{
	  cfg->pid_file=strdup(value);
	  syslog(LOG_DEBUG,"config: set PID file to %s",cfg->dump_file);
	}
      else if(strcasecmp(key, "multicast groups")==0)
	{
	  tmpc=value;
	  while((value=strtok(tmpc,",")))
	    {
	      cfg->mcast_group|=1<<(atoi(value)-1);
	      syslog(LOG_DEBUG,"config: adding mcast group %u",atoi(value));
	      tmpc=NULL;
	    }
	  syslog(LOG_DEBUG,"config: set multicast group to 0x%x",cfg->mcast_group);
	}
      else if (strcasecmp(key, "empty interface")==0)
	{
	  tmpc=cfg->empty_iface;
	  while (*value)
	    {
	      switch(*value)
		{
		case '\\':
		  switch(*++value)
		    {
		    case 't': *tmpc++='\t'; break;
		    case 'n': *tmpc++='\n'; break;
		    case 'r': *tmpc++='\r'; break;
		    case 'f': *tmpc++='\f'; break;
		    case 'e': *tmpc++='\e'; break;
		    case '%': strcpy(tmpc,"%%"); tmpc+=2; break;
		    default: *tmpc++=*value; break;
		    }
		  value++;
		  break;
		case '"': value++; break;
		default: *tmpc++=*value++; break;
		}
	    }
	  *tmpc='\0';
	  syslog(LOG_DEBUG,"config: set empty interface string to \"%s\"",cfg->empty_iface);
	}
      else if (strcasecmp(key, "empty prefix")==0)
	{
	  tmpc=cfg->empty_prefix;
	  while (*value)
	    {
	      switch(*value)
		{
		case '\\':
		  switch(*++value)
		    {
		    case 't': *tmpc++='\t'; break;
		    case 'n': *tmpc++='\n'; break;
		    case 'r': *tmpc++='\r'; break;
		    case 'f': *tmpc++='\f'; break;
		    case 'e': *tmpc++='\e'; break;
		    case '%': strcpy(tmpc,"%%"); tmpc+=2; break;
		    default: *tmpc++=*value; break;
		    }
		  value++;
		  break;
		case '"': value++; break;
		default: *tmpc++=*value++; break;
		}
	    }
	  *tmpc='\0';
	  syslog(LOG_DEBUG,"config: set empty prefix string to \"%s\"",cfg->empty_iface);
	}
      else if(strcasecmp(key, "flush")==0)
	{
	  cfg->flush = atoi(value);
	  syslog(LOG_DEBUG,"config: set flushing to %u",cfg->flush);
	}
      else if(strcasecmp(key, "fdelay")==0)
	{
	  cfg->fdelay = atoi(value);
	  syslog(LOG_DEBUG,"config: set fdelay to %u",cfg->fdelay);
	}
      else if(strcasecmp(key, "socket receive buffer")==0)
	{
	  cfg->so_rcvbuf = atoi(value);
	  syslog(LOG_DEBUG,"config: set socket receive buffer to %zu",cfg->so_rcvbuf);
	}
      else if (strcasecmp(key, "hash table size")==0)
	{
	  cfg->hash_table_size = atoi(value);
	  /* Round up to next power of 2 */
	  for (i=1; i < cfg->hash_table_size; i*=2);
	  cfg->hash_table_size = i;
	  cfg->hash_mask = i-1;
	  syslog(LOG_DEBUG,"config: set hash table size to %du",cfg->hash_table_size);
	}
      else if (strcasecmp(key, "hash init value")==0)
	{
	  cfg->hash_initval = atoi(value);
	  syslog(LOG_DEBUG,"config: set hash init value to %zu",cfg->so_rcvbuf);
	}
      else if (strcasecmp(key, "logger nice value")==0)
	{
	  cfg->logger_nice_value = atoi(value);
	  syslog(LOG_DEBUG,"config: set logger nice value to %du",cfg->hash_table_size);
	}
      else
	{
	  syslog(LOG_ERR, "%s: unknown keyword \"%s\" in line %u",fname,key,line);
	  return NULL;
	}
    }

  /*
    We are done parsing. Let's check some values.
  */
  
  if(cfg->acct_file == NULL)
    {
      syslog(LOG_ERR, "config: no accounting file given");
      return NULL;
    }
  if(cfg->dbg_file == NULL)
    {
      syslog(LOG_INFO, "config: no debugfile given, using /dev/null");
      cfg->dbg_file = strdup("/dev/null");
    }
  if(cfg->pid_file == NULL)
    {
      syslog(LOG_INFO, "config: no pidfile given, using /var/run/nflog-acctd.pid");
      cfg->pid_file = strdup("/var/run/nflog-acctd.pid");
    }
  
  fclose(f);
  return cfg;
}
