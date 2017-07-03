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


  Packet processing module

  $Id: process.c,v 1.29 2005/02/03 09:25:52 bengen Exp $
*/

#include <sys/time.h>
#include <sys/wait.h>

#include <errno.h>

#include "process.h"
#include "debug.h"
#include "config.h"
#include "capture.h"
#include "daemon.h"
#include "utils.h"

#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#include <syslog.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

volatile int running;
struct statistics *stats;
struct statistics *stats0;

static struct ipv4data **plist;

static struct ipv4data *output_list;

unsigned long int plistsize;
unsigned long int olistsize;

static volatile sig_atomic_t lck;
/* static volatile sig_atomic_t writing; */
/* static volatile sig_atomic_t dumping; */

volatile pid_t writepid;
volatile pid_t dumppid;

int sigflag_reopen_files=0;
int sigflag_reread_config=0;
int sigflag_reopen_socket=0;
int sigflag_may_write=0;
int sigflag_write_log=0;
int sigflag_child_finished=0;

int err_delay, max_err_delay;
volatile time_t now;
static time_t next_write_log = 0;

uid_t get_tcp_local_uid(u_int32_t, u_int32_t, u_int16_t, u_int16_t);

struct localuiddata * read_proc_file(char* filename);

/* A modified jhash_3words from include/linux/jhash.h */
u_int32_t HASH(u_int32_t a, u_int32_t b, u_int16_t sp, u_int16_t dp, u_int8_t pt)
{
  /* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO	0x9e3779b9

  u_int32_t c;
  a += JHASH_GOLDEN_RATIO;
  b += JHASH_GOLDEN_RATIO;
  c = (sp << 16) + dp + pt + cfg->hash_initval;

  a -= b; a -= c; a ^= (c>>13);
  b -= c; b -= a; b ^= (a<<8);
  c -= a; c -= b; c ^= (b>>13);
  a -= b; a -= c; a ^= (c>>12);
  b -= c; b -= a; b ^= (a<<16);
  c -= a; c -= b; c ^= (b>>5);
  a -= b; a -= c; a ^= (c>>3);
  b -= c; b -= a; b ^= (a<<10);
  c -= a; c -= b; c ^= (b>>15);

  return ( c & cfg->hash_mask);
}

void reopen_socket(void)
{
  int save1, save2;
  
  /* critical section */
  save1 = sigflag_may_write;
  sigflag_may_write = 0;
  save2 = lck;
  lck = 1;
  /* end */ 
    
  DEBUG(DBG_STATE, "reopen_socket [before]: lck = 1");
  
  exit_capture();
  init_capture();
  
  lck = save2;
  
  DEBUG(DBG_STATE, my_sprintf("reopen_socket [after]: lck = %d",save2)); 
  
  sigflag_may_write = save1;
}


void do_acct()
{
  int i;

  stats = calloc(2, sizeof(struct statistics));
  stats0 = stats+1;

  memset(stats, 0, sizeof(struct statistics));

  plist=malloc(cfg->hash_table_size*sizeof(struct ipv4data));
  if (!plist) {
    syslog(LOG_ERR,"FATAL: Could not allocate hash table.");
  }

  for (i =0; i < cfg->hash_table_size; i++) {
     plist[i] = NULL;
  }

  olistsize = plistsize = 0;
  lck = 0;
  dumppid = writepid = 0;

  max_err_delay = cfg -> err_delay;
  err_delay = 0;

  sigflag_may_write = 1;

  now = time(NULL);
  next_write_log = now + cfg -> flush;

  alarm(1);
  running=1;

  packet_loop();
}

void register_packet(struct iphdr *tmp_iphdr, size_t packet_length,
		     char indev_name[], char outdev_name[], char prefix[],
		     unsigned char mac_len, unsigned char mac[])
{
  int hash_val;

  unsigned char j;

  /* For parsing IP headers */
  struct udphdr *tmp_udphdr=
    (struct udphdr*) ((char*) tmp_iphdr+(tmp_iphdr->ihl*4));
  struct tcphdr *tmp_tcphdr=
    (struct tcphdr*) ((char*) tmp_iphdr+(tmp_iphdr->ihl*4));
  struct icmphdr *tmp_icmphdr=
    (struct icmphdr*) ((char*) tmp_iphdr+(tmp_iphdr->ihl*4));

  unsigned short srcport, dstport;
  uid_t uid = -1;

  int i;

  /* In case we want to log the entire packet for debugging
     purposes */
  char logbuf[packet_length * 3];

  /* We need the entire IP header, plus
        4 bytes for TCP/UDP source and destination ports. 
     or
        2 bytes for ICMP type and code. */
  unsigned int hdr_len = tmp_iphdr->ihl*4;
  switch(tmp_iphdr->protocol)
    {
    case IPPROTO_UDP:
    case IPPROTO_TCP:
      if ((ENABLED(OUT_SRCPORT)||ENABLED(OUT_DSTPORT)))
	hdr_len+=4;
      break;
    case IPPROTO_ICMP:
      if ((ENABLED(OUT_SRCPORT)||ENABLED(OUT_DSTPORT)))
	hdr_len+=2;
    }

  if (hdr_len > packet_length)
    {
      if ((stats->ipv4_short++ == 0) || (hdr_len > stats->min_cprange))
	{
	  stats->min_cprange=hdr_len;
	  DEBUG(DBG_ERR, my_sprintf("Short IP header. Rcvd: %d, needed: %d.", 
				    packet_length, hdr_len));
	  syslog(LOG_ERR, "Short IP header. Rcvd: %zu, needed: %d.", 
				    packet_length, hdr_len);
	  if (packet_length<sizeof(struct iphdr)) 
	    {
	      DEBUG(DBG_ERR,"copy range is too short to even capture IP headers. ALL IP PACKETS WILL BE DROPPED!");
	      syslog(LOG_ERR, "copy range is too short to even capture IP headers. ALL IP PACKETS WILL BE DROPPED!");
	    }
	}

      for (i=0; i < packet_length;i++)
	{
	  snprintf(logbuf+i*3, sizeof(logbuf), "%.2X ", ((unsigned char*)tmp_iphdr)[i]);
	}
      DEBUG(DBG_ERR_PKT, my_sprintf("indev=%s outdev=%s pkt=\"%s\"", indev_name, outdev_name, logbuf));

      /* If we captured the IP header, we can at least record
	 source/destination IP address, protocol type and size. 
	 Otherwise, things are going wrong, anyhow. */
      if (packet_length>=sizeof(struct iphdr)) 
	{
	  srcport = dstport = 0;
	  switch(tmp_iphdr->protocol)
	    {
	    case IPPROTO_UDP:
	      stats->ipv4_udp++;
	      break;
	    case IPPROTO_TCP:
	      stats->ipv4_tcp++;
	      break;
	    case IPPROTO_ICMP:
	      stats->ipv4_icmp++;
	      break;
	    default:
	      stats->ipv4_other++;
	      break;
	    }
	}
      else
	return;
    }
  /* Everything is well, just account the package. */
  else 
    {
      if (hdr_len > stats->min_cprange)
	stats->min_cprange=hdr_len;
      switch(tmp_iphdr->protocol) 
	{
	case IPPROTO_UDP:
	  stats->ipv4_udp++;
	  srcport = ntohs(tmp_udphdr->source);
	  dstport = ntohs(tmp_udphdr->dest);
	  break;
	case IPPROTO_TCP:
	  stats->ipv4_tcp++;
	  srcport = ntohs(tmp_tcphdr->source);
	  dstport = ntohs(tmp_tcphdr->dest);
	  if (ENABLED(OUT_LOCAL_UID) && ((indev_name[0]==0)||(outdev_name[0]==0)))
	    uid=get_tcp_local_uid(tmp_iphdr->saddr,tmp_iphdr->daddr,
				  srcport,dstport);
	  break;
	case IPPROTO_ICMP:
	  stats->ipv4_icmp++;
	  srcport = tmp_icmphdr->type; 
	  dstport = tmp_icmphdr->code;
	  break;
	default:
	  stats->ipv4_other++;
	  srcport = dstport = 0;
	  break;
	}
    }

  stats->ipv4++;

  hash_val = HASH(tmp_iphdr->saddr,
		  tmp_iphdr->daddr,
		  srcport,
		  dstport,
		  tmp_iphdr->protocol);
  
  if(lck==0)
    {
      struct ipv4data *p;
      DEBUG(DBG_ANNOYING, "lck = 1");
      lck = 1;
      p = plist[ hash_val ];
      stats->list_lookups++;
      if (mac_len>80)
	mac_len=0;
      /* Traverse the chain to find identical packet */
      while(p)
	{
	  stats->list_compares++;
	  if( (DISABLED(OUT_PROTO) || (p->proto == tmp_iphdr->protocol)) 
	      && (DISABLED(OUT_SRC) || (p->src == tmp_iphdr->saddr)) 
	      && (DISABLED(OUT_DST) || (p->dst == tmp_iphdr->daddr)) 
	      && (DISABLED(OUT_SRCPORT) || (p->srcport == srcport)) 
	      && (DISABLED(OUT_DSTPORT) || (p->dstport == dstport)) 
	      && (DISABLED(OUT_INDEV) || !strcmp(p->indev,indev_name))
	      && (DISABLED(OUT_OUTDEV) || !strcmp(p->outdev,outdev_name))
	      && (DISABLED(OUT_OUTDEV) || !strcmp(p->prefix,prefix))
	      && (DISABLED(OUT_LOCAL_UID) || (p->local_uid == uid))
	      && (DISABLED(OUT_MAC) || (mac_equals(mac_len, mac, p->mac_len, p->mac))))
	    {
	      p->bytes += ntohs(tmp_iphdr->tot_len);
	      p->when = now;
	      p->count++;
	      lck = 0;
	      DEBUG(DBG_ANNOYING, "lck = 0");
	      return;
	    }
	  p = p->next;
	}
      /* Insert new entry at the beginning of the chain */
      p = malloc(sizeof(struct ipv4data));
      if(p == NULL)
	{
	  stats -> dropped++;
	  lck = 0;
	  DEBUG(DBG_ERR, "out of memory");
	  DEBUG(DBG_ANNOYING, "lck = 0");
	  return;
	}
      plistsize++;
      p -> src = tmp_iphdr->saddr;
      p -> dst = tmp_iphdr->daddr;
      p -> proto = tmp_iphdr->protocol;
      p -> srcport = srcport;
      p -> dstport = dstport;
      p -> bytes = ntohs(tmp_iphdr->tot_len);
      p -> count = 1;
      p -> indev = strdup(indev_name);
      p -> outdev = strdup(outdev_name);
      p -> prefix = strdup(prefix);
      p -> next = plist[ hash_val ];
      p->since = p -> when = now;
      p -> local_uid = uid;
      p -> mac_len = mac_len;
      for (j=0;j<mac_len;j++)
	  p->mac[j] = mac[j];
      
      plist[ hash_val ] = p;
      lck = 0;
      DEBUG(DBG_ANNOYING, "lck = 0");
    }
  else
    {
      stats->dropped++;
    }
}

/* If the packet is not routed by this machine, but comes from it or
   goes to it, the connection's owner can be determined by looking at
   /proc/net/{tcp,udp}.

   At the moment, this funcion just returns 0 (=root) */
uid_t get_tcp_local_uid(u_int32_t saddr,u_int32_t daddr, u_int16_t srcport,u_int16_t dstport)
{
  static struct localuiddata *tcpdata=NULL, *tmpdata, *tmpptr;
  for (tmpdata=tcpdata;tmpdata!=NULL;tmpdata=tmpdata->next)
    {
      if (((tmpdata->localaddr==saddr) &&
	   (tmpdata->localport==srcport) &&
	   (tmpdata->remoteaddr==daddr) && 
	   (tmpdata->remoteport==dstport)) ||
	  ((tmpdata->localaddr==daddr) &&
	   (tmpdata->localport==dstport) &&
	   (tmpdata->remoteaddr==saddr) && 
	   (tmpdata->remoteport==srcport)))
	return tmpdata->uid;
    }
  tmpdata=tcpdata;
  while (tmpdata!=NULL)
    {
      tmpptr=tmpdata->next;
      free(tmpdata);
      tmpdata=tmpptr;
    }
  tcpdata=read_proc_file("/proc/net/tcp");
  for (tmpdata=tcpdata;tmpdata!=NULL;tmpdata=tmpdata->next)
    {
      if (((tmpdata->localaddr==saddr) &&
	   (tmpdata->localport==srcport) &&
	   (tmpdata->remoteaddr==daddr) && 
	   (tmpdata->remoteport==dstport)) ||
	  ((tmpdata->localaddr==daddr) &&
	   (tmpdata->localport==dstport) &&
	   (tmpdata->remoteaddr==saddr) && 
	   (tmpdata->remoteport==srcport)))
	return tmpdata->uid;
    }
  return 0;
}

/* Reads /proc/net/{tcp,udp}, returns localuid data */
struct localuiddata* read_proc_file(char* filename)
{
  FILE *procinfo;
  static char buffer[255];
  struct localuiddata *firstrec, *oldrec, *tmprec;
  int state;
  int num;

  if ((procinfo = fopen(filename, "r")) == NULL)
    return(NULL);

  /* Skip first line */
  fgets(buffer, sizeof(buffer), procinfo); /* skip header line */

  firstrec=NULL;
  oldrec=NULL;
  while (!feof(procinfo) && (fgets(buffer, sizeof(buffer), procinfo)!=NULL))
    {
      tmprec=malloc (sizeof(struct localuiddata));
      num = sscanf(buffer,
		   "%*d: %X:%hX %X:%hX %X %*X:%*X %*X:%*X %*X %d %*d %*d\n",
		   &(tmprec->localaddr), &(tmprec->localport), 
		   &(tmprec->remoteaddr), &(tmprec->remoteport),
		   &state, &(tmprec->uid));
      if ((num < 5) || state >= TCP_LISTEN)
	{
	  free(tmprec);
	  continue;
	}
      tmprec->next=NULL;
      if (firstrec)
	oldrec->next=tmprec;
      else
	{
	  firstrec=tmprec;
	}
      oldrec=tmprec;
    }
  fclose(procinfo);
  return(firstrec);
}

/* Write one list of packet data--one chain from the hash table or the
   prepared output list--to file descriptor */
int write_output_list(int fd, struct ipv4data *output_list)
{
  struct ipv4data *p;
  
  static char src[16];
  static char dst[16];

  static char indev[32];
  static char outdev[32];
  static char prefix[32];

  static char timestring_since[128];
  static char timestring[128];

  struct tm timestructure;

  static char buf[1024];
  int len;

  char mac_str[240];

  p=output_list;

  time_t rawtime;
  time(&rawtime);

  struct tm *timeinfo = localtime(&rawtime);
  len = strftime(buf, sizeof(buf), "# Statistic write  %d %b %Y   %X\n", timeinfo);

  if (write(fd,buf,len)==-1)
  {
    syslog(LOG_ERR, "error writing %d bytes of accounting data to output file %d: %s", len, fd, strerror(errno));
    return 1;
  }

  while (p) {
    /* Convert in_addr to strings for src IP, dst IP */
    if (ENABLED(OUT_SRC))
      strcpy(src,inet_ntoa(*((struct in_addr*)&(p->src))));
    if (ENABLED(OUT_DST))
      strcpy(dst,inet_ntoa(*((struct in_addr*)&(p->dst))));
    /* Replace indev, outdev, prefix with empty default, if
       necessary */
    if (ENABLED(OUT_INDEV))
      strcpy(indev,(*(p->indev)?p->indev:cfg->empty_iface));
    if (ENABLED(OUT_OUTDEV))
      strcpy(outdev,(*(p->outdev)?p->outdev:cfg->empty_iface));
    if (ENABLED(OUT_PREFIX))
      strcpy(prefix,(*(p->prefix)?p->prefix:cfg->empty_prefix));
    /* MAC address */
    if (ENABLED(OUT_MAC)) 
      {
	if (p->mac_len)
	  {
	    unsigned char j;
	    for(j=0;j<p->mac_len;j++)
	      sprintf(&(mac_str[j*3]),"%.2hhX:",p->mac[j]);
	    mac_str[3*j-1]=0;
	  }
	else
	  mac_str[0]=0;
      }
    
    /* Time-as-string handling */
    if(ENABLED(OUT_TIMESTRING))
      {
        localtime_r(&p->since, &timestructure);
	strftime(timestring_since, sizeof(timestring_since),
	         cfg->date_format, &timestructure);

	localtime_r(&p->when, &timestructure);
	strftime(timestring, sizeof(timestring), 
		 cfg->date_format,&timestructure);
      }
    
    len=snprintf(buf, 1023, cfg->acct_format, p->since, p->when, p->proto,
		 src, p->srcport, dst, p->dstport,
		 p->count, p->bytes,
		 indev, outdev,
		 prefix,
		 (int) p->local_uid,
		 timestring_since, timestring,
		 mac_str);

    if (write(fd,buf,len)==-1)
      {
	syslog(LOG_ERR, "error writing %d bytes of accounting data to output file %d: %s", len, fd, strerror(errno));
	return 1;
      }
    p=p->next;
  }
  return 0;
}


/* write and clear olist */
void write_list(void)
{
  char tmpn[255];

  while( (writepid = fork()) < 0) sleep(1);
  /* FIXME: Check for fork() error */
  if (writepid!=0) return;

  /* Here goes the child */

  /* Set nice value */
  if (cfg->logger_nice_value) nice(cfg->logger_nice_value);

  DEBUG(DBG_STATE, my_sprintf("* write process %d forked", (int) getpid()));

  sprintf(tmpn, "%s.write.%d", cfg->acct_file, (int) getpid());

  if (link(cfg->acct_file, tmpn) != 0)
    {
      DEBUG(DBG_ERR, my_sprintf("Coud not create link %s: %m."));
    }

  openlog("nflog-acctd (write)", LOG_PID, LOG_DAEMON);

  if(write_output_list(acct_file, output_list) != 0)
    {
      unlink(tmpn);
      syslog(LOG_ERR, "error writing to file %s: %m", cfg->acct_file);
      exit(1);
    }

  unlink(tmpn);

  DEBUG(DBG_STATE, my_sprintf("* write finished, count = %ld", olistsize));

  exit(0);
}

void dump_curr_list(void)
{
  int dump_file;
  char tmpn[255];
  int i;

  if(cfg->dump_file == NULL)
    {
      DEBUG(DBG_STATE, "* no dumpfile given: not dumping anything");
      return;
    }
  if(plistsize == 0)
    {
      DEBUG(DBG_STATE, "No dump necessary, dump empty");
      return;
    }

  while( (dumppid = fork()) < 0) sleep(1);
  if (dumppid!=0) return;

  /* Here goes the child */

  /* Set nice value */
  if (cfg->logger_nice_value) nice(cfg->logger_nice_value);

  DEBUG(DBG_STATE, my_sprintf("* dump process %d forked", (int) getpid()));

  sprintf(tmpn, "%s.write.%d", cfg->dump_file, (int) getpid());
  if (link(cfg->acct_file, tmpn) != 0)
    {
      DEBUG(DBG_ERR, my_sprintf("Coud not create link %s: %m."));
    }

  openlog("nflog-acctd (dump)", LOG_PID, LOG_DAEMON);

  dump_file = open(cfg->dump_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);
  if(dump_file==-1)
    {
      unlink(tmpn);
      syslog(LOG_ERR, "error opening file %s: %m",cfg->dump_file);
      exit(1);
    }

  for(i=0;i<cfg->hash_table_size;i++)
    {
      if(write_output_list(dump_file, plist[i]) != 0)
	{
	  unlink(tmpn);
	  syslog(LOG_ERR, "error writing to file %s: %m", cfg->dump_file);
	  exit(1);
	}
    }

  if(close(dump_file)==-1)
    {
      DEBUG(DBG_STATE, my_sprintf("error closing dump file: %s", strerror(errno)));
    }

  unlink(tmpn);

  DEBUG(DBG_STATE, my_sprintf("* dump finished, count = %ld", plistsize));

  exit(0);
}

void wait_children(void)
{
  int status;
  pid_t pid;

  sigflag_child_finished=0;

  while((pid = waitpid((pid_t) -1, &status, WNOHANG)) != 0)
    {
      DEBUG(DBG_STATE, my_sprintf("waitpid returned %d, status = %d, errno = %d", pid, status, errno));
      if(pid == -1)
	{
	  if(errno == ECHILD)
	    break; /* no child processes */
	  DEBUG(DBG_SIGNAL, my_sprintf("waitpid: signaled error: %s", strerror(errno)));
	}

      DEBUG(DBG_STATE, my_sprintf("  child %d signaled return",(int) pid));

      if(pid == writepid)
	{
	  DEBUG(DBG_STATE, "set writepid to 0");
	  writepid = 0;
	  if(WIFEXITED(status))
	    {
	      if(WEXITSTATUS(status)==0)
		{
		  /* normal exit */
		}
	      else
		{
		  /* exit with error condition */
		  DEBUG(DBG_STATE, "set err_delay");
		  syslog(LOG_ERR, 
			 "child %d exited with error status %d.",
			 pid, WEXITSTATUS(status));
		  err_delay = max_err_delay;
		}
	    }
	  else
	    {
	      /* terminated by signal */
	      syslog(LOG_ERR,
		     "Huh? Child %d terminated or stopped by signal (%m)",
		     pid);
	    }
	  /* Free memory that was used by output list items */
	  struct ipv4data *p;
	  p = output_list;
	  while(p)
	    {
	      output_list = p->next;
	      free(p->indev);
	      free(p->outdev);
	      free(p->prefix);
	      free(p);
	      p = output_list;
	    }
	  DEBUG(DBG_STATE, "done freeing output list");
	}
      else if (pid == dumppid)
	{
	  DEBUG(DBG_STATE, "set dumppid to 0");
	  dumppid = 0;
	  if(WIFEXITED(status))
	    {
	      if(WEXITSTATUS(status)==0)
		{
		  /* normal exit */
		}
	      else
		{
		  /* exit with error condition */
		  syslog(LOG_ERR, 
			 "child %d exited with error status %d.",
			 pid, WEXITSTATUS(status));
		}
	    }
	  else
	    {
	      /* terminated by signal */
	      syslog(LOG_ERR,
		     "Huh? Child %d terminated or stopped by signal (%m)",
		     pid);
	    }
	}
      else 
	{
	  /* unknown child */
	  syslog(LOG_ERR, "Huh? Child (%d) returned, but not the one we expected (%d, %d)!", (int) pid, writepid, dumppid);
	  DEBUG(DBG_STATE, my_sprintf("  unexpected child %d signaled return (writepid = %d, dumppid = %d",(int) pid, writepid, dumppid));	
	}
    }
}

void child_finished(int sig)
{
  DEBUG(DBG_SIGNAL, my_sprintf("got signal %d, handling", sig));
  sigflag_child_finished=1;
}

void alarm_handler(int sig)
{
  static time_t last_check = 0;
  
  DEBUG( ((sig == SIGALRM) ? DBG_ANNOYING : DBG_SIGNAL), my_sprintf("got signal %d, handling", sig));
  if (sig == SIGALRM)
    {
      DEBUG(DBG_STATE, my_sprintf("got signal %d, handling", sig));
    }
  
  now++;

  /* Adjust timer every minute */
  if((now - last_check) > 60)
    {
      time_t nnow = time(NULL);
      if(nnow!=now)
	{
	  if((abs(nnow - now) > 2))
	    {
	      DEBUG(DBG_MISC, my_sprintf("internal clock corrected (off by %d seconds)",(int) (nnow-now)));
	    }
	  now = nnow;
	}
      last_check = now;
    }

  if(now >= next_write_log)
    {
      /* Schedule log write */
      sigflag_write_log++;
      next_write_log = now + cfg -> flush;
    }

  /* Set next timer */
  alarm(1);
}

int write_log(int force)
{
  struct ipv4data *p, *q;
  static struct ipv4data *tmp_list; /* temp */
  int i;
  int ret=0;

  DEBUG(DBG_STATE, "write_log called");

  if(err_delay>0)
    {
      err_delay--;
      syslog(LOG_INFO,"flushing delayed due to error");
      DEBUG(DBG_STATE, "flushing delayed due to error");
      ret=0;
    }
  else if(writepid||lck||(!sigflag_may_write))
    /* delay if another write cycle is still in progress or if writing
       has been disabled by SIGTSTP */
    {
      DEBUG(DBG_STATE, my_sprintf("flushing delayed (writing == %d, lck == %d, sigflag_may_write == %d)",writepid,lck,sigflag_may_write));
      ret=1;
    }
  else
    /* Go ahead. Write. */
    {
      DEBUG(DBG_STATISTICS, my_sprintf("IPv4: %ld (UDP: %ld TCP: %ld ICMP: %ld other: %ld) short: %ld", stats->ipv4, stats->ipv4_udp, stats->ipv4_tcp, stats->ipv4_icmp, stats->ipv4_other, stats->ipv4_short));
      DEBUG(DBG_STATISTICS, my_sprintf("min cprange: %d drop: %ld nlmsg trunc: %ld  recv err: %ld", stats->min_cprange, stats->dropped, stats->nl_truncated, stats->nl_recv_error));
      DEBUG(DBG_STATISTICS, my_sprintf("lookups: %d, compares: %d, c/l: %f", stats->list_lookups, stats->list_compares, ((float) stats->list_compares / (float) stats->list_lookups)));

      /* Update global stats, reset per-run stats */
      stats0->ipv4+=stats->ipv4;
      stats0->ipv4_udp+=stats->ipv4_udp;
      stats0->ipv4_tcp+=stats->ipv4_tcp;
      stats0->ipv4_icmp+=stats->ipv4_icmp;
      stats0->ipv4_other+=stats->ipv4_other;
      stats0->dropped+=stats->dropped;
      stats0->ipv4_short+=stats->ipv4_short;
      stats0->nl_truncated+=stats->nl_truncated;
      stats0->nl_recv_error+=stats->nl_recv_error;
      stats0->list_lookups+=stats->list_lookups;
      stats0->list_compares+=stats->list_compares;
      if (stats->min_cprange > stats0->min_cprange)
	stats0->min_cprange=stats->min_cprange;
      memset(stats, 0, sizeof(struct statistics));

      /* This happens only when the daemon is stopped. */
      if (force)
	{
	  DEBUG(DBG_STATISTICS, "Since start of daemon:");
	  DEBUG(DBG_STATISTICS, my_sprintf("IPv4: %ld (UDP: %ld TCP: %ld ICMP: %ld other: %ld) short: %ld", stats0->ipv4, stats0->ipv4_udp, stats0->ipv4_tcp, stats0->ipv4_icmp, stats0->ipv4_other, stats0->ipv4_short));
	  DEBUG(DBG_STATISTICS, my_sprintf("min cprange: %d drop: %ld nlmsg trunc: %ld  recv err: %ld", stats0->min_cprange, stats0->dropped, stats0->nl_truncated, stats0->nl_recv_error));
	  DEBUG(DBG_STATISTICS, my_sprintf("lookups: %d, compares: %d, c/l: %f", stats0->list_lookups, stats0->list_compares, ((float) stats0->list_compares / (float) stats0->list_lookups)));
	}

      DEBUG(DBG_STATE, "lck = 1");
      lck = 1; /* can't update the list now */
      
      DEBUG(DBG_MISC, my_sprintf("Total of %ld entries", plistsize));
      
      /* 
	 We build two lists:
	 1) output_list, which will be written out
	 2) tmp_list, which will be the new plist (just for this hash row)
      */
      
      olistsize = 0;
      plistsize = 0;

      output_list = NULL;

      for (i = 0; i < cfg->hash_table_size; i++) {
	 p = plist[i];
	 tmp_list = NULL;
	 
	 while(p)
	   {
	     q = p->next;
	     if(((now - p->when) > cfg->fdelay) || force)
	       {
		 /* Insert p at the beginning of output_list */
		 p->next = output_list;
		 output_list = p;
		 olistsize++;
	       }
	     else
	       {
		 /* Insert p before new plist */
		 p->next = tmp_list;
		 tmp_list = p;
		 plistsize++;
	       }
	     p = q;
	   }
	 plist[i] = tmp_list;
      }

      DEBUG(DBG_MISC, my_sprintf("Split into %ld [hold] and %ld [write] = %ld [total] entries", plistsize, olistsize, plistsize + olistsize)); 

      /* Output list and new plist have been built. */

      if(dumppid == 0)
	{
	  dump_curr_list();
 	  DEBUG(DBG_STATE, my_sprintf("dumppid is %d", (int) dumppid));
	}
      else
	{
	  DEBUG(DBG_STATE, my_sprintf("Not dumping--process %d is still dumping.", (int) dumppid));
	}
      
      lck = 0;
      DEBUG(DBG_STATE, "lck = 0");
      
      write_list(); /* this forks off a child to do the actual writing */

      DEBUG(DBG_STATE, my_sprintf("writepid is %d", (int) writepid));

      ret=0;
    }

  return ret;
}

void signal_debug(int sig)
{
  DEBUG(DBG_SIGNAL, my_sprintf("got signal %d, handling", sig));

  if(sig==SIGTSTP)
    {
      DEBUG(DBG_STATE, "received SIGTSTP");
      sigflag_may_write = 0;
    }
  else if(sig==SIGCONT)
    {
      DEBUG(DBG_STATE, "received SIGCONT");
      sigflag_reopen_files++;
      /* sigflag_may_write = 1 in main loop */
    }
  else if(sig==SIGIOT)
    {
      DEBUG(DBG_STATE, "received SIGIOT");
      sigflag_reopen_socket++;
    }
  else if(sig == SIGHUP)
    {
      DEBUG(DBG_STATE, "received SIGHUP");
      sigflag_reread_config++;
    }
  else
    {
      DEBUG(DBG_SIGNAL, my_sprintf("signal_debug received signal %d, this can't happen", sig));
      syslog(LOG_INFO,"signal_debug received signal %d, this can't happen", sig);
    }
}

void signal_ignore(int sig)
{
  DEBUG(DBG_SIGNAL, my_sprintf("got signal %d, ignoring", sig));
}
