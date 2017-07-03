/*
  nflog-acctd

  (C) 2002 Hilko Bengen (original ulog-acctd)
  (C) 2017 Iarcev Anton

  $Id: process.h,v 1.14 2005/02/03 09:25:52 bengen Exp $
*/

#include <sys/time.h>
#include <sys/types.h>

/* Output record format */
#define OUT_TIMESTAMP 0
#define OUT_PROTO     1
#define OUT_SRC       2
#define OUT_SRCPORT   3
#define OUT_DST       4
#define OUT_DSTPORT   5
#define OUT_PACKETS   6
#define OUT_BYTES     7
#define OUT_INDEV     8
#define OUT_OUTDEV    9
#define OUT_PREFIX    10
#define OUT_LOCAL_UID 11
#define OUT_TIMESTRING 12
#define OUT_MAC       13
#define OUT_SINCE     14
#define OUT_TIMESTRING_SINCE 15

#define ENABLED(n) (cfg->output & (1<<n))
#define DISABLED(n) !ENABLED(n)

struct statistics
{
  unsigned long int ipv4;
  /* IPv4 protocol types: Sum should be equal to ipv4 */
  unsigned long int ipv4_udp, ipv4_tcp, ipv4_icmp, ipv4_other;
  /* errors */
  unsigned long int dropped, ipv4_short, nl_truncated, nl_recv_error;
  unsigned long int list_compares, list_lookups, unknown_user;
  /* diagnostics */
  unsigned int min_cprange;
};

struct ipv4data
{
  u_int8_t proto;
  u_int32_t src, dst;
  u_int16_t srcport, dstport;
  unsigned long int bytes;
  unsigned long int count;
  char *indev, *outdev, *prefix;
  uid_t local_uid;
  time_t since, when;
  unsigned char mac_len;
  unsigned char mac[80];
  struct ipv4data *next;
};

struct localuiddata
{
  u_int32_t localaddr, remoteaddr;
  u_int16_t localport, remoteport;
  uid_t uid;
  struct localuiddata *next;
};

extern volatile int running;
extern struct statistics *packets;

extern int sigflag_reopen_socket;
extern int sigflag_reopen_files;
extern int sigflag_reread_config;
extern int sigflag_may_write;
extern int sigflag_write_log;
extern int sigflag_child_finished;

/* process.c */
int write_log(int force);
void alarm_handler(int sig);
void child_finished(int sig);
void signal_debug(int sig);
void signal_ignore(int sig);
void reopen_socket(void);

void wait_children(void);

#include <netinet/ip.h>
void register_packet(struct iphdr*, size_t, char[], char [], char[], unsigned char, unsigned char[]);
