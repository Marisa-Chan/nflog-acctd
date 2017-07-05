/*
  nflog-acctd

  (C) 2002 Hilko Bengen (original ulog-acctd)
  (C) 2017 Iarcev Anton

  $Id: config.h,v 1.13 2004/04/06 08:49:35 bengen Exp $
*/

#define CFG_MAX_GROUPS 128

struct config
{
  char *acct_file;
  char *dump_file;
  char *dbg_file;
  char *pid_file;
  char *acct_format;
  char *date_format;
  int flush; /* in seconds */
  int fdelay; /* in seconds */
  int err_delay; /* how many cycles to delay on error ? */
  int mcast_group[CFG_MAX_GROUPS];
  int output, debug; /* bitmasks */
  size_t so_rcvbuf;
  size_t so_rcvbuf_max;
  unsigned int hash_table_size;
  unsigned int hash_mask;
  unsigned int hash_initval;
  int logger_nice_value;
  char empty_iface[32];
  char empty_prefix[32];
  size_t buffsz;
};

extern struct config *cfg; 

extern int acct_file;
extern int dump_file;
extern int dbg_file;

extern char *fname;

#define DEFAULT_CONFFILE "/etc/nflog-acctd.conf"
#define DEFAULT_DATEFORMAT "%d/%m/%y %H:%M:%S"

/* default settings for naccttab */
#define DEFAULT_FLUSH 300
#define DEFAULT_ERR_DELAY 3
#define DEFAULT_FDELAY 60

#define FORCE_STAT_TIME 5

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define NFLOG_BUFSIZE_DEFAULT	150000

#define VERSION "0.4.4"

/* config.c */
struct config *read_config(char *fname);
