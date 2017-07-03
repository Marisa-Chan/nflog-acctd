/*
  nflog-acctd

  (C) 2002 Hilko Bengen (original ulog-acctd)
  (C) 2017 Iarcev Anton

  $Id: utils.h,v 1.2 2002/12/17 03:14:38 bengen Exp $
*/

char* my_sprintf(char *fmt, ...);
int mac_equals(unsigned char, unsigned char[], unsigned char, unsigned char[]);
