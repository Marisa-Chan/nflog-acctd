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


  Utility functions

  $Id: utils.c,v 1.3 2003/04/01 21:53:08 bengen Exp $
*/

#include <stdio.h>
#include <stdarg.h>

/*
  Return a formatted string. Useful for DEBUG macro
*/
char* my_sprintf(char *fmt, ...)
{
  static char tmpstring[255];
  va_list argp;
  va_start(argp, fmt);
  vsnprintf(tmpstring, sizeof(tmpstring), fmt, argp);
  va_end(argp);
  return tmpstring;
}

/*
  Compares two MAC address strings
*/
int mac_equals(unsigned char mac1_len, unsigned char mac1[], 
	       unsigned char mac2_len, unsigned char mac2[])
{
  unsigned char i;
  if (mac1_len != mac2_len)
    return 0;
  for (i=0;i<mac1_len;i++)
    {
      if (mac1[i] != mac2[i])
	return 0;
    }
  return 1;
}
