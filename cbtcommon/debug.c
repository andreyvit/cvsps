/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>

#include "debug.h"
#include "rcsid.h"

#ifdef _WIN32
#include <windows.h>
#endif

RCSID("$Id: debug.c,v 1.14 2001/11/29 00:00:30 amb Exp $");

unsigned int debuglvl = ~0;
static FILE *debug_output_channel[DEBUG_NUM_FACILITIES];

#ifdef MACINTOSH
int ffs( int val )
{
    int i = 0;
    for( i = 0; i < 32; i++ )
    {
	if( val & ( 1 << i ) )
	    return i+1;
    }
    return 0;
}
#endif

void vdebug(int dtype, const char *fmt, va_list ap)
{
  int  keep_errno;   
  char msgbuff[8192];

  /* errno could be changed by vsprintf or perror */
  keep_errno = errno;

  if (debuglvl & dtype)
  {
      FILE * channel = debug_output_channel[ffs(dtype)];

      if (!channel)
	  channel = stderr;

#ifdef MACINTOSH
      vsprintf(msgbuff, fmt, ap);
#else
      vsnprintf(msgbuff, sizeof(msgbuff), fmt, ap);
#endif

      /* DEBUG_ERROR (aka DEBUG_SYSERROR) */
      if (dtype == DEBUG_ERROR)
      {
	  const char * errmsg = "";

#ifndef MACINTOSH
	  errmsg = strerror(errno);
#endif

	  fprintf(channel, "%s: %s\n", msgbuff, errmsg);
      }
      else
	  fprintf(channel, "%s\n", msgbuff);
      
      fflush(channel);
#ifdef _WIN32
      if (dtype == DEBUG_SYSERROR || dtype == DEBUG_APPERROR)
	  MessageBox(NULL, msgbuff, "Application Error", MB_OK);
#endif
  }
  
  errno = keep_errno;
}

void vmdebug(int dtype, const char * fmt, va_list ap)
{
    FILE * chn[DEBUG_NUM_FACILITIES];
    int i;

    memcpy(chn, debug_output_channel, sizeof(FILE*) * DEBUG_NUM_FACILITIES);

    for (i = 0; i < DEBUG_NUM_FACILITIES; i++)
	if (chn[i] == NULL)
	    chn[i] = stderr;

    for (i = 0; i < DEBUG_NUM_FACILITIES; i++)
    {
	if ((dtype & (1 << i)) && chn[i])
	{

	    if (debuglvl & (1 << i))
	    {
		int j; 

		vdebug(1 << i, fmt, ap);
		
		for (j = i + 1; j < DEBUG_NUM_FACILITIES; j++)
		    if (chn[j] == chn[i])
			chn[j] = NULL;
	    }
	}
    }
}

/* FIXME: use actual debug output core routine vdebug... */
void hexdump(const char *ptr, int size, const char *fmt, ...) 
{
    static char hexbuff[49];
    static char printbuff[17];
    int count = 0;
    va_list ap;
    
    if ( !debuglvl & DEBUG_STATUS )
	return;
    
    va_start(ap, fmt);
    
    /* print the heading/banner */
    vdebug(DEBUG_STATUS, fmt, ap);
    
    memset(hexbuff, 0, 49);
    memset(printbuff, 0, 17);
    
    while (size--) 
    {
	sprintf(hexbuff + (count*3), "%02x ", (int)*((unsigned char *)ptr));
	
	if (isprint(*ptr))
	    printbuff[count] = *ptr;
	else
	    printbuff[count] = '.';
	
	ptr++;
	
	if ( count++ == 15 ) 
	{
	    count = 0;
	    debug(DEBUG_STATUS, "%s %s", hexbuff, printbuff);
	    memset(hexbuff, 0, 49);
	    memset(printbuff, 0, 17);
	}
    }
    
    if ( count > 0 ) {
	while ( count % 16 != 0 ) {
	    sprintf(hexbuff + (count * 3), "xx ");
	    printbuff[count++] = '.';
	}
	debug(DEBUG_STATUS, "%s %s", hexbuff, printbuff);
    }
    
    va_end(ap);
}

void
to_hex( char* dest, const char* src, size_t n )
{
    while ( n-- ) 
    {
	sprintf( dest, "%02x ", (int)*((unsigned char *)src));
	dest += 3;
	src++;
    }
    
    *dest = 0;
}

void debug_set_error_file(FILE *f)
{
    int i;
    for (i = 0; i < DEBUG_NUM_FACILITIES; i++)
	debug_output_channel[i] = f;
}

void debug_set_error_facility(int fac, FILE * f)
{
    int i;

    for (i = 0; i < DEBUG_NUM_FACILITIES; i++)
	if (!debug_output_channel[i])
	    debug_output_channel[i] = stderr;

    debug_output_channel[ffs(fac)] = f;
}
