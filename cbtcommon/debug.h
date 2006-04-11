/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <stdarg.h>
#ifndef MACINTOSH
#include <sys/types.h>
#endif

#include "inline.h"

#define DEBUG_NUM_FACILITIES  32 /* should be 64 on 64bit CPU... */
#define DEBUG_SYSERROR  1  /* same as DEBUG_ERROR, but here for clarity */
#define DEBUG_ERROR     1
#define DEBUG_STATUS    2
#define DEBUG_TCP       4
#define DEBUG_SIGNALS   8
#define DEBUG_APPERROR  16
#define DEBUG_APPMSG1   32
#define DEBUG_APPMSG2   64
#define DEBUG_APPMSG3   128
#define DEBUG_APPMSG4   256
#define DEBUG_APPMSG5   512
#define DEBUG_LIBERROR  1024
#define DEBUG_LIBSTATUS 2048

#ifdef __cplusplus
extern "C" 
{
#endif

extern unsigned int debuglvl;

void hexdump( const char *ptr, int size, const char *fmt, ... );
void vdebug(int dtype, const char *fmt, va_list);
void vmdebug(int dtype, const char *fmt, va_list);
void to_hex( char* dest, const char* src, size_t n );
void debug_set_error_file(FILE *);
void debug_set_error_facility(int mask, FILE *);

static INLINE void debug(unsigned int dtype, const char *fmt, ...)
{
    va_list ap;
    
    if (!(debuglvl & dtype))
	return;
    
    va_start(ap, fmt);
    vdebug(dtype, fmt, ap);
    va_end(ap);
}

static INLINE void mdebug(unsigned int dtype, const char *fmt, ...)
{
    va_list ap;
    
    if (!(debuglvl & dtype))
	return;
    
    va_start(ap, fmt);
    vmdebug(dtype, fmt, ap);
    va_end(ap);
}

#ifdef __cplusplus
}
#endif


#endif /* DEBUG_H */
