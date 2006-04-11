/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

/**
 * Copyright (c) 1998 Cobite, Inc. All Rights Reserved.
 * @author Karl LaRocca
 * @created Fri Nov  6 14:48:04 1998
 * @version $Revision: 1.4 $$Date: 2001/10/25 18:36:11 $
 */
#ifndef _TEXT_UTIL_H
#define _TEXT_UTIL_H

#ifdef __cplusplus
extern "C"
{
#endif

char*       chop( char* src );
char*       digits( char* src );
char*       lower_case( char* src );
char*       reverse( char* src );
char*       trim( char* src );
void        trim_zeros_after_decimal( char* src );
char*       upper_case( char* src );
int         strrcmp( const char* haystack, const char* needle );

const char* cents2money( long cents );
long        money2cents( const char* money );

// these two allocate returned memory, so be sure to free it...
char*       frobstr( char* src );
char*       unfrobstr( char* src );

void        str2hex( char* dest, const char* src, int slen );
void        hex2str( char* dest, const char* src, int slen );

#ifdef __cplusplus
}
#endif

#endif /* _TEXT_UTIL_H */
