/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

/**
 * Copyright (c) 1998 Cobite, Inc. All Rights Reserved.
 * @author Karl LaRocca
 * @created Fri Nov  6 14:33:29 1998
 * @version $Revision: 1.9 $$Date: 2001/10/25 18:36:11 $
 */
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "text_util.h"
#include "rcsid.h"

RCSID("$Id: text_util.c,v 1.9 2001/10/25 18:36:11 adam Exp $");

char* 
chop( char* src )
{
  char* p = src + strlen(src) - 1;

  while( p >= src )
  {
    if ( *p == '\n' || *p == '\r' )
    {
      *p-- = 0;
    } 

    else
    {
      break;
    }
  }

  return( src );
}

char*
digits( char* src )
{
  char* start = src;
  char* check = src;

  while( *check )
  {
    if ( isdigit( *check ) )
    {
      *start++ = *check;
    }

    check++;
  }

  *start = 0;

  return( src );
}

char* 
lower_case( char* src )
{
  char* p = src;

  while( *p )
  {
      *p = tolower( *p );
      p++;
  }

  return( src );
}

char*
reverse( char* src )
{
  int  i;
  int  len = strlen( src );
  char tmp;

  for( i = len / 2; --i >= 0; )
  {
    tmp = src[ i ];
    src[ i ] = src[ len - i - 1 ];
    src[ len - i - 1 ] = tmp;
  }

  return( src );
}

char* 
trim( char* src )
{
  char *p = src + strlen(src) - 1;

  while( p >= src && isspace(*p) )
      *p-- = '\0';

  return src;
}

char* 
upper_case( char* src )
{
  char* p = src;

  while( *p )
  {
    *p = toupper(*p);
    p++;
  }

  return( src );
}

int
strrcmp( const char* haystack, const char* needle )
{
    int hlen = strlen( haystack );
    int nlen = strlen( needle );
    if( hlen < nlen )
	return( -1 );
    else 
	return( strcmp( haystack + hlen - nlen, needle ) );
}

/* 
 * Finding a - anywhere in the string makes it money negative. 
 * all characters other than digits, '-', and '.' are ignored, so:
 * ab36-.g98 = -36.98
 * This is fair, I think, if we don't want to reject anything as 
 * improperly formatted.
 */
long 
money2cents( const char* money )
{
    long retval = 0;
    int decimal_places = -1;
    int neg = 0;

    while( *money && decimal_places < 2 )
    {
	if ( isdigit( *money ) )
	{
	    if ( decimal_places >= 0 )
		decimal_places++;

	    retval *= 10;
	    retval += (*money) - '0';
	}
	
	else if ( *money == '.' )
	    decimal_places = 0;

	else if ( *money == '-' )
	    neg = 1;

	money++;
    }
    
    if ( decimal_places == 1 )
	retval *= 10;
    
    else if ( decimal_places <= 0 )
	retval *= 100;
    
    return( neg ? -retval : retval );
}

const char* 
cents2money( long cents )
{
  static char buff[ 64 ];
  int idx = 0; 
  char* d = buff;

  if ( cents == 0 )
  {
    strcpy( buff, "0.00" );
  }

  else if ( cents < 100 )
  {
    sprintf( buff, "0.%2.2ld", cents );
  }

  else
  {
    while( cents > 0 )
    {
      *d++ = '0' + ( cents % 10 );
      cents = cents / 10;
      
      if ( idx == 1 )
      {
	*d++ = '.';
      }
      
      else if ( cents > 0 && ( idx - 1 ) % 3 == 0 )
      {
	*d++ = ',';
      }
      
      idx++;
    }

    *d++ = 0;
  
    reverse( buff );
  }

  return( buff );
}

void trim_zeros_after_decimal( char* src )
{
    char * end = src + strlen( src ) - 1;

    while( end != src )
    {
	if( *end == '0' )
	    *end = 0;
	else if( *end == '.' )
	{
	    *end = 0;
	    break;
	}
	else
	    break;

	end--;
    }
}

#ifdef linux
extern void *memfrob(void *, size_t);
#else
static void * memfrob(void * mem, size_t len)
{
    size_t i;
    char *c = (char *)mem;

    for (i = 0; i < len; i++)
    {
	*c = *c ^ 42;
	c++;
    }

    return mem;
}
#endif

// simple functions to obfuscate strings in a binary
char* frobstr( char* src )
{
    char* retval = (char*)malloc( strlen(src) * 2 + 1 );

    memfrob( src, strlen( src ) );
    str2hex( retval, src, 0 );
    memfrob( src, strlen( src ) );

    return( retval );
}

char* unfrobstr( char* src )
{
    int slen = strlen( src ) / 2;
    char* retval = (char*)malloc( slen + 1 );

    hex2str( retval, src, 0 );
    memfrob( retval, slen );

    return( retval );
}

void str2hex( char* dest, const char* src, int slen )
{
    int i;
    char* p = dest;

    if( slen == 0 )
	slen = strlen( src );

    for ( i = 0; i < slen; i++ )
    {
	sprintf( p, "%02x", src[i] );
	p += 2;
    }
    
    *p = 0;
}

void hex2str( char* dest, const char* src, int slen )
{
    const char* p = src;
    int i;
    unsigned int v;

    if( slen == 0 )
	slen = strlen( src );

    slen /= 2;

    for( i = 0; i < slen; i++ )
    {
	sscanf( p, "%02x", &v );
	dest[i] = (char)v;
	p += 2;
    }
    
    dest[ slen ] = 0;
}

