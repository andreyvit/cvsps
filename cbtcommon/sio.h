/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef _SIO_H
#define _SIO_H

/* include for typedefs */
#ifdef WIN32
#include <stdio.h>
typedef int ssize_t;
#else
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif
/* these are W.R.Stevens' famous io routines to read or write bytes to fd */
ssize_t readn(int, void *, size_t);
ssize_t writen(int, const void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _SIO_H */
