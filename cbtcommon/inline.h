/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef UTIL_INLINE_H
#define UTIL_INLINE_H

#ifdef __GNUC__
#define INLINE __inline__
#endif

#ifdef WIN32
#define INLINE __inline
#endif

/* INLINE of last resort... heh */

#ifndef INLINE
#define INLINE /* void */
#endif

#endif
