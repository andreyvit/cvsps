/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef _COMMON_RCSID_H
#define _COMMON_RCSID_H

/* RCS Id macro (complements of bod@compusol.com.au (Brendan O'Dea)) */
#ifdef lint
# define RCSID(i)
#else /* lint */
# ifdef __GNUC__
#  define ATTRIB_UNUSED __attribute__ ((unused))
# else /* __GNUC__ */
#  define ATTRIB_UNUSED
# endif /* __GNUC__ */
# define RCSID(i) static char const *rcsid ATTRIB_UNUSED = (i)
#endif /* lint */

#endif /* _COMMON_RCSID_H */
