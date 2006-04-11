/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>

#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include <errno.h>

#include "sio.h"
#include "rcsid.h"

RCSID("$Id: sio.c,v 1.5 2001/10/25 18:36:11 adam Exp $");

ssize_t readn(int fd, void *buf, size_t len)
{

  int nleft,nread;

  nleft = len;

  while (nleft > 0)
  {
    nread = read(fd,buf,nleft);

    /* there is an issue which EINTR which could leave us a bit haywire
     * if we get a signal after having read some bytes. special handling
     * N.B: we *do* return EINTR if no data has been read yet (thanks Karl)
     */
    if (nread < 0)
    {
      if (errno == EINTR && nleft != (int)len)
        continue;
      else
	    return (nread);
    }
    else if (nread == 0)
      break;

    nleft -= nread;

    if (nleft)
      buf = ((char *)buf) + nread;
  }
  return (len - nleft);
}

ssize_t writen(int fd, const void *buf, size_t len)
{
  
  int nleft, nwritten;

  nleft = len;

  while (nleft > 0)
  {
    nwritten = write(fd,buf,nleft);

    /* there is an issue with EINTR if we have already written
       a few bytes! return if we have not written any yet */
    if (nwritten < 0 && errno == EINTR)
    {
      if (nleft == (int)len)
	return nwritten;
      
      continue;
    }
    

    if (nwritten <= 0)
      return nwritten;

    nleft -= nwritten;

    if (nleft)
      buf = ((char *)buf) + nwritten;
  }
  
  return (len - nleft);
}

