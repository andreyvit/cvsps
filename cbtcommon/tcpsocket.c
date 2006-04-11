/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifdef SOLARIS
#include <strings.h>
#else
#include <string.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#else /* not windows */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#ifdef SOLARIS
#include <netinet/tcp.h>
#endif

#endif /* if windows */

#include "tcpsocket.h"
#include "debug.h"
#include "rcsid.h"
#ifdef WIN32
#include "win32fd.h"
#endif

RCSID("$Id: tcpsocket.c,v 1.6 1999/12/27 20:35:34 david Exp $");

int
tcp_create_socket(int reuse_addr)
{
  int retval;
  int yes = 1;

  if ((retval = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    debug(DEBUG_ERROR, "tcp: can't create socket");
  }

  if (reuse_addr)
  {
    setsockopt( retval, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(int));
  }

  debug(DEBUG_TCP, "tcp: socket created");
#ifdef WIN32
  return get_fd(retval, WIN32_SOCKET);
#else
  return retval;
#endif
}

int
tcp_bind_and_listen(int sockfd, unsigned short tcp_port)
{
  struct sockaddr_in addr;

  memset((char *) &addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port        = htons(tcp_port);

#ifdef WIN32
  sockfd = win32_file_table[sockfd].win32id;
#endif

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    debug(DEBUG_ERROR, "tcp: can't bind to socket");
    return -1;
  }


  if (listen(sockfd, LISTEN_QUEUE_SIZE) < 0)
  {
    debug(DEBUG_ERROR, "tcp: can't listen on socket");
    return -1;
  }

  debug(DEBUG_TCP, "tcp: socket bound and listening");

  return 0;
}

int
tcp_accept_connection(int sockfd)
{
  struct sockaddr_in remaddr;
  int addrlen;
  int retval;

#ifdef WIN32
  sockfd = win32_file_table[sockfd].win32id;
#endif

  addrlen = sizeof(struct sockaddr_in);

#ifdef WIN32
  if ((retval = accept(sockfd, (struct sockaddr *) &remaddr, &addrlen)) == INVALID_SOCKET)
  {
	  debug(DEBUG_APPERROR, "tcp: error accepting connection");
	  return -1;
  }
#else
  if ((retval = accept(sockfd, (struct sockaddr *) &remaddr, &addrlen)) < 0)
  {
    if (errno != EINTR )
      debug(DEBUG_ERROR, "tcp: error accepting connection");

    return -1;
  }
#endif

  debug(DEBUG_TCP, "tcp: got connection (fd=%d)", retval);

  return retval;
}

unsigned int
tcp_get_client_ip(int fd)
{
  struct sockaddr_in remaddr;
  int addrlen;
  int retval;
  unsigned int saddr;

#ifdef WIN32
  fd = win32_file_table[fd].win32id;
#endif

  addrlen = sizeof(struct sockaddr_in);

  if ((retval = getpeername(fd, (struct sockaddr *) &remaddr, &addrlen)) < 0)
  {
    debug(DEBUG_ERROR, "tcp: error getting remote's ip address");
    return 0;
  }

  saddr = ntohl(remaddr.sin_addr.s_addr);

  return saddr;
}

int
tcp_connect(int sockfd, const char *rem_addr, unsigned short port)
{
  struct sockaddr_in addr;
  int addrlen;
  long ipno;

#ifdef WIN32
  sockfd = win32_file_table[sockfd].win32id;
#endif

  if ( convert_address(&ipno , rem_addr) < 0 )
  {
    return -1;
  }

  addrlen = sizeof(struct sockaddr_in);

  memset((char *) &addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = ipno;
  addr.sin_port        = htons(port);

  if (connect(sockfd, (struct sockaddr *)&addr, addrlen) < 0)
  {
    debug(DEBUG_ERROR, "connect error");
    return -1;
  }
  
  debug(DEBUG_STATUS, "tcp: connection established on port %d", port);
  return 0;
}

int
convert_address(long *dest, const char *addr_str)
{
#ifdef LINUX
  struct in_addr ip;
#endif
  int retval = 0;
  char errstr[256];
  
  /* first try converting "numbers and dots" notation */
#ifdef LINUX
  if ( inet_aton(addr_str, &ip) )
  {
    memcpy(dest, &ip.s_addr, sizeof(ip.s_addr));
  }
#else
  if ( (*dest = inet_addr(addr_str)) != -1)
  {
    /* nothing */
  }
#endif
  else   /* if it fails, do a gethostbyname() */
  {
    struct hostent *host;
    if ((host = gethostbyname(addr_str)) == NULL)
    {
      switch(h_errno)
      {
      case HOST_NOT_FOUND:
	strcpy(errstr, "HOST_NOT_FOUND");
	break;

      case NO_ADDRESS:
	strcpy(errstr, "NO_ADDRESS");
	break;

      case NO_RECOVERY:
	strcpy(errstr, "NO_RECOVERY");
	break;

      case TRY_AGAIN:
	strcpy(errstr, "TRY_AGAIN");
	break;
      }
      
      debug(DEBUG_ERROR, "gethostbyname failed for %s: ", addr_str, errstr);

      retval = -1;
    }
    
    memcpy(dest, host->h_addr_list[0], sizeof(unsigned long));
  }
  
  
  return retval;
}

int tcp_get_local_address(int sockfd, unsigned int *ip, unsigned short *port)
{
    struct sockaddr_in addr;
    int addrlen = sizeof(struct sockaddr_in);
  
    if(getsockname(sockfd, (struct sockaddr *)&addr, &addrlen) < 0)
    {
	debug(DEBUG_SYSERROR, "getsockname failed" );  
	return -1;
    }

    *ip = ntohl( addr.sin_addr.s_addr );
    *port = ntohs( addr.sin_port );
  
    return 0;
}
