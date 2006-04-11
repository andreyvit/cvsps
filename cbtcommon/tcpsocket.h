/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef _TCPSOCKET_H
#define _TCPSOCKET_H

#ifdef __cplusplus
extern "C" 
{
#endif

#ifndef LISTEN_QUEUE_SIZE
#define LISTEN_QUEUE_SIZE 5
#endif

#define REUSE_ADDR        1
#define NO_REUSE_ADDR     0

int tcp_create_socket(int reuse_addr);
int tcp_bind_and_listen(int sockfd, unsigned short tcpport);
int tcp_accept_connection(int sockfd);
unsigned int tcp_get_client_ip(int fd);
int tcp_connect(int sockfd, const char *rem_addr, unsigned short port);
int convert_address(long *dest, const char *addr_str);
int tcp_get_local_address(int sockfd, unsigned int *, unsigned short *);

#ifdef __cplusplus
}
#endif

#endif /* TCPSOCKET_H */
