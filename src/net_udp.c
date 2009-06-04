/*
 * FILE:     net_udp.c
 * AUTHOR:   Colin Perkins 
 * MODIFIED: Orion Hodson, Piers O'Hanlon, Kristian Hasler
 * 
 * Copyright (c) 1998-2000 University College London
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions 
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* If this machine supports IPver6 the symbol HAVE_IPv6 should */
/* be defined in either config_unix.h or config_win32.h. The */
/* appropriate system header files should also be included   */
/* by those files.                                           */

#include "config_unix.h"
#include "config_win32.h"
#include "debug.h"
#include "memory.h"
#include "inet_pton.h"
#include "inet_ntop.h"
#include "vsnprintf.h"
#include "net_udp.h"

#ifdef NEED_ADDRINFO_H
#include "addrinfo.h"
#endif

#define IPver4	4
#define IPver6	6

#ifdef WIN2K_IPV6
const struct	in6_addr	in6addr_any = {IN6ADDR_ANY_INIT};
#endif

/* This is pretty nasty but it's the simplest way to get round */
/* the Detexis bug that means their MUSICA IPver6 stack uses     */
/* IPPROTO_IP instead of IPPROTO_IPV6 in setsockopt calls      */
/* We also need to define in6addr_any */
#ifdef  MUSICA_IPV6
#define	IPPROTO_IPV6	IPPROTO_IP
struct	in6_addr	in6addr_any = {IN6ADDR_ANY_INIT};

/* These DEF's are required as MUSICA's winsock6.h causes a clash with some of the 
 * standard ws2tcpip.h definitions (eg struct in_addr6).
 * Note: winsock6.h defines AF_INET6 as 24 NOT 23 as in winsock2.h - I have left it
 * set to the MUSICA value as this is used in some of their function calls. 
 */
//#define AF_INET6        23
#define IP_MULTICAST_LOOP      11 /*set/get IP multicast loopback */
#define	IP_MULTICAST_IF		9 /* set/get IP multicast i/f  */
#define	IP_MULTICAST_TTL       10 /* set/get IP multicast ttl */
#define	IP_MULTICAST_LOOP      11 /*set/get IP multicast loopback */
#define	IP_ADD_MEMBERSHIP      12 /* add an IP group membership */
#define	IP_DROP_MEMBERSHIP     13/* drop an IP group membership */

#define IN6_IS_ADDR_UNSPECIFIED(a) (((a)->s6_addr32[0] == 0) && \
									((a)->s6_addr32[1] == 0) && \
									((a)->s6_addr32[2] == 0) && \
									((a)->s6_addr32[3] == 0))
struct ip_mreq {
	struct in_addr imr_multiaddr;	/* IP multicast address of group */
	struct in_addr imr_interface;	/* local IP address of interface */
};
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

struct _socket_udp {
	int	 	 mode;	/* IPver4 or IPver6 */
        char	        *addr;
	uint16_t	 rx_port;
	uint16_t	 tx_port;
	ttl_t	 	 ttl;
	fd_t	 	 fd;
	struct in_addr	 addr4;
#ifdef HAVE_IPv6
	struct in6_addr	 addr6;
#endif /* HAVE_IPv6 */
    struct in_addr	iface_addr;
};

#ifdef WIN32

#include <Iphlpapi.h>

/* Want to use both Winsock 1 and 2 socket options, but since
* IPver6 support requires Winsock 2 we have to add own backwards
* compatibility for Winsock 1.
*/
#define SETSOCKOPT winsock_versions_setsockopt
#define CLOSE closesocket
#else
#define SETSOCKOPT setsockopt
#define CLOSE close
#endif /* WIN32 */

/*****************************************************************************/
/* Support functions...                                                      */
/*****************************************************************************/

static void
socket_error(const char *msg, ...)
{
	char		buffer[255];
	uint32_t	blen = sizeof(buffer) / sizeof(buffer[0]);
	va_list		ap;

#ifdef WIN32
#define WSERR(x) {#x,x}
	struct wse {
		char  errname[20];
		int my_errno;
	};
	struct wse ws_errs[] = {
		WSERR(WSANOTINITIALISED), WSERR(WSAENETDOWN),     WSERR(WSAEACCES),
		WSERR(WSAEINVAL),         WSERR(WSAEINTR),        WSERR(WSAEINPROGRESS),
		WSERR(WSAEFAULT),         WSERR(WSAENETRESET),    WSERR(WSAENOBUFS),
		WSERR(WSAENOTCONN),       WSERR(WSAENOTSOCK),     WSERR(WSAEOPNOTSUPP),
		WSERR(WSAESHUTDOWN),      WSERR(WSAEWOULDBLOCK),  WSERR(WSAEMSGSIZE),
		WSERR(WSAEHOSTUNREACH),   WSERR(WSAECONNABORTED), WSERR(WSAECONNRESET),
		WSERR(WSAEADDRNOTAVAIL),  WSERR(WSAEAFNOSUPPORT), WSERR(WSAEDESTADDRREQ),
		WSERR(WSAENETUNREACH),    WSERR(WSAETIMEDOUT),    WSERR(0)
	};
	
	int i, e = WSAGetLastError();
	i = 0;
	while(ws_errs[i].my_errno && ws_errs[i].my_errno != e) {
		i++;
	}
	va_start(ap, msg);
	_vsnprintf(buffer, blen, msg, ap);
	va_end(ap);
	printf("ERROR: %s, (%d - %s)\n", msg, e, ws_errs[i].errname);
#else
	va_start(ap, msg);
	vsnprintf(buffer, blen, msg, ap);
	va_end(ap);
	perror(buffer);
#endif
}

#ifdef WIN32
/* ws2tcpip.h defines these constants with different values from
* winsock.h so files that use winsock 2 values but try to use 
* winsock 1 fail.  So what was the motivation in changing the
* constants ?
*/
#define WS1_IP_MULTICAST_IF     2 /* set/get IP multicast interface   */
#define WS1_IP_MULTICAST_TTL    3 /* set/get IP multicast timetolive  */
#define WS1_IP_MULTICAST_LOOP   4 /* set/get IP multicast loopback    */
#define WS1_IP_ADD_MEMBERSHIP   5 /* add  an IP group membership      */
#define WS1_IP_DROP_MEMBERSHIP  6 /* drop an IP group membership      */

/* winsock_versions_setsockopt tries 1 winsock version of option 
* optname and then winsock 2 version if that failed.
* note: setting the TTL never fails, so we have to try both.
*/

static int
winsock_versions_setsockopt(SOCKET s, int level, int optname, const char FAR * optval, int optlen)
{
	int success = -1;
	switch (optname) {
	case IP_MULTICAST_IF:
		success = setsockopt(s, level, WS1_IP_MULTICAST_IF, optval, optlen);
		break;
	case IP_MULTICAST_TTL:
		success = setsockopt(s, level, WS1_IP_MULTICAST_TTL, optval, optlen);
		success = setsockopt(s, level, optname, optval, optlen);
		break;
	case IP_MULTICAST_LOOP:
		success = setsockopt(s, level, WS1_IP_MULTICAST_LOOP, optval, optlen);
		break;
	case IP_ADD_MEMBERSHIP: 
		success = setsockopt(s, level, WS1_IP_ADD_MEMBERSHIP, optval, optlen);
		break;
	case IP_DROP_MEMBERSHIP: 
		success = setsockopt(s, level, WS1_IP_DROP_MEMBERSHIP, optval, optlen);
		break;
	}
	if (success != -1) {
		return success;
	}
	return setsockopt(s, level, optname, optval, optlen);
}
#endif

#ifdef NEED_INET_ATON
#ifdef NEED_INET_ATON_STATIC
static 
#endif
int inet_aton(const char *name, struct in_addr *addr)
{
	addr->s_addr = inet_addr(name);
	return (addr->s_addr != (in_addr_t) INADDR_NONE);
}
#endif

#ifdef NEED_IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(addr) ((addr)->s6_addr[0] == 0xffU)
#endif

#if defined(NEED_IN6_IS_ADDR_UNSPECIFIED) && defined(MUSICA_IPV6)
#define IN6_IS_ADDR_UNSPECIFIED(addr) IS_UNSPEC_IN6_ADDR(*addr)
#endif



/*****************************************************************************/
/* IPver4 specific functions...                                                */
/*****************************************************************************/

static int udp_addr_valid4(const char *dst)
{
        struct in_addr addr4;
	struct hostent *h;

	if (INET_PTON(AF_INET, dst, &addr4)) {
		return TRUE;
	} 

	h = gethostbyname(dst);
	if (h != NULL) {
		return TRUE;
	}
	socket_error("Can't resolve IP address for %s", dst);

        return FALSE;
}

uint32_t    udp_socket_addr4(socket_udp *s)
{
  if (s == NULL) {
    return 0;
  }

  if (s->mode != IPver4) {
    return 0;
  }

  return (uint32_t)(s->addr4.s_addr);  
}

uint16_t    udp_socket_txport(socket_udp *s)
{
	if (s == NULL) {
		return 0;
	}

	return s->tx_port;
}

int udp_socket_ttl(socket_udp *s)
{
	if (s == NULL) {
		return -1;
	}

	return s->ttl;
}

static socket_udp *udp_init4(const char *addr, const char *iface, uint16_t rx_port, uint16_t tx_port, int ttl)
{
	int                 	 reuse = 1, udpbufsize=131072;
	struct sockaddr_in  	 s_in;

#ifdef WIN32
      int recv_buf_size = 65536;
#endif
	socket_udp         	*s = (socket_udp *)malloc(sizeof(socket_udp));
	s->mode    = IPver4;
	s->addr    = NULL;
	s->rx_port = rx_port;
	s->tx_port = tx_port;
	s->ttl     = ttl;
	
	if (INET_PTON(AF_INET, addr, &s->addr4) != 1) {
		struct hostent *h = gethostbyname(addr);
		if (h == NULL) {
			socket_error("Can't resolve IP address for %s", addr);
                        free(s);
			return NULL;
		}
		memcpy(&(s->addr4), h->h_addr_list[0], sizeof(s->addr4));
	}
	if (iface != NULL) {
		if (INET_PTON(AF_INET, iface, &s->iface_addr) != 1) {
			debug_msg("Illegal interface specification\n");
                        free(s);
			return NULL;
		}
	} else {
		s->iface_addr.s_addr = 0;
	}
	s->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (s->fd < 0) {
		socket_error("socket");
		return NULL;
	}
	if (SETSOCKOPT(s->fd, SOL_SOCKET, SO_SNDBUF, (char *) &udpbufsize, sizeof(udpbufsize)) != 0) {
		socket_error("setsockopt SO_SNDBUF");
		return NULL;
	}
	if (SETSOCKOPT(s->fd, SOL_SOCKET, SO_RCVBUF, (char *) &udpbufsize, sizeof(udpbufsize)) != 0) {
		socket_error("setsockopt SO_RCVBUF");
		return NULL;
	}
	if (SETSOCKOPT(s->fd, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse, sizeof(reuse)) != 0) {
		socket_error("setsockopt SO_REUSEADDR");
		return NULL;
	}
#ifdef SO_REUSEPORT
	if (SETSOCKOPT(s->fd, SOL_SOCKET, SO_REUSEPORT, (char *) &reuse, sizeof(reuse)) != 0) {
		socket_error("setsockopt SO_REUSEPORT");
		return NULL;
	}
#endif
	s_in.sin_family      = AF_INET;
	s_in.sin_addr.s_addr = INADDR_ANY;
	s_in.sin_port        = htons(rx_port);
	if (bind(s->fd, (struct sockaddr *) &s_in, sizeof(s_in)) != 0) {
		socket_error("bind");
		return NULL;
	}
	if (IN_MULTICAST(ntohl(s->addr4.s_addr))) {
		char            loop = 1;
		struct ip_mreq  imr;
		
		imr.imr_multiaddr.s_addr = s->addr4.s_addr;
		imr.imr_interface.s_addr = s->iface_addr.s_addr;
		
		if (SETSOCKOPT(s->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &imr, sizeof(struct ip_mreq)) != 0) {
			socket_error("setsockopt IP_ADD_MEMBERSHIP");
			return NULL;
		}
#ifndef WIN32
		if (SETSOCKOPT(s->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) != 0) {
			socket_error("setsockopt IP_MULTICAST_LOOP");
			return NULL;
		}
#endif
		if (SETSOCKOPT(s->fd, IPPROTO_IP, IP_MULTICAST_TTL, (char *) &s->ttl, sizeof(s->ttl)) != 0) {
			socket_error("setsockopt IP_MULTICAST_TTL");
			return NULL;
		}
		if (s->iface_addr.s_addr != 0) {
			if (SETSOCKOPT(s->fd, IPPROTO_IP, IP_MULTICAST_IF, (char *) &s->iface_addr, sizeof(s->iface_addr)) != 0) {
				socket_error("setsockopt IP_MULTICAST_IF");
				return NULL;
			}
		}
	} else {
		if (SETSOCKOPT(s->fd, IPPROTO_IP, IP_TTL, (char *) &ttl, sizeof(ttl)) != 0) {
			socket_error("setsockopt IP_TTL");
			return NULL;
	}
	}
        s->addr = strdup(addr);
	return s;
}

static void udp_exit4(socket_udp *s)
{
	if (IN_MULTICAST(ntohl(s->addr4.s_addr))) {
		struct ip_mreq  imr;
		imr.imr_multiaddr.s_addr = s->addr4.s_addr;
		imr.imr_interface.s_addr = s->iface_addr.s_addr;

		if (SETSOCKOPT(s->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *) &imr, sizeof(struct ip_mreq)) != 0) {
			socket_error("setsockopt IP_DROP_MEMBERSHIP");
			abort();
		}
		debug_msg("Dropped membership of multicast group\n");
	}
	CLOSE(s->fd);
        free(s->addr);
	free(s);
}

static inline int 
udp_send4(socket_udp *s, char *buffer, int buflen)
{
	struct sockaddr_in	s_in;
	
	assert(s != NULL);
	assert(s->mode == IPver4);
	assert(buffer != NULL);
	assert(buflen > 0);
	
	memset(&s_in, 0, sizeof(struct sockaddr_in));
	s_in.sin_family      = AF_INET;
	s_in.sin_addr.s_addr = s->addr4.s_addr;
	s_in.sin_port        = htons(s->tx_port);
	return sendto(s->fd, buffer, buflen, 0, (struct sockaddr *) &s_in, sizeof(s_in));
}

#ifndef WIN32
static inline int 
udp_sendv4(socket_udp *s, struct iovec *vector, int count)
{
	struct msghdr		msg;
	struct sockaddr_in	s_in;
	
	assert(s != NULL);
	assert(s->mode == IPver4);
	
	s_in.sin_family      = AF_INET;
	s_in.sin_addr.s_addr = s->addr4.s_addr;
	s_in.sin_port        = htons(s->tx_port);

	msg.msg_name       = (caddr_t) &s_in;
	msg.msg_namelen    = sizeof(s_in);
	msg.msg_iov        = vector;
	msg.msg_iovlen     = count;
#ifdef HAVE_MSGHDR_MSGCTRL /* Solaris does something different here... can we just ignore these fields? [csp] */
	msg.msg_control    = 0;
	msg.msg_controllen = 0;
	msg.msg_flags      = 0;
#endif
	return sendmsg(s->fd, &msg, 0);
}
#endif

static const char *udp_host_addr4(void)
{
	static char    		 hname[MAXHOSTNAMELEN];
	struct hostent 		*hent;
	struct in_addr  	 iaddr;
	
	if (gethostname(hname, MAXHOSTNAMELEN) != 0) {
		debug_msg("Cannot get hostname!");
		abort();
	}
	hent = gethostbyname(hname);
	if (hent == NULL) {
		socket_error("Can't resolve IP address for %s", hname);
		return NULL;
	}
	assert(hent->h_addrtype == AF_INET);
	memcpy(&iaddr.s_addr, hent->h_addr, sizeof(iaddr.s_addr));
	strncpy(hname, inet_ntoa(iaddr), MAXHOSTNAMELEN);
	return (const char*)hname;
}

/*****************************************************************************/
/* IPver6 specific functions...                                                */
/*****************************************************************************/

static int udp_addr_valid6(const char *dst)
{
#ifdef HAVE_IPv6
        struct in6_addr addr6;
	switch (INET_PTON(AF_INET6, dst, &addr6)) {
        case 1:  
                return TRUE;
                break;
        case 0: 
                return FALSE;
                break;
        case -1: 
                debug_msg("inet_pton failed\n");
                errno = 0;
        }
#endif /* HAVE_IPv6 */
        UNUSED(dst);
        return FALSE;
}

static socket_udp *udp_init6(const char *addr, const char *iface, uint16_t rx_port, uint16_t tx_port, int ttl)
{
#ifdef HAVE_IPv6
	int                 reuse = 1;
	struct sockaddr_in6 s_in;
	socket_udp         *s = (socket_udp *) malloc(sizeof(socket_udp));
	s->mode    = IPver6;
	s->addr    = NULL;
	s->rx_port = rx_port;
	s->tx_port = tx_port;
	s->ttl     = ttl;
	
	if (iface != NULL) {
		debug_msg("Not yet implemented\n");
		abort();
	}

	if (INET_PTON(AF_INET6, addr, &s->addr6) != 1) {
		/* We should probably try to do a DNS lookup on the name */
		/* here, but I'm trying to get the basics going first... */
		debug_msg("IPver6 address conversion failed\n");
                free(s);
		return NULL;	
	}
	s->fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s->fd < 0) {
		socket_error("socket");
		return NULL;
	}
	if (SETSOCKOPT(s->fd, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse, sizeof(reuse)) != 0) {
		socket_error("setsockopt SO_REUSEADDR");
		return NULL;
	}
#ifdef SO_REUSEPORT
	if (SETSOCKOPT(s->fd, SOL_SOCKET, SO_REUSEPORT, (char *) &reuse, sizeof(reuse)) != 0) {
		socket_error("setsockopt SO_REUSEPORT");
		return NULL;
	}
#endif
	
	memset((char *)&s_in, 0, sizeof(s_in));
	s_in.sin6_family = AF_INET6;
	s_in.sin6_port   = htons(rx_port);
#ifdef HAVE_SIN6_LEN
	s_in.sin6_len    = sizeof(s_in);
#endif
	s_in.sin6_addr = in6addr_any;
	if (bind(s->fd, (struct sockaddr *) &s_in, sizeof(s_in)) != 0) {
		socket_error("bind");
		return NULL;
	}
	
	if (IN6_IS_ADDR_MULTICAST(&(s->addr6))) {
		unsigned int      loop = 1;
		struct ipv6_mreq  imr;
#ifdef MUSICA_IPV6
		imr.i6mr_interface = 1;
		imr.i6mr_multiaddr = s->addr6;
#else
		imr.ipv6mr_multiaddr = s->addr6;
		imr.ipv6mr_interface = 0;
#endif
		
		if (SETSOCKOPT(s->fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *) &imr, sizeof(struct ipv6_mreq)) != 0) {
			socket_error("setsockopt IPV6_ADD_MEMBERSHIP");
			return NULL;
		}
		
		if (SETSOCKOPT(s->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *) &loop, sizeof(loop)) != 0) {
			socket_error("setsockopt IPV6_MULTICAST_LOOP");
			return NULL;
		}
		if (SETSOCKOPT(s->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *) &ttl, sizeof(ttl)) != 0) {
			socket_error("setsockopt IPV6_MULTICAST_HOPS");
			return NULL;
		}
	} else {
		if (SETSOCKOPT(s->fd, IPPROTO_IP, IP_TTL, (char *) &ttl, sizeof(ttl)) != 0) {
			socket_error("setsockopt IP_TTL");
			return NULL;
		}
	}

	assert(s != NULL);

        s->addr = strdup(addr);
	return s;
#else
	UNUSED(addr);
	UNUSED(iface);
	UNUSED(rx_port);
	UNUSED(tx_port);
	UNUSED(ttl);
	return NULL;
#endif
}

static void udp_exit6(socket_udp *s)
{
#ifdef HAVE_IPv6
	if (IN6_IS_ADDR_MULTICAST(&(s->addr6))) {
		struct ipv6_mreq  imr;
#ifdef MUSICA_IPV6
		imr.i6mr_interface = 1;
		imr.i6mr_multiaddr = s->addr6;
#else
		imr.ipv6mr_multiaddr = s->addr6;
		imr.ipv6mr_interface = 0;
#endif
		
		if (SETSOCKOPT(s->fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *) &imr, sizeof(struct ipv6_mreq)) != 0) {
			socket_error("setsockopt IPV6_DROP_MEMBERSHIP");
			abort();
		}
	}
	CLOSE(s->fd);
        free(s->addr);
	free(s);
#else
	UNUSED(s);
#endif  /* HAVE_IPv6 */
}

static int udp_send6(socket_udp *s, char *buffer, int buflen)
{
#ifdef HAVE_IPv6
	struct sockaddr_in6	s_in;
	
	assert(s != NULL);
	assert(s->mode == IPver6);
	assert(buffer != NULL);
	assert(buflen > 0);
	
	memset((char *)&s_in, 0, sizeof(s_in));
	s_in.sin6_family = AF_INET6;
	s_in.sin6_addr   = s->addr6;
	s_in.sin6_port   = htons(s->tx_port);
#ifdef HAVE_SIN6_LEN
	s_in.sin6_len    = sizeof(s_in);
#endif
	return sendto(s->fd, buffer, buflen, 0, (struct sockaddr *) &s_in, sizeof(s_in));
#else
	UNUSED(s);
	UNUSED(buffer);
	UNUSED(buflen);
	return -1;
#endif
}

#ifndef WIN32
static int 
udp_sendv6(socket_udp *s, struct iovec *vector, int count)
{
#ifdef HAVE_IPv6
	struct msghdr		msg;
	struct sockaddr_in6	s_in;
	
	assert(s != NULL);
	assert(s->mode == IPver6);
	
	memset((char *)&s_in, 0, sizeof(s_in));
	s_in.sin6_family = AF_INET6;
	s_in.sin6_addr   = s->addr6;
	s_in.sin6_port   = htons(s->tx_port);
#ifdef HAVE_SIN6_LEN
	s_in.sin6_len    = sizeof(s_in);
#endif
	msg.msg_name       = &s_in;
	msg.msg_namelen    = sizeof(s_in);
	msg.msg_iov        = vector;
	msg.msg_iovlen     = count;
#ifdef HAVE_MSGHDR_MSGCTRL  
	msg.msg_control    = 0;
	msg.msg_controllen = 0;
	msg.msg_flags      = 0;
#endif
	return sendmsg(s->fd, &msg, 0);
#else
	UNUSED(s);
	UNUSED(vector);
	UNUSED(count);
	return -1;
#endif
}
#endif

static const char *udp_host_addr6(socket_udp *s)
{
#ifdef HAVE_IPv6
	static char		 hname[MAXHOSTNAMELEN];
	int 			 gai_err, newsock;
	struct addrinfo 	 hints, *ai;
	struct sockaddr_in6 	 local, addr6;
	uint32_t			len = sizeof(local);
	int					result = 0;

	newsock=socket(AF_INET6, SOCK_DGRAM,0);
    memset ((char *)&addr6, 0, len);
    addr6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
    addr6.sin6_len    = len;
#endif
    bind (newsock, (struct sockaddr *) &addr6, len);
    addr6.sin6_addr = s->addr6;
    addr6.sin6_port = htons (s->rx_port);
    connect (newsock, (struct sockaddr *) &addr6, len);

    memset ((char *)&local, 0, len);
	if ((result = getsockname(newsock,(struct sockaddr *)&local, &len)) < 0){
		local.sin6_addr = in6addr_any;
		local.sin6_port = 0;
		debug_msg("getsockname failed\n");
	}

	CLOSE(newsock);

	if (IN6_IS_ADDR_UNSPECIFIED(&local.sin6_addr) || IN6_IS_ADDR_MULTICAST(&local.sin6_addr)) {
		if (gethostname(hname, MAXHOSTNAMELEN) != 0) {
			debug_msg("gethostname failed\n");
			abort();
		}
		
		hints.ai_protocol  = 0;
		hints.ai_flags     = 0;
		hints.ai_family    = AF_INET6;
		hints.ai_socktype  = SOCK_DGRAM;
		hints.ai_addrlen   = 0;
		hints.ai_canonname = NULL;
		hints.ai_addr      = NULL;
		hints.ai_next      = NULL;

		if ((gai_err = getaddrinfo(hname, NULL, &hints, &ai))) {
			debug_msg("getaddrinfo: %s: %s\n", hname, gai_strerror(gai_err));
			abort();
		}
		
		if (inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)(ai->ai_addr))->sin6_addr), hname, MAXHOSTNAMELEN) == NULL) {
			debug_msg("inet_ntop: %s: \n", hname);
			abort();
		}
		freeaddrinfo(ai);
		return (const char*)hname;
	}
	if (inet_ntop(AF_INET6, &local.sin6_addr, hname, MAXHOSTNAMELEN) == NULL) {
		debug_msg("inet_ntop: %s: \n", hname);
		abort();
	}
	return (const char*)hname;
#else  /* HAVE_IPv6 */
	UNUSED(s);
	return "::";	/* The unspecified address... */
#endif /* HAVE_IPv6 */
}
	
/*****************************************************************************/
/* Generic functions, which call the appropriate protocol specific routines. */
/*****************************************************************************/

/**
 * udp_addr_valid:
 * @addr: string representation of IPver4 or IPver6 network address.
 *
 * Returns TRUE if @addr is valid, FALSE otherwise.
 **/

int udp_addr_valid(const char *addr)
{
        return udp_addr_valid4(addr) | udp_addr_valid6(addr);
}

/*
 * On Windows, determine the name of the interface
 * that will be used for this group.
 *
 * If we don't do this, rat will break on machines
 * with multiple network interfaces.
 */
#ifdef WIN32
/*#include <strsafe.h>

void ErrorExit(LPTSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();
	dw=2;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf)+lstrlen((LPCTSTR)lpszFunction)+40)*sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 
    //MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 
	debug_msg(lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    //ExitProcess(dw); 
}
*/

char *find_win32_interface(const char *addr, int ttl)
{
    struct in_addr inaddr;
	char *iface = 0;


    if (INET_PTON(AF_INET, addr, &inaddr))
    {
		MIB_IPFORWARDROW route;
		DWORD retval;
		DWORD IfIndex;

		memset(&route, 0, sizeof(route));

		if ((retval=GetBestRoute((DWORD)(inaddr.s_addr), 0, &route)) == NO_ERROR)
		{
			IP_ADAPTER_INFO oneinfo;
			PIP_ADAPTER_INFO allinfo = 0;
			int len;
			struct in_addr dst, mask, nexthop;

		    debug_msg("Got BestRoute\n");
			dst.s_addr = route.dwForwardDest;
			mask.s_addr = route.dwForwardMask;
			nexthop.s_addr = route.dwForwardNextHop;

			debug_msg("found route dst=%s mask=%s nexthop=%s ifindex=%d\n",
				inet_ntoa(dst), inet_ntoa(mask), inet_ntoa(nexthop),
				route.dwForwardIfIndex);

			len = sizeof(oneinfo);
			if (GetAdaptersInfo(&oneinfo, &len) == ERROR_SUCCESS)
			{
				debug_msg("got allinfo in one\n");
				allinfo = &oneinfo;
			}
			else
			{
				allinfo = (PIP_ADAPTER_INFO) malloc(len);
				if (GetAdaptersInfo(allinfo, &len) != ERROR_SUCCESS)
				{
					debug_msg("Could not get adapter info\n");
					free(allinfo);
					allinfo = 0;
				}
			}

			if (allinfo)
			{

				PIP_ADAPTER_INFO a;
				{
					for (a = allinfo; a != 0; a = a->Next)
					{

						debug_msg("name='%s' desc='%s' index=%d\n", 
							a->AdapterName, a->Description, a->Index);

						if (a->Index == route.dwForwardIfIndex)
						{
							PIP_ADDR_STRING s;
							/* Take the first address. */

							s = &a->IpAddressList;
							iface = _strdup(s->IpAddress.String);
							debug_msg("Found address '%s'\n", iface);
						}
					}
				}
				free(allinfo);
			}
#if 0 /* This is the stuff that just works on XP, sigh. */
			len = sizeof(addrs);
			if (GetAdaptersAddresses(AF_INET, 0, 0, addrs, &len) == ERROR_SUCCESS)
			{
				PIP_ADAPTER_ADDRESSES a;

				a = addrs;

				while (a && (iface == 0))
				{
					if (a->IfIndex == route.dwForwardIfIndex)
					{
						struct sockaddr_in *sockaddr;
				
						sockaddr = (struct sockaddr_in *) a->FirstUnicastAddress->Address.lpSockaddr;

						debug_msg("name=%s addr=%s\n", 
							a->AdapterName, inet_ntoa(sockaddr->sin_addr));
						iface = _strdup(inet_ntoa(sockaddr->sin_addr));
					}
					a = a->Next;
				}
			}
#endif
		} else {
			debug_msg("GetBestRoute failed (%d) %d - trying GetBestInterface...\n",retval, retval );

			if (0 && GetBestInterface(inaddr.s_addr, &IfIndex) == NO_ERROR)
			{
				IP_ADAPTER_INFO oneinfo;
				PIP_ADAPTER_INFO allinfo = 0;
				int len;
//				struct in_addr dst, mask, nexthop;
//				dst.s_addr = route.dwForwardDest;
//				mask.s_addr = route.dwForwardMask;
//				nexthop.s_addr = route.dwForwardNextHop;

				debug_msg("GotBestInterface IfIndex=%d\n",IfIndex);

				len = sizeof(oneinfo);
				if (GetAdaptersInfo(&oneinfo, &len) == ERROR_SUCCESS)
				{
					debug_msg("got allinfo in one\n");
					allinfo = &oneinfo;
				}
				else
				{
					allinfo = (PIP_ADAPTER_INFO) malloc(len);
					if (GetAdaptersInfo(allinfo, &len) != ERROR_SUCCESS)
					{
						debug_msg("Could not get adapter info\n");
						free(allinfo);
						allinfo = 0;
					}
				}

				if (allinfo)
				{

					PIP_ADAPTER_INFO a;
					{
						for (a = allinfo; a != 0; a = a->Next)
						{

							debug_msg("name='%s' desc='%s' index=%d\n", 
								a->AdapterName, a->Description, a->Index);

							if (a->Index == IfIndex)
							{
								PIP_ADDR_STRING s;
								/* Take the first address. */

								s = &a->IpAddressList;
								iface = _strdup(s->IpAddress.String);
								debug_msg("Found address '%s'\n", iface);
							}
						}
					}
				}
			} else {
				#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x)) 
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
/* Note: could also use malloc() and free() */

				    PMIB_IPFORWARDTABLE pIpForwardTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    char szDestIp[128];
    char szMaskIp[128];
    char szGatewayIp[128];

    struct in_addr IpAddr;

    int i;
        debug_msg("GetIpForwardTable\n");


    pIpForwardTable = (MIB_IPFORWARDTABLE*) MALLOC(sizeof(MIB_IPFORWARDTABLE));
    if (pIpForwardTable == NULL) {
        debug_msg("GetIpForwardTable Error allocating memory\n");
	    //ErrorExit(TEXT("Error allocating memory for GetIpForwardTable\n"));
    }

    if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pIpForwardTable);
        pIpForwardTable = (MIB_IPFORWARDTABLE*) MALLOC(dwSize);
        if (pIpForwardTable == NULL) {
            debug_msg("GetIpForwardTable Error allocating more memory\n");
			//ErrorExit(TEXT("Error allocating memory for Larger GetIpForwardTable\n"));
		    exit(1);
		}
    }

    /* Note that the IPv4 addresses returned in 
     * GetIpForwardTable entries are in network byte order 
     */
    if ( (dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 0)) == NO_ERROR) {
        printf("\tNumber of entries: %d\n", (int) pIpForwardTable->dwNumEntries);
        for (i = 0; i < (int) pIpForwardTable->dwNumEntries; i++) {
            /* Convert IPv4 addresses to strings */

            IpAddr.S_un.S_addr = (u_long) pIpForwardTable->table[i].dwForwardDest;
            strcpy_s(szDestIp, sizeof(szDestIp), inet_ntoa(IpAddr) );
            IpAddr.S_un.S_addr =  (u_long) pIpForwardTable->table[i].dwForwardMask;
            strcpy_s(szMaskIp, sizeof(szMaskIp), inet_ntoa(IpAddr) );
            IpAddr.S_un.S_addr = (u_long) pIpForwardTable->table[i].dwForwardNextHop;
            strcpy_s(szGatewayIp, sizeof(szGatewayIp), inet_ntoa(IpAddr) );

            debug_msg("\n\tRoute[%d] Dest IP: %s\n", i, szDestIp);
            debug_msg("\tRoute[%d] Subnet Mask: %s\n", i, szMaskIp);
            debug_msg("\tRoute[%d] Next Hop: %s\n", i, szGatewayIp);
            debug_msg("\tRoute[%d] If Index: %ld\n", i, pIpForwardTable->table[i].dwForwardIfIndex);
            debug_msg("\tRoute[%d] Type: %ld - ", i, pIpForwardTable->table[i].dwForwardType);
            switch (pIpForwardTable->table[i].dwForwardType) {
                /*case MIB_IPROUTE_TYPE_OTHER:
                    debug_msg("other\n");
                    break;
                case MIB_IPROUTE_TYPE_INVALID:
                    debug_msg("invalid route\n");
                    break;
                case MIB_IPROUTE_TYPE_DIRECT:
                    debug_msg("local route where next hop is final destination\n");
                    break;
                case MIB_IPROUTE_TYPE_INDIRECT:
                    debug_msg("remote route where next hop is not final destination\n");
                    break;*/
                default:               
                    debug_msg("UNKNOWN Type value\n");
                    break;
            } 
            debug_msg("\tRoute[%d] Proto: %ld - ", i, pIpForwardTable->table[i].dwForwardProto);
            switch (pIpForwardTable->table[i].dwForwardProto) {
                /*case MIB_IPPROTO_OTHER:
                    debug_msg("other\n");
                    break;
                case MIB_IPPROTO_LOCAL:
                    debug_msg("local interface\n");
                    break;
                case MIB_IPPROTO_NETMGMT:
                    debug_msg("static route set through network management \n");
                    break;
                case MIB_IPPROTO_ICMP:
                    debug_msg("result of ICMP redirect\n");
                    break;
                case MIB_IPPROTO_EGP:
                    debug_msg("Exterior Gateway Protocol (EGP)\n");
                    break;
                case MIB_IPPROTO_GGP:
                    debug_msg("Gateway-to-Gateway Protocol (GGP)\n");
                    break;
                case MIB_IPPROTO_HELLO:
                    debug_msg("Hello protocol\n");
                    break;
                case MIB_IPPROTO_RIP:
                    debug_msg("Routing Information Protocol (RIP)\n");
                    break;
                case MIB_IPPROTO_IS_IS:
                    debug_msg("Intermediate System-to-Intermediate System (IS-IS) protocol\n");
                    break;
                case MIB_IPPROTO_ES_IS:
                    debug_msg("End System-to-Intermediate System (ES-IS) protocol\n");
                    break;
                case MIB_IPPROTO_CISCO:
                    debug_msg("Cisco Interior Gateway Routing Protocol (IGRP)\n");
                    break;
                case MIB_IPPROTO_BBN:
                    debug_msg("BBN Internet Gateway Protocol (IGP) using SPF\n");
                    break;
                case MIB_IPPROTO_OSPF:
                    debug_msg("Open Shortest Path First (OSPF) protocol\n");
                    break;
                case MIB_IPPROTO_BGP:
                    debug_msg("Border Gateway Protocol (BGP)\n");
                    break;
                case MIB_IPPROTO_NT_AUTOSTATIC:
                    debug_msg("special Windows auto static route\n");
                    break;
                case MIB_IPPROTO_NT_STATIC:
                    debug_msg("special Windows static route\n");
                    break;
                case MIB_IPPROTO_NT_STATIC_NON_DOD:
                    debug_msg("special Windows static route not based on Internet standards\n");
                    break;*/
                default:               
                    debug_msg("UNKNOWN Proto value\n");
                    break;
            } 

            debug_msg("\tRoute[%d] Age: %ld\n", i, pIpForwardTable->table[i].dwForwardAge);
            debug_msg("\tRoute[%d] Metric1: %ld\n", i, pIpForwardTable->table[i].dwForwardMetric1);
			if ((inaddr.s_addr&pIpForwardTable->table[i].dwForwardMask) == pIpForwardTable->table[i].dwForwardDest) {
			//if ((inaddr.S_un.S_un_b.s_b1&IpAddr.S_un.S_un_b.s_b1) == IpAddr.S_un.S_un_b.s_b1)
				debug_msg("Match!:%d\n",ttl);
				if (pIpForwardTable->table[i].dwForwardNextHop==inet_addr("127.0.0.1") ) {
					/*if (!ttl) {
					    IfIndex=pIpForwardTable->table[i].dwForwardIfIndex;
						debug_msg("TTL=0 - Use loopback address: %d\n",IfIndex);
					    break;
					}*/
				} else {
					if (pIpForwardTable->table[i].dwForwardDest==inet_addr("0.0.0.0")) {
					   IfIndex=pIpForwardTable->table[i].dwForwardIfIndex;
					   debug_msg("Default Route - setting in case there's nothing else: %d\n", IfIndex);
					} else {
					   IfIndex=pIpForwardTable->table[i].dwForwardIfIndex;
					   debug_msg("Found better match - Using it: %d\n",IfIndex);
					   break;
					}
				}
			}
       }
	   FREE(pIpForwardTable);
	   {
	   			IP_ADAPTER_INFO oneinfo;
				PIP_ADAPTER_INFO allinfo = 0;
				int len;
//				struct in_addr dst, mask, nexthop;
//				dst.s_addr = route.dwForwardDest;
//				mask.s_addr = route.dwForwardMask;
//				nexthop.s_addr = route.dwForwardNextHop;

				debug_msg("GotBestInterface IfIndex=%d\n",IfIndex);

				len = sizeof(oneinfo);
				if (GetAdaptersInfo(&oneinfo, &len) == ERROR_SUCCESS)
				{
					debug_msg("got allinfo in one\n");
					allinfo = &oneinfo;
				}
				else
				{
					allinfo = (PIP_ADAPTER_INFO) malloc(len);
					if (GetAdaptersInfo(allinfo, &len) != ERROR_SUCCESS)
					{
						debug_msg("Could not get adapter info\n");
						free(allinfo);
						allinfo = 0;
					}
				}

				if (allinfo)
				{

					PIP_ADAPTER_INFO a;
					{
						for (a = allinfo; a != 0; a = a->Next)
						{

							debug_msg("name='%s' desc='%s' index=%d\n", 
								a->AdapterName, a->Description, a->Index);

							if (a->Index == IfIndex)
							{
								PIP_ADDR_STRING s;
								/* Take the first address. */

								s = &a->IpAddressList;
								iface = _strdup(s->IpAddress.String);
								debug_msg("Found address '%s'\n", iface);
							}
						}
					}
				}
				if (!iface && IfIndex==1) 
					iface=_strdup("127.0.0.1");
	   }
//       return 0;
    }
    else {
       debug_msg("\tGetIpForwardTable failed.\n");
       FREE(pIpForwardTable);
//       return 1;
    }


/*				struct sockaddr_in DestAddr;
				DWORD dwBestIfIndex;

				debug_msg("GetBestInterface failed\n");
				DestAddr.sin_family = AF_INET;
				DestAddr.sin_addr.s_addr = inaddr.s_addr;
				DestAddr.sin_port = 0;
				GetBestInterfaceEx((struct sockaddr*)(&DestAddr), &dwBestIfIndex);
				debug_msg("GetBestInterfaceEx %d\n",dwBestIfIndex);
*/

			}
		}
	} else {
	    debug_msg("Cannot convert address\n");
	}

	if (iface==0) debug_msg("Did not find suitable interface\n");

	return iface;
}
#endif /* WIN32 */

/**
 * udp_init:
 * @addr: character string containing an IPver4 or IPver6 network address.
 * @rx_port: receive port.
 * @tx_port: transmit port.
 * @ttl: time-to-live value for transmitted packets.
 *
 * Creates a session for sending and receiving UDP datagrams over IP
 * networks. 
 *
 * Returns: a pointer to a valid socket_udp structure on success, NULL otherwise.
 **/
socket_udp *udp_init(const char *addr, uint16_t rx_port, uint16_t tx_port, int ttl)
{
	return udp_init_if(addr, NULL, rx_port, tx_port, ttl);
}

/**
 * udp_init_if:
 * @addr: character string containing an IPver4 or IPver6 network address.
 * @iface: character string containing an interface name.
 * @rx_port: receive port.
 * @tx_port: transmit port.
 * @ttl: time-to-live value for transmitted packets.
 *
 * Creates a session for sending and receiving UDP datagrams over IP
 * networks.  The session uses @iface as the interface to send and
 * receive datagrams on.
 * 
 * Return value: a pointer to a socket_udp structure on success, NULL otherwise.
 **/
socket_udp *udp_init_if(const char *addr, const char *iface, uint16_t rx_port, uint16_t tx_port, int ttl)
{
	socket_udp *res;
	
	if (strchr(addr, ':') == NULL) {
		char *computed_iface = 0;
		/* 
		 * On WIN32, if user did not pass an interface, 
		 * find the default interface for that address
		 * and pass it in .
		 */

#ifdef WIN32
		if (iface == 0)
		{
			computed_iface = find_win32_interface(addr, ttl);
			iface = computed_iface;
		}
#endif

		res = udp_init4(addr, iface, rx_port, tx_port, ttl);

		if (computed_iface)
			free(computed_iface);

	} else {
		res = udp_init6(addr, iface, rx_port, tx_port, ttl);
	}
	return res;
}

/**
 * udp_exit:
 * @s: UDP session to be terminated.
 *
 * Closes UDP session.
 * 
 **/
void udp_exit(socket_udp *s)
{
    switch(s->mode) {
    case IPver4 : udp_exit4(s); break;
    case IPver6 : udp_exit6(s); break;
    default   : abort();
    }
}

/**
 * udp_send:
 * @s: UDP session.
 * @buffer: pointer to buffer to be transmitted.
 * @buflen: length of @buffer.
 * 
 * Transmits a UDP datagram containing data from @buffer.
 * 
 * Return value: 0 on success, -1 on failure.
 **/
int udp_send(socket_udp *s, char *buffer, int buflen)
{
	switch (s->mode) {
	case IPver4 : return udp_send4(s, buffer, buflen);
	case IPver6 : return udp_send6(s, buffer, buflen);
	default   : abort(); /* Yuk! */
	}
	return -1;
}


#ifndef WIN32
int         
udp_sendv(socket_udp *s, struct iovec *vector, int count)
{
	switch (s->mode) {
	case IPver4 : return udp_sendv4(s, vector, count);
	case IPver6 : return udp_sendv6(s, vector, count);
	default   : abort(); /* Yuk! */
	}
	return -1;
}
#endif

/**
 * udp_recv:
 * @s: UDP session.
 * @buffer: buffer to read data into.
 * @buflen: length of @buffer.
 * 
 * Reads from datagram queue associated with UDP session.
 *
 * Return value: number of bytes read, returns 0 if no data is available.
 **/
int udp_recv(socket_udp *s, char *buffer, int buflen)
{
	/* Reads data into the buffer, returning the number of bytes read.   */
	/* If no data is available, this returns the value zero immediately. */
	/* Note: since we don't care about the source address of the packet  */
	/* we receive, this function becomes protocol independent.           */
	int		len;

	assert(buffer != NULL);
	assert(buflen > 0);

	errno = 0;

	len = recvfrom(s->fd, buffer, buflen, 0, 0, 0);
	if (len > 0) {
		return len;
	}
	if (errno != ECONNREFUSED) {
		socket_error("recvfrom");
	}
	return 0;
}

/**
 * udp_fd_zero:
 * 
 * Clears file descriptor from set associated with UDP sessions (see select(2)).
 * 
 **/
void udp_fd_zero( fd_set *readset, fd_t *max_fd )
{
	FD_ZERO(readset);
	*max_fd = 0;
}

/**
 * udp_fd_set:
 * @s: UDP session.
 * 
 * Adds file descriptor associated of @s to set associated with UDP sessions.
 **/
void udp_fd_set( fd_set *readset, fd_t *max_fd, socket_udp *s)
{
	FD_SET(s->fd, readset);
	if (s->fd > (fd_t)*max_fd) {
		*max_fd = s->fd;
	}
}

/**
 * udp_fd_isset:
 * @s: UDP session.
 * 
 * Checks if file descriptor associated with UDP session is ready for
 * reading.  This function should be called after udp_select().
 *
 * Returns: non-zero if set, zero otherwise.
 **/
int udp_fd_isset( fd_set *readset, fd_t *max_fd, socket_udp *s)
{
	UNUSED(max_fd);

	return FD_ISSET(s->fd, readset);
}

/**
 * udp_select:
 * @timeout: maximum period to wait for data to arrive.
 * 
 * Waits for data to arrive for UDP sessions.
 * 
 * Return value: number of UDP sessions ready for reading.
 **/
int udp_select( fd_set *readset, fd_t max_fd, struct timeval *timeout)
{
	return select(max_fd + 1, readset, NULL, NULL, timeout);
}

/**
 * udp_host_addr:
 * @s: UDP session.
 * 
 * Return value: character string containing network address
 * associated with session @s.
 **/
const char *udp_host_addr(socket_udp *s)
{
	switch (s->mode) {
	case IPver4 : return udp_host_addr4();
	case IPver6 : return udp_host_addr6(s);
	default   : abort();
	}
	return NULL;
}

/**
 * udp_fd:
 * @s: UDP session.
 * 
 * This function allows applications to apply their own socketopt()'s
 * and ioctl()'s to the UDP session.
 * 
 * Return value: file descriptor of socket used by session @s.
 **/
int udp_fd(socket_udp *s)
{
	if (s && s->fd > 0) {
		return s->fd;
	} 
	return 0;
}


