#ifndef __INET_NTOP_H__
#define __INET_NTOP_H__

#ifndef NEED_INET_NTOP
#define INET_NTOP inet_ntop
#else
#define INET_NTOP inet_ntop_ucl

#if defined(__cplusplus)
extern "C" {
#endif

const char *inet_ntop_ucl(int af, const void *src, char *dst, socklen_t size);

#if defined(__cplusplus)
}
#endif

#endif /* NEED_INET_NTOP */

#endif /* __INET_NTOP_H__ */
