#ifndef __INET_NTOP_H__
#define __INET_NTOP_H__

#ifdef NEED_INET_NTOP

#if defined(__cplusplus)
extern "C" {
#endif

const char *inet_ntop(int af, const void *src, char *dst,socklen_t size  size);

#if defined(__cplusplus)
}
#endif

#endif /* NEED_INET_NTOP */

#endif /* __INET_NTOP_H__ */
