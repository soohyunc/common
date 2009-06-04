#ifndef NEED_INET_PTON
#define INET_PTON inet_pton
#else
#define INET_PTON inet_pton_ucl
#if defined(__cplusplus)
extern "C" {
#endif

int inet_pton_ucl(int af, const char *src, void *dst);

#if defined(__cplusplus)
}
#endif
#endif /* NEED_INET_PTON */

