#if __FreeBSD__
#include <stdint.h>
#include <sys/socket.h>
#endif

#include "sockaddrutil.h"
#include <arpa/inet.h>
#include <errno.h>
#include <kit.h>
#include <string.h>

char *
sockaddr_to_buf(const struct sockaddr *sa, char *buf, size_t size, size_t *len_out)
{
    const void *addr;

    switch (sa->sa_family) {
    case AF_INET:
        addr = &((const struct sockaddr_in *)sa)->sin_addr;
        break;
    case AF_INET6:
        addr = &((const struct sockaddr_in6 *)sa)->sin6_addr;
        break;
    default:
        return NULL;
    }

    if (inet_ntop(sa->sa_family, addr, buf, size) == NULL)
        return NULL;

    if (len_out)
        *len_out = strlen(buf);

    return buf;
}

static char *
port_sscan(const char *str, in_port_t *port)
{
    char *tmp;
    unsigned long ul;

    errno = 0;
    ul = kit_strtoul(str, &tmp, 10);
    if (str == tmp || errno != 0 || ul > UINT16_MAX)
        return NULL;
    *port = ul;
    return tmp;
}

bool
sockaddr_sscan(const char *str, in_port_t default_port, struct sockaddr *sa, socklen_t *sockaddr_len)
{
    char *addr_str, buf[INET6_ADDRSTRLEN + sizeof("[]:65535") - 1], *p, *port_str;
    struct in6_addr in6_addr;
    struct in_addr in_addr;
    in_port_t port;
    size_t i;

    if ((i = strlen(str) + 1) > sizeof(buf))
        return false;
    memcpy(buf, str, i);

    if (strchr(buf, '.') != NULL && (p = strchr(buf, ':')) != NULL) {
        /* <IPv4 address>:<port> */
        addr_str = buf;
        port_str = p + 1;
        *p = 0;
    } else if (buf[0] == '[' && (p = strstr(buf, "]:")) != NULL) {
        /* [<IPv6 address>]:<port> */
        addr_str = buf + 1;
        port_str = p + 2;
        *p = 0;
    } else {
        addr_str = buf;
        port_str = NULL;
    }

    if (port_str == NULL)
        port = default_port;
    else if ((p = port_sscan(port_str, &port)) == NULL || *p != 0)
        return false;

    if (inet_pton(AF_INET, addr_str, &in_addr) > 0) {
        if ((size_t) *sockaddr_len < sizeof(struct sockaddr_in))
            return false;
        *sockaddr_len = sizeof(struct sockaddr_in);
        memset(sa, '\0', *sockaddr_len);
        ((struct sockaddr_in *)sa)->sin_family = AF_INET;
        ((struct sockaddr_in *)sa)->sin_port = htons(port);
        ((struct sockaddr_in *)sa)->sin_addr = in_addr;
    } else if (inet_pton(AF_INET6, addr_str, &in6_addr) > 0) {
        if ((size_t) *sockaddr_len < sizeof(struct sockaddr_in6))
            return false;
        *sockaddr_len = sizeof(struct sockaddr_in6);
        memset(sa, '\0', *sockaddr_len);
        ((struct sockaddr_in6 *)sa)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)sa)->sin6_port = htons(port);
        ((struct sockaddr_in6 *)sa)->sin6_addr = in6_addr;
    } else
        return false;

    return true;
}
