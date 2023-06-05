#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <mock.h>
#include <tap.h>

#include "kit.h"

#define TEST_MESSAGE      "0123456789ABCDEF"
#define TEST_MESSAGE_SIZE (sizeof(TEST_MESSAGE) - 1)

static int
#if __GNUC__ >= 9
test_gettimeofday(struct timeval *tv, void *__restrict tz)
#else
test_gettimeofday(struct timeval *tv, struct timezone *tz)
#endif
{
    (void)tz;
    memset(tv, 0, sizeof(*tv));    // Current time is Jan 1 1970 UTC
    return 0;
}

int
main(void)
{
    int                   fd_recv;
    int                   fd_send;
    struct sockaddr_in    addr_to;      // Address sent to (i.e. address of the receiver)
    struct sockaddr_in    addr_from;    // Address received from
    struct sockaddr_in    addr_dest;    // Destination address of received msg
#   define ADDR_FROM      ((struct sockaddr *)&addr_from)
#   define ADDR_DEST      ((struct sockaddr *)&addr_dest)
    socklen_t             addr_len;
    socklen_t             addr_dest_len;
    unsigned char         buffer[TEST_MESSAGE_SIZE];
    unsigned long         delay_in_msec;
    struct kit_udp_ttltos ttltos = {255, 0};

    plan_tests(66);
    ok((fd_send = socket(AF_INET, SOCK_DGRAM, 0)) >= 0,           "Created send socket");
    ok((fd_recv = kit_udp_socket(AF_INET, KIT_UDP_DELAY))  >= 0,  "Created recv socket asking for delay");

    addr_to.sin_family = AF_INET;
    addr_to.sin_port   = 0;
    addr_len           = sizeof(addr_to);
    ok(inet_aton("127.0.0.1", &addr_to.sin_addr),                 "Created IP address");
    ok(bind(fd_recv, (struct sockaddr *)&addr_to, addr_len) >= 0, "Bound IP address to socket");
    ok(getsockname(fd_recv, &addr_to, &addr_len) >= 0,            "Got bound sockaddr (to send to)");
    ok(addr_to.sin_port != 0,                                     "Port was set to %hu", ntohs(addr_to.sin_port));

    diag("Test happy path with timestamp");
    is(sendto(fd_send, TEST_MESSAGE, TEST_MESSAGE_SIZE, 0, (struct sockaddr *)&addr_to, sizeof(addr_to)), TEST_MESSAGE_SIZE,
       "Sent first %zu bytes (errno=%s)", TEST_MESSAGE_SIZE, strerror(errno));
    is(kit_recvfrom(fd_recv, buffer, sizeof(buffer), MSG_DONTWAIT, ADDR_FROM, &addr_len, NULL, NULL, &delay_in_msec, &ttltos),
       TEST_MESSAGE_SIZE, "Received first %zu bytes", TEST_MESSAGE_SIZE);
    ok(delay_in_msec != ~0UL, "Delay in milliseconds was %lu", delay_in_msec);
    is(ttltos.ttl, 255,       "TTL should not be changed");
    is(ttltos.tos, 0,         "TOS should not be changed");

    diag("Test that without MSG_TRUNC, oversize packets are received and silently truncated");
    is(sendto(fd_send, TEST_MESSAGE, TEST_MESSAGE_SIZE, 0, (struct sockaddr *)&addr_to, sizeof(addr_to)), TEST_MESSAGE_SIZE,
       "Sent second %zu bytes (errno=%s)", TEST_MESSAGE_SIZE, strerror(errno));
    is(kit_recvfrom(fd_recv, buffer, sizeof(buffer) / 2, MSG_DONTWAIT, ADDR_FROM, &addr_len, NULL, NULL, &delay_in_msec, NULL),
       sizeof(buffer) / 2, "Received part of second %zu bytes into %zu byte buffer (errno=%s)", TEST_MESSAGE_SIZE,
       sizeof(buffer) / 2, strerror(errno));

    diag("Test that with MSG_TRUNC, oversize packets are received and truncated but their full size is returned");
    is(sendto(fd_send, TEST_MESSAGE, TEST_MESSAGE_SIZE, 0, (struct sockaddr *)&addr_to, sizeof(addr_to)), TEST_MESSAGE_SIZE,
       "Sent third %zu bytes (errno=%s)", TEST_MESSAGE_SIZE, strerror(errno));
    is(kit_recvfrom(fd_recv, buffer, sizeof(buffer) / 2, MSG_DONTWAIT | MSG_TRUNC, ADDR_FROM, &addr_len, NULL, NULL, &delay_in_msec, NULL),
       sizeof(buffer), "Received part of third %zu bytes into %zu byte buffer (errno=%s)", TEST_MESSAGE_SIZE,
       sizeof(buffer) / 2, strerror(errno));

    diag("Test that no timestamp is returned if time goes backward");
    MOCK_SET_HOOK(gettimeofday, test_gettimeofday);
    is(sendto(fd_send, TEST_MESSAGE, TEST_MESSAGE_SIZE, 0, (struct sockaddr *)&addr_to, sizeof(addr_to)), TEST_MESSAGE_SIZE,
       "Sent fourth %zu bytes (errno=%s)", TEST_MESSAGE_SIZE, strerror(errno));
    is(kit_recvfrom(fd_recv, buffer, sizeof(buffer), MSG_DONTWAIT, ADDR_FROM, &addr_len, NULL, NULL, &delay_in_msec, NULL),
       TEST_MESSAGE_SIZE, "Received fourth %zu bytes", TEST_MESSAGE_SIZE);
    is(delay_in_msec, ~0UL, "Delay in milliseconds is not returned when time goes backward");
    MOCK_SET_HOOK(gettimeofday, gettimeofday);    // Back to the future!

    diag("Test asking for destination addresses");
    {
        ok((fd_recv = kit_udp_socket(AF_INET, KIT_UDP_DST_ADDR)) >= 0,
           "Created recv socket asking for destination address");
        addr_to.sin_family = AF_INET;
        addr_to.sin_port = 0;
        addr_len = sizeof(addr_to);
        ok(inet_aton("127.0.0.1", &addr_to.sin_addr), "Created IP address");
        ok(bind(fd_recv, (struct sockaddr *)&addr_to, addr_len) >= 0, "Bound IP address to socket");
        ok(getsockname(fd_recv, &addr_to, &addr_len) >= 0, "Got bound sockaddr");
        ok(addr_to.sin_port != 0, "Port was set to %hu", ntohs(addr_to.sin_port));
        is(sendto(fd_send, TEST_MESSAGE, TEST_MESSAGE_SIZE, 0, (struct sockaddr *)&addr_to, sizeof(addr_to)),
           TEST_MESSAGE_SIZE,
           "Sent %zu bytes (errno=%s)", TEST_MESSAGE_SIZE, strerror(errno));

        addr_dest_len = sizeof(addr_dest);
        memset(ADDR_DEST, '\0', addr_dest_len);
        is(kit_recvfrom(fd_recv, buffer, sizeof(buffer), MSG_DONTWAIT, ADDR_FROM, &addr_len, ADDR_DEST, &addr_dest_len,
                        NULL, NULL),
           TEST_MESSAGE_SIZE, "Received %zu bytes", TEST_MESSAGE_SIZE);

        is(addr_dest_len, sizeof(struct sockaddr_in), "Got expected destination address length");
        is_eq(inet_ntoa(addr_dest.sin_addr), "127.0.0.1", "Destination address is 127.0.0.1");

        addr_dest_len = sizeof(addr_dest);
        is(kit_recvfrom(fd_recv, buffer, sizeof(buffer), MSG_DONTWAIT, ADDR_FROM, &addr_len, ADDR_DEST, &addr_dest_len,
                        NULL, NULL),
           -1, "Failed to receive when no data was sent");

        is(addr_dest_len, 0, "No destination address without data to receive");
    }

    diag("Test with intentionally broken timestamps");
    close(fd_recv);
    ok((fd_recv = socket(AF_INET, SOCK_DGRAM, 0)) >= 0,           "Created no timestamp receive socket");
    addr_to.sin_family = AF_INET;
    addr_to.sin_port   = 0;
    addr_len           = sizeof(addr_to);
    ok(inet_aton("127.0.0.1", &addr_to.sin_addr),                 "Created IP address");
    ok(bind(fd_recv, (struct sockaddr *)&addr_to, addr_len) >= 0, "Bound IP address to socket");
    ok(getsockname(fd_recv, &addr_to, &addr_len) >= 0,            "Got bound sockaddr");
    ok(addr_to.sin_port != 0,                                     "Port was set to %hu", ntohs(addr_to.sin_port));
    is(sendto(fd_send, TEST_MESSAGE, TEST_MESSAGE_SIZE, 0, (struct sockaddr *)&addr_to, sizeof(addr_to)), TEST_MESSAGE_SIZE,
       "Sent %zu bytes (errno=%s)", TEST_MESSAGE_SIZE, strerror(errno));
    is(kit_recvfrom(fd_recv, buffer, sizeof(buffer), MSG_DONTWAIT, ADDR_FROM, &addr_len, NULL, NULL, &delay_in_msec, NULL),
       TEST_MESSAGE_SIZE, "Received %zu bytes", TEST_MESSAGE_SIZE);
    is(delay_in_msec, ~0UL, "Delay in milliseconds is not returned on no timestamp UDP socket");

    diag("Test failure when there is no data");
    is(kit_recvfrom(fd_recv, buffer, sizeof(buffer), MSG_DONTWAIT, ADDR_FROM, &addr_len, NULL, NULL, &delay_in_msec, NULL),
       -1, "Receive failed when socket empty");
    is(errno, EAGAIN, "Got status EGAIN (%s)",  strerror(errno));

    diag("Test failure when the socket is closed");
    close(fd_recv);
    is(kit_recvfrom(fd_recv, buffer, sizeof(buffer), MSG_DONTWAIT, ADDR_FROM, &addr_len, NULL, NULL, &delay_in_msec, NULL),
       -1, "Receive failed when socket empty");
    is(errno, EBADF, "Got status EBADF (%s)",  strerror(errno));

    diag("Test asking for TTL/TOS");
    ok((fd_recv = kit_udp_socket(AF_INET, KIT_UDP_TTLTOS))  >= 0, "Created recv socket asking for TTL/TOS");
    addr_to.sin_family = AF_INET;
    addr_to.sin_port   = 0;
    addr_len           = sizeof(addr_to);
    ok(inet_aton("127.0.0.1", &addr_to.sin_addr),                 "Created IP address");
    ok(bind(fd_recv, (struct sockaddr *)&addr_to, addr_len) >= 0, "Bound IP address to socket");
    ok(getsockname(fd_recv, &addr_to, &addr_len) >= 0,            "Got bound sockaddr");
    ok(addr_to.sin_port != 0,                                     "Port was set to %hu", ntohs(addr_to.sin_port));
    is(sendto(fd_send, TEST_MESSAGE, TEST_MESSAGE_SIZE, 0, (struct sockaddr *)&addr_to, sizeof(addr_to)), TEST_MESSAGE_SIZE,
       "Sent %zu bytes (errno=%s)", TEST_MESSAGE_SIZE, strerror(errno));
    delay_in_msec = 0;
    is(kit_recvfrom(fd_recv, buffer, sizeof(buffer), MSG_DONTWAIT, ADDR_FROM, &addr_len, NULL, NULL, &delay_in_msec, &ttltos),
       TEST_MESSAGE_SIZE, "Received %zu bytes", TEST_MESSAGE_SIZE);
    is(delay_in_msec, ~0UL, "Delay in milliseconds is not returned on no timestamp UDP socket");
    ok(ttltos.ttl != 255, "TTL %u is not 255", (unsigned)ttltos.ttl);
    diag("TOS is %u", (unsigned)ttltos.tos);

    close(fd_recv);
    close(fd_send);

    diag("Test limits");
    ok((fd_recv = kit_udp_socket(AF_INET, KIT_UDP_DELAY | KIT_UDP_TTLTOS | KIT_UDP_DST_ADDR)) >= 0, "Created recv socket asking for all the things");
    addr_to.sin_family = AF_INET;
    addr_to.sin_port = 0;
    ok(inet_aton("127.0.0.1", &addr_to.sin_addr), "Created IP address");
    ok(bind(fd_recv, (struct sockaddr *)&addr_to, sizeof(addr_to)) >= 0, "Bound IP address to socket");
    addr_len = sizeof(addr_to);
    ok(getsockname(fd_recv, &addr_to, &addr_len) >= 0, "Got bound sockaddr");
    ok(addr_to.sin_port != 0, "Port was set to %hu", ntohs(addr_to.sin_port));

    ok((fd_send = socket(AF_INET, SOCK_DGRAM, 0)) >= 0, "Recreated send socket");
    addr_from.sin_family = AF_INET;
    addr_from.sin_port = 0;
    ok(inet_aton("127.1.2.3", &addr_from.sin_addr), "Created IP address");
    ok(bind(fd_send, (struct sockaddr *)&addr_from, sizeof(addr_from)) >= 0, "Bound IP address to send socket");
    is(sendto(fd_send, TEST_MESSAGE, TEST_MESSAGE_SIZE, 0, (struct sockaddr *)&addr_to, sizeof(addr_to)), TEST_MESSAGE_SIZE,
       "Sent %zu bytes (errno=%s)", TEST_MESSAGE_SIZE, strerror(errno));

    delay_in_msec = 0;
    memset(&addr_from, '\0', sizeof(addr_from));
    addr_dest_len = sizeof(addr_dest);
    memset(ADDR_DEST, '\0', addr_dest_len);

    is(kit_recvfrom(fd_recv, buffer, TEST_MESSAGE_SIZE, MSG_DONTWAIT, ADDR_FROM, &addr_len, ADDR_DEST, &addr_dest_len, &delay_in_msec, &ttltos),
       TEST_MESSAGE_SIZE, "Received %zu bytes", TEST_MESSAGE_SIZE);
    ok(delay_in_msec != ~0UL, "Delay in milliseconds was set (%lu)", delay_in_msec);
    ok(ttltos.ttl != 255, "TTL %u is not 255", (unsigned)ttltos.ttl);
    diag("TOS is %u", (unsigned)ttltos.tos);
    is(addr_from.sin_family, AF_INET, "Got an IPv4 from addr");
    is_eq(inet_ntoa(addr_from.sin_addr), "127.1.2.3", "Source address is 127.1.2.3");
    is(addr_dest_len, sizeof(struct sockaddr_in), "Got expected destination address length");
    is_eq(inet_ntoa(addr_dest.sin_addr), "127.0.0.1", "Destination address is 127.0.0.1");


    close(fd_recv);
    close(fd_send);

    return exit_status();
}
