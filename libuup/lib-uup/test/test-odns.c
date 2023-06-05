// Test the odns object, which is built from the EDNS options sent by the forwarder.

#include <tap.h>

#include "odns.h"
#include "netsock.h"

int
main(void) {
    struct odns    odns;
    struct netaddr clientaddr;
    struct netaddr encapip;

    plan_tests(5);

    is(netaddr_from_str(&clientaddr, "127.0.0.1", AF_INET), &clientaddr, "Successfully created a clientaddr");
    memset(&odns, 0, sizeof(odns));    // odns_init is not really an init function
    odns_init(&odns, &clientaddr, 0, 0, NULL, NULL, NULL);
    is_eq(odns_content(&odns), "flags=0x0 fields=0x10 remoteip=127.0.0.1", "Simple odns content is as expected");

    is(netaddr_from_str(&encapip, "::1", AF_INET6), &encapip, "Successfully created a V6 encapip");
    odns_init(&odns, &clientaddr, 666, 0, NULL, NULL, NULL);
    is_eq(odns_content(&odns), "flags=0x0 fields=0x18 org=666 remoteip=127.0.0.1",
          "Odns with overidden orgid 666 content is as expected");

    odns_init(&odns, &clientaddr, 2, 0xde41ce, NULL, NULL, NULL);
    is_eq(odns_content(&odns), "flags=0x0 fields=0x1c org=2 va=14565838 remoteip=127.0.0.1",
          "Odns with updated orgid 2 content is as expected");

    return exit_status();
}
