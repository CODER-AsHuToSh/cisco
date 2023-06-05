/*
 * todo: This would be a great place to do a speed test
 */
#include <arpa/inet.h>
#include <tap.h>

#include "cidr-ipv4.h"
#include "cidrlist.h"
#include "conf-loader.h"

int
main(int argc, char **argv)
{
    struct conf_loader cfgl;
    struct netsock sock;
    struct cidrlist *cl;

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(7);

    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cfgl);
    sock.a.family = AF_INET;
    sock.port = 0;

    diag("Test large list");
    {
        char str[200000];
        int got, n, pos, prefix;
        time_t then;
        unsigned i;
        const char *consumed;

        n = pos = 0;
        while (sizeof(str) - pos > strlen("XXX.XXX.XXX.XXX/NN") + 2) {
            sock.a.in_addr.s_addr = (in_addr_t)rand();
            prefix = rand() % 33;
            pos += snprintf(str + pos, sizeof(str) - pos, "%s%s/%d", pos ? " " : "", inet_ntoa(sock.a.in_addr), prefix);
            n++;
        }
        ok(n, "Created a big input string (%d entries)", n);

        cl = cidrlist_new_from_string(str, " ", &consumed, NULL, PARSE_CIDR_ONLY);
        ok(cl, "Created a cidrlist from the input string");
        is(*consumed, '\0', "Consumed the whole input string");
        skip_if(!cl, 2, "Cannot verify cidrlist - not created") {
            time(&then);
            got = 0;
            for (i = 0; i < cl->in4.count; i++) {
                sock.a.in_addr.s_addr = htonl(cl->in4.cidr[i].addr);
                if (cidrlist_search(cl, &sock.a, NULL, NULL))
                    got++;
                else
                    diag("Oops, missed %08x/%08x", cl->in4.cidr[i].addr, cl->in4.cidr[i].mask);
            }
            is(got, cl->in4.count, "Retrieved all %u entries in %ld seconds", cl->in4.count, (long)time(NULL) - (long)then);

            cidrlist_refcount_dec(cl);
        }
    }

    diag("Test malware2ips file");
    {
        time_t then;
        unsigned i;
        int got;

        conf_loader_open(&cfgl, "../test/malware2ips", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        cl = cidrlist_new_from_file(&cfgl, PARSE_IP_ONLY);
        ok(cl, "Created a cidrlist from malware2ips");
        skip_if(!cl, 2, "Cannot verify cidrlist - not created") {
            is(cl->in4.count, 16260, "The cidrlist contains 16260 entries");

            time(&then);
            got = 0;
            for (i = 0; i < cl->in4.count; i++) {
                sock.a.in_addr.s_addr = htonl(cl->in4.cidr[i].addr);
                got += cidrlist_search(cl, &sock.a, NULL, NULL) ? 1 : 0;
            }
            is(got, cl->in4.count, "Retrieved all %u entries in %ld seconds", cl->in4.count, (long)time(NULL) - (long)then);

            cidrlist_refcount_dec(cl);
        }
    }

    conf_loader_fini(&cfgl);

    return exit_status();
}
