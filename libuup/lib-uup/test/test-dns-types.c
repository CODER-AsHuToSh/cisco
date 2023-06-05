#include <sxe-log.h>
#include <tap.h>

#include "rr-type.h"

#define ENTRY(i) { RR_TYPE_ ## i, #i }

static struct {
    rr_type_t type;
    const char *txt;
} types[] = {
    ENTRY(A),
    ENTRY(NS),
    ENTRY(MD),
    ENTRY(MF),
    ENTRY(CNAME),
    ENTRY(SOA),
    ENTRY(MB),
    ENTRY(MG),
    ENTRY(MR),
    ENTRY(NULL),
    ENTRY(WKS),
    ENTRY(PTR),
    ENTRY(HINFO),
    ENTRY(MINFO),
    ENTRY(MX),
    ENTRY(TXT),
    ENTRY(RP),
    ENTRY(AFSDB),
    ENTRY(X25),
    ENTRY(ISDN),
    ENTRY(RT),
    ENTRY(NSAP),
    ENTRY(NSAP_PTR),
    ENTRY(SIG),
    ENTRY(KEY),
    ENTRY(PX),
    ENTRY(GPOS),
    ENTRY(AAAA),
    ENTRY(LOC),
    ENTRY(NXT),
    ENTRY(EID),
    ENTRY(NIMLOC),
    ENTRY(SRV),
    ENTRY(ATMA),
    ENTRY(NAPTR),
    ENTRY(KX),
    ENTRY(CERT),
    ENTRY(A6),
    ENTRY(DNAME),
    ENTRY(SINK),
    ENTRY(OPT),
    ENTRY(APL),
    ENTRY(DS),
    ENTRY(SSHFP),
    ENTRY(IPSECKEY),
    ENTRY(RRSIG),
    ENTRY(NSEC),
    ENTRY(DNSKEY),
    ENTRY(DHCID),
    ENTRY(NSEC3),
    ENTRY(NSEC3PARAM),
    ENTRY(TALINK),
    ENTRY(SPF),
    ENTRY(UINFO),
    ENTRY(UID),
    ENTRY(GID),
    ENTRY(UNSPEC),
    ENTRY(TSIG),
    ENTRY(IXFR),
    ENTRY(AXFR),
    ENTRY(MAILB),
    ENTRY(MAILA),
    ENTRY(ANY),
    ENTRY(DLV),
};

int
main(int argc, char **argv)
{
    unsigned i;

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(66);

    for (i = 0; i < sizeof(types) / sizeof(*types); i++)
        is_eq(rr_type_to_str(types[i].type), types[i].txt, "DNS type %u is %s", (unsigned)types[i].type, types[i].txt);

    is_eq(rr_type_to_str((rr_type_t)CONST_HTONS(54)), "TYPE54", "DNS type 54 is TYPE54");

    is_eq(rr_type_to_str(RR_TYPE_LAST), "ADDR", "DNS type %u is %s", (unsigned)RR_TYPE_LAST, "ADDR");

    return exit_status();
}
