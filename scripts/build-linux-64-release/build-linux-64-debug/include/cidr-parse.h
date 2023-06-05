#ifndef CIDR_PARSE_H
#define CIDR_PARSE_H

#define CIDR_PARSE_TXT(how)    ((how) == PARSE_IP_ONLY ? "PARSE_IP_ONLY" : (how) == PARSE_CIDR_ONLY ? "PARSE_CIDR_ONLY" : "PARSE_IP_OR_CIDR")
enum cidr_parse {
    PARSE_IP_ONLY,
    PARSE_CIDR_ONLY,
    PARSE_IP_OR_CIDR
};

#endif
