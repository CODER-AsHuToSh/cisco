#include "kit.h"

#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define HOSTNAME_LOOKUP_INTERVAL 60    /* Lookup the hostname every 60 seconds from each thread */

const char *
kit_hostname(void)
{
    static __thread char hostname[MAXHOSTNAMELEN];
    static __thread int32_t then = -1;
    int32_t now;

    now = kit_time_cached_sec();
    if (now == 0 || now > then + HOSTNAME_LOOKUP_INTERVAL) {
        if (gethostname(hostname, sizeof(hostname)) != 0)
            snprintf(hostname, sizeof(hostname), "Amnesiac");    /* COVERAGE EXCLUSION: todo: Make gethostname() fail */
        then = now;
    }

    return hostname;
}

const char *
kit_short_hostname(void)
{
    const char *hostname;
    char *dot;

    hostname = kit_hostname();
    if ((dot = strchr(hostname, '.')) != NULL && (dot = strchr(dot + 1, '.')) != NULL)
        *dot = '\0';                                  /* COVERAGE EXCLUSION: todo: Some hostnames contain two '.'s, some don't */

    return hostname;
}
