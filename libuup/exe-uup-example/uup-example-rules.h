#ifndef UUP_EXAMPLE_RULES_H
#define UUP_EXAMPLE_RULES_H

#include <conf.h>

#define DEFAULT_RULES_PORT 1234
#define DEFAULT_RULES_ADDR "127.0.0.1"

#define RULES_BUF_SIZE 4096

extern module_conf_t CONF_RULES;

struct uup_example_rules_args {
    const char *addr;
    unsigned port;
};

bool uup_example_rules_start(struct uup_example_config *config);
void *uup_example_rules_thread(void *args);

#endif
