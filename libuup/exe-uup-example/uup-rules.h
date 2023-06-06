#include <conf.h>


#define RULES_BUF_SIZE 4096

extern module_conf_t CONF_RULES;

struct uup_example_rules_args {
    const char *addr;
    unsigned port;
};
bool uup_example_rules_startt(struct uup_example_config *config,cJSON *facts);

