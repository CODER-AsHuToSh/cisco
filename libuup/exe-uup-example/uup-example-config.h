#ifndef UUP_EXAMPLE_CONFIG_H
#define UUP_EXAMPLE_CONFIG_H

#include <pthread.h>

struct uup_example_config {
    /* Command-line configurable items */
    const char    *config_directory;
    const char    *last_good_path;
    const char    *graphitelog_path;           // Output path to the graphite log
    unsigned       rules_port;
    const char    *rules_addr;

    /* Service components */
    pthread_t           graphitelog_thr;
    int                 graphitelog_fd;
    struct confset     *conf;
    useconds_t          stat_delay;
    pthread_t           rules_thr;

};

struct uup_example_config *uup_example_new_config(void);
void uup_example_cleanup(struct uup_example_config *config);
bool uup_example_setup_conf(struct uup_example_config *config);
int uup_example_conf_loop(struct uup_example_config *config);
void uup_example_terminate(int sig);

#endif
