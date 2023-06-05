#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tap.h>
#include <unistd.h>

#include "kit-fsevent.h"

int
main(void)
{
    struct kit_fsevent fsev;
    const char *watchdir = "watchdir";
    const char *watchfile = "watchdir/watchfile.txt";
    int wd, fd;
    struct kit_fsevent_iterator iter;
    kit_fsevent_ev_t *event;

    plan_tests(12);

    bzero(&fsev, sizeof(struct kit_fsevent));
    kit_fsevent_init(&fsev);
    kit_fsevent_iterator_init(&iter);

    ok(fsev.fd, "kit_fsevent initialized");

    /* Setup a watched directory */
    ok(mkdir(watchdir, 0755) == 0, "Created directory %s", watchdir);
    ok(wd = kit_fsevent_add_watch(&fsev, watchdir, KIT_FSEVENT_CREATE|KIT_FSEVENT_DELETE|KIT_FSEVENT_MOVED_TO|KIT_FSEVENT_MOVED_FROM|KIT_FSEVENT_MODIFY),
       "Added watch for %s", watchdir);

    /* Create a file in the watched directory */
    fd = open(watchfile, O_WRONLY|O_CREAT, 0666);
    ok(fd >= 0, "Successfully created %s", watchfile);
    close(fd);

    /* Verify detection of the created file */
    ok(event = kit_fsevent_read(&fsev, &iter), "Got an kit_fsevent after file creation");
    ok(KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_CREATE), "Event indicated file creation");
    ok(kit_fsevent_read(&fsev, &iter) == NULL, "No more events");

    /* Delete the file and verify detection */
    ok(remove(watchfile) == 0, "Successfully removed file %s", watchfile);
    ok(event = kit_fsevent_read(&fsev, &iter), "Got an kit_fsevent after file deletion");
    ok(KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_DELETE), "Event indicated file deletion");
    ok(kit_fsevent_read(&fsev, &iter) == NULL, "No more events");

    /* Cleanup watches */
    kit_fsevent_rm_watch(&fsev, wd);
    kit_fsevent_fini(&fsev);

    /* Cleanup files */
    ok(rmdir(watchdir) == 0, "Successfully removed directory %s", watchdir);

    return exit_status();
}
