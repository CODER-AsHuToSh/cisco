#include <kit-alloc.h>
#include <mockfail.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "common-test.h"
#include "pref-segments.h"

static int
create_file_ok(const char *fn, const char *data)
{
    return ok(create_atomic_file(fn, "%s", data), "Created %s", fn);
}

int
main(void)
{
    uint64_t start_allocations;
    const struct preffile *pf;
    struct pref_segments *ps;

    plan_tests(153);
#ifdef __FreeBSD__
    plan_skip_all("DPT-186 - Need to implement inotify as dtrace event");
    exit(0);
#endif

    kit_memory_initialize(false);
    start_allocations = memory_allocations();

    diag("13 micro tests");
    {
        ok(system("rm -fr pref-segments-dir") == 0, "Cleaned out old pref-segments-dir");
        pref_segments_free(NULL);    /* A no-op */

        ps = pref_segments_new("pref-segments-dir");
        pref_segments_free(ps);
        ok(ps != NULL, "Created and freed a pref-segments structure pointing at a non-existent directory");

        ps = pref_segments_new("*pref-segments-dir");
        ok(ps == NULL, "Can't create a pref-segments with a '*' glob in the final component");

        ps = pref_segments_new("pref-?-segments-dir");
        ok(ps == NULL, "Can't create a pref-segments with a '?' glob in the final component");

        ps = pref_segments_new("pref-?-segments-dir%u");
        ok(ps == NULL, "Can't create a pref-segments with a '?' glob and a %%u in the only component");

        ps = pref_segments_new("*/pref-?-segments-dir%u");
        ok(ps == NULL, "Can't create a pref-segments with a '?' glob and a %%u in the final component");

        ps = pref_segments_new("*/pref-segments-dir");
        ok(ps == NULL, "Can't create a pref-segments with a glob but no %%u in the final component");

        ps = pref_segments_new("something-%u-else/pref-segments-dir");
        ok(ps == NULL, "Can't create a pref-segments with a %%u in a directory component");

        ps = pref_segments_new("*/something-%u-else/pref-segments-dir");
        ok(ps == NULL, "Can't create a pref-segments with a glob, then a %%u, both in their own subdirectory components");

        ps = pref_segments_new("pref-segments-dir/*/pref-?-segments-dir%u");
        ok(ps == NULL, "Can't create a pref-segments with a not-immediately-obvious '?' glob and a %%u in the final component");

        ps = pref_segments_new("pref-segments-dir%u%u");
        ok(ps == NULL, "Can't create a pref-segments with two %%u's in the only component");

        ps = pref_segments_new("pref-segments-dir/*/pref-segments-%u%u");
        ok(ps == NULL, "Can't create a pref-segments with two not-immediately-obvious %%u's in the final component");

        is(memory_allocations(), start_allocations, "All memory allocations were freed");
    }

    diag("13 overflow tests");
    {
        char base[PATH_MAX], dir[PATH_MAX], fn[PATH_MAX], match[PATH_MAX + 1];
        size_t add, blen, dlen, flen, mlen;

        memset(match, 'x', sizeof(match) - 1);
        match[sizeof(match) - 1] = '\0';
        ps = pref_segments_new(match);
        ok(ps == NULL, "Can't create a pref-segments with a match path of %zu characters", strlen(match));

        /*
         * We want our match string (match) '.../??/file-%u' to be < PATH_MAX long
         * We want our inotify dir (dir) '...xxxx/yy/' to be < PATH_MAX long
         * We want our actual file (fn) '...xxxx/yy/file-1' to be PATH_MAX-1 long
         * We want our inotify path '...xxxx/yy/file-%u' to be PATH_MAX long
         *
         * For this, we need a base path (base) '...xxxxxx/' to be PATH_MAX - 10 (blen) long (including the trailing /)
         */

        ok(getcwd(base, sizeof(base)), "Got the current directory");
        blen = strlen(base);
        ok(blen < PATH_MAX - 31, "current directory length %zu is less than %u", blen, PATH_MAX - 31);
        skip_if(blen >= PATH_MAX - 31, 9, "Current directory is too deep for these tests") {
            strcpy(base + blen, "/pref-segments-dir");
            blen += strlen(base + blen);
            ok(mkdir(base, 0755) == 0, "Created pref-segments-dir/");
            memcpy(match, base, mlen = blen);

            while (blen < PATH_MAX - 11) {
                add = blen > PATH_MAX - 64 ? PATH_MAX - 12 - blen : 50;

                base[blen++] = '/';
                memset(base + blen, 'x', add);
                blen += add;
                base[blen] = '\0';
                mkdir(base, 0755);

                match[mlen++] = '/';
                match[mlen++] = '*';
            }
            base[blen++] = '/';
            base[blen] = '\0';

            strcpy(match + mlen, "/?""?/file-%u");

            memcpy(dir, base, dlen = blen);
            strcpy(dir + dlen, "yy");
            mkdir(dir, 0755);

            memcpy(fn, base, flen = blen);
            strcpy(fn + flen, "yy/file-1");
            flen += 9;
            create_file_ok(fn, "Deep file\n");

            diag("Prepared base length %zu, fn length %zu", blen, strlen(fn));

            ps = pref_segments_new(match);
            ok(ps != NULL, "Created a pref-segments with a match length of %zu", strlen(match));
            skip_if(!ps, 1, "Cannot test without a pref-segments handle") {
                /* The inotify path is the same as fn except that the "file-1" end is "file-%u" - one byte longer */
                ok(!pref_segments_ischanged(ps), "Got no immediate event - path is too long (length %zu)", flen + 1);
                pref_segments_free(ps);
            }

            /*
             * Now reduce everything by 1 byte and expect success
             * - The actual file (fn) '...xxxx/y/file-1' to be PATH_MAX-2 long
             * - The inotify path '...xxxx/y/file-%u' to be PATH_MAX-1 long
             */

            strcpy(match + mlen, "/?/file-%u");

            memcpy(dir, base, dlen = blen);
            strcpy(dir + dlen, "y");
            mkdir(dir, 0755);

            memcpy(fn, base, flen = blen);
            strcpy(fn + flen, "y/file-1");
            flen += 8;
            create_file_ok(fn, "Shallow file\n");

            diag("Adjusted fn length to %zu", strlen(fn));
            ps = pref_segments_new(match);
            ok(ps != NULL, "Created a pref-segments with a match length of %zu", strlen(match));
            skip_if(!ps, 2, "Cannot test without a pref-segments handle") {
                /* The inotify path is the same as fn except that the "file-1" end is "file-%u" - one byte longer */
                pf = pref_segments_changed(ps);
                ok(pf != NULL, "Got an immediate event - path is not too long (length %zu)", flen + 1);
                skip_if(!pf, 1, "Didn't get a preffile to verify")
                    is_eq(pf->path, fn, "The event reported the monitored file");
                pref_segments_free(ps);
            }

            ok(system("rm -fr pref-segments-dir") == 0, "Cleaned out old pref-segments-dir again");
        }

        is(memory_allocations(), start_allocations, "All memory allocations were freed");
    }

    diag("11 single file tests");
    {
        FILE *fp;

        ps = pref_segments_new("pref-segments-dir");
        ok(ps, "Created a pref-segments structure");
        skip_if(!ps, 9, "Cannot test without a pref-segments handle") {
            mkdir("pref-segments-dir", 0775);
            ok(!pref_segments_ischanged(ps), "Nothing changes when we create the monitored directory");

            rmdir("pref-segments-dir");
            ok(!pref_segments_ischanged(ps), "Nothing changes when we remove the monitored directory");

            fp = fopen("pref-segments-dir", "w");
            pf = pref_segments_changed(ps);
            ok(pf != NULL, "Got an event when the monitored file was created");
            skip_if(!pf, 2, "Didn't get a preffile to verify") {
                is_eq(pf->path, "pref-segments-dir", "The event reported the monitored file");
                is(pf->flags, PREFFILE_ADDED, "The event reported that the file was added");
            }

            fprintf(fp, "Hello world\n");
            fclose(fp);
            unlink("pref-segments-dir");
            pf = pref_segments_changed(ps);
            ok(pf != NULL, "Got an event when the monitored file was updated & removed");
            skip_if(!pf, 3, "Didn't get a preffile to verify") {
                is_eq(pf->path, "pref-segments-dir", "The event reported the monitored file");
                is(pf->flags, PREFFILE_MODIFIED|PREFFILE_REMOVED, "The event reported that the file was modified and removed");
                is(pf->id, 0, "The reported file was id 0");
            }

            pref_segments_free(ps);
        }

        is(memory_allocations(), start_allocations, "All memory allocations were freed");
    }

    diag("48 multi-file tests");
    {
        const struct preffile *pf1, *pf2;
        struct preffile *pfcopy;
        unsigned i, n;
        FILE *fp;

        unlink("pref-segments-9");
        unlink("pref-segments-69");
        unlink("pref-segments-123");

        ps = pref_segments_new("pref-segments-%u");
        ok(ps, "Created a pref-segments structure");
        skip_if(!ps, 25, "Cannot test without a pref-segments handle") {
            fp = fopen(".pref-segments-9", "w");
            pf = pref_segments_changed(ps);
            ok(pf == NULL, "Got no event when a dot file was created");

            fprintf(fp, "Hello world\n");
            fclose(fp);
            ok(!pref_segments_ischanged(ps), "Got no event when the dot file was updated");

            rename(".pref-segments-9", "pref-segments-9");
            pf = pref_segments_changed(ps);
            ok(pf != NULL, "Got an event when the monitored file was moved into place");
            skip_if(!pf, 3, "Didn't get a preffile to verify") {
                is_eq(pf->path, "pref-segments-9", "The event reported the monitored file");
                ok(pf->flags & PREFFILE_ADDED, "The event reported that the file was added");
                is(pf->id, 9, "The reported file was id 9");
            }

            create_file_ok("pref-segments-69", "File 69\n");
            create_file_ok("pref-segments-123", "File 123\n");
            create_file_ok("pref-segments-9", "File 9\n");

            struct {
                unsigned id;
                int flags;
                const char *name;
                const char *action;
            } expect[] = {
                { 9, PREFFILE_MODIFIED, "pref-segments-9", "modified" },
                { 69, PREFFILE_ADDED, "pref-segments-69", "added" },
                { 123, PREFFILE_ADDED, "pref-segments-123", "added" },
            }, *item[3];

            for (i = 0; i < 3; i++)
                item[i] = expect + i;

            for (i = 0; i < 3; i++) {
                pf = pref_segments_changed(ps);
                ok(pf != NULL, "Got event %u after three relevant actions", i);
                skip_if(!pf, 3, "Didn't get a preffile to verify") {
                    for (n = 0; n < 3; n++)
                        if (item[n] && item[n]->id == pf->id)
                            break;
                    ok(n < 3, "This event was expected (id %u)", pf->id);
                    skip_if(n == 3, 2, "Event %u wasn't expected", i) {
                        is_eq(pf->path, item[n]->name, "The event reported the expected file (%s)", item[n]->name);
                        is(pf->flags, item[n]->flags, "The event reported that it was %s", item[n]->action);
                        item[n] = NULL;
                    }
                }
            }

            unlink("pref-segments-9");
            pf = pref_segments_changed(ps);
            ok(pf != NULL, "Got an event when the monitored file was removed");
            skip_if(!pf, 3, "Didn't get a preffile to verify") {
                is_eq(pf->path, "pref-segments-9", "The event reported the monitored file");
                ok(pf->flags & PREFFILE_REMOVED, "The event reported that the file was removed");
                is(pf->id, 9, "The reported file was id 9");
            }

            pref_segments_free(ps);
        }

        ps = pref_segments_new("pref-segments-%u");
        ok(ps, "Created another pref-segments structure");
        skip_if(!ps, 23, "Cannot test without a pref-segments handle") {
            ok(pf1 = pref_segments_changed(ps), "A first event is available immediately at startup");
            MOCKFAIL_START_TESTS(1, PREF_SEGMENTS_PREFFILE_COPY);
            ok(!preffile_copy(pf1), "preffile_copy() returns NULL when it fails");
            MOCKFAIL_END_TESTS();
            ok(pfcopy = preffile_copy(pf1), "preffile_copy() can normally copy the event");
            pf1 = pfcopy;
            pf2 = pref_segments_changed(ps);
            ok(pf2 != NULL, "A second event is available immediately at startup");
            ok(!pref_segments_ischanged(ps), "A third event isn't available immediately at startup");
            skip_if(!pf1 || !pf2, 5, "Didn't get two preffiles to verify") {
                if (pf1->id != 69) {
                    pf = pf1;
                    pf1 = pf2;
                    pf2 = pf;
                }
                is(pf1->id, 69, "One event reported id 69");
                is(pf2->id, 123, "The other event reported id 123");
                is_eq(pf1->path, "pref-segments-69", "One event reported file pref-segments-69");
                is_eq(pf2->path, "pref-segments-123", "The other event reported file pref-segments-123");
                ok(pf1->flags == PREFFILE_ADDED && pf2->flags == PREFFILE_ADDED, "Both events reported that the file was added");
            }
            preffile_free(pfcopy);

            create_file_ok("pref-segments-69", "File 69 modification\n");
            ok(pref_segments_ischanged(ps), "Our modification resulted in an event");

            ok(!pref_segments_setpath(ps, "pref-segments-*"), "Cannot change the path to an invalid path");
            ok(pref_segments_ischanged(ps), "The event is still pending");

            ok(pref_segments_setpath(ps, "pref-segments-%u.not"), "Changed the path to a glob with no files");
            pf = pref_segments_changed(ps);
            ok(pf, "Grabbed the event");
            skip_if(!pf, 1, "Didn't get a preffile to verify")
                ok(pf->id == 69 && pf->flags == (PREFFILE_MODIFIED | PREFFILE_REMOVED), "The event reported id 69 was modified *AND* removed");

            pf = pref_segments_changed(ps);
            ok(pf, "Grabbed another event");
            skip_if(!pf, 1, "Didn't get a preffile to verify")
                ok(pf->id == 123 && pf->flags == PREFFILE_REMOVED, "The event reported id 123 was removed");
            ok(!pref_segments_ischanged(ps), "No other events are pending");

            ok(pref_segments_setpath(ps, "pref-segments-%u"), "Changed the path back to the original glob");
            ok(pref_segments_ischanged(ps), "Events are pending again");

            ok(pref_segments_setpath(ps, "pref-segments-%u"), "Re-set the path to the same value");

            /* The two events are left to exercise the "dirty deletion code" in pref_segments_free() */

            pref_segments_free(ps);
        }

        is(memory_allocations(), start_allocations, "All memory allocations were freed");
    }

    diag("48 overflow tests");
    {
        FILE *fp;

        unlink("pref-segments-overflow-9");

        ps = pref_segments_new("pref-segments-overflow-%u");
        ok(ps, "Created a pref-segments structure");
        skip_if(!ps, 25, "Cannot test overflows without a pref-segments handle") {
            fp = fopen(".pref-segments-overflow-9", "w");
            ok(pref_segments_changed(ps) == NULL, "Got no event when a dot file was created");
            fprintf(fp, "Hello world\n");
            fclose(fp);
            ok(!pref_segments_ischanged(ps), "Got no event when the dot file was updated");
            rename(".pref-segments-overflow-9", "pref-segments-overflow-9");
            ok(pf = pref_segments_changed(ps), "Got an event when the monitored file was moved into place");
            skip_if(!pf, 3, "Didn't get a preffile to verify") {
                is_eq(pf->path, "pref-segments-overflow-9", "The event reported the monitored file");
                ok(pf->flags & PREFFILE_ADDED, "The event (0x%02X) reported that the file was ADDED", pf->flags);
                is(pf->id, 9, "The reported file was id 9");
            }

            fp = fopen(".pref-segments-overflow-9", "w");
            fprintf(fp, "Hello world again\n");
            fclose(fp);
            rename(".pref-segments-overflow-9", "pref-segments-overflow-9");
            ok(pf = pref_segments_changed(ps), "Got an event when the monitored file was moved into place");
            skip_if(!pf, 3, "Didn't get a preffile to verify") {
                is_eq(pf->path, "pref-segments-overflow-9", "The event reported the monitored file");
                ok(pf->flags & PREFFILE_MODIFIED, "The event (0x%02X) reported that the file was MODIFIED", pf->flags);
                is(pf->id, 9, "The reported file was id 9");
            }

            MOCKFAIL_START_TESTS(5, PREF_SEGMENTS_FSEVENT_OVERFLOW);
            fp = fopen(".pref-segments-overflow-9", "w");
            fprintf(fp, "Hello world a third time\n");
            fclose(fp);
            rename(".pref-segments-overflow-9", "pref-segments-overflow-9");
            ok(pref_segments_ischanged(ps), "ischanged works ok, despite an inotify failure");

            fp = fopen(".pref-segments-overflow-9", "w");
            fprintf(fp, "Hello world a fourth time\n");
            fclose(fp);
            rename(".pref-segments-overflow-9", "pref-segments-overflow-9");
            ok(pf = pref_segments_changed(ps), "Got an event when the monitored file was moved into place");
            skip_if(!pf, 3, "Didn't get a preffile to verify") {
                is_eq(pf->path, "pref-segments-overflow-9", "The event reported the monitored file");
                ok(pf->flags & PREFFILE_ADDED, "The event (0x%02X) reported that the file was ADDED (not MODIFIED) due to the inotify overflow", pf->flags);
                is(pf->id, 9, "The reported file was id 9");
            }
            MOCKFAIL_END_TESTS();

            pref_segments_free(ps);
        }
    }

    diag("49 globbed multi-file tests");
    {
        const struct preffile *pf1, *pf2;
        struct preffile *pfcopy;
        const char *dir;
        unsigned id;

        ok(system("rm -fr pref-segments-dir") == 0, "Cleaned out old pref-segments-dir");
        ok(mkdir("pref-segments-dir", 0775) == 0, "Created pref-segments-dir");

        ps = pref_segments_new("pref-segments-dir/*b/?""?/%u-file");
        ok(ps, "Created a pref-segments structure for 'pref-segments-dir/*b/?""?/%%u-file'");
        skip_if(!ps, 45, "Cannot test without a pref-segments handle") {
            ok(!pref_segments_changed(ps), "No events are available immediately at startup");
            ok(mkdir("pref-segments-dir/sub", 0775) == 0, "Created pref-segments-dir/sub/");
            ok(mkdir("pref-segments-dir/sub/00", 0775) == 0, "Created pref-segments-dir/sub/00/");
            ok(mkdir("pref-segments-dir/sub/new-10", 0775) == 0, "Created pref-segments-dir/sub/new-10/");

            create_file_ok("pref-segments-dir/sub/new-10/100-file", "File 100\n");
            ok(!pref_segments_ischanged(ps), "No events yet");

            create_file_ok("pref-segments-dir/sub/00/1-file", "File 1\n");
            pf = pref_segments_changed(ps);
            ok(pf, "Got an event");
            skip_if(!pf, 1, "Didn't get a preffile to verify")
                ok(pf->id == 1 && pf->flags == PREFFILE_ADDED, "The event reported id 1 was added");

            ok(rename("pref-segments-dir/sub/new-10", "pref-segments-dir/sub/10") == 0, "Moved pref-segments-dir/sub/new-10 to pref-segments-dir/sub/10");
            pf = pref_segments_changed(ps);
            ok(pf, "Got an event");
            skip_if(!pf, 1, "Didn't get a preffile to verify")
                ok(pf->id == 100 && pf->flags == PREFFILE_ADDED, "The event reported id 100 was added");

            create_file_ok("pref-segments-dir/sub/00/1-file", "File 1 - updated\n");
            ok(rename("pref-segments-dir/sub", "pref-segments-dir/.sub") == 0, "Moved pref-segments-dir/sub to pref-segments-dir/.sub");
            pf1 = pfcopy = preffile_copy(pref_segments_changed(ps));
            ok(pf1 != NULL, "A first event is available after the hierarchy rename");
            pf2 = pref_segments_changed(ps);
            ok(pf2 != NULL, "A second event is available after the hierarchy rename");
            ok(!pref_segments_ischanged(ps), "A third event isn't available after the hierarchy rename");
            skip_if(!pf1 || !pf2, 11, "Didn't get two preffiles to verify") {
                if (pf1->id != 1) {
                    pf = pf1;
                    pf1 = pf2;
                    pf2 = pf;
                }
                is(pf1->id, 1, "One event reported id 1");
                is(pf2->id, 100, "The other event reported id 100");
                is_eq(pf1->path, "pref-segments-dir/sub/00/1-file", "One event reported file 1-file");
                is_eq(pf2->path, "pref-segments-dir/sub/10/100-file", "The other event reported file 100-file");
                is(pf1->flags, PREFFILE_MODIFIED|PREFFILE_REMOVED, "1-file was reported as modified and removed");
                is(pf2->flags, PREFFILE_REMOVED, "100-file was reported as removed");

                pref_segments_retry(ps, pf2, 1);
                ok(!pref_segments_changed(ps), "After a 1 second retry, no event is immediately available");

                sleep(1);
                ok(pref_segments_ischanged(ps), "The event becomes available after 1 second");
                pf2 = pref_segments_changed(ps);
                ok(pf2 != NULL, "Retrieved the event");
                is_eq(pf2->path, "pref-segments-dir/sub/10/100-file", "The event reports file 100-file");
                is(pf2->flags, PREFFILE_REMOVED|PREFFILE_RETRY, "The event reports 100-file as removed and as a retry");
            }
            preffile_free(pfcopy);

            ok(rename("pref-segments-dir/.sub", "pref-segments-dir/sub") == 0, "Moved pref-segments-dir/.sub back to pref-segments-dir/sub");
            pf1 = pfcopy = preffile_copy(pref_segments_changed(ps));
            ok(pf1 != NULL, "A first event is available after the hierarchy rename");
            pf2 = pref_segments_changed(ps);
            ok(pf2 != NULL, "A second event is available after the hierarchy rename");
            ok(!pref_segments_ischanged(ps), "A third event isn't available after the hierarchy rename");
            skip_if(!pf1 || !pf2, 13, "Didn't get two preffiles to verify") {
                id = pf1->id;
                dir = id == 1 ? "pref-segments-dir/sub/00" : "pref-segments-dir/sub/10";
                if (pf1->id != 1) {
                    pf = pf1;
                    pf1 = pf2;
                    pf2 = pf;
                }
                is(pf1->id, 1, "One event reported id 1");
                is(pf2->id, 100, "The other event reported id 100");
                is_eq(pf1->path, "pref-segments-dir/sub/00/1-file", "One event reported file 1-file");
                is_eq(pf2->path, "pref-segments-dir/sub/10/100-file", "The other event reported file 100-file");
                ok(pf1->flags == PREFFILE_ADDED && pf2->flags == PREFFILE_ADDED, "Both events reported that the file was added");

                ok(rename(dir, "pref-segments-dir/hide") == 0, "Moved %s to pref-segments-dir/hide (covering SLIST_REMOVE_AFTER() prefdir code)", dir);
                pf = pref_segments_changed(ps);
                ok(pf, "Got an event after the directory rename");
                skip_if(pf == NULL, 1, "Didn't get an event after the rename")
                    is(pf->id, id, "The event reported id %u", id);

                ok(mkdir("pref-segments-dir/b", 0755) == 0, "Created pref-segments-dir/b/ (covering the end of prefdir_matches_base())");
                ok(!pref_segments_ischanged(ps), "Didn't get an event after creating pref-segments-dir/b/");

                ok(mkdir("pref-segments-dir/another-sub", 0000) == 0, "Created pref-segments-dir/another-sub/ with dodgy permissions (covering opendir() failures)");
                ok(!pref_segments_ischanged(ps), "Didn't get an event after creating pref-segments-dir/b/");
                ok(chmod("pref-segments-dir/another-sub", 0755) == 0, "Fixed permissions on pref-segments-dir/another-sub/");
            }
            preffile_free(pfcopy);

            pref_segments_free(ps);
        }

        is(memory_allocations(), start_allocations, "All memory allocations were freed");
    }

    return exit_status();
}
