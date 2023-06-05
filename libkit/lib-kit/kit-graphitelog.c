/*
 * This module takes all defined counters (see kit-counters.c) and outputs their
 * values to a file on at a regular interval, in a format that can be sent to a
 * graphite instance for monitoring.
 */

#include <stdio.h>
#include <sxe-log.h>
#include <time.h>

#include "kit.h"
#include "kit-counters.h"
#include "kit-safe-rw.h"
#include "kit-graphitelog.h"

static __thread int graphitelog_fd = -1;
static volatile unsigned graphitelog_json_limit;
static volatile unsigned graphitelog_interval = 0;
static volatile bool timetodie = false;

struct kit_graphitelog_buffer {
    char buf[INT16_MAX];
    int pos;                /* position in the buffer */
    int counter;            /* the current position of element in current log. */
    time_t now;             /* the timestamp for current log iteration */
    uint8_t json_complete;  /* Flag indicating whether '}' is added to end of json */
};

static void
kit_graphitelog_complete(struct kit_graphitelog_buffer *buffer)
{
    if (!buffer->json_complete) {
        if (buffer->pos < (int)sizeof(buffer->buf))
            buffer->pos += snprintf(buffer->buf + buffer->pos, sizeof(buffer->buf) - buffer->pos, "}\n");

        if (buffer->pos >= (int)sizeof(buffer->buf))
            SXEL3("graphitelog buffer overflow - graphite data has been truncated and is invalid");    /* COVERAGE EXCLUSION: Not possible to overflow with current stats */

        buffer->json_complete = 1;
        kit_safe_write(graphitelog_fd, buffer->buf, (size_t)buffer->pos, -1);
    }
}

static void
kit_graphitelog_counter_callback(void *v, const char *key, const char *value)
{
    struct kit_graphitelog_buffer *buffer = v;

    /* Start a new json object */
    if (buffer->counter % graphitelog_json_limit == 0) {
        buffer->pos = snprintf(buffer->buf, sizeof(buffer->buf), "{\"log.timestamp\":\"%lu\"", (unsigned long)buffer->now);
        SXEA1(buffer->pos < (int)sizeof(buffer->buf), "Internal error: buffer is unusably small!");
        buffer->json_complete = 0;
    }

    if (buffer->pos < (int)sizeof(buffer->buf)) {
        buffer->pos += snprintf(buffer->buf + buffer->pos, sizeof(buffer->buf) - buffer->pos, ",\"%s\":\"%s\"", key, value);
        buffer->counter++;
    }

    /* If the limit is reached (or the buffer has overflowed), send the (possibly truncated) JSON object */
    if (buffer->counter % graphitelog_json_limit == 0 || buffer->pos >= (int)sizeof(buffer->buf)) {
        kit_graphitelog_complete(buffer);
    }
}

/**
 * Set or update the configurable options
 *
 * @param json_limit  Maximum number of counters in a single json line
 * @param interval    Seconds between outputting counters to the graphite log
 */
void
kit_graphitelog_update_set_options(unsigned json_limit, unsigned interval)
{
    graphitelog_json_limit = json_limit;
    graphitelog_interval = interval;

}

/**
 * Launch the graphite logging thread
 *
 * @param arg  Pointer to a struct kit_graphitelog_thread containing the log file
 *             descriptor and counter slot.
 */
void *
kit_graphitelog_start_routine(void *arg)
{
    struct kit_graphitelog_thread *thr = arg;
    struct kit_graphitelog_buffer buffer;
    uint64_t now_usec, sleep_ms;
    bool bedtime, exittime;

    SXEL4("kit_graphitelog_start_routine(): thread started");
    kit_counters_init_thread(thr->counter_slot);
    graphitelog_fd = thr->fd;
    SXEL6("Graphitelog is %s", graphitelog_fd >= 0 ? "enabled" : "disabled");

    for (exittime = false; !exittime; ) {
        if (timetodie)
            exittime = true;    /* This will be our last time through! */

        SXEA1(graphitelog_interval, "No configuration acquired; cannot run graphitelog thread");
        time(&buffer.now);

        if (graphitelog_fd >= 0) {
            buffer.counter = 0;
            kit_counters_mib_text("", &buffer, kit_graphitelog_counter_callback, -1, COUNTER_FLAG_NONE);
            kit_graphitelog_complete(&buffer);
        }

        for (bedtime = true; !timetodie && bedtime; ) {
            now_usec = kit_time_nsec() / 1000;

            /* Aim to wake up at the next half-interval */
            sleep_ms = graphitelog_interval * 1000000 -
                       (now_usec + graphitelog_interval * 500000) % (graphitelog_interval * 1000000);

            if (sleep_ms > 1000000)
                /* Sleep for 3/4 second at a time so that we wake up reasonably quickly when it's time to die */
                sleep_ms = 750000;
            else
                bedtime = false;
            usleep(sleep_ms);
        }
    }

    return NULL;
}

/**
 * Signal the graphitelog thread to gracefully terminate
 *
 * @note This initiates the termination, but it happens asynchronously. thread_join the thread to synchronize.
 */
void
kit_graphitelog_terminate(void)
{
    timetodie = true;
}

