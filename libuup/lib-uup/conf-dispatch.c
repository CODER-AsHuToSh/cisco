#include <kit.h>
#include <kit-alloc.h>
#include <kit-queue.h>

#include "conf-dispatch.h"
#include "conf.h"

struct loadjob {
    struct conf_dispatch cd;
    TAILQ_ENTRY(loadjob) q;    /* Our loadjobq TAILQ membership (queue.*) */
};

TAILQ_HEAD(loadjobq, loadjob);

struct lockable_queue {
    struct loadjobq queue;
    pthread_mutex_t lock;
};

struct blockable_queue {
    struct loadjobq queue;
    pthread_mutex_t lock;
    pthread_cond_t block;
};

static struct {
    struct lockable_queue dead;     /* Jobs that aren't loadable any more (free-list) */
    struct lockable_queue wait;     /* Jobs that have just been loaded and aren't ready to be loaded again yet */
    struct blockable_queue todo;    /* Jobs that need to be done */
    struct lockable_queue live;     /* Jobs that are in progress */
    struct blockable_queue done;    /* Jobs that are complete */
} dispatch = {
    .dead = { TAILQ_HEAD_INITIALIZER(dispatch.dead.queue), PTHREAD_MUTEX_INITIALIZER },
    .wait = { TAILQ_HEAD_INITIALIZER(dispatch.wait.queue), PTHREAD_MUTEX_INITIALIZER },
    .todo = { TAILQ_HEAD_INITIALIZER(dispatch.todo.queue), PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER },
    .live = { TAILQ_HEAD_INITIALIZER(dispatch.live.queue), PTHREAD_MUTEX_INITIALIZER },
    .done = { TAILQ_HEAD_INITIALIZER(dispatch.done.queue), PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER }
};

/*
 * If multiple dispatch locks are to be held, then they must be taken in this
 * order to avoid deadlock:
 *   - todo -> live -> done
 *                  -> dead (done and dead are currently never mutually held)
 *   - wait (wait currently never held with others)
 */

void
conf_dispatch_put(struct conf_dispatch *cd, enum conf_dispatch_queue queue)
{
    struct conf_dispatch *wcd;
    pthread_mutex_t *lock;
    pthread_cond_t *block;
    struct loadjob *job;
    struct loadjobq *wq;

    switch (queue) {
    case CONF_DISPATCH_WAIT:
        wq = &dispatch.wait.queue;
        lock = &dispatch.wait.lock;
        block = NULL;
        break;
    case CONF_DISPATCH_TODO:
        wq = &dispatch.todo.queue;
        lock = &dispatch.todo.lock;
        block = &dispatch.todo.block;
        break;
    default:
        SXEA1(0, "Cannot put work into queue %d", queue);    /* COVERAGE EXCLUSION: This had better be impossible */
    }

    pthread_mutex_lock(&dispatch.dead.lock);
    if ((job = TAILQ_FIRST(&dispatch.dead.queue)) != NULL)
        TAILQ_REMOVE(&dispatch.dead.queue, job, q);
    pthread_mutex_unlock(&dispatch.dead.lock);
    SXEA1(job != NULL || (job = kit_malloc(sizeof(*job))) != NULL, "Couldn't allocate a new dispatch job");

    if (!cd)
        memset(&job->cd, '\0', sizeof(job->cd));
    wcd = cd ?: &job->cd;
    if (queue == CONF_DISPATCH_WAIT) {
        kit_time_cached_update();
        wcd->wait_ms = kit_time_cached_nsec() / 1000000U;
    }
    if (cd)
        job->cd = *cd;
    else
        SXEA6(CONF_DISPATCH_ISEXIT(job->cd), "Failed to create an EXIT job");
    pthread_mutex_lock(lock);
    TAILQ_INSERT_TAIL(wq, job, q);
    if (block)
        pthread_cond_broadcast(block);
    pthread_mutex_unlock(lock);
}

bool
conf_dispatch_getresult(struct conf_dispatch *cd, bool (*block_check_under_spinlock)(void))
{
    struct loadjob *job;

    pthread_mutex_lock(&dispatch.done.lock);

    while ((job = TAILQ_FIRST(&dispatch.done.queue)) == NULL
        && block_check_under_spinlock && block_check_under_spinlock()
        && (TAILQ_FIRST(&dispatch.todo.queue) || TAILQ_FIRST(&dispatch.live.queue)))
        pthread_cond_wait(&dispatch.done.block, &dispatch.done.lock);

    if (job)
        TAILQ_REMOVE(&dispatch.done.queue, job, q);

    pthread_mutex_unlock(&dispatch.done.lock);

    if (job) {
        *cd = job->cd;
        pthread_mutex_lock(&dispatch.dead.lock);
        TAILQ_INSERT_TAIL(&dispatch.dead.queue, job, q);
        pthread_mutex_unlock(&dispatch.dead.lock);
    }

    return !!job;
}

bool
conf_dispatch_getwait(struct conf_dispatch *cd, uint64_t *min_ms)
{
    struct loadjob *job;
    uint64_t age, new_ms;

    pthread_mutex_lock(&dispatch.wait.lock);

    new_ms = min_ms ? *min_ms : 0;
    if ((job = TAILQ_FIRST(&dispatch.wait.queue)) != NULL && new_ms) {
        kit_time_cached_update();                                          /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        age = kit_time_cached_nsec() / 1000000ULL - job->cd.wait_ms;       /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        if (age < new_ms) {                                                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            new_ms = new_ms - age;    /* Maybe a better time to wait */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            job = NULL;                                                    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        }
    }

    if (job)
        TAILQ_REMOVE(&dispatch.wait.queue, job, q);

    pthread_mutex_unlock(&dispatch.wait.lock);

    if (job) {
        *cd = job->cd;
        pthread_mutex_lock(&dispatch.dead.lock);
        TAILQ_INSERT_TAIL(&dispatch.dead.queue, job, q);
        pthread_mutex_unlock(&dispatch.dead.lock);
    }

    if (min_ms)
        *min_ms = new_ms;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    return !!job;
}

conf_dispatch_handle_t
conf_dispatch_getwork(struct conf_dispatch *cd, bool block)
{
    struct loadjob *job;

    pthread_mutex_lock(&dispatch.todo.lock);

    while ((job = TAILQ_FIRST(&dispatch.todo.queue)) == NULL && block)
        pthread_cond_wait(&dispatch.todo.block, &dispatch.todo.lock);

    if (job) {
        /*
         * We hold the 'done' lock while we move a job from 'todo' to 'live'
         * so that conf_dispatch_getresult() callers continue to block.
         */
        pthread_mutex_lock(&dispatch.live.lock);
        pthread_mutex_lock(&dispatch.done.lock);

        TAILQ_REMOVE(&dispatch.todo.queue, job, q);
        TAILQ_INSERT_TAIL(&dispatch.live.queue, job, q);

        pthread_mutex_unlock(&dispatch.done.lock);
        pthread_mutex_unlock(&dispatch.live.lock);
        *cd = job->cd;
    }

    pthread_mutex_unlock(&dispatch.todo.lock);

    return job;
}

void
conf_dispatch_deadwork(conf_dispatch_handle_t job)
{
    pthread_mutex_lock(&dispatch.live.lock);
    pthread_mutex_lock(&dispatch.dead.lock);
    TAILQ_REMOVE(&dispatch.live.queue, job, q);
    TAILQ_INSERT_TAIL(&dispatch.dead.queue, job, q);

    if (job->cd.segment) {
        /*
         * This is a segment completion and is never moved to the done queue,
         * signal the done CV in case there is a waiter in conf_dispatch_getresult().
         */
        pthread_cond_broadcast(&dispatch.done.block);
    }

    pthread_mutex_unlock(&dispatch.dead.lock);
    pthread_mutex_unlock(&dispatch.live.lock);
}

void
conf_dispatch_donework(struct conf_dispatch *cd, conf_dispatch_handle_t job)
{
    job->cd = *cd;

    pthread_mutex_lock(&dispatch.live.lock);
    pthread_mutex_lock(&dispatch.done.lock);
    TAILQ_REMOVE(&dispatch.live.queue, job, q);
    TAILQ_INSERT_TAIL(&dispatch.done.queue, job, q);
    pthread_cond_broadcast(&dispatch.done.block);
    pthread_mutex_unlock(&dispatch.done.lock);
    pthread_mutex_unlock(&dispatch.live.lock);
}

/* Return an active job from the live queue to the todo queue */
void
conf_dispatch_requeue(struct conf_dispatch *cd, conf_dispatch_handle_t job)
{
    job->cd = *cd;

    pthread_mutex_lock(&dispatch.todo.lock);
    pthread_mutex_lock(&dispatch.live.lock);

    TAILQ_REMOVE(&dispatch.live.queue, job, q);
    TAILQ_INSERT_TAIL(&dispatch.todo.queue, job, q);
    pthread_cond_broadcast(&dispatch.todo.block);

    pthread_mutex_unlock(&dispatch.live.lock);
    pthread_mutex_unlock(&dispatch.todo.lock);
}

void
conf_dispatch_purge(void (*cb)(struct conf_dispatch *cd))
{
    struct {
        struct loadjobq *queue;
        pthread_mutex_t *lock;
        void (*cb)(struct conf_dispatch *);
    } purge[] = {
        { &dispatch.wait.queue, &dispatch.wait.lock, cb },
        { &dispatch.todo.queue, &dispatch.todo.lock, cb },
        { &dispatch.dead.queue, &dispatch.dead.lock, NULL },
    };
    struct loadjobq cbq;
    struct loadjob *job;
    unsigned i;

    TAILQ_INIT(&cbq);
    for (i = 0; i < sizeof(purge) / sizeof(*purge); i++) {
        pthread_mutex_lock(purge[i].lock);
        while ((job = TAILQ_FIRST(purge[i].queue)) != NULL) {
            TAILQ_REMOVE(purge[i].queue, job, q);
            TAILQ_INSERT_TAIL(&cbq, job, q);
        }
        pthread_mutex_unlock(purge[i].lock);

        /* Callback is done without the lock held */
        while ((job = TAILQ_FIRST(&cbq)) != NULL) {
            TAILQ_REMOVE(&cbq, job, q);
            if (CONF_DISPATCH_ISFREE(job->cd))
                conf_free(job->cd.data);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            else if (purge[i].cb)
                purge[i].cb(&job->cd);
            kit_free(job);
        }
    }

    SXEA1(!TAILQ_FIRST(&dispatch.live.queue), "%s(): Live queue is still active", __FUNCTION__);
    SXEA1(!TAILQ_FIRST(&dispatch.done.queue), "%s(): Done queue is still active", __FUNCTION__);
}
