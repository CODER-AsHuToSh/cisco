#include <kit-alloc.h>
#include <kit-queue.h>
#include <mockfail.h>
#include <murmurhash3.h>
#include <pthread.h>

#include "object-hash.h"
#include "uup-counters.h"

/*-
 * How the domainlist hash table works with a perl script to help illustrate:
 *
 * #
 * # +---+---+---+---+---+---+---+---+
 * # |   |   |   |   |   |   |   |   | <-- row #1; happens to be cache line sized friendly :-)
 * # +---+---+---+---+---+---+---+---+
 * # :
 * # :
 * # +---+---+---+---+---+---+---+---+
 * # |   |   |   |   |   |   |   |   | <-- row #n
 * # +---+---+---+---+---+---+---+---+
 * #
 * #   ^   ^   ^   ^   ^   ^   ^       <-- cells 0..6; pointers to domainlist structures or NULL
 * #                               ^   <-- cells    7; row overflow pointer to newly malloc()d row
 * #
 * # $ perl simple-cuckoo-4-x-8.pl
 * # - hashing 770703 elements into 131072 rows of 8 cells (1048576 cells total) using 8.000000 MB
 * # - #0 row extensions necessary
 * #
 *
 * -------------------------------------- 8>< --------------------------------------
 * use strict;
 * use Digest::MurmurHash3 qw( murmur128_x64 );
 *
 * my $approx_unique_domainlists = 1 << 19;      # 515,727 as of Dec 2012
 * my $keys = $approx_unique_domainlists * 1.47; # 770,703 domainlists possible before simple cuckoo hash table uses row extensions
 * my $rows = $approx_unique_domainlists / 4;
 * my $cells = 8; # 7 pointers to domainlists & one row extension pointer
 * my @array;
 * my @hash; # 4 * 32bit hashes per array row
 * my $extensions; # number of row extensions
 * printf qq[- hashing %u elements into %u rows of %u cells (%u cells total) using %f MB\n], $keys, $rows, $cells, $rows * $cells, $rows * $cells * 8 / 1024 / 1024; # 8 bytes for pointer size
 * SEARCH: foreach my $i ( 1..$keys ) {
 *    my ( $h64_1, $h64_2 ) = murmur128_x64( $i );
 *    $hash[0] = int ( ( $h64_1 >>  0 ) & ( $rows - 1 ) );
 *    $hash[1] = int ( ( $h64_1 >> 32 ) & ( $rows - 1 ) );
 *    $hash[2] = int ( ( $h64_2 >>  0 ) & ( $rows - 1 ) );
 *    $hash[3] = int ( ( $h64_2 >> 32 ) & ( $rows - 1 ) );
 *    foreach my $c ( 0..($cells - 1 - 1) ) {
 *       foreach my $h ( 0..3 ) {
 *          if ( not defined $array[$hash[$h]][$c] ) { $array[$hash[$h]][$c] ++; last SEARCH; }
 *       }
 *    }
 *    $extensions ++;
 *    printf qq[- extension #%u for key #%u // $hash[0] $hash[1] $hash[2] $hash[3]\n], $extensions, $i;
 * }
 * printf qq[- #%u row extensions necessary\n], $extensions;
 * -------------------------------------- 8>< --------------------------------------
 */

#define OBJECT_HASH_CELLS      7
#define HASHEDROW(oh, hash)    (oh->table + (hash & ((oh)->rows - 1)))
#define HASHEDLOCK(oh, hash)   do { if ((oh)->locks) pthread_spin_lock(oh->lock + (hash & ((oh)->locks - 1))); } while (0)
#define HASHEDUNLOCK(oh, hash) do { if ((oh)->locks) pthread_spin_unlock(oh->lock + (hash & ((oh)->locks - 1))); } while (0)
#define EXTRALOCK(oh)          do { if ((oh)->locks) pthread_spin_lock(oh->lock + (oh)->locks); } while (0)
#define EXTRAUNLOCK(oh)        do { if ((oh)->locks) pthread_spin_unlock(oh->lock + (oh)->locks); } while (0)

struct object_hash_row {
    void *cell[OBJECT_HASH_CELLS];
    struct object_hash_row *next;
};

struct object_hash_row_extra {
    struct object_hash_row row;
    SLIST_ENTRY(object_hash_row_extra) link;
};

struct object_hash {
    unsigned magic;                                /* Chosen by the hash creator */
    SLIST_HEAD(, object_hash_row_extra) extras;    /* overflow extensions */
    unsigned locks;                                /* Usable allocated object_hash::lock entries, not including the extra lock */
    pthread_spinlock_t *lock;                      /* object_hash::locks locks plus one for 'extras' */
    unsigned rows;                                 /* Number of allocated object_hash::table entries */
    struct object_hash_row *table;                 /* object_hash::rows items */

    unsigned entries;                              /* The current number of table entries, protected by the 'extras' lock */
};

struct object_hash *
object_hash_new(unsigned rows, unsigned locks, unsigned magic)
{
    struct object_hash *oh;
    unsigned lk, lockalloc;

    SXEA6((rows != 0) && !(rows & (rows - 1)), "rows (%u) must be a power of two", rows);
    SXEA6(locks == 0 || !(locks & (locks - 1)), "locks (%u) must be zero or a power of two", locks);

    lockalloc = locks ? locks + 1 : 0;
    if ((oh = MOCKFAIL(object_hash_new, NULL, kit_calloc(1, sizeof(*oh) + rows * sizeof(*oh->table) + lockalloc * sizeof(*oh->lock)))) == NULL)
        SXEL2("Cannot allocate object-hash with %u rows and %u locks", rows, lockalloc);
    else {
        oh->magic = magic;
        SLIST_INIT(&oh->extras);
        oh->rows = rows;
        oh->table = (struct object_hash_row *)(oh + 1);
        oh->locks = locks;
        oh->lock = locks ? (pthread_spinlock_t *)((uint8_t *)(oh + 1) + rows * sizeof(*oh->table)) : NULL;
        for (lk = 0; lk < lockalloc; lk++)
            pthread_spin_init(oh->lock + lk, PTHREAD_PROCESS_PRIVATE);
    }

    return oh;
}

unsigned
object_hash_magic(struct object_hash *oh)
{
    return oh->magic;
}

unsigned
object_hash_entries(struct object_hash *oh)
{
    return oh->entries;
}

const void *
object_hash_extras(struct object_hash *oh)
{
    return SLIST_FIRST(&oh->extras);
}

void
object_hash_free(struct object_hash *oh)
{
    struct object_hash_row_extra *extra;
    unsigned lk, lockalloc;

    if (oh) {
        SXEA1(!oh->entries, "Attempt to delete an object-hash with %u entr%s", oh->entries, oh->entries == 1 ? "y" : "ies");
        while ((extra = SLIST_FIRST(&oh->extras)) != NULL) {
            SLIST_REMOVE_HEAD(&oh->extras, link);
            kit_free(extra);
        }
        lockalloc = oh->locks ? oh->locks + 1 : 0;
        for (lk = 0; lk < lockalloc; lk++)
            pthread_spin_destroy(oh->lock + lk);
        kit_free(oh);
    }
}

static void
setup_hashes_and_rows(struct object_hash_row *row[4], uint32_t hash[4], struct object_hash *oh, const uint8_t *fp, unsigned fplen)
{
    const uint32_t seed = 0xa59bc9d7;
    unsigned h, o;

    MurmurHash3_xnn_128(fp, fplen, seed, hash);
    for (h = 0; h < 4; h++) {
        row[h] = HASHEDROW(oh, hash[h]);
        for (o = 0; o < h; o++)
            if (row[o] == row[h]) {
                row[h] = NULL;
                break;
            }
    }
}

void *
object_hash_action(struct object_hash *oh, const uint8_t *fp, unsigned fplen, bool (*action)(void *udata, void **obj), void *udata)
{
    struct object_hash_row *row[4];
    uint32_t hash[4];
    unsigned c, h;
    void *result;
    int more;

    setup_hashes_and_rows(row, hash, oh, fp, fplen);
    result = NULL;
    do {
        for (more = 0, h = 0; result == NULL && h < 4; h++)
            if (row[h]) {
                HASHEDLOCK(oh, hash[h]);
                for (c = 0; c < OBJECT_HASH_CELLS; c++) {
                    result = row[h]->cell[c];
                    if (row[h]->cell[c] && action(udata, row[h]->cell + c)) {
                        if (row[h]->cell[c] == NULL) {
                            EXTRALOCK(oh);
                            oh->entries--;
                            EXTRAUNLOCK(oh);
                        }
                        break;
                    }
                    result = NULL;
                }
                HASHEDUNLOCK(oh, hash[h]);
                if ((row[h] = row[h]->next) != NULL)
                    more++;
            }
    } while (more && result == NULL);

    return result;
}

void *
object_hash_add(struct object_hash *oh, void *obj, const uint8_t *fp, unsigned fplen)
{
    struct object_hash_row_extra *extra;
    struct object_hash_row *row[4];
    uint32_t hash[4];
    int extend, more;
    unsigned c, h;
    void *result;

    setup_hashes_and_rows(row, hash, oh, fp, fplen);
    result = NULL;
    extend = -1;
    do {
        for (more = 0, h = 0; result == NULL && h < 4; h++)
            if (row[h]) {
                HASHEDLOCK(oh, hash[h]);
                for (c = 0; c < OBJECT_HASH_CELLS; c++)
                    if (!row[h]->cell[c]) {
                        EXTRALOCK(oh);
                        oh->entries++;
                        EXTRAUNLOCK(oh);
                        result = row[h]->cell[c] = obj;
                        break;
                    }
                HASHEDUNLOCK(oh, hash[h]);
                if ((row[h] = row[h]->next) != NULL)
                    more++;
                else if (extend == -1)
                    extend = h;
            }
    } while (more && result == NULL);

    if (result == NULL) {
        SXEA6(extend != -1, "I don't know what to extend");
        kit_counter_incr(COUNTER_UUP_OBJECT_HASH_OVERFLOWS);
        if ((extra = MOCKFAIL(object_hash_add, NULL, kit_calloc(1, sizeof(*extra)))) == NULL)
            obj = NULL;
        else {
            extra->row.cell[0] = obj;
            HASHEDLOCK(oh, hash[extend]);
            for (row[extend] = HASHEDROW(oh, hash[extend]); row[extend]->next; row[extend] = row[extend]->next)
                ;
            for (c = 0; result == NULL && c < OBJECT_HASH_CELLS; c++)
                if (!row[extend]->cell[c])
                    result = row[extend]->cell[c] = obj;    /* COVERAGE EXCLUSION: someone else created this extension since I last had the hashed lock */
            if (result == NULL)
                row[extend]->next = &extra->row;
            HASHEDUNLOCK(oh, hash[extend]);

            EXTRALOCK(oh);
            if (result == NULL)
                SLIST_INSERT_HEAD(&oh->extras, extra, link);
            oh->entries++;
            EXTRAUNLOCK(oh);

            if (result)
                kit_free(extra);                        /* COVERAGE EXCLUSION: someone else created this extension since I last had the hashed lock */
            else
                result = obj;
        }
    }

    return result;
}
