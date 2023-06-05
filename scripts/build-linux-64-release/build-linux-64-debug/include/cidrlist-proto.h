/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif


/* Only used by tests - to get the original cidrlist type contents
 */
const struct conf_type * cidrlist_get_real_type_internals(struct conf_type *copy) ;
void cidrlist_set_type_internals(const struct conf_type *replacement) ;
void cidrlist_register(module_conf_t *m, const char *name, const char *fn, bool loadable) ;
void iplist_register(module_conf_t *m, const char *name, const char *fn, bool loadable) ;
const struct cidrlist * cidrlist_conf_get(const struct confset *set, module_conf_t m) ;

/**
 * Get the cidrlist, which the additional constraint that it be an IP list
 */
const struct cidrlist * iplist_conf_get(const struct confset *set, module_conf_t m) ;
struct cidrlist * cidrlist_new(enum cidr_parse how) ;
void cidrlist_sort(struct cidrlist *me) ;
bool cidrlist_append(struct cidrlist *me, const struct cidrlist *cl) ;
struct cidrlist * cidrlist_new_from_string(const char *str, const char *delims, const char **endptr, struct object_fingerprint *of, enum cidr_parse how) ;
struct cidrlist * cidrlist_new_from_file(struct conf_loader *cl, enum cidr_parse how) ;
void cidrlist_refcount_inc(struct cidrlist *me) ;
void cidrlist_refcount_dec(struct cidrlist *me) ;

/**
 * Search for a matching CIDR in a CIDR list.
 *
 * @param me       urllist to search in
 * @param addr     netaddr to search for
 * @param x        xray pointer or NULL
 * @param listname name of the list being searched or NULL (used only by xray and debug build)
 *
 * @return 0 if no match, the number of bits in the matching CIDR, or CIDR_MATCH_ALL if the matching CIDR was 0.0.0.0/0
 */
unsigned cidrlist_search(const struct cidrlist *me, const struct netaddr *addr, struct xray *x, const char *listname) ;
char * cidrlist_to_buf(const struct cidrlist *me, char *buf, size_t sz, size_t *len_out) ;

/**
 *  Return the worst case buffer size needed to convert the cidrlist into a string
 */
size_t cidrlist_buf_size(const struct cidrlist *me) ;

/**
 * Deallocate a index randomization list
 */
void iplist_random_free(struct random_list_index **rli_ptr) ;

/**
 * Lookup a random IP from the provided list, excluding any IPs in an ignore list.
 */
bool iplist_random(const struct cidrlist *me, struct random_list_index **rli_ptr, struct netsock *sock, struct cidrlist *ignore,
              struct xray *x, const char *listname) ;

#ifdef __cplusplus
}
#endif