/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif

void urllist_get_real_type_internals(struct conf_type *copy) ;
void urllist_set_type_internals(const struct conf_type *replacement) ;
void urllist_register(module_conf_t *m, const char *name, const char *fn, bool loadable) ;
const struct urllist * urllist_conf_get(const struct confset *set, module_conf_t m) ;

/**
 * Search for a matching URL in a URL list. Partial URLs are matched
 *
 * @param ul      urllist to search in
 * @param url     URL to search for, which MUST be in normal form
 * @param url_len length of the URL
 *
 * @return 0 if no match or the length of the matching URL
 */
unsigned urllist_match(const struct urllist *ul, const char *url, unsigned url_len) ;
struct urllist * urllist_new_from_buffer(const char *buf, int len, struct object_fingerprint *of, uint32_t loadflags) ;
struct urllist * urllist_new(struct conf_loader *cl) ;
struct urllist * urllist_new_strict(struct conf_loader *cl, unsigned maxlines) ;
void urllist_refcount_inc(struct urllist *me) ;
void urllist_refcount_dec(struct urllist *me) ;

#ifdef __cplusplus
}
#endif
