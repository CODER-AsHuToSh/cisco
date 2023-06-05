/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif

const char * pref_categories_to_buf(const pref_categories_t *cat, unsigned size, char *buf) ;
const char * pref_categories_idstr(const pref_categories_t *cat) ;
size_t pref_categories_sscan(pref_categories_t *cat, const char *str) ;
void pref_categories_setall(pref_categories_t *cat) ;
void pref_categories_setbit(pref_categories_t *cat, unsigned bit) ;
void pref_categories_unsetbit(pref_categories_t *cat, unsigned bit) ;
bool pref_categories_getbit(const pref_categories_t *cat, unsigned bit) ;
void pref_categories_setnone(pref_categories_t *cat) ;
bool pref_categories_equal(const pref_categories_t *left, const pref_categories_t *right) ;
bool pref_categories_isnone(const pref_categories_t *cat) ;
bool pref_categories_isnone_ignorebit(const pref_categories_t *cat, unsigned bit) ;
bool pref_categories_intersect(pref_categories_t *cat, const pref_categories_t *cat1, const pref_categories_t *cat2) ;
bool pref_categories_union(pref_categories_t *cat, const pref_categories_t *cat1, const pref_categories_t *cat2) ;
void pref_categories_clear(pref_categories_t *cat, const pref_categories_t *clear) ;
const pref_categories_t * pref_categories_usable(pref_categories_t *cat,
                       const pref_categories_t *base_blocked_categories,
                       const pref_categories_t *policy_categories,
                       const pref_categories_t *overridable) ;
void * pref_categories_pack(const pref_categories_t *cat) ;
bool pref_categories_unpack(pref_categories_t *cat, const void *v) ;

#ifdef __cplusplus
}
#endif