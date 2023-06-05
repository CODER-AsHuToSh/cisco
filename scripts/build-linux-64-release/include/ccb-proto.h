/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif

int ccb_pos2handling(unsigned pos) ;
void ccb_register(module_conf_t *m, const char *name, const char *fn, bool loadable) ;
struct ccb * ccb_new(struct conf_loader *cl) ;
bool ccb_handling_pos_intersects(const struct ccb *me, pref_categories_t *ret, unsigned hpos, const pref_categories_t *cat) ;
const char * ccb_label(const struct ccb *me, unsigned bit) ;
const char * ccb_allowlisted_txt(const struct ccb *me) ;
bool ccb_ismasked(const struct ccb *me, unsigned bit) ;
void ccb_masked(const struct ccb *me, pref_categories_t *ret) ;
const struct conf * ccb_conf(const struct ccb *me) ;
uint8_t ccb_version(const struct ccb *me) ;
void ccb_refcount_inc(struct ccb *me) ;
void ccb_refcount_dec(struct ccb *me) ;
void ccb_deinitialize(void) ;
const struct ccb * ccb_conf_get(const struct confset *set, module_conf_t m) ;
const char * ccb_pref_categories_str(const struct ccb *ccb, const pref_categories_t *cat) ;
const char * ccb_handling_str(int handling) ;

#ifdef __cplusplus
}
#endif
