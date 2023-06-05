/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif

void application_register_resolver(module_conf_t *m, const char *name, const char *fn, bool loadable) ;
void application_register_proxy(module_conf_t *m, const char *name, const char *fn, bool loadable) ;
void application_register(module_conf_t *m, const char *name, const char *fn, bool loadable) ;
const struct application * application_conf_get(const struct confset *set, module_conf_t m) ;
bool application_match_domain(const struct application *me, const uint8_t *name, struct xray *x, const char *listname) ;
bool application_proxy(const struct application *me, const uint8_t *name, struct xray *x, const char *listname) ;
const uint8_t * application_lookup_domainlist_byid(const struct application *me, uint32_t appid, const uint8_t *name, bool proxy, struct xray *x) ;
const uint8_t * application_match_domain_byid(const struct application *me, uint32_t appid, const uint8_t *name, struct xray *x) ;
const uint8_t * application_proxy_byid(const struct application *me, uint32_t appid, const uint8_t *name, struct xray *x) ;
bool application_match_url_byid(const struct application *me, uint32_t appid, const char *url, unsigned urllen) ;

#ifdef __cplusplus
}
#endif