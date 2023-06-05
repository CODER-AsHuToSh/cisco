/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif

void lists_org_refcount_dec(void *obj) ;
void lists_org_refcount_inc(void *obj) ;
void * lists_org_new(uint32_t orgid, struct conf_loader *cl, const struct conf_info *info) ;

/**
 * Lookup a DNS name in all the domainlists of a list_org. Partial matches are returned.
 *
 * @param me             Pointer to the list_org to look in
 * @param subset         NULL to look in all lists, or a sorted array of listids
 * @param count          Number of listids in the subset
 * @param next           0 on the first call, or the number returned from the previous call
 * @param name           The DNS name to look for
 * @param listid_matched Pointer to a variable populated with the listid of the list containing name
 * @param name_matched   Pointer to a variable populated with a pointer to the part of name that matched
 * @param bit_out        Pointer to a variable that will be set to the list bit (0 if none), or NULL
 *
 * @return 0 if not found or a positive integer that should be passed as 'next' to continue the lookup
 */
unsigned lists_org_lookup_domainlist(const struct lists_org *me, uint32_t *subset, unsigned count, unsigned next, const uint8_t *name,
                            uint32_t *listid_matched, const uint8_t **name_matched, uint8_t *bit_out) ;

/**
 * Lookup a URL in all or a subset of the urllists of a list_org. Partial matches are returned.
 *
 * @param me             Pointer to the list_org to look in
 * @param subset         NULL to look in all lists, or a sorted array of listids
 * @param count          Number of listids in the subset
 * @param next           0 on the first call, or the number returned from the previous call
 * @param url            URL to look for
 * @param length         Length of the URL
 * @param listid_matched Pointer to a variable populated with the listid of the list containing name
 * @param length_matched Pointer to a variable populated with the length of the partial URL that matched
 * @param bit_out        Pointer to a variable that will be set to the list bit (0 if none), or NULL
 *
 * @return 0 if not found or a positive integer that should be passed as 'next' to continue the lookup
 */
unsigned lists_org_lookup_urllist(const struct lists_org *me, uint32_t *subset, unsigned count, unsigned next, const char *url,
                         unsigned length, uint32_t *listid_matched, unsigned *length_matched, uint8_t *bit_out) ;

/**
 * Lookup a CIDR in all or a subset of the cidrlists of a list_org. Partial matches are returned.
 *
 * @param me             Pointer to the list_org to look in
 * @param subset         NULL to look in all lists, or a sorted array of listids
 * @param count          Number of listids in the subset
 * @param next           0 on the first call, or the number returned from the previous call
 * @param url            URL to look for
 * @param length         Length of the URL
 * @param listid_matched Pointer to a variable set to the listid of the list containing name
 * @param bits_matched   Pointer to a variable set to the number of bits in the matched CIDR (CIDR_MATCH_ALL for 0.0.0.0/0)
 * @param bit_out        Pointer to a variable that will be set to the list bit (0 if none), or NULL
 *
 * @return 0 if not found or a positive integer that should be passed as 'next' to continue the lookup
 */
unsigned lists_org_lookup_cidrlist(const struct lists_org *me, uint32_t *subset, unsigned count, unsigned next, struct netaddr *ipaddr,
                          uint32_t *listid_matched, unsigned *bits_matched, uint8_t *bit_out) ;

#ifdef __cplusplus
}
#endif