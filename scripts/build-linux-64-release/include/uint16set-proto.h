/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif

struct uint16set * uint16set_new(const char *txt, unsigned *consumed) ;
bool uint16set_match(const struct uint16set *me, uint16_t val) ;
const char * uint16set_to_str(const struct uint16set *me) ;
unsigned uint16set_count(const struct uint16set *me) ;
void uint16set_free(struct uint16set *me) ;

#ifdef __cplusplus
}
#endif
