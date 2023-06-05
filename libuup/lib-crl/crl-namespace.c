#include <string.h>
#include <sxe-log.h>

#include "crl.h"

#define CRL_NAMESPACE_OBJECT     0
#define CRL_NAMESPACE_ATTRIBUTES 1

static __thread struct crl_namespace *crl_namespaces = NULL;

/**
 * Push a namespace based on a JSON object onto the per thread stack of namespaces.
 *
 * @param namespace Pointer to a namespace
 * @param object    Pointer to the JSON object that implements the namespace
 */
void
crl_namespace_push_object(struct crl_namespace *namespace, cJSON *object)
{
    namespace->type   = CRL_NAMESPACE_OBJECT;
    namespace->object = object;
    namespace->next   = crl_namespaces;
    crl_namespaces    = namespace;
}

/**
 * Push a namespace based on a CRL attribute set onto the per thread stack of namespaces.
 *
 * @param namespace  Pointer to a namespace
 * @param attributes Pointer to the CRL attributes set that implements the namespace
 */
void
crl_namespace_push_attributes(struct crl_namespace *namespace, struct crl_value *attributes)
{
    namespace->type       = CRL_NAMESPACE_ATTRIBUTES;
    namespace->attributes = attributes;
    namespace->next       = crl_namespaces;
    crl_namespaces        = namespace;
}

/**
 * Pop the top namespace off the per thread stack of namespaces.
 *
 * @return the namespace popped or NULL if the stack was empty
 */
struct crl_namespace *
crl_namespace_pop(void)
{
    struct crl_namespace *namespace = crl_namespaces;

    crl_namespaces = crl_namespaces ? crl_namespaces->next : NULL;
    return namespace;
}

/**
 * Look up a name in the per thread stack of namespaces.
 *
 * @param name Pointer to the name to look up
 * @param len  Length of the name
 *
 * @return The matching JSON value from the first matching namespace or NULL if the name wasn't found in any namespace
 */
cJSON *
crl_namespace_lookup(const char *name, unsigned len)
{
    struct crl_namespace   *namespace;
    cJSON                  *json;
    const struct crl_value *value;
    char                    namestring[256];

    SXEA1(len < sizeof(namestring),
          "Name '%.*s...' exceeds %zu byte maximum", (int)(sizeof(namestring) - 1), name, sizeof(namestring) - 1);

    memcpy(namestring, name, len);
    namestring[len] = '\0';

    for (namespace = crl_namespaces; namespace != NULL; namespace = namespace->next)
        if (namespace->type == CRL_NAMESPACE_OBJECT) {
            if ((json = cJSON_GetObjectItemCaseSensitive(namespace->object, namestring)))
                return json;
        }
        else if ((value = crl_attributes_get_value(namespace->attributes, namestring))) {
            SXEA6(crl_value_get_type(value) == CRL_TYPE_JSON, "Attributes in namespaces are expected to be evaluated");
            return value->pointer;
        }

    SXEL2("Failed to lookup '%.*s'", len, name);
    return NULL;
}
