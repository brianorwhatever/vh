#ifndef VH_LOG_H
#define VH_LOG_H
#include <json-c/json.h>
#include <stddef.h>

/* Each context owns its request's allocations. Results remain valid until free.
 * Independent contexts may be used concurrently. */
typedef struct vh_context vh_context;
vh_context *vh_context_new(void);
void vh_context_free(vh_context *context);
/* Returns an owned-by-context protocol response; never writes to stdout. */
json_object *vh_request(vh_context *context, const char *request);
#endif
