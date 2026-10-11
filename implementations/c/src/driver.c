#define _POSIX_C_SOURCE 200809L
#include "vh_log.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    if (sodium_init() < 0)
        return 1;
    char *line = NULL;
    size_t capacity = 0;
    while (getline(&line, &capacity, stdin) >= 0) {
        vh_context *context = vh_context_new();
        if (!context) {
            free(line);
            return 1;
        }
        json_object *response = vh_request(context, line);
        puts(json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN |
                                                          JSON_C_TO_STRING_NOSLASHESCAPE));
        fflush(stdout);
        vh_context_free(context);
    }
    free(line);
    return ferror(stdin) ? 1 : 0;
}
