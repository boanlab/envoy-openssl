#include "stacktrace.h"
#include "log.h"

void print_stacktrace() {
    void* array[20];
    size_t size = backtrace(array, 20);
    char** strings = backtrace_symbols(array, size);

    //fprintf(stderr, "\nStack trace:\n");
    // bssl_compat_info("[+]Stack trace:");
    for (size_t i = 0; i < size; i++) {
        //fprintf(stderr, "#%zu %s\n", i, strings[i]);
        bssl_compat_info("[DEBUG]#%zu %s", i, strings[i]);
    }
    free(strings);
}