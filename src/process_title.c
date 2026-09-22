#define _GNU_SOURCE
#include "agent_vm/process_title.h"
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

extern char **environ;
static char *title_start;
static size_t title_capacity;

int avm_process_title_init(int argc, char **argv)
{
    if (title_start || argc < 1 || !argv || !argv[0]) return 0;
    char *end = argv[0];
    for (int i = 0; i < argc && argv[i] == end; ++i) end += strlen(end) + 1;
    size_t envc = 0;
    while (environ && environ[envc]) {
        if (environ[envc] == end) end += strlen(end) + 1;
        ++envc;
    }
    char **args = calloc((size_t)argc + 1, sizeof(char *));
    char **env = calloc(envc + 1, sizeof(char *));
    if (!args || !env) { free(args); free(env); return -1; }
    for (int i = 0; i < argc; ++i) {
        args[i] = strdup(argv[i]);
        if (!args[i]) goto failed;
    }
    for (size_t i = 0; i < envc; ++i) {
        env[i] = strdup(environ[i]);
        if (!env[i]) goto failed;
    }
    title_start = argv[0];
    title_capacity = (size_t)(end - title_start);
    for (int i = 0; i < argc; ++i) argv[i] = args[i];
    free(args);
    environ = env;
    return 0;
failed:
    for (int i = 0; i < argc; ++i) free(args[i]);
    for (size_t i = 0; i < envc; ++i) free(env[i]);
    free(args); free(env);
    return -1;
}

int avm_process_title(const char *name, const char *title)
{
    if (prctl(PR_SET_NAME, name, 0, 0, 0)) return -1;
    if (title_start && title_capacity) {
        memset(title_start, 0, title_capacity);
        size_t size = strlen(title);
        if (size >= title_capacity) size = title_capacity - 1;
        for (size_t i = 0; i < size; ++i) {
            unsigned char byte = (unsigned char)title[i];
            title_start[i] = byte < 32 || byte == 127 ? '?' : (char)byte;
        }
    }
    return 0;
}
