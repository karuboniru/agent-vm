#ifndef AVM_PROCESS_TITLE_H
#define AVM_PROCESS_TITLE_H
#ifdef __cplusplus
extern "C" {
#endif
/* Call once at entry, before reading argv/environ. Relocates their strings so
 * later titles cannot overwrite configuration or the workload's arguments. */
int avm_process_title_init(int argc, char **argv);
/* Set comm and the original argv storage used by ps. Before seccomp only.
 * Full titles are truncated to the original contiguous argv/environment area. */
int avm_process_title(const char *name, const char *title);
#ifdef __cplusplus
}
#endif
#endif
