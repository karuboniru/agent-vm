#ifndef AVM_GUEST_PATHS_H
#define AVM_GUEST_PATHS_H
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
bool avm_path_valid(const char *path);
/* Inputs to policy functions must first pass avm_path_valid. */
bool avm_path_within(const char *path, const char *parent);
bool avm_protected_target(const char *path, bool custom_mount);
#ifdef __cplusplus
}
#endif
#endif
