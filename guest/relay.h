#ifndef AGENT_VM_GUEST_RELAY_H
#define AGENT_VM_GUEST_RELAY_H

#include <stdint.h>
#include <sys/types.h>

/* Call before dropping privileges. Only newly created parent directories are
 * assigned to uid/gid; existing directories retain ownership and permissions. */
int avm_relay_prepare(const char *socket_path, uid_t uid, gid_t gid);

/* Call after dropping to the workload UID/GID. Returns a supervisor PID only
 * once socket_path is listening. On failure returns -1 and preserves errno.
 * Stop it with SIGTERM and reap it with waitpid(). */
pid_t avm_relay_start(const char *socket_path, uint32_t port);

#endif
