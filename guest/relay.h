#ifndef AGENT_VM_GUEST_RELAY_H
#define AGENT_VM_GUEST_RELAY_H

#include <sys/types.h>

/* Call after dropping to the workload UID/GID. Returns a supervisor PID only
 * once socket_path is listening. On failure returns -1 and preserves errno.
 * Stop it with SIGTERM and reap it with waitpid(). */
pid_t avm_relay_start(const char *socket_path);

#endif
