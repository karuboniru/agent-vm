#ifndef AGENT_VM_PROTOCOL_H
#define AGENT_VM_PROTOCOL_H
#include <stdint.h>

/* Native endian, same-architecture host/guest. Strings are u32 length + bytes,
 * without NUL. Header is followed by home, cwd, then argc and envc strings.
 * Each environment string is KEY=VALUE. Maximum complete config: 1 MiB. */
#define AVM_SPEC_MAGIC 0x41564d31u
#define AVM_SPEC_VERSION 1u
#define AVM_SPEC_MAX (1024u * 1024u)
#define AVM_FLAG_NETWORK 1u
#define AVM_FLAG_SSH 2u
#define AVM_CONTROL_PORT 1024u
#define AVM_SSH_PORT 1025u

/* Internal SSH relay transport over vsock: each frame starts with one
 * network-byte-order uint32_t. DATA has 1..MAX following bytes; EOF and ACK
 * carry no payload. Only host -> guest may send ACK, after both streams have
 * drained and both logical EOFs have been handled. The host keeps its vsock
 * backend socket open until the guest consumes ACK and closes the transport.
 * This avoids libkrun's Unix backend dropping unread bytes on host EPOLLHUP. */
#define AVM_STREAM_MAX 65536u
#define AVM_STREAM_EOF 0u
#define AVM_STREAM_ACK UINT32_MAX
#define AVM_GUEST_HELPER "/.agent-vm/guest"
#define AVM_GUEST_SPEC "/.agent-vm/spec.bin"
#define AVM_MOUNT_SPEC "/.agent-vm/mounts.bin"
#define AVM_BOOTSTRAP "/.agent-vm/bootstrap"
#define AVM_NEW_ROOT "/.agent-vm/root"
#define AVM_MOUNT_MAGIC 0x41564d46u
#define AVM_MOUNT_VERSION 1u
#define AVM_MOUNT_TMPFS 1u
#define AVM_MOUNT_DIRECTORY 2u
#define AVM_MOUNT_FILE 3u
#define AVM_EXPORT_TAG "/.agent-vm/exports"
/* Native endian: header, then count entries of four u32 values (kind, mode,
 * uid, gid) followed by length-prefixed target and object-path strings. Object
 * paths are relative to AVM_EXPORT_TAG's root (with a leading slash). tmp_mib
 * is a per-filesystem limit. Two devices (bootstrap and object catalog) avoid
 * exhausting libkrun's IRQ budget as the number of configured mounts grows.
 * All host access restrictions are enforced before exporting any object. */
struct avm_mount_header {
    uint32_t magic, version, count, tmp_mib;
};
#define AVM_CONTROL_SOCKET "/.agent-vm/ipc/control.sock"
#define AVM_SSH_SOCKET "/.agent-vm/ipc/ssh.sock"

struct avm_spec_header {
    uint32_t magic, version, uid, gid, flags, argc, envc, reserved;
};
#define AVM_CONTROL_MAGIC 0x41564331u
#define AVM_CONTROL_ACK_MAGIC 0x41564332u
#define AVM_CONTROL_SIGNAL 1u
#define AVM_CONTROL_RESIZE 2u
/* One message per connection; no host filesystem path or variable-length data. */
struct avm_control_message {
    uint32_t magic, operation, signal, rows, columns;
};
#endif
