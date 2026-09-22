#pragma once

#include <string>
#include <vector>
#include <sys/types.h>

namespace avm::detail {
// Setup only, before parsing any guest bytes. The controller retains its PID
// for the host supervisor. Data children are cloned into individual PID namespaces.
struct SocketDirectory {
    std::string source;
    std::vector<std::string> names;
};
void enter_socket_control_namespace(const std::string& root, const std::vector<SocketDirectory>& directories);
void enter_socket_data_namespace();
void seal_socket_control(const std::vector<int>& listeners, const std::vector<int>& channels,
                         const std::vector<int>& directories, int status, const std::vector<pid_t>& data_pids);
void seal_socket_data(int channel, int status);
}
