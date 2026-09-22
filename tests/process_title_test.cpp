#include "agent_vm/process_title.h"
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

static std::string read(const char* file) {
    std::ifstream input(file);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
int main(int argc, char** argv) {
    if (argc != 2 || !getenv("PATH")) return 1;
    const std::string argument = argv[1], path = getenv("PATH");
    if (avm_process_title_init(argc, argv)) return 1;
    const char* title = "agent-vm: socket[7] /tmp/host.sock -> guest:/run/client.sock";
    if (avm_process_title("avm-sock-7", title)) return 1;
    if (read("/proc/self/comm") != "avm-sock-7\n" || !read("/proc/self/cmdline").starts_with(title)) return 1;
    if (argument != argv[1] || path != getenv("PATH")) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        if (avm_process_title("avm-child", "agent-vm: child\nlabel") ||
            !read("/proc/self/cmdline").starts_with("agent-vm: child?label")) _exit(1);
        // Bound writes even when a title exceeds the original argument area.
        std::string long_title(1024 * 1024, 'x');
        if (avm_process_title("avm-child", long_title.c_str()) ||
            argument != argv[1] || path != getenv("PATH")) _exit(1);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    if (!read("/proc/self/cmdline").starts_with(title)) return 1;
    std::cout << "process title tests passed: comm, full title, argv/environment preservation, fork and truncation\n";
}
