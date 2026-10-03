#include "agent_vm/runtime.hpp"

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>

#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(std::string(message) + " (errno=" + std::to_string(errno) + ")");
}

template <typename Callback> void expect_failure(Callback callback, const char* message) {
    bool failed = false;
    try { callback(); } catch (const std::exception&) { failed = true; }
    require(failed, message);
}

void invalid_ports() {
    for (const auto& port : {avm::PortSpec{"not-an-ipv4-address", 1234, 80, false},
                             avm::PortSpec{"127.0.0.1", 0, 80, false},
                             avm::PortSpec{"127.0.0.1", 1234, 0, true}}) {
        avm::RunSpec spec;
        spec.ports.push_back(port);
        expect_failure([&] { auto process = avm::start_passt(spec); close(process.fd); avm::stop_child(process.pid); },
                       "passt rejects invalid port mapping");
    }
}

void passt_lifecycle() {
    avm::RunSpec spec;
    int unrelated[2];
    require(pipe2(unrelated, O_CLOEXEC) == 0, "create unrelated FD sentinel");
    sigset_t blocked, previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    require(sigprocmask(SIG_BLOCK, &blocked, &previous) == 0, "block parent termination signal");
    avm::NetworkProcess process;
    try {
        process = avm::start_passt(spec);
        require(sigprocmask(SIG_SETMASK, &previous, nullptr) == 0, "restore parent signals");
        require(process.fd >= 0 && process.pid > 0, "passt returns socket and PID");
        const int flags = fcntl(process.fd, F_GETFD);
        require(flags >= 0 && (flags & FD_CLOEXEC), "passt socket is close-on-exec");
        require(getpgid(process.pid) == process.pid && getpgid(process.pid) != getpgrp(),
                "passt has its own process group");
        close(unrelated[1]); unrelated[1] = -1;
        pollfd leaked{unrelated[0], POLLIN, 0};
        require(poll(&leaked, 1, 1000) > 0, "passt retained an unrelated descriptor");
        char byte;
        require(read(unrelated[0], &byte, 1) == 0, "unrelated pipe reaches EOF");
        const pid_t pid = process.pid;
        avm::stop_child(pid);
        process.pid = -1;
        require(waitpid(pid, nullptr, WNOHANG) < 0 && errno == ECHILD, "passt was reaped");
        avm::stop_child(pid); // Reaped children and invalid PIDs are harmless.
        avm::stop_child(-1);
        close(process.fd); process.fd = -1;
        close(unrelated[0]); unrelated[0] = -1;
    } catch (...) {
        (void)sigprocmask(SIG_SETMASK, &previous, nullptr);
        if (process.fd >= 0) close(process.fd);
        avm::stop_child(process.pid);
        for (int fd : unrelated) if (fd >= 0) close(fd);
        throw;
    }
}
}

int main() {
    try {
        invalid_ports();
        if (access("/usr/bin/passt", X_OK) != 0) {
            std::cout << "passt unavailable; port validation passed\n";
            return 0;
        }
        passt_lifecycle();
        std::cout << "network tests passed: passt validation and lifecycle\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "network test failed: " << error.what() << '\n';
        return 1;
    }
}
