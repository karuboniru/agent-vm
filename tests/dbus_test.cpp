#include "agent_vm/runtime.hpp"
#include <chrono>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

int main() {
    if (access("/usr/bin/xdg-dbus-proxy", X_OK)) {
        std::cout << "SKIP: xdg-dbus-proxy not installed\n";
        return 77;
    }
    char pattern[] = "/tmp/avm-dbus-test-XXXXXX";
    char* directory = mkdtemp(pattern);
    if (!directory) return 1;
    std::filesystem::path root(directory);
    avm::NetworkProcess proxy;
    try {
        avm::DbusSpec spec;
        spec.address = "unix:path=" + (root / "missing-upstream").string();
        proxy = avm::start_dbus_proxy(spec, (root / "proxy").string());
        if (!std::filesystem::is_socket(root / "proxy")) throw std::runtime_error("readiness before socket creation");
        close(proxy.fd); proxy.fd = -1;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        int status;
        for (;;) {
            if (waitpid(proxy.pid, &status, WNOHANG) == proxy.pid) { proxy.pid = -1; break; }
            if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("proxy did not exit when lifetime FD closed");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status)) throw std::runtime_error("proxy lifetime shutdown failed");
        spec.args = {"--not-a-real-option"};
        bool rejected = false;
        try { proxy = avm::start_dbus_proxy(spec, (root / "invalid").string()); }
        catch (const std::exception&) { rejected = true; }
        if (!rejected) throw std::runtime_error("invalid proxy argument did not fail startup");
        if (waitpid(-1, nullptr, WNOHANG) != -1 || errno != ECHILD) throw std::runtime_error("startup failure left a child");
        std::filesystem::remove_all(root);
        std::cout << "D-Bus helper tests passed: readiness, lifetime FD, startup failure and reaping\n";
        return 0;
    } catch (const std::exception& error) {
        avm::stop_child(proxy.pid);
        if (proxy.fd >= 0) close(proxy.fd);
        std::filesystem::remove_all(root);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
