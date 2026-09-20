#include "agent_vm/runtime.hpp"
#include "agent_vm/protocol.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(std::string(message) + " (errno=" + std::to_string(errno) + ")");
}
sockaddr_un address(const std::string& path) {
    sockaddr_un result {};
    result.sun_family = AF_UNIX;
    require(path.size() < sizeof(result.sun_path), "test path too long");
    std::memcpy(result.sun_path, path.c_str(), path.size() + 1);
    return result;
}
int connect_to(const std::string& path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "create client socket");
    sockaddr_un target = address(path);
    if (connect(fd, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) < 0) {
        close(fd);
        throw std::runtime_error("connect client socket");
    }
    return fd;
}
bool write_all(int fd, const char* data, size_t size) {
    while (size) {
        ssize_t count = send(fd, data, size, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        data += count;
        size -= static_cast<size_t>(count);
    }
    return true;
}

// Every connection streams bytes back and appends a marker after reading EOF.
// The marker verifies that a client SHUT_WR doesn't discard its response side.
pid_t echo_server(const std::string& path) {
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(listener >= 0, "create echo listener");
    sockaddr_un target = address(path);
    require(bind(listener, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) == 0, "bind echo listener");
    require(listen(listener, 64) == 0, "listen echo");
    pid_t parent = getpid();
    pid_t server = fork();
    require(server >= 0, "fork echo server");
    if (server == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent) _exit(1);
        signal(SIGCHLD, SIG_IGN);
        while (true) {
            int client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0 && errno == EINTR) continue;
            if (client < 0) _exit(1);
            pid_t own_pid = getpid();
            pid_t worker = fork();
            if (worker < 0) _exit(1);
            if (worker == 0) {
                if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != own_pid) _exit(1);
                close(listener);
                std::array<char, 8192> data {};
                while (true) {
                    ssize_t count = read(client, data.data(), data.size());
                    if (count < 0 && errno == EINTR) continue;
                    if (count < 0) _exit(1);
                    if (!count) break;
                    if (!write_all(client, data.data(), static_cast<size_t>(count))) _exit(1);
                }
                if (!write_all(client, "<EOF>", 5)) _exit(1);
                shutdown(client, SHUT_WR);
                close(client);
                _exit(0);
            }
            close(client);
        }
    }
    close(listener);
    return server;
}

void round_trip(const std::string& path, size_t size, unsigned seed) {
    int client = connect_to(path);
    require(fcntl(client, F_SETFL, O_NONBLOCK) == 0, "nonblock client");
    std::string payload(size, '\0');
    for (size_t i = 0; i < size; ++i) payload[i] = static_cast<char>((i * 31 + seed) % 251);
    std::string wire;
    for (size_t at = 0; at < payload.size();) {
        uint32_t length = static_cast<uint32_t>(std::min<size_t>(AVM_STREAM_MAX, payload.size() - at));
        uint32_t encoded = htonl(length);
        wire.append(reinterpret_cast<const char*>(&encoded), sizeof(encoded));
        wire.append(payload, at, length);
        at += length;
    }
    uint32_t eof = htonl(AVM_STREAM_EOF);
    wire.append(reinterpret_cast<const char*>(&eof), sizeof(eof));
    std::string received;
    received.reserve(size + 5);
    std::string received_wire;
    size_t parsed = 0;
    size_t sent = 0;
    bool remote_eof = false, ack = false;
    std::array<char, 7777> buffer {};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (!ack) {
        require(std::chrono::steady_clock::now() < deadline, "round trip timeout");
        pollfd pending {client, static_cast<short>(POLLIN | (sent == wire.size() ? 0 : POLLOUT)), 0};
        int result = poll(&pending, 1, 100);
        if (result < 0 && errno == EINTR) continue;
        require(result >= 0, "poll client");
        require(!(pending.revents & (POLLERR | POLLNVAL)), "client socket error");
        if (pending.revents & POLLOUT) {
            ssize_t count = send(client, wire.data() + sent, std::min<size_t>(20411, wire.size() - sent), MSG_NOSIGNAL);
            if (count > 0) sent += static_cast<size_t>(count);
            else require(count < 0 && (errno == EAGAIN || errno == EINTR), "send payload");
        }
        if (pending.revents & (POLLIN | POLLHUP)) {
            ssize_t count = recv(client, buffer.data(), buffer.size(), 0);
            require(count != 0, "transport must remain open until ACK is consumed");
            if (count > 0) received_wire.append(buffer.data(), static_cast<size_t>(count));
            else require(errno == EAGAIN || errno == EINTR, "receive payload");
        }
        while (received_wire.size() - parsed >= sizeof(uint32_t)) {
            uint32_t encoded;
            std::memcpy(&encoded, received_wire.data() + parsed, sizeof(encoded));
            uint32_t length = ntohl(encoded);
            if (length == AVM_STREAM_ACK) {
                require(remote_eof && sent == wire.size(), "ACK follows both EOFs");
                parsed += 4;
                ack = true;
                break;
            }
            require(length <= AVM_STREAM_MAX && !remote_eof, "valid response frame before EOF");
            if (received_wire.size() - parsed - 4 < length) break;
            parsed += 4;
            if (length == AVM_STREAM_EOF) remote_eof = true;
            else received.append(received_wire, parsed, length);
            parsed += length;
        }
    }
    close(client);
    require(sent == wire.size() && remote_eof && ack, "whole request acknowledged");
    require(received == payload + "<EOF>", "response and post-half-close marker match");
}

template <typename Callback> void expect_failure(Callback callback, const char* message) {
    bool failed = false;
    try { callback(); } catch (const std::exception&) { failed = true; }
    require(failed, message);
}

void reject_frame(const std::string& path, uint32_t length) {
    int client = connect_to(path);
    uint32_t encoded = htonl(length);
    require(write_all(client, reinterpret_cast<const char*>(&encoded), sizeof(encoded)), "send invalid frame");
    pollfd pending {client, POLLIN, 0};
    require(poll(&pending, 1, 1000) > 0, "invalid frame is rejected promptly");
    char byte;
    ssize_t count = read(client, &byte, 1);
    require(count == 0 || (count < 0 && errno == ECONNRESET), "invalid frame closes only that connection");
    close(client);
}

void wait_ok(pid_t child) {
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    require(result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "concurrent round trip child");
}
}

int main() {
    alarm(45);
    char temp[] = "/tmp/agent-vm-network-test.XXXXXX";
    char* directory = mkdtemp(temp);
    if (!directory) return 1;
    const std::string dir = directory;
    const std::string upstream = dir + "/agent.sock";
    const std::string broker_path = dir + "/broker.sock";
    pid_t server = -1, broker = -1;
    int active = -1;
    try {
        server = echo_server(upstream);
        expect_failure([&] { avm::start_socket_broker(dir + "/missing/broker.sock", upstream); }, "reject absent parent");
        expect_failure([&] { avm::start_socket_broker(broker_path, dir); }, "reject non-socket upstream");
        expect_failure([&] { avm::start_socket_broker(broker_path, "/" + std::string(108, 'x')); }, "reject oversized path");
        expect_failure([&] { avm::start_socket_broker(upstream, upstream); }, "refuse existing broker path");

        int unrelated[2];
        require(pipe2(unrelated, O_CLOEXEC) == 0, "create unrelated FD sentinel");
        sigset_t blocked, previous;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGTERM);
        require(sigprocmask(SIG_BLOCK, &blocked, &previous) == 0, "block parent termination signal");
        broker = avm::start_socket_broker(broker_path, upstream);
        require(getpgid(broker) == broker && getpgid(broker) != getpgrp(),
                "broker is outside the caller's foreground process group");
        require(sigprocmask(SIG_SETMASK, &previous, nullptr) == 0, "restore parent signals");
        close(unrelated[1]);
        pollfd leaked {unrelated[0], POLLIN, 0};
        require(poll(&leaked, 1, 1000) > 0, "broker did not retain unrelated descriptor");
        char byte;
        require(read(unrelated[0], &byte, 1) == 0, "unrelated pipe reaches EOF");
        close(unrelated[0]);
        struct stat info {};
        require(lstat(broker_path.c_str(), &info) == 0 && S_ISSOCK(info.st_mode) &&
                (info.st_mode & 0777) == 0600, "broker socket mode 0600");

        round_trip(broker_path, 0, 0);
        round_trip(broker_path, 17, 1);
        reject_frame(broker_path, AVM_STREAM_MAX + 1);
        reject_frame(broker_path, AVM_STREAM_ACK); // Guest may never send host ACK.
        std::vector<pid_t> clients;
        for (unsigned index = 0; index < 8; ++index) {
            pid_t client = fork();
            require(client >= 0, "fork concurrent client");
            if (client == 0) {
                try { round_trip(broker_path, 2 * 1024 * 1024 + index, index); _exit(0); }
                catch (const std::exception& error) { dprintf(2, "client test: %s\n", error.what()); _exit(1); }
            }
            clients.push_back(client);
        }
        for (pid_t client : clients) wait_ok(client);

        // A fixed endpoint is reconnected by pathname for each client. Replacing
        // that endpoint is supported without exposing the directory to the VM.
        avm::stop_child(server);
        server = -1;
        require(unlink(upstream.c_str()) == 0, "remove original agent socket");
        server = echo_server(upstream);
        round_trip(broker_path, 90001, 5);

        active = connect_to(broker_path);
        uint32_t active_header = htonl(7);
        require(write_all(active, reinterpret_cast<const char*>(&active_header), sizeof(active_header)) &&
                write_all(active, "pending", 7), "send active connection");
        size_t header_got = 0;
        while (header_got < sizeof(active_header)) {
            ssize_t count = read(active, reinterpret_cast<char*>(&active_header) + header_got, sizeof(active_header) - header_got);
            require(count > 0, "receive active frame header");
            header_got += static_cast<size_t>(count);
        }
        require(ntohl(active_header) == 7, "active echo frame length");
        std::array<char, 7> echoed {};
        size_t got = 0;
        while (got < echoed.size()) {
            ssize_t count = read(active, echoed.data() + got, echoed.size() - got);
            require(count > 0, "receive active echo");
            got += static_cast<size_t>(count);
        }
        auto begin = std::chrono::steady_clock::now();
        pid_t stopped_group = broker;
        avm::stop_child(broker);
        broker = -1;
        require(waitpid(stopped_group, nullptr, WNOHANG) < 0 && errno == ECHILD,
                "stopped broker has been reaped");
        require(kill(-stopped_group, 0) < 0 && errno == ESRCH,
                "stopped broker leaves no processes in its helper group");
        require(std::chrono::steady_clock::now() - begin < std::chrono::seconds(1), "broker handles TERM despite inherited blocked mask");
        require(lstat(broker_path.c_str(), &info) < 0 && errno == ENOENT, "broker unlinks listen socket");
        pollfd disconnected {active, POLLIN, 0};
        require(poll(&disconnected, 1, 1000) > 0, "active worker closes during broker shutdown");
        require(read(active, &byte, 1) == 0, "active worker connection EOF after shutdown");
        close(active);
        active = -1;
        avm::stop_child(server);
        server = -1;
        avm::stop_child(server); // Negative and already reaped children are harmless.
        std::filesystem::remove_all(dir);
        std::cout << "network tests passed: relay, concurrency, backpressure, half-close, reconnect, FD and process cleanup\n";
        return 0;
    } catch (const std::exception& error) {
        if (active >= 0) close(active);
        avm::stop_child(broker);
        avm::stop_child(server);
        std::filesystem::remove_all(dir);
        std::cerr << "network test failed: " << error.what() << '\n';
        return 1;
    }
}
