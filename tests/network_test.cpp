#include "agent_vm/runtime.hpp"
#include "agent_vm/protocol.h"
#include "agent_vm/process_title.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
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
pid_t echo_server(const std::string& path, const std::string& marker = "<EOF>") {
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
                if (!write_all(client, marker.data(), marker.size())) _exit(1);
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

void round_trip(const std::string& path, size_t size, unsigned seed, const std::string& marker = "<EOF>") {
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
    require(received == payload + marker, "response and post-half-close marker match");
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

pid_t data_process(pid_t broker) {
    std::ifstream children("/proc/" + std::to_string(broker) + "/task/" + std::to_string(broker) + "/children");
    pid_t data = -1, extra = -1;
    require(bool(children >> data) && !(children >> extra), "exactly one persistent data process");
    return data;
}

void check_process_policy(pid_t pid, bool data) {
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    require(bool(status), "read live broker status");
    std::string line;
    unsigned seen = 0;
    while (std::getline(status, line)) {
        std::istringstream fields(line);
        std::string key, value;
        fields >> key >> value;
        if (key == "CapInh:" || key == "CapPrm:" || key == "CapEff:" || key == "CapBnd:" || key == "CapAmb:") {
            require(std::stoull(value, nullptr, 16) == 0, "live broker retains capabilities");
            ++seen;
        } else if (key == "NoNewPrivs:") {
            require(value == "1", "live broker lacks no_new_privs"); ++seen;
        } else if (key == "Seccomp:") {
            require(value == "2", "live broker lacks seccomp filter"); ++seen;
        } else if (key == "NSpid:" && data) {
            std::string next;
            bool nested = false;
            while (fields >> next) { value = next; nested = true; }
            require(nested && value == "1", "live data process lacks private PID namespace"); ++seen;
        }
    }
    require(seen == (data ? 8u : 7u), "missing live broker confinement fields");
}

void malformed_connections(const std::string& path) {
    // Partial headers and payloads must not retain framing state in a reused
    // session slot or take down the other sessions in the persistent process.
    for (size_t truncated = 1; truncated <= 7; ++truncated) {
        int client = connect_to(path);
        uint32_t encoded = htonl(17);
        std::string wire(reinterpret_cast<char*>(&encoded), sizeof(encoded));
        wire += "abc";
        require(write_all(client, wire.data(), truncated), "send truncated request");
        close(client);
    }
    int client = connect_to(path);
    const char after_eof[5]{};
    require(write_all(client, after_eof, sizeof(after_eof)), "send data after EOF");
    pollfd event{client, POLLIN, 0};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    for (;;) {
        require(std::chrono::steady_clock::now() < deadline, "data after EOF not rejected");
        require(poll(&event, 1, 100) >= 0, "poll malformed EOF");
        if (!(event.revents & (POLLIN | POLLHUP | POLLERR))) continue;
        char buffer[128];
        ssize_t got = recv(client, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (got == 0 || (got < 0 && errno == ECONNRESET)) break;
        require(got > 0 || errno == EAGAIN, "receive malformed EOF response");
    }
    close(client);
    round_trip(path, AVM_STREAM_MAX + 1, 19);
}

std::string process_text(pid_t pid, const char* file) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/" + file);
    require(bool(input), "read process label");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void grouped_brokers(const std::string& dir) {
    std::filesystem::create_directories(dir + "/group/nested");
    const std::string first = dir + "/group/service", second = dir + "/group/nested/service";
    const std::string first_listener = dir + "/first.sock", second_listener = dir + "/second.sock";
    const std::string third_listener = dir + "/third.sock", slow_path = dir + "/group/slow";
    pid_t a = -1, b = -1, controller = -1;
    int slow = -1;
    std::vector<int> queued;
    try {
        a = echo_server(first, "<FIRST>"); b = echo_server(second, "<SECOND>");
        slow = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        auto slow_address = address(slow_path);
        require(slow >= 0 && bind(slow, reinterpret_cast<sockaddr*>(&slow_address), sizeof(slow_address)) == 0 &&
                listen(slow, 1) == 0, "create slow upstream");
        // Fill its Unix listen backlog without accepting. It must not hold up
        // connections to either of the independent healthy routes.
        queued.push_back(connect_to(slow_path)); queued.push_back(connect_to(slow_path));
        controller = avm::start_socket_brokers({
            {first_listener, first, "/run/first.sock"},
            {second_listener, second, "/run/second.sock"},
            {third_listener, slow_path, "/run/slow.sock"}});
        std::ifstream children("/proc/" + std::to_string(controller) + "/task/" + std::to_string(controller) + "/children");
        std::vector<pid_t> data;
        pid_t child;
        while (children >> child) data.push_back(child);
        require(data.size() == 3, "one controller must have one data child per route");
        require(process_text(controller, "comm") == "avm-sock-ctl\n", "controller short name");
        require(process_text(controller, "cmdline").starts_with("agent-vm: socket controller (3 forwards)"), "controller full title");
        const std::string sources[]{first, second, slow_path};
        for (size_t i = 0; i < data.size(); ++i) {
            check_process_policy(data[i], true); // Each must independently be PID 1.
            require(process_text(data[i], "comm") == "avm-sock-" + std::to_string(i) + "\n", "data short name");
            auto title = process_text(data[i], "cmdline");
            require(title.find(sources[i]) != std::string::npos && title.find("guest:/run/") != std::string::npos,
                    "data title must describe both paths");
        }
        int blocked_client = connect_to(third_listener);
        auto started = std::chrono::steady_clock::now();
        round_trip(first_listener, 100001, 2, "<FIRST>");
        round_trip(second_listener, 100003, 3, "<SECOND>");
        close(blocked_client);
        require(std::chrono::steady_clock::now() - started < std::chrono::seconds(2), "slow upstream blocked unrelated routes");
        reject_frame(first_listener, AVM_STREAM_ACK);
        round_trip(second_listener, 31, 4, "<SECOND>");
        avm::stop_child(a); a = -1;
        require(unlink(first.c_str()) == 0, "replace grouped upstream");
        a = echo_server(first, "<REPLACED>");
        round_trip(first_listener, 10000, 5, "<REPLACED>");
        round_trip(second_listener, 10000, 6, "<SECOND>");
        const pid_t group = controller;
        require(kill(data[0], SIGKILL) == 0, "kill grouped data process");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        int status = 0;
        pid_t reaped;
        while ((reaped = waitpid(controller, &status, WNOHANG)) == 0) {
            require(std::chrono::steady_clock::now() < deadline, "group controller missed child failure");
            usleep(1000);
        }
        require(reaped == controller && WIFEXITED(status) && WEXITSTATUS(status) == 125, "group failure status");
        avm::stop_child(controller); controller = -1;
        require(kill(-group, 0) < 0 && errno == ESRCH, "group failure left data processes behind");
        for (const auto& path : {first_listener, second_listener, third_listener})
            require(access(path.c_str(), F_OK) < 0 && errno == ENOENT, "group listener cleanup");
        avm::stop_child(a); a = -1; avm::stop_child(b); b = -1;
        for (int fd : queued) close(fd);
        close(slow);
    } catch (...) {
        avm::stop_child(controller); avm::stop_child(a); avm::stop_child(b);
        for (int fd : queued) close(fd);
        if (slow >= 0) close(slow);
        throw;
    }
}

void wait_ok(pid_t child) {
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    require(result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "concurrent round trip child");
}
}

int main(int argc, char** argv) {
    if (avm_process_title_init(argc, argv)) return 1;
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
        pid_t persistent_data = data_process(broker);
        check_process_policy(broker, false);
        check_process_policy(persistent_data, true);
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
        malformed_connections(broker_path);
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
        require(data_process(broker) == persistent_data, "data process was replaced per connection");

        // A fixed endpoint is reconnected by pathname for each client. Replacing
        // that endpoint is supported without exposing the directory to the VM.
        avm::stop_child(server);
        server = -1;
        require(unlink(upstream.c_str()) == 0, "remove original agent socket");
        server = echo_server(upstream);
        round_trip(broker_path, 90001, 5);
        require(data_process(broker) == persistent_data, "upstream reconnect restarted data process");

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
        // A crashed data plane must fail the controller and allow the caller
        // to reclaim the listener even after it has reaped the controller.
        server = echo_server(dir + "/failure.sock");
        broker = avm::start_socket_broker(broker_path, dir + "/failure.sock");
        pid_t failed_data = data_process(broker);
        require(kill(failed_data, SIGKILL) == 0, "kill data process for lifecycle test");
        const auto failure_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        int failed_status = 0;
        pid_t reaped;
        while ((reaped = waitpid(broker, &failed_status, WNOHANG)) == 0) {
            require(std::chrono::steady_clock::now() < failure_deadline, "controller missed data-plane death");
            usleep(1000);
        }
        require(reaped == broker, "reap failed controller");
        require(WIFEXITED(failed_status) && WEXITSTATUS(failed_status) == 125, "data failure must fail controller");
        avm::stop_child(broker); broker = -1;
        require(lstat(broker_path.c_str(), &info) < 0 && errno == ENOENT, "reaped controller left listener behind");
        avm::stop_child(server); server = -1;
        grouped_brokers(dir);
        std::filesystem::remove_all(dir);
        std::cout << "network tests passed: persistent relay, confinement, malformed frames, concurrency, backpressure, half-close, reconnect and cleanup\n";
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
