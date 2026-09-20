#include "agent_vm/spec.hpp"
#include <unistd.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace {
int failures = 0, checks = 0;
void check(bool condition, const std::string& description) {
    ++checks;
    if (!condition) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
}
avm::Options parse(std::vector<std::string> args) {
    args.insert(args.begin(), "agent-vm");
    std::vector<char*> ptrs;
    for (auto& arg : args) ptrs.push_back(arg.data());
    return avm::parse_options(static_cast<int>(ptrs.size()), ptrs.data());
}
void reject(const std::vector<std::string>& args, const std::string& reason) {
    try { parse(args); check(false, reason + " (accepted)"); }
    catch (const std::exception&) { check(true, reason); }
}
void write(const fs::path& path, const std::string& content) {
    std::ofstream file(path); file << content;
    if (!file) throw std::runtime_error("cannot write test fixture");
}
} // namespace

int main() {
    auto old_cwd = fs::current_path();
    char pattern[] = "/tmp/agent-vm-config-test-XXXXXX";
    char* directory = mkdtemp(pattern);
    if (!directory) return 2;
    fs::path root(directory);
    try {
        fs::create_directories(root / "home/work");
        fs::create_directories(root / "home/.ssh");
        fs::create_directories(root / "home/existing/outer-only");
        fs::create_directories(root / "data/nested");
        write(root / "home/file", "parent file\n");
        write(root / "data/file", "child file\n");
        fs::create_directory_symlink(root / "home/existing", root / "home/link");
        fs::create_directories(root / "config/agent-vm");
        setenv("HOME", (root / "home").c_str(), 1);
        setenv("XDG_CONFIG_HOME", (root / "config").c_str(), 1);
        unsetenv("SSH_AUTH_SOCK");
        unsetenv("AVM_UNSET_TEST_VARIABLE");
        fs::current_path(root / "home/work");
        const std::string cwd = fs::current_path();
        const std::string home = (root / "home").string();
        auto options = parse({"--no-config"});
        check(options.spec.uid == getuid() && options.spec.gid == getgid(), "identity uses caller IDs");
        check(options.spec.home == home && options.spec.cwd == cwd, "default canonical home/cwd");
        check(options.spec.mounts.size() == 1 && !options.spec.mounts[0].read_only, "default only shares cwd rw");
        check(!options.spec.network && !options.spec.ssh_agent, "network and SSH disabled by default");
        check(options.spec.command == std::vector<std::string>{"/bin/sh"}, "default shell");
        check(!options.spec.environment.contains("SSH_AUTH_SOCK"), "host SSH socket does not leak to environment");
        check(avm::path_within("/a/b", "/a") && !avm::path_within("/ab", "/a"), "path component containment");
        check(avm::path_within("/a/b/../c", "/a/") && avm::path_within("/a", "/"), "normalized path containment");

        options = parse({"plan", "--no-config", "--home", "shared", "--mask", "~/.ssh", "--mount", "src=" + home + ",dst=/backup,ro"});
        check(options.action == avm::Options::Action::Plan && options.spec.mounts.size() == 3, "home, cwd and alias mounts accepted together");
        check(options.spec.mask_sources == std::vector<std::string>{home + "/.ssh"}, "mask canonicalized for all source aliases");
        reject({"--no-config", "--mask", cwd}, "CWD inside mask refused");
        reject({"--no-config", "--home", "shared", "--mask", "~/.missing"}, "missing mask under writable shared parent refused");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/backup,ro", "--mask", "~/.missing"}, "missing mask under read-only shared parent refused");
        reject({"--no-config", "--mask", "~/.ssh", "--mount", "src=" + home + "/.ssh,dst=/keys"}, "direct source mask bypass refused");
        fs::create_directory_symlink(root / "home/.ssh", root / "alias");
        reject({"--no-config", "--mask", "~/.ssh", "--mount", "src=" + (root / "alias").string() + ",dst=/keys"}, "symlink alias bypass refused");
        parse({"--no-config", "--mask", "~/.missing"});
        check(true, "missing mask without shared ancestor is safe");
        reject({"--no-config", "--mask", "/usr/bin"}, "implicit /usr source masks fail explicitly");
        reject({"--no-config", "--mask-target", cwd}, "target mask on cwd refused");
        reject({"--no-config", "--mask-target", cwd + "/missing"}, "target mask missing beneath shared source refused");
        parse({"--no-config", "--mask-target", "/private/missing"});
        check(true, "private target mask can be created in generated root");

        reject({"--no-config", "--mount", "src=/usr,dst=/system,rw"}, "writable alias of /usr refused");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/usr/local"}, "reserved system subtree protected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/"}, "reserved system ancestors protected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/var/../etc"}, "target normalization prevents traversal bypass");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/run"}, "runtime path protected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=relative"}, "relative target refused");
        reject({"--no-config", "--mount", "src=" + home + ",dst=" + cwd}, "explicit duplicate default target refused");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data", "--mount", "src=" + home + ",dst=/data/new"}, "nested target cannot create host path");
        check(!fs::exists(root / "home/new"), "validation never creates a host mount point");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/data", "--mount", "src=" + home + ",dst=/data/existing"});
        check(true, "existing nested target accepted");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/existing,rw"});
        check(options.spec.mounts[0].read_only && !options.spec.mounts[1].read_only, "rw child below ro mount accepted with independent modes");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=/data/existing,rw", "--mount", "src=" + home + ",dst=/data,ro"});
        check(!options.spec.mounts[0].read_only && options.spec.mounts[1].read_only, "rw child below ro mount accepted before its parent in CLI order");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=" + home + ",ro"});
        check(options.spec.mounts.size() == 2 && options.spec.mounts[0].read_only && !options.spec.mounts[1].read_only, "default rw CWD allowed below explicit ro home");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=" + home + ",ro", "--cwd-mode", "ro"});
        check(options.spec.mounts.size() == 2 && options.spec.mounts[1].read_only, "cwd-mode ro keeps CWD read-only below ro home");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=/data,rw", "--mount", "src=" + home + ",dst=/data/existing,ro"});
        check(!options.spec.mounts[0].read_only && options.spec.mounts[1].read_only, "ro child below rw ancestor remains supported");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/data,rw", "--mount", "src=" + home + ",dst=/data/existing,rw"});
        check(true, "rw child below rw ancestor remains supported");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/new,rw"}, "rw child under ro parent still requires an existing target");
        check(!fs::exists(root / "home/new"), "missing rw child target does not create a host path");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/file,rw"}, "directory child cannot cover a regular file target");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + (root / "data/file").string() + ",dst=/data/existing,rw"}, "file child cannot cover a directory target");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + (root / "data/file").string() + ",dst=/data/file,rw"});
        check(true, "writable file child below ro directory accepted");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/link,rw"}, "rw child cannot use a symlink target");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/link/outer-only,rw"}, "rw child target cannot traverse an intermediate symlink");
        parse({"--no-config", "--mount", "src=" + cwd + ",dst=/data/existing/nested,rw", "--mount", "src=" + (root / "data").string() + ",dst=/data/existing,ro", "--mount", "src=" + home + ",dst=/data,ro"});
        check(true, "nested target is resolved in nearest shared parent regardless of CLI order");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + (root / "data").string() + ",dst=/data/existing,ro", "--mount", "src=" + cwd + ",dst=/data/existing/outer-only,rw"}, "target existing only in a hidden ancestor source is rejected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro,rw"}, "ambiguous mount flags refused");

        options = parse({"--no-config", "--cwd-mode", "none"});
        check(options.spec.mounts.empty() && options.spec.cwd == home, "disabled cwd sharing defaults workdir to private home");
        options = parse({"--no-config", "--workdir", "/tmp"});
        check(options.spec.cwd == "/tmp" && options.spec.mounts[0].source == cwd, "workdir leaves source cwd sharing intact");
        reject({"--no-config", "--workdir", "/not/provided"}, "inaccessible workdir rejected");
        reject({"--no-config", "--workdir", "/.agent-vm"}, "private bootstrap workdir rejected");
        fs::current_path(home);
        options = parse({"--no-config", "--home", "shared", "--cwd-mode", "ro"});
        check(options.spec.mounts.size() == 1 && options.spec.mounts[0].read_only, "home equal to cwd merges with cwd mode");
        fs::current_path(cwd);

        setenv("AVM_INHERIT", "secret-value", 1);
        options = parse({"--no-config", "-e", "AVM_INHERIT", "--env", "EMPTY=", "-eLITERAL=$(touch /must-not-run)", "--", "echo", "$(literal)", "--help"});
        check(options.spec.environment.at("AVM_INHERIT") == "secret-value" && options.spec.environment.at("EMPTY").empty(), "env inheritance and empty values");
        check(options.spec.environment.at("LITERAL") == "$(touch /must-not-run)", "values remain literal");
        check(options.spec.command == std::vector<std::string>{"echo", "$(literal)", "--help"}, "command argv preserved");
        std::ostringstream output;
        auto old = std::cout.rdbuf(output.rdbuf()); avm::print_plan(options.spec); std::cout.rdbuf(old);
        check(output.str().find("secret-value") == std::string::npos && output.str().find("AVM_INHERIT") != std::string::npos, "plan hides environment values");
        check(output.str().find("Network: none") != std::string::npos &&
              output.str().find("fixed control channel enabled") != std::string::npos &&
              output.str().find("implicit vsock/TSI disabled") != std::string::npos,
              "network-none plan accurately declares the fixed control vsock");
        reject({"--no-config", "-e", "AVM_UNSET_TEST_VARIABLE"}, "undefined inherited variable rejected");
        reject({"--no-config", "-e", "A-B=bad"}, "invalid env name rejected");
        reject({"--no-config", "-e", "KRUN_INIT=/bad"}, "reserved bootstrap env rejected");
        reject({"--no-config", "-e", "SSH_AUTH_SOCK=/bad"}, "SSH env requires explicit forwarding");
        reject({"--no-config", "--ssh-agent"}, "missing host SSH socket rejected");
        parse({"--no-config", "--ssh-agent", "--no-ssh-agent"});
        check(true, "later CLI SSH disable overrides enable");

        options = parse({"--no-config", "--network=passt", "-p8080:80", "--publish", "0.0.0.0:5353:53/udp"});
        check(options.spec.ports.size() == 2 && options.spec.ports[0].address == "127.0.0.1" && options.spec.ports[1].udp, "IPv4 publication and loopback default");
        for (const std::string bad : {"80", "localhost:80:80", "127.0.0.1:0:80", "65536:80", "80:80/sctp", "80-81:80", "::1:80:80", " 80:80"})
            reject({"--no-config", "--network", "passt", "-p", bad}, "invalid publication " + bad);
        reject({"--no-config", "-p", "8080:80"}, "network none rejects publication");
        reject({"--no-config", "--network", "passt", "-p", "8080:80", "-p", "0.0.0.0:8080:81"}, "overlapping bind address publication rejected");
        reject({"--no-config", "--cpus", "256"}, "CPU count overflow rejected");
        reject({"--no-config", "--memory", "-1"}, "negative memory rejected");
        reject({"--no-config", "--tmp-size", "0"}, "empty temporary size rejected");
        reject({"--no-config", "--typo"}, "unknown option rejected");
        reject({"--no-config", "--config", "anything"}, "conflicting config controls rejected");

        const fs::path config = root / "config/agent-vm/config.toml";
        write(config, "version = 1\n[vm]\ncpus = 3\nmemory_mib = 1024\n[filesystem]\ncwd = 'ro'\n[environment.set]\nOVERRIDE = 'config'\n[network]\nmode = 'passt'\n");
        options = parse({"--cpus", "4", "-e", "OVERRIDE=cli"});
        check(options.spec.cpus == 4 && options.spec.memory_mib == 1024 && options.spec.network, "config loaded and CLI scalar precedence");
        check(options.spec.environment.at("OVERRIDE") == "cli" && options.spec.mounts[0].read_only, "config env and cwd defaults");
        options = parse({"--no-config"});
        check(options.spec.cpus == 2 && !options.spec.network, "no-config ignores user file");
        write(config, "unknown = 1\n");
        reject({}, "unknown top-level config field rejected");
        write(config, "[filesystem]\nunknown = 1\n");
        reject({}, "unknown nested config field rejected");
        write(config, "[vm]\ncpus = 1.5\n");
        reject({}, "wrong TOML scalar type rejected");
        write(config, "[environment]\ninherit = [1]\n");
        reject({}, "wrong TOML array type rejected");
        write(config, "[environment]\ninherit = ['ASSIGNMENT=value']\n");
        reject({}, "config inherit accepts variable names only");
        write(config, "invalid toml !");
        check(parse({"doctor"}).action == avm::Options::Action::Doctor, "doctor ignores invalid user config");
        check(parse({"--help"}).action == avm::Options::Action::Help, "help ignores invalid user config");
        check(parse({"--version"}).action == avm::Options::Action::Version, "version ignores invalid user config");
        fs::remove(config);
        fs::create_symlink(root / "missing.toml", config);
        reject({}, "dangling default config symlink does not drop policy silently");
        fs::remove(config);
        write(root / "relative.toml", "[[mounts]]\nsource = 'data'\ntarget = '/dataset'\n");
        options = parse({"--config", (root / "relative.toml").string()});
        check(options.spec.mounts[0].source == (root / "data").string(), "config-relative source uses config directory");
        write(root / "relative.toml", "[environment]\ninherit = ['KRUN_INIT']\n");
        reject({"--config", (root / "relative.toml").string()}, "config cannot inherit bootstrap settings");
    } catch (const std::exception& error) {
        ++failures;
        std::cerr << "UNEXPECTED: " << error.what() << '\n';
    }
    fs::current_path(old_cwd);
    fs::remove_all(root);
    std::cout << checks << " policy/parser checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
