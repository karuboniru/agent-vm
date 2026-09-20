#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <sys/types.h>

namespace avm {
struct MountSpec {
    std::string source; // Absolute, canonical host path.
    std::string target; // Absolute, lexically normalized guest path.
    bool read_only = true;
};
struct PortSpec {
    std::string address = "127.0.0.1";
    uint16_t host_port = 0;
    uint16_t guest_port = 0;
    bool udp = false;
};
struct RunSpec {
    uid_t uid = 0;
    gid_t gid = 0;
    std::string username;
    std::string home;
    std::string cwd;
    uint8_t cpus = 2;
    uint32_t memory_mib = 2048;
    uint32_t tmp_mib = 256;
    bool network = false;
    bool ssh_agent = false;
    bool debug = false;
    std::string ssh_socket;
    std::vector<MountSpec> mounts;
    std::vector<std::string> mask_sources;
    std::vector<std::string> mask_targets;
    std::vector<PortSpec> ports;
    std::map<std::string, std::string> environment;
    std::vector<std::string> command;
};
struct Options {
    enum class Action { Run, Plan, Doctor, Help, Version } action = Action::Run;
    RunSpec spec;
};
Options parse_options(int argc, char** argv);
void print_help();
void print_plan(const RunSpec& spec);
// Performs pure policy validation plus filesystem checks, without mounting.
void validate_spec(const RunSpec& spec);
bool path_within(const std::string& path, const std::string& parent);
}
