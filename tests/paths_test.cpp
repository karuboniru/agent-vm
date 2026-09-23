#include "agent_vm/paths.hpp"
#include "paths.h"
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace avm::paths;
static void require(bool value, const std::string& label) {
    if (!value) throw std::runtime_error(label);
}
int main() {
    try {
        std::vector<std::string> cases = {"", "/", "relative", "//usr", "/usr/", "/a/../usr", "/a/./b",
            "/a//b", "/work", "/run/media/user", "/etc/resolv.conf", "/etc/resolv.conf/child", "/etc/resolv.conf-other"};
        for (const auto* path : reserved) {
            cases.emplace_back(path);
            cases.emplace_back(std::string(path) + "/child");
            cases.emplace_back(std::string(path) + "-sibling");
        }
        for (const auto& path : cases) {
            bool valid = true;
            try { check_absolute(path); } catch (...) { valid = false; }
            require(valid == avm_path_valid(path.c_str()), "C/C++ validation drift: " + path);
            if (!valid) continue;
            for (bool custom : {false, true})
                require(forbidden_target(path, custom) == avm_protected_target(path.c_str(), custom), "C/C++ policy drift: " + path);
            for (const auto& parent : cases)
                if (avm_path_valid(parent.c_str()))
                    require(within(path, parent) == avm_path_within(path.c_str(), parent.c_str()), "C/C++ containment drift");
        }
        require(within("/work/a/../b/", "/work/"), "containment normalization");
        require(!within("/worker", "/work"), "component boundary");
        for (const auto* path : {"/", "/run", "/.oldroot", "/.oldroot/child", "/etc/resolv.conf/child"})
            require(forbidden_target(path, true), std::string("reserved target allowed: ") + path);
        for (const auto* path : {"/run/media", "/usr/local", "/etc/custom"}) {
            require(!forbidden_target(path, true), "mount exception rejected");
            require(forbidden_target(path, false), "mask exception accepted");
        }
        std::cout << "host/guest path policy parity passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
