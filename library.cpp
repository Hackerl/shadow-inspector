#include "library.h"
#include <elfio/elfio.hpp>
#include <zero/log.h>
#include <zero/proc/process.h>
#include <zero/filesystem/path.h>
#include <sys/user.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <unistd.h>
#include <regex>

using BindPtr = int (*)(int, const sockaddr *, socklen_t);

constexpr auto RELOCATION_PLT_SECTION = ".rela.plt";
constexpr auto BIND_SYMBOL = "bind";
constexpr auto CMDLINE_PATH = "/proc/self/cmdline";

constexpr auto DEFAULT_PORT = 9229;
constexpr auto SHADOW_PORT = 29229;

static bool enabled = false;
static BindPtr origin = nullptr;

short getInspectorPort() {
    std::ifstream stream = std::ifstream(CMDLINE_PATH);
    std::string cmdline((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

    std::smatch sm;
    std::regex re(R"(inspect(?:-brk)?=(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}:)?(\d+))");

    short port = 0;

    if (std::regex_search(cmdline, sm, re) && zero::strings::toNumber(sm.str(1), port))
        return port;

    const char *env = getenv("NODE_OPTIONS");

    if (!env)
        return DEFAULT_PORT;

    std::cmatch cm;

    if (std::regex_search(env, cm, re) && zero::strings::toNumber(cm.str(1), port))
        return port;

    return DEFAULT_PORT;
}

bool getGOTEntry(const std::string &symbol, uintptr_t &address) {
    std::string path = zero::filesystem::path::getApplicationPath();

    zero::proc::CProcessMapping processMapping = {};

    if (!zero::proc::getImageBase(getpid(), path, processMapping)) {
        LOG_ERROR("find node image base failed");
        return false;
    }

    LOG_INFO("node image base: 0x%lx", processMapping.start);

    ELFIO::elfio reader;

    if (!reader.load(path)) {
        LOG_ERROR("open elf failed: %s", path.c_str());
        return false;
    }

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return s->get_name() == RELOCATION_PLT_SECTION;
            });

    if (it == reader.sections.end()) {
        LOG_ERROR("can't find relocation plt section");
        return false;
    }

    unsigned long baseAddress = 0;

    if (reader.get_type() != ET_EXEC) {
        std::vector<ELFIO::segment *> loads;

        std::copy_if(
                reader.segments.begin(),
                reader.segments.end(),
                std::back_inserter(loads),
                [](const auto &i){
                    return i->get_type() == PT_LOAD;
                });

        auto minElement = std::min_element(
                loads.begin(),
                loads.end(),
                [](const auto &i, const auto &j) {
                    return i->get_virtual_address() < j->get_virtual_address();
                });

        baseAddress = processMapping.start - ((*minElement)->get_virtual_address() & ~(PAGE_SIZE - 1));
    }

    ELFIO::relocation_section_accessor relocations(reader, *it);

    for (ELFIO::Elf_Xword i = 0; i < relocations.get_entries_num(); i++) {
        ELFIO::Elf64_Addr offset = 0;
        ELFIO::Elf64_Addr symbolValue = 0;
        std::string symbolName;
        ELFIO::Elf_Word type = 0;
        ELFIO::Elf_Sxword addend = 0;
        ELFIO::Elf_Sxword calcValue = 0;

        if (!relocations.get_entry(i, offset, symbolValue, symbolName, type, addend, calcValue)) {
            LOG_ERROR("get relocation entry %lu failed", i);
            return false;
        }

        if (symbolName == BIND_SYMBOL) {
            address = baseAddress + offset;
            break;
        }
    }

    return address != 0;
}

int shadow_bind(int fd, const sockaddr *address, socklen_t length) {
    if (enabled)
        return origin(fd, address, length);

    if (address->sa_family != AF_INET)
        return origin(fd, address, length);

    in_port_t *port = &((sockaddr_in *)address)->sin_port;
    in_port_t inspectorPort = getInspectorPort();

    LOG_INFO("check inspector port: %hd %hd", ntohs(*port), inspectorPort);

    if (*port != htons(inspectorPort))
        return origin(fd, address, length);

    enabled = true;
    *port = htons(SHADOW_PORT);

    return origin(fd, address, length);
}

int init() {
    INIT_CONSOLE_LOG(zero::INFO);

    uintptr_t address = 0;

    if (!getGOTEntry(BIND_SYMBOL, address)) {
        LOG_ERROR("can't find bind GOT entry");
        return -1;
    }

    LOG_INFO("bind GOT entry: 0x%lx", address);

    zero::proc::CProcessMapping processMapping = {};

    if (!zero::proc::getAddressMapping(getpid(), address, processMapping)) {
        LOG_ERROR("can't find GOT entry memory mapping");
        return -1;
    }

    int protection = (processMapping.permissions & zero::proc::READ_PERMISSION ? PROT_READ : 0) |
                     (processMapping.permissions & zero::proc::WRITE_PERMISSION ? PROT_WRITE : 0) |
                     (processMapping.permissions & zero::proc::EXECUTE_PERMISSION ? PROT_EXEC : 0);

    if ((protection & PROT_READ) && (protection & PROT_WRITE)) {
        origin = *(BindPtr *)address;
        *(BindPtr *)address = shadow_bind;
        return 0;
    }

    uintptr_t start = address & ~(PAGE_SIZE - 1);
    uintptr_t end = (address + sizeof(BindPtr) + PAGE_SIZE) & ~(PAGE_SIZE - 1);

    if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE) < 0) {
        LOG_ERROR("change memory protection failed");
        return -1;
    }

    origin = *(BindPtr *)address;
    *(BindPtr *)address = shadow_bind;

    if (mprotect((void *)start, end - start, protection) < 0) {
        LOG_ERROR("change memory protection failed");
        return -1;
    }

    return 0;
}
