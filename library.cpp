#include "library.h"
#include <elfio/elfio.hpp>
#include <common/log.h>
#include <common/utils/process.h>
#include <sys/user.h>
#include <netinet/in.h>
#include <sys/mman.h>

using BindPtr = int (*)(int, const sockaddr *, socklen_t);

constexpr auto RELOCATION_PLT_SECTION = ".rela.plt";
constexpr auto BIND_SYMBOL = "bind";

BindPtr origin = nullptr;

int shadow_bind(int fd, const sockaddr *address, socklen_t length) {
    if (address->sa_family != AF_INET) {
        return origin(fd, address, length);
    }

    in_port_t *port = &((sockaddr_in *)address)->sin_port;

    if (*port != htons(9229)) {
        return origin(fd, address, length);
    }

    *port = htons(29229);

    return origin(fd, address, length);
}

int init() {
    INIT_CONSOLE_LOG(INFO);

    std::string path = CPath::getApplicationPath();

    CProcessMap processMap;

    if (!CProcess::getImageBase(getpid(), path, processMap)) {
        LOG_ERROR("find node image base failed");
        return -1;
    }

    LOG_INFO("node image base: 0x%lx", processMap.start);

    ELFIO::elfio reader;

    if (!reader.load(path)) {
        LOG_ERROR("open elf failed: %s", path.c_str());
        return -1;
    }

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return s->get_name() == RELOCATION_PLT_SECTION;
            });

    if (it == reader.sections.end()) {
        LOG_ERROR("can't find relocation plt section");
        return -1;
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

        baseAddress = processMap.start - ((*minElement)->get_virtual_address() & ~(PAGE_SIZE - 1));
    }

    ELFIO::Elf64_Addr gotEntry = 0;
    ELFIO::relocation_section_accessor relocations(reader, *it);

    for (ELFIO::Elf_Xword i = 0; i < relocations.get_entries_num(); i++) {
        ELFIO::Elf64_Addr offset;
        ELFIO::Elf64_Addr symbolValue;
        std::string symbolName;
        ELFIO::Elf_Word type;
        ELFIO::Elf_Sxword addend;
        ELFIO::Elf_Sxword calcValue;

        if (!relocations.get_entry(i, offset, symbolValue, symbolName, type, addend, calcValue)) {
            LOG_ERROR("get relocation entry %lu failed", i);
            return -1;
        }

        if (symbolName == BIND_SYMBOL) {
            gotEntry = baseAddress + offset;
            break;
        }
    }

    if (!gotEntry) {
        LOG_ERROR("can't find bind got entry");
        return -1;
    }

    LOG_INFO("bind got entry: 0x%lx", gotEntry);

    unsigned long start = gotEntry & ~(PAGE_SIZE - 1);
    unsigned long end = (gotEntry + sizeof(BindPtr) + PAGE_SIZE) & ~(PAGE_SIZE - 1);

    if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE) < 0) {
        LOG_ERROR("change memory protection failed");
        return -1;
    }

    origin = *(BindPtr *)gotEntry;
    *(BindPtr *)gotEntry = shadow_bind;

    return 0;
}
