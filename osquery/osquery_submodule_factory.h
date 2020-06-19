#pragma once
#include "osquery_process_submodule.h"
#include <iostream>
class FactorySubModule {
public:
    static std::unique_ptr<SubModule> Create(
        const EventType type,
        void* callback, 
        const size_t interval)
    {
        if (SUBMODULE_PROCESS == type) {
            std::cout << "submodule created" << std::endl;
            return std::make_unique<ProcessSubModule>(callback, interval);
        }
        return std::make_unique<SubModule>();
    }
};