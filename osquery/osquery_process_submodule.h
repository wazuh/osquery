#pragma once
#include "osquery_submodule.h"

class ProcessSubModule : public SubModule {
public:
    ProcessSubModule(void* callback, const size_t interval);
};