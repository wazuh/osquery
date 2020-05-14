#pragma once
#include <memory>
#include <osquery/core.h>
#include <osquery/core/watcher.h>
#include <osquery/devtools/devtools.h>
#include <osquery/dispatcher/distributed_runner.h>
#include <osquery/dispatcher/scheduler.h>
#include <osquery/config/config.h>
#include "osquery_submodule.h"

class OSQueryImplementation {
 public:
 
  static OSQueryImplementation& getInstance() {
    static OSQueryImplementation instance;
    return instance;
  }
  bool Release();
  bool ExecuteQuery(const std::string& query, char** value);
  bool Initialize(char* argv0, const InitType init_type, void* callback, void* context);
  bool InitializeSubModule(const EventType event_type, void* callback, const size_t interval);
 private:
  std::unique_ptr<osquery::Initializer> m_runner;
  
  OSQueryImplementation() = default;
  ~OSQueryImplementation() = default;
  OSQueryImplementation(const OSQueryImplementation&) = delete;
  OSQueryImplementation& operator=(const OSQueryImplementation&) = delete;

};
