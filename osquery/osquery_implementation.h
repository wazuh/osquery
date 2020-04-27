#pragma once
#include <osquery/core.h>
#include <osquery/core/watcher.h>
#include <osquery/devtools/devtools.h>
#include <osquery/dispatcher/distributed_runner.h>
#include <osquery/dispatcher/scheduler.h>

class OSQueryImplementation {
 public:
 
  static OSQueryImplementation& getInstance() {
    static OSQueryImplementation instance;
    return instance;
  }
  bool Release();
  bool ExecuteQuery(const std::string& query, char** value);
  bool Initialize(void* callback);
 private:
  std::unique_ptr<osquery::Initializer> m_runner;
  bool m_initialized;

  OSQueryImplementation() = default;
  ~OSQueryImplementation() = default;
  OSQueryImplementation(const OSQueryImplementation&) = delete;
  OSQueryImplementation& operator=(const OSQueryImplementation&) = delete;

};
