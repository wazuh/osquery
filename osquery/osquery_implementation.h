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
  bool ExecuteQuery(const std::string& query, std::string& value);
  bool Initialize(char* argv0, const InitType init_type, void* callback, void* context);
  bool InitializeSubModule(const EventType event_type, void* callback, const size_t interval);
  bool GetCreateTableStatement(const std::string& table, std::string& sql_statement);
  bool GetTableList(std::vector<std::string>& table_list);
 private:
  std::unique_ptr<osquery::Initializer> m_runner;
  bool GetAllCreateTableStatement(std::string& sql_statement);
  bool GetOneTableCreateStatement(const std::string& table, std::string& table_create_statement);

  OSQueryImplementation() = default;
  ~OSQueryImplementation() = default;
  OSQueryImplementation(const OSQueryImplementation&) = delete;
  OSQueryImplementation& operator=(const OSQueryImplementation&) = delete;

};
