#pragma once
#include <memory>
#include <mutex>
#include <vector>
#include <osquery/packs.h>
#include "osquery_submodule.h"
#include "osquery_submodule_factory.h"

class OSQuerySubModuleManager {
 public:
 
  static OSQuerySubModuleManager& getInstance() {
    static OSQuerySubModuleManager instance;
    return instance;
  }
  void Release();
  bool Add(std::unique_ptr<SubModule>& sub_module);
  void Remove(const std::string& query_name);
  bool GetClonePack(const EventType type, std::unique_ptr<osquery::Pack>& pack);
  bool GetStatusRelations(const std::string& query_name, std::map<std::string, std::pair<std::string, std::string>>& relations);
  bool GetEventKey(const std::string& query_name, std::string& event_key);
 private:
  std::mutex m_mutex;
  std::vector<std::unique_ptr<SubModule>> m_sub_modules;
  const std::vector<std::unique_ptr<SubModule>>::const_iterator GetSubModuleBasedOnQueryName(const std::string& query_name) const;
  OSQuerySubModuleManager() = default;
  ~OSQuerySubModuleManager() = default;
  OSQuerySubModuleManager(const OSQuerySubModuleManager&) = delete;
  OSQuerySubModuleManager& operator=(const OSQuerySubModuleManager&) = delete;

};