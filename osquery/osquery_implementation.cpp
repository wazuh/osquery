#include "osquery_implementation.h"
#include "osquery_submodule_factory.h"
#include "osquery_submodule_manager.h"
#include "osquery_interface.h"
#include <iostream>

bool OSQueryImplementation::ExecuteQuery(
  const std::string& query, 
  std::string& value) {

  return osquery::executeQuery(query, value) ? false : true;
}

bool OSQueryImplementation::Initialize(char* argv0, const InitType init_type, void* callback, void* context) {

  auto fake_argc{0};
  
  char** fake_argv = &argv0;
  constexpr auto kWatcherWorkerName{"osqueryd: worker"};

  auto ret_val{false};

  try {
    m_runner = std::make_unique<osquery::Initializer>(
      fake_argc, 
      fake_argv, 
      InitType::DAEMON == init_type ? osquery::ToolType::DAEMON : osquery::ToolType::SHELL_DAEMON);

    m_runner->initDaemon();
    
    if(InitType::DAEMON == init_type) {
      m_runner->initWorkerWatcher(kWatcherWorkerName);
      m_runner->start();
      osquery::startScheduler(callback, context);
    } else if(InitType::SYNC_QUERIES == init_type) {
      m_runner->start();
    }

    ret_val = true;
  } catch (const std::bad_alloc& e) {
    std::cout << "Allocation failed: " << e.what() << std::endl;
  }
  
  return ret_val;
}

bool OSQueryImplementation::Release() {
  OSQuerySubModuleManager::getInstance().Release();
  return 0 == m_runner->shutdown(0);
}


bool OSQueryImplementation::InitializeSubModule(
  const EventType event_type, 
  void* callback, 
  const size_t interval)
{
  bool ret_val { false };

  auto sub_module_instance = FactorySubModule::Create(event_type, callback, interval);
  if(SUBMODULE_NONE != sub_module_instance->GetType()) {
    ret_val = OSQuerySubModuleManager::getInstance().Add(sub_module_instance);
    osquery::Config::get().addPackPreCreated();
  }
  return ret_val;
}


bool OSQueryImplementation::GetCreateTableStatement(
  const std::string& table, 
  std::string& sql_statement) {

  auto ret_val { false };
  if (0 == table.compare(ALL_TABLES)) {
    ret_val = GetAllCreateTableStatement(sql_statement);
  } else {
    std::string table_create_statement;
    ret_val = GetOneTableCreateStatement(table, sql_statement);
  }
  return ret_val;
}

bool OSQueryImplementation::GetAllCreateTableStatement(
  std::string& sql_statement) {

  bool ret_val { true };
  std::vector<std::string> table_list;

  if (GetTableList(table_list)) {
    for (const auto& value : table_list) {
      if (!GetOneTableCreateStatement(value, sql_statement)) {
        ret_val = false;
        break;
      }
    }
  }

  return ret_val;
}

bool OSQueryImplementation::GetOneTableCreateStatement(
  const std::string& table, 
  std::string& table_create_statement) {
  return osquery::getTableSchema(table, table_create_statement);
}


bool OSQueryImplementation::GetTableList(
  std::vector<std::string>& table_list) {

  return osquery::getTableList(table_list);
}