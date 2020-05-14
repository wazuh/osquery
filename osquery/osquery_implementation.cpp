#include "osquery_implementation.h"
#include "osquery_submodule_factory.h"
#include "osquery_submodule_manager.h"
#include <iostream>

bool OSQueryImplementation::ExecuteQuery(
  const std::string& query, 
  char** value) {

  std::string result;
  auto ret_val{ osquery::executeQuery(query, result) ? false : true };

  if (ret_val) {
    *value = new (std::nothrow) char[result.length() + 1];
    if (nullptr != value) {
      strncpy(*value, result.c_str(), result.length() + 1);
    }
    else {
      ret_val = false;
    }
  }
  return ret_val;
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

