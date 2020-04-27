#include "osquery_implementation.h"
#include <iostream>

bool OSQueryImplementation::ExecuteQuery(
  const std::string& query, 
  char** value) {

  std::string result;
  auto ret_val{ osquery::executeQuery(query, result) ? false : true };

  if (ret_val) {
    *value = new (std::nothrow) char[result.length() + 1];
    if (nullptr != value) {
      strncpy_s(*value, result.length() + 1, result.c_str(), result.length());
    }
    else {
      ret_val = false;
    }
  }
  return ret_val;
}

bool OSQueryImplementation::Initialize(void* callback) {

  auto fake_argc{0};
  char* fake_process_name{"wazuh.process"};
  char** fake_argv = &fake_process_name;
  constexpr auto kWatcherWorkerName{"osqueryd: worker"};

  auto ret_val{false};

  try {
    m_runner = std::make_unique<osquery::Initializer>(
      fake_argc, 
      fake_argv, 
      osquery::ToolType::DAEMON);

    m_runner->initDaemon();
    m_runner->initWorkerWatcher(kWatcherWorkerName);
    m_runner->start();

    osquery::startScheduler(callback);

    ret_val = true;
  } catch (const std::bad_alloc& e) {
    std::cout << "Allocation failed: " << e.what() << '\n';
  }
  
  return ret_val;
}

bool OSQueryImplementation::Release() {
  return m_runner->shutdown(0);

}


