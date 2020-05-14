#include "osquery_interface.h"
#include "osquery_implementation.h"
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif

int initialize(char* argv0, const InitType init_type, void* callback, void* context) {
  auto ret_val{ 0l };
  if (nullptr == callback || 
    nullptr == argv0 ||
    !OSQueryImplementation::getInstance().Initialize(argv0, init_type, callback, context)) {
    std::cout << "Cannot initialize OSQueryImplementation" << std::endl;
    ret_val = -1;
  }
  return ret_val;
}

void teardown() {
  if(!OSQueryImplementation::getInstance().Release()) {
    std::cout << "Error when release OSQueryImplementation" << std::endl;
  }
}

int execute_query(
    const char* query,
    char** return_values) {

  auto ret_val{ -1l };

  if (nullptr != return_values) {
    if (OSQueryImplementation::getInstance().ExecuteQuery(
      query, 
      return_values)) {
      ret_val = 0;
    }
  }
  
  return ret_val;
}

int free_query_results(char** return_values) {
  int ret_val = -1;
  
  if (nullptr != *return_values) {
    free(*return_values);
    ret_val = 0;
  }
  
  return ret_val;
}

int init_event_sub_module(
  const EventType event_type, 
  void* callback, 
  const unsigned long interval) {
  auto ret_val{ 0l };
  if (nullptr == callback ||
    !OSQueryImplementation::getInstance().InitializeSubModule(event_type, callback, interval)) {
    std::cout << "Cannot initialize SubModule" << std::endl;
    ret_val = -1;
  }
  return ret_val;
}

#ifdef __cplusplus
}
#endif
