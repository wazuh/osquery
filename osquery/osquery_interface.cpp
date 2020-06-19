#include "osquery_interface.h"
#include "osquery_implementation.h"
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif

int osquery_initialize(char* argv0, const InitType init_type, void* callback, void* context) {
  auto ret_val{ 0l };
  if (nullptr == argv0 ||
    !OSQueryImplementation::getInstance().Initialize(argv0, init_type, callback, context)) {
    std::cout << "Cannot initialize OSQueryImplementation" << std::endl;
    ret_val = -1;
  }
  return ret_val;
}

void osquery_teardown() {
  if(!OSQueryImplementation::getInstance().Release()) {
    std::cout << "Error when release OSQueryImplementation" << std::endl;
  }
}

int osquery_execute_query(
    const char* query,
    char** return_values) {

  auto ret_val{ -1l };

  if (nullptr != return_values) {
    std::string result;
    if (OSQueryImplementation::getInstance().ExecuteQuery(
      query, 
      result)) {
      ret_val = 0l;
      
      *return_values = new (std::nothrow) char[result.length() + 1];
      if (nullptr != return_values) {
        strncpy(*return_values, result.c_str(), result.length() + 1);
      }
      else {
        ret_val = -2l;
      }
    } 
  }
  
  return ret_val;
}

int osquery_free_results(char** return_values) {
  int ret_val = -1l;
  
  if (nullptr != *return_values) {
    delete *return_values;
    ret_val = 0l;
  }
  
  return ret_val;
}

int osquery_init_event_sub_module(
  const EventType event_type, 
  void* callback, 
  const unsigned long interval){
  auto ret_val{ 0l };
  if (nullptr == callback ||
    !OSQueryImplementation::getInstance().InitializeSubModule(event_type, callback, interval)) {
    std::cout << "Cannot initialize SubModule" << std::endl;
    ret_val = -1l;
  }
  return ret_val;
}

int osquery_get_table_create_statement(const char* table, char** sql_statement)
{
  auto ret_val { 0l };
  std::string sql_statement_string;
  if (nullptr == table ||
    !OSQueryImplementation::getInstance().GetCreateTableStatement(table, sql_statement_string))
  {
    std::cout << "Cannot get the creation tables statement." << std::endl;
    ret_val = -1l;
  } else {
    *sql_statement = new (std::nothrow) char[sql_statement_string.length() + 1];
    if (nullptr != sql_statement) {
      strncpy(*sql_statement, sql_statement_string.c_str(), sql_statement_string.length() + 1);
    }
    else {
      ret_val = -2l;
    }
  }
  return ret_val;
}

#ifdef __cplusplus
}
#endif
