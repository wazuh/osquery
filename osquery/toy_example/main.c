#include <stdio.h>
#include <time.h> 
#include "../osquery_interface.h"

void callback(const char* result, void* context)
{
  printf("result_callback: %s\n", result);
}

int main(int argc, char* argv[]) 
{
    const char query[] = { "SELECT * from process_events;" };
    char *query_ret = 0;
    if (-1 != initialize(argv[0], &callback, NULL))
    {
      if (-1 !=init_event_sub_module(SUBMODULE_PROCESS, &callback, 0))
      {
        do {
          if (-1 != execute_query(query, &query_ret))
          {
            printf("result: %s\n", query_ret);
            free_query_results(&query_ret);
          }
        }while(getc(stdin) != 'x');
      }
      teardown();
    }
    return 0;
}