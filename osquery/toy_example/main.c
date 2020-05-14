#include <stdio.h>
#include <time.h> 
#include "../osquery_interface.h"

void callback(const char* result, void* context)
{
  printf("result_callback: %s\n", result);
}

int main(int argc, char* argv[]) 
{
    const char query[] = { "SELECT * from processes;" };
    char *query_ret = 0;
    if (-1 != initialize(argv[0], SYNC_QUERIES, &callback, NULL))
    {
      do {
        if (-1 != execute_query(query, &query_ret))
        {
          printf("result: %s\n", query_ret);
          free_query_results(&query_ret);
        }
      }while(getc(stdin) != 'q');
      teardown();
    }
    return 0;
}