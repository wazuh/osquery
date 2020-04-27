#include <Windows.h>
#include <stdio.h>
#include <time.h> 
#include "../osquery_interface.h"

void callback(const char* result)
{
  printf("result: %s %lu\n", result, GetCurrentThreadId());
}

int main(void) 
{
    const char query[] = { "SELECT pid, path FROM processes;" };
    char *query_ret = 0;
    if (-1 != initialize(&callback))
    {
      if (-1 != execute_query(query, &query_ret))
      {
        printf("result: %s %lu\n", query_ret, GetCurrentThreadId());
        getc(stdin);
      }
      getc(stdin);
      teardown();
    }
    
    return 0;
}