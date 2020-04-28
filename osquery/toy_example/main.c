#include <stdio.h>
#include <time.h> 
#include "../osquery_interface.h"

void callback(const char* result)
{
  printf("result: %s\n", result);
}

int main(int argc, char* argv[]) 
{
    const char query[] = { "SELECT pid, path FROM processes LIMIT 10;" };
    char *query_ret = 0;
    if (-1 != initialize(argv[0], &callback))
    {
      if (-1 != execute_query(query, &query_ret))
      {
        printf("result: %s\n", query_ret);
        getc(stdin);
      }
      teardown();
    }
    return 0;
}