#pragma once

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif


#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Turn off the services provided by the shared library.
 */
    EXPORTED void teardown(void);

/**
 * @brief Initialize OSQuery.
 *
 * @param argv0 File path of the invoker host process.
 * @param callback This pointer to function is called when some data
 * is returned from scheduled queries.
 *
 * @return 0 if the initialization is success.
 */
    EXPORTED int initialize(char* argv0, void* callback);

/**
 * @brief Execute on-demand query.
 *
 * @param query Query to be executed
 * @param return_values The results in JSON format (this need to be deallocated
 * with free_query_resutls(return_values)) 
 *
 * @return return 0 if the query is correctly executed
 */
    EXPORTED int execute_query(const char* query,
                               char** return_values);

/**
 * @brief deallocate query executed results.
 *
 * @param return_values pointer with the result data.
 *
 * @return 0 if the deallocation is success
 */
    EXPORTED int free_query_results(char** return_values);
#ifdef __cplusplus
    }
#endif