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


typedef enum {
    SUBMODULE_NONE = 0,
    SUBMODULE_PROCESS = 1,
    SUBMODULE_LAST = 2
}EventType;

typedef enum {
    SYNC_QUERIES = 0,
    DAEMON = 1
}InitType;

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
 * @param init_type Selector to establish the way to start osquery module
 * @param callback This pointer to function is called when some data
 * is returned from scheduled queries.
 * @param context This pointer is a reference of the context, to sent in callbacks

 *
 * @return 0 if the initialization is success.
 */
    EXPORTED int initialize(char* argv0, const InitType init_type, void* callback, void* context);

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

/**
 * @brief Initialize and subscribe to events provided by osquery.
 *
 * @param event_type qualificator of the event type.
 * @param callback This pointer to function is called when some data
 * is returned from events.
 * @param interval interval in seconds, to query for new events
 * @return 0 if the sub module is initialized.
 */
    EXPORTED int init_event_sub_module(const EventType event_type, void* callback, const unsigned long interval);

    
#ifdef __cplusplus
    }
#endif