#include "osquery_process_submodule.h"

constexpr auto QueryName = "PROCESS_EVENTS";
constexpr auto QueryString = "SELECT * FROM process_events;";

constexpr auto ProcessStatusObjectName = "process_status";
constexpr auto ProcessStatusTable = "processes";
constexpr auto StatusProcessKey= "pid";
constexpr auto EventProcessKey = "pid";



ProcessSubModule::ProcessSubModule(
    void* callback, 
    const size_t interval)
{
    m_type = SUBMODULE_PROCESS;
    m_pack = std::make_unique<SubModulePack>(
        Source,
        QueryName,
        QueryString,
        interval,
        callback); 
    m_event_table_key = EventProcessKey;
    m_status_relation_keys[ProcessStatusObjectName] = std::make_pair(ProcessStatusTable, StatusProcessKey);
}