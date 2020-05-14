#pragma once
#include "osquery_interface.h"
#include <osquery/packs.h>
#include <osquery/core/sql/scheduled_query.h>
#include <iostream>
#include <string>

constexpr auto Source = "WAZUH";

class SubModulePack : public osquery::Pack 
{
public:
    SubModulePack(const std::string& source,
                 const std::string& query_name,
                 const std::string& query_string,
                 const size_t interval,
                 void* callback) 
                 : Pack(source+query_name, source) { 
        platform_.clear();
        version_.clear();
        discovery_queries_.clear();
        discovery_cache_ = std::make_pair<size_t, bool>(0, false);
        valid_ = true;

        osquery::ScheduledQuery query(
                name_, query_name, query_string);
        query.oncall = false;
        query.interval = interval;
        query.splayed_interval = osquery::restoreSplayedValue(query_name, interval);
        query.options["snapshot"] = false;
        query.options["removed"] = false;
        query.options["blacklist"] = false;
        query.callback = callback;

        schedule_.emplace(std::make_pair(query_name, std::move(query)));
    }

private:
    SubModulePack() = delete;
};

class SubModule {
public: 
    SubModule() : 
    m_type(SUBMODULE_NONE), 
    m_callback(nullptr) { };
    virtual ~SubModule() = default;
    
    const std::unique_ptr<SubModulePack>& GetPack()  { return m_pack; }
    EventType GetType() { return m_type; }
    const std::map<std::string, std::pair<std::string, std::string>>& GetStatusKeyRelations() { return m_status_relation_keys; }
    const std::string& GetEventTableKey() { return m_event_table_key; }
    
protected:
    std::unique_ptr<SubModulePack> m_pack;
    std::map<std::string, std::pair<std::string, std::string>> m_status_relation_keys;
    std::string m_event_table_key;
    EventType m_type;
    void* m_callback;

};