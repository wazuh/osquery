#include "osquery_submodule_manager.h"
#include <algorithm>
#include <utility>

void OSQuerySubModuleManager::Release()
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_sub_modules.clear();
}
bool OSQuerySubModuleManager::Add(std::unique_ptr<SubModule>& sub_module)
{
  bool ret_val { false };
  std::lock_guard<std::mutex> lock(m_mutex);
  const auto it = std::find_if(m_sub_modules.begin(),
                          m_sub_modules.end(), 
                          [&sub_module] (const std::unique_ptr<SubModule>& sub_module_param)
                          {
                            return sub_module->GetType() == sub_module_param->GetType();
                          });

  if (m_sub_modules.end() == it)
  {
    m_sub_modules.push_back(std::move(sub_module));
    ret_val = true;
  }

  return ret_val;
}
void OSQuerySubModuleManager::Remove(const std::string& query_name)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_sub_modules.erase(std::remove_if(m_sub_modules.begin(),
                                    m_sub_modules.end(),
                                    [&](const std::unique_ptr<SubModule>& sub_module_param)
                                    {
                                      return 0 == query_name.compare(sub_module_param->GetPack()->getName());
                                    }),
                      m_sub_modules.end());

}

const std::vector<std::unique_ptr<SubModule>>::const_iterator OSQuerySubModuleManager::GetSubModuleBasedOnQueryName(const std::string& query_name) const
{
  return std::find_if(m_sub_modules.begin(),
                      m_sub_modules.end(), 
                      [&query_name] (const std::unique_ptr<SubModule>& sub_module_param)
                      {
                        std::cout << sub_module_param->GetPack()->getName()  << "- " << query_name << std::endl;
                        return 0 == sub_module_param->GetPack()->getName().compare(query_name);
                      });
}

bool OSQuerySubModuleManager::GetEventKey(const std::string& query_name, std::string& event_key) {
  bool ret_val{ false };
  std::lock_guard<std::mutex> lock(m_mutex);
  
  const auto& it = GetSubModuleBasedOnQueryName(query_name);

  if (m_sub_modules.end() != it) {
    event_key = (*it)->GetEventTableKey();
    ret_val = true;
  }
  return ret_val;
}

bool OSQuerySubModuleManager::GetStatusRelations(const std::string& query_name, std::map<std::string, std::pair<std::string, std::string>>& relations) {
  bool ret_val{ false };
  std::lock_guard<std::mutex> lock(m_mutex);

  const auto& it = GetSubModuleBasedOnQueryName(query_name);

  if (m_sub_modules.end() != it) {
    for(const auto& table_value : (*it)->GetStatusKeyRelations()) {
      relations[table_value.first] = std::make_pair(table_value.second.first, table_value.second.second);
    }
    ret_val = true;
  }
  return ret_val;
}

bool OSQuerySubModuleManager::GetClonePack(const EventType type, std::unique_ptr<osquery::Pack>& pack){
  bool ret_val { false };
  std::lock_guard<std::mutex> lock(m_mutex);
  const auto it = std::find_if(m_sub_modules.begin(),
                          m_sub_modules.end(), 
                          [&type] (const std::unique_ptr<SubModule>& sub_module_param)
                          {
                            return type == sub_module_param->GetType();
                          });

  if (m_sub_modules.end() != it) {
    auto pack_name = (*it)->GetPack()->getName();
    pack_name = pack_name.substr(std::string(Source).length(), pack_name.length());

    pack = std::make_unique<SubModulePack>((*it)->GetPack()->getSource(),
                                          (*it)->GetPack()->getName(),
                                          (*it)->GetPack()->getSchedule()[pack_name].query,
                                          (*it)->GetPack()->getSchedule()[pack_name].interval,
                                          (*it)->GetPack()->getSchedule()[pack_name].callback);
    ret_val = true;
  }
  return ret_val;
}