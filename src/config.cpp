#include <sys/sysinfo.h>
#include <linux/if.h>
#include <netlink/route/qdisc.h>

#include <inttypes.h>
#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include <iostream>
#include <map>
#include <string>

#include "config.hpp"
#include "operational.hpp"

using std::string;

static std::map<string, link_data_t> links_info;

string get_interface_description(string name)
{
	if (links_info.find(name) != links_info.end()) {
		return links_info.at(name).description;
	} else {
		return "(not found)";
	}
}

static std::map<string, link_data_t> get_existing_links(void)
{
    std::map<string, link_data_t> output;
	struct nl_cache *cache = NULL;
	struct nl_sock *socket = nl_socket_alloc();

	if (socket == NULL) {
		std::cerr << "nl_socket_alloc error: invalid socket\n";
	} else {
		int error = nl_connect(socket, NETLINK_ROUTE);
		if (error) {
			std::cerr << "nl_connect error (" << error << "): " << nl_geterror(error) << "\n";
		} else {
			error = rtnl_link_alloc_cache(socket, AF_UNSPEC, &cache);
			if (error) {
				std::cerr << "rtnl_link_alloc_cache error (" << error << "): " << nl_geterror(error) << "\n";
			}
		}
	}

	if (cache) {
		struct rtnl_link *link = (struct rtnl_link *) nl_cache_get_first(cache);

		while (link != NULL) {
			string iface_name = rtnl_link_get_name(link);
            link_data_t ld;
			
            ld.type =  get_link_type(link);

            // enabled
            uint8_t tmp_enabled = rtnl_link_get_operstate(link);
            // lo interface has state unknown, treat it as enabled
            // otherwise it will be set to down, and dns resolution won't work
            if (IF_OPER_UP == tmp_enabled || IF_OPER_UNKNOWN == tmp_enabled) {
                ld.enabled = "true";
            } else if (IF_OPER_DOWN == tmp_enabled ) {
                ld.enabled = "false";
            }

            output[iface_name] = ld;

			// continue to next link node
			link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) link);
		}

        rtnl_link_put(link);
        nl_cache_free(cache);
	}

	nl_socket_free(socket);

	return output;
}

static const std::map<string, string> get_inteface_items(const std::map<string, link_data_t>& links)
{
    std::map<string, string> out;

	for (const auto& [name, ld] : links) {
		string interface_path = "/ietf-interfaces:interfaces/interface[name=\"" + name + "\"]/";
        out[interface_path + "name"] = name;
        out[interface_path + "description"] = ld.description;
        out[interface_path + "type"] = ld.type;
        out[interface_path + "enabled"] = ld.enabled;
    }

	return out;
}

void sync_sysrepo_to_kernel(sr_session_ctx_t *session)
{
    links_info = get_existing_links();
    const auto items = get_inteface_items(links_info);

    for (const auto& [path, value] : items) {
        std::cerr << path << ": " << value << "\n";
		int error = sr_set_item_str(session, path.c_str(), value.c_str(), NULL, SR_EDIT_DEFAULT);
		if (error) {
            std::cerr << "sr_set_item_str error (" << error << "): " << sr_strerror(error) << "\n";
		}
	}

	int error = sr_apply_changes(session, 0);
	if (error) {
		std::cerr << "sr_set_item_str error (" << error << "): " << sr_strerror(error) << "\n";
	}
}

static int set_link_state(char *name, const char *enabled)
{
	int error = SR_ERR_OK;
	struct nl_cache *cache = NULL;
	struct nl_sock *socket = nl_socket_alloc();

	if (socket == NULL) {
		std::cerr << "nl_socket_alloc error: invalid socket\n";
	} else {
		int error = nl_connect(socket, NETLINK_ROUTE);
		if (error) {
			std::cerr << "nl_connect error (" << error << "): " << nl_geterror(error) << "\n";
		} else {
			error = rtnl_link_alloc_cache(socket, AF_UNSPEC, &cache);
			if (error) {
				std::cerr << "rtnl_link_alloc_cache error (" << error << "): " << nl_geterror(error) << "\n";
			}
		}
	}

	if (cache) {
		struct rtnl_link *old = rtnl_link_get_by_name(cache, name);
		struct rtnl_link *request = rtnl_link_alloc();

		// enabled
		if (enabled != NULL) {
			if (strcmp(enabled, "true") == 0) {
				// set the interface to UP
				rtnl_link_set_flags(request, (unsigned int) rtnl_link_str2flags("up"));
				rtnl_link_set_operstate(request, IF_OPER_UP);
			} else {
				// set the interface to DOWN
				rtnl_link_unset_flags(request, (unsigned int) rtnl_link_str2flags("up"));
				rtnl_link_set_operstate(request, IF_OPER_DOWN);
			}
		}

		if (old != NULL) {
			// the interface with name already exists, change it
			error = rtnl_link_change(socket, old, request, 0);
			if (error != 0) {
				std::cerr << "rtnl_link_change error (" << error << "): " << nl_geterror(error) << "\n";
			}
		}

		rtnl_link_put(old);
		rtnl_link_put(request);
	}

	nl_socket_free(socket);
	nl_cache_free(cache);

	return error;
}

static int set_config_value(const char* xpath, const char* value)
{
	int error = SR_ERR_OK;

	char *interface_node = sr_xpath_node_name(xpath);
	if (interface_node == NULL) {
        std::cerr << "sr_xpath_key_value\n";
		error = SR_ERR_CALLBACK_FAILED;
	} else {
        sr_xpath_ctx_t state = {0};
        char *interface_node_name = sr_xpath_key_value((char*)xpath, "interface", "name", &state);
        if (interface_node_name == NULL) {
            std::cerr << "sr_xpath_key_value\n";
            error = SR_ERR_CALLBACK_FAILED;
        }

        if (strcmp(interface_node, "enabled") == 0) {
            std::cerr << "set_config_value: " << interface_node_name << " = " << value << "\n";
            if (set_link_state(interface_node_name, value) == 0) {
				if (links_info.find(interface_node_name) != links_info.end()) {
					links_info.at(interface_node_name).enabled = value;
				}
			}
        }

        if (strcmp(interface_node, "description") == 0) {
            std::cerr << "set_config_value: " << interface_node_name << " = " << value << "\n";
			if (links_info.find(interface_node_name) != links_info.end()) {
				links_info.at(interface_node_name).description = value;
			}
        }		
    }
        
	return error;
}

int module_change_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath,
					sr_event_t event, uint32_t request_id, void *private_data)
{
    int error = SR_ERR_OK;    

    std::cout << "module_change_cb()\n";
    std::cout << "module_name: " << module_name << ", xpath: " << xpath;
    std::cout << ", event: " << event << ", request_id: " << request_id << "\n";

	if (event == SR_EV_ABORT) {
		std::cerr << "aborting changes for: " << xpath << "\n";
		error = SR_ERR_CALLBACK_FAILED;
	}

	if (event == SR_EV_DONE) {
		error = sr_copy_config(session, "ietf-interfaces", SR_DS_RUNNING, 0);
		if (error) {
            std::cerr << "sr_copy_config error (" << error << "): " << sr_strerror(error) << "\n";
            error = SR_ERR_CALLBACK_FAILED;
		}
	}

	if (event == SR_EV_CHANGE) {
        sr_change_iter_t *it = NULL;
		error = sr_get_changes_iter(session, xpath, &it);
		if (error) {
            std::cerr << "sr_get_changes_iter error (" << error << "): " << sr_strerror(error) << "\n";
        } else {
            sr_val_t *old_value = NULL;
            sr_val_t *new_value = NULL;
            sr_change_oper_t oper;
            while (sr_get_change_next(session, it, &oper, &old_value, &new_value) == SR_ERR_OK) {
                if (new_value) {
					if (new_value->type == SR_BOOL_T) {
                    	set_config_value(new_value->xpath, new_value->data.bool_val ? "true" : "false");
					}
					if (new_value->type == SR_STRING_T) {
						set_config_value(new_value->xpath, new_value->data.string_val);
					}
                }
                sr_free_val(old_value);
                sr_free_val(new_value);
            }
        }
    }

    return (error != 0) ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}
