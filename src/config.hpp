#ifndef CONFIG_H_ONCE
#define CONFIG_H_ONCE

#include <string>

using std::string;

typedef struct link_data_s link_data_t;

struct link_data_s {
	string description;
	string type;
	string enabled;
};

void sync_sysrepo_to_kernel(sr_session_ctx_t *session);

int module_change_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath,
					sr_event_t event, uint32_t request_id, void *private_data);

string get_interface_description(string name);

#endif /* CONFIG_H_ONCE */
