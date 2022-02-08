#ifndef OPERATIONAL_H_ONCE
#define OPERATIONAL_H_ONCE

int dp_get_items_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *path,
		const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

void receive_available_event_notifications(void);
int init_state_changes(void);
string get_link_type(struct rtnl_link *link);

#endif /* OPERATIONAL_H_ONCE */
