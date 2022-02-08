#include <sys/sysinfo.h>
#include <linux/if.h>
#include <netlink/route/qdisc.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#include "if_nic_stats.hpp"
#include "config.hpp"

#include <fstream>
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <algorithm>

using std::string;

#define DATETIME_BUF_SIZE 64
#define MAC_ADDR_MAX_LENGTH 32

// link manager used for cacheing links info constantly
static struct nl_cache_mngr *link_manager = NULL;
static struct nl_cache *link_cache = NULL;

static std::map<string, std::pair<uint8_t, time_t>> if_state_changes;

static int get_system_boot_time(string& result)
{
	time_t now = 0;
	struct tm *ts = {0};
	struct sysinfo s_info = {0};
	time_t uptime_seconds = 0;
	char boot_datetime[DATETIME_BUF_SIZE] = {0};	

	now = time(NULL);

	ts = localtime(&now);
	if (ts == NULL)
		return -1;

	if (sysinfo(&s_info) != 0)
		return -1;

	uptime_seconds = s_info.uptime;

	time_t diff = now - uptime_seconds;

	ts = localtime(&diff);
	if (ts == NULL)
		return -1;

	strftime(boot_datetime, DATETIME_BUF_SIZE, "%FT%TZ", ts);

	result = boot_datetime;

	return 0;
}

static string get_phys_address(struct rtnl_link *link)
{
	struct nl_addr *addr = rtnl_link_get_addr(link);
	char phys_address[MAC_ADDR_MAX_LENGTH] = {0};
	nl_addr2str(addr, phys_address, MAC_ADDR_MAX_LENGTH);
	return string(phys_address);
}

string get_link_type(struct rtnl_link *link)
{
	const std::map<string, string> type_string_map {
		{"lo", "iana-if-type:softwareLoopback"},
		{"eth", "iana-if-type:ethernetCsmacd"},
		{"vlan", "iana-if-type:l2vlan"},
		{"bridge", "iana-if-type:bridge"},
		{"dummy", "iana-if-type:other"}         
	};

	char *type = rtnl_link_get_type(link);
	if (type) {
		if (type_string_map.find(type) != type_string_map.end()) {
			return type_string_map.at(type);
		}
	} else {
		/* rtnl_link_get_type() will return NULL for interfaces that were not
		 * set with rtnl_link_set_type()
 	 	 *
	 	 * get the type from: /sys/class/net/<interface_name>/type
	 	 */
		int type_id = 0;
		string path = string("/sys/class/net/") + rtnl_link_get_name(link) + "/type";
		std::fstream type_file(path, std::ios_base::in);

		type_file >> type_id;
		//std::cout << "get_link_type: " << path << " type_id: " << type_id << "\n";

		// values taken from: if_arp.h
		if (type_id == 1) {
			return type_string_map.at("eth");
		} else if (type_id == 772) {
			return type_string_map.at("lo");
		}
	}

	return type_string_map.at("dummy");
}

static std::multimap<string, string> get_interface_data(void)
{
	const std::map<uint8_t, string> oper_string_map {
		{IF_OPER_UNKNOWN, "unknown"},
		{IF_OPER_NOTPRESENT, "not-present"},
		{IF_OPER_DOWN, "down"},
		{IF_OPER_LOWERLAYERDOWN, "lower-layer-down"},
		{IF_OPER_TESTING, "testing"},
		{IF_OPER_DORMANT, "dormant"},
		{IF_OPER_UP, "up"}
	};

	std::multimap<string, string> output;
	std::map<string, std::vector<string>> master_info;
	std::map<string, std::vector<string>> slave_info;
	std::map<string, struct rtnl_link *> link_info;

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
		// collect all higher-layer interfaces
		struct rtnl_link *link = (struct rtnl_link *) nl_cache_get_first(cache);

		while (link != NULL) {
			string iface_name = rtnl_link_get_name(link);
			link_info[iface_name] = link;
			std::vector<string> masters;
			int32_t tmp_if_index = rtnl_link_get_master(link);
			while (tmp_if_index) {
				struct rtnl_link *tmp_link = rtnl_link_get(cache, tmp_if_index);
				string master_name = rtnl_link_get_name(tmp_link);
				masters.push_back(master_name);
				tmp_if_index = rtnl_link_get_master(tmp_link);
			}

			if (!masters.empty()) {
				master_info[iface_name] = masters;
			}
		
			// continue to next link node
			link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) link);
		}
	}

	// collect all lower-layer interfaces
	for (const auto& [iface_name, link] : link_info) {
		std::vector<string> slaves;
		for (const auto& [slave_name, masters] : master_info) {
			if (std::find(masters.begin(), masters.end(), iface_name) != masters.end()) {
				slaves.push_back(slave_name);
			}
		}
		if (!slaves.empty()) {
			slave_info[iface_name] = slaves;
		}
	}

	for (const auto& [iface_name, link] : link_info) {
		std::map<string, string> iface {};

		iface["description"] = get_interface_description(iface_name);
		iface["type"] = get_link_type(link);
		iface["enabled"] = (rtnl_link_get_operstate(link) == IF_OPER_UP) ? "true" : "false";
		iface["oper-status"] = oper_string_map.at(rtnl_link_get_operstate(link));

		// default value of last-change should be system boot time
		get_system_boot_time(iface["last-change"]);
		if (if_state_changes.find(iface_name) != if_state_changes.end()) { // TODO: Mutex
            auto [state, last_change] = if_state_changes.at(iface_name);
			if (last_change) {
				char system_time[DATETIME_BUF_SIZE] = {0};
				strftime(system_time, sizeof(system_time), "%FT%TZ", localtime(&last_change));
				iface["last-change"] = system_time;
			}
		}

		iface["phys-address"] = get_phys_address(link);
		struct nl_cache *qdisc_cache;
		if (rtnl_qdisc_alloc_cache(socket, &qdisc_cache) == 0) {
			struct rtnl_qdisc *qdisc = rtnl_qdisc_get_by_parent(qdisc_cache, rtnl_link_get_ifindex(link), TC_H_ROOT);
			if (qdisc) {
				iface["speed"] = std::to_string(rtnl_tc_get_stat(TC_CAST(qdisc), RTNL_TC_RATE_BPS) * 8);
				nl_object_free((struct nl_object *) qdisc);
			}
			nl_cache_free(qdisc_cache);
		}

		get_system_boot_time(iface["statistics/discontinuity-time"]);

		// gather interface statistics that are not accessable via netlink
		nic_stats_t nic_stats = {0};
		if (get_nic_stats(iface_name.c_str(), &nic_stats) != 0) {
			std::cerr << "get_nic_stats(" << iface_name << ") failed\n";
		}

		// Rx
		iface["statistics/in-octets"] = std::to_string(rtnl_link_get_stat(link, RTNL_LINK_RX_BYTES));
		iface["statistics/in-broadcast-pkts"] = std::to_string(nic_stats.rx_broadcast);
		uint64_t in_multicast_pkts = rtnl_link_get_stat(link, RTNL_LINK_MULTICAST);
		iface["statistics/in-multicast-pkts"] = std::to_string(in_multicast_pkts);
		if (nic_stats.rx_packets) {
			iface["statistics/in-unicast-pkts"] = std::to_string(nic_stats.rx_packets - nic_stats.rx_broadcast - in_multicast_pkts);
		} else {
			iface["statistics/in-unicast-pkts"] = std::to_string(nic_stats.rx_unicast);
		}

		iface["statistics/in-discards"] = std::to_string(rtnl_link_get_stat(link, RTNL_LINK_RX_DROPPED));
		iface["statistics/in-errors"] = std::to_string(rtnl_link_get_stat(link, RTNL_LINK_RX_ERRORS));
		iface["statistics/in-unknown-protos"] = std::to_string(rtnl_link_get_stat(link, RTNL_LINK_IP6_INUNKNOWNPROTOS));

		// Tx
		iface["statistics/out-octets"] = std::to_string(rtnl_link_get_stat(link, RTNL_LINK_TX_BYTES));
		iface["statistics/out-broadcast-pkts"] = std::to_string(nic_stats.tx_broadcast);
		iface["statistics/out-multicast-pkts"] = std::to_string(nic_stats.tx_multicast);
		uint64_t out_pkts = rtnl_link_get_stat(link, RTNL_LINK_TX_PACKETS);
		iface["statistics/out-unicast-pkts"] = std::to_string(out_pkts - nic_stats.tx_broadcast - nic_stats.tx_multicast);
		iface["statistics/out-discards"] = std::to_string(rtnl_link_get_stat(link, RTNL_LINK_TX_DROPPED));
		iface["statistics/out-errors"] = std::to_string(rtnl_link_get_stat(link, RTNL_LINK_TX_ERRORS));

		string interface_path = string("/ietf-interfaces:interfaces/interface[name=\"") + iface_name + "\"]/";

		for (const auto& [path, value] : iface) {
			output.insert({interface_path + path, value});
    	}

		if (master_info.find(iface_name) != master_info.end()) {
			for (const auto& master_name : master_info.at(iface_name)) {
				output.insert({interface_path + "higher-layer-if", master_name});
			}
		}

		if (slave_info.find(iface_name) != slave_info.end()) {
			for (const auto& slave_name : slave_info.at(iface_name)) {
				output.insert({interface_path + "lower-layer-if", slave_name});
			}
		}
	}

	nl_cache_free(cache);
    nl_socket_free(socket);

	return output;
}

static void yang_dnode_edit(struct lyd_node *dnode, const struct ly_ctx *ly_ctx,
	const std::string &path, const std::string &value)
{
    struct lyd_node *ret;
	LY_ERR err = lyd_new_path(dnode, ly_ctx, path.c_str(),
				  value.c_str(), LYD_NEW_PATH_UPDATE, &dnode);
    if (err != LY_SUCCESS) {
        std::cerr << path << ": " << value << "\n";
        std::cerr << "lyd_new_path err\n";
    }
}

int dp_get_items_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *path,
		const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void)session;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    std::cout << "Data requested for module: " << module_name << "\n xpath: " << path << "\n";

	if (*parent == NULL) {
		const struct ly_ctx *ly_ctx = sr_get_context(sr_session_get_connection(session));
        yang_dnode_edit(*parent, ly_ctx, request_xpath, NULL);
	}

    const auto& m = get_interface_data();
	for (const auto& [path, value] : m) {
		 yang_dnode_edit(*parent, NULL, path, value);
    }

    return SR_ERR_OK;
}

static void cache_change_cb(struct nl_cache *cache, struct nl_object *obj, int val, void *arg)
{
	struct rtnl_link *link = NULL;
	std::cerr << "entered cb function for a link manager\n";

	link = (struct rtnl_link *) nl_cache_get_first(cache);

	while (link != NULL) {
		std::string name = rtnl_link_get_name(link);
        if (if_state_changes.find(name) != if_state_changes.end()) {
            auto& [state, last_change] = if_state_changes.at(name);
            uint8_t tmp_state = rtnl_link_get_operstate(link);
            if (tmp_state != state) {
                std::cerr << "Interface " << name << " changed operstate from " << std::to_string(state) << " to " << std::to_string(tmp_state) << "\n";
                state = tmp_state;
                last_change = time(NULL);
            }
        }

		link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) link);
	}
}

void receive_available_event_notifications(void)
{
	nl_cache_mngr_data_ready(link_manager);
}

int init_state_changes(void)
{
	int error = 0;
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
	    struct rtnl_link * link = (struct rtnl_link *) nl_cache_get_first(cache);
        while (link != NULL) {
            std::string name = rtnl_link_get_name(link);
            if_state_changes[name] = {rtnl_link_get_operstate(link), time(NULL)};
            link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) link);
        }
    }

	error = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, 0, &link_manager);
	if (error != 0) {
		std::cerr << "nl_cache_mngr_alloc error (" << error << "): " << nl_geterror(error) << "\n";
	} else {
        error = nl_cache_mngr_add(link_manager, "route/link", cache_change_cb, NULL, &link_cache);
        if (error != 0) {
			std::cerr << "nl_cache_mngr_add error (" << error << "): " << nl_geterror(error) << "\n";
        }
    }

	// clear libnl data
	nl_cache_free(cache);
	nl_socket_free(socket);

	return error;
}