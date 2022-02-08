#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sysrepo.h>

#include <iostream>
#include <thread>

#include "config.hpp"
#include "operational.hpp"

using namespace std::chrono_literals;

static volatile int exit_application = 0;

static void sigint_handler(int signum)
{
    (void)signum;
    exit_application = 1;
}

static void manager_thread_cb(void)
{
    do {
		receive_available_event_notifications();
        std::this_thread::sleep_for(1000ms);
	} while (exit_application == 0);
}

int main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    int rc = SR_ERR_OK;
    const char *mod_name = "ietf-interfaces";
    const char *path = "/ietf-interfaces:interfaces/*";

    std::cout << "Application will provide data " << path << " of " << mod_name << "\n";

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc == SR_ERR_OK) {
        sr_session_ctx_t *session = NULL;
        /* start session */
        rc = sr_session_start(connection, SR_DS_RUNNING, &session);
        if (rc == SR_ERR_OK) {
            sr_subscription_ctx_t *subscription = NULL;            
            sync_sysrepo_to_kernel(session);

            rc = sr_module_change_subscribe(session, mod_name, "/ietf-interfaces:*//.", 
                                            module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subscription);
            if (rc == SR_ERR_OK) {
                /* subscribe for providing the operational data */
                rc = sr_oper_get_items_subscribe(session, mod_name, path, 
                                                dp_get_items_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
                if (rc == SR_ERR_OK) {

                    if (init_state_changes() == 0) {
                        std::thread manager_thread (manager_thread_cb);
                        manager_thread.detach();
                    }

                    std::cout << "Listening for requests\n";

                    /* loop until ctrl-c is pressed / SIGINT is received */
                    signal(SIGINT, sigint_handler);
                    signal(SIGPIPE, SIG_IGN);
                    while (!exit_application) {
                        std::this_thread::sleep_for(1000ms);
                    }

                    std::cout << "Application exit requested, exiting.\n";
                }
            }
        }
    }

    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
