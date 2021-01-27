/****************************************************************************
 *          MAIN_YUNETA_AGENT.C
 *          yuneta_agent main
 *
 *          Copyright (c) 2014,2018 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#include <yuneta_tls.h>
#include <yuneta.h>
#include "c_agent.h"
#include "yuno_yuneta_agent.h"

/***************************************************************************
 *                      Names
 ***************************************************************************/
#define APP_NAME        "yuneta_agent"
#define APP_DOC         \
"Yuneta Realm Agent."\
"Si quieres vivir en mi reino tienes que cumplir unas reglas."\
"De lo contrario, vive como un standalone." \

#define APP_VERSION     "4.7.6"
#define APP_DATETIME    __DATE__ " " __TIME__
#define APP_SUPPORT     "<niyamaka at yuneta.io>"

/***************************************************************************
 *                      Default config
 ***************************************************************************/
PRIVATE char fixed_config[]= "\
{                                                                   \n\
    'environment': {                                                \n\
        'realm_owner': 'agent',                                     \n\
        'work_dir': '/yuneta',                                      \n\
        'domain_dir': 'realms/agent/agent'                          \n\
    },                                                              \n\
    'yuno': {                                                       \n\
        'yuno_role': 'yuneta_agent',                                \n\
        'tags': ['yuneta', 'core']                                  \n\
    }                                                               \n\
}                                                                   \n\
";

PRIVATE char variable_config[]= "\
{                                                                   \n\
    '__json_config_variables__': {                                  \n\
        '__realm_id__': 'agent.yunetacontrol.com',                  \n\
        '__input_url__': 'ws://127.0.0.1:1991',                     \n\
        '__top_url__': 'wss://0.0.0.0:1993'                         \n\
    },                                                              \n\
    'environment': {                                                \n\
        'realm_id': '(^^__realm_id__^^)',                           \n\
        'use_system_memory': true,                                  \n\
        'log_gbmem_info': true,                                     \n\
        'MEM_MIN_BLOCK': 512,                                       \n\
        'MEM_MAX_BLOCK': 209715200,             #^^  200*M          \n\
        'MEM_SUPERBLOCK': 209715200,            #^^  200*M          \n\
        'MEM_MAX_SYSTEM_MEMORY': 2147483648,    #^^ 2*G             \n\
        'console_log_handlers': {                                   \n\
            'to_stdout': {                                          \n\
                'handler_type': 'stdout',                           \n\
                'handler_options': 255                              \n\
            },                                                      \n\
            'to_udp': {                                             \n\
                'handler_type': 'udp',                              \n\
                'url': 'udp://127.0.0.1:1992',                      \n\
                'handler_options': 255                              \n\
            }                                                       \n\
        },                                                          \n\
        'daemon_log_handlers': {                                    \n\
            'to_file': {                                            \n\
                'handler_type': 'file',                             \n\
                'handler_options': 255,                             \n\
                'filename_mask': 'yuneta_agent-MM-DD.log'           \n\
            },                                                      \n\
            'to_udp': {                                             \n\
                'handler_type': 'udp',                              \n\
                'url': 'udp://127.0.0.1:1992',                      \n\
                'handler_options': 255                              \n\
            }                                                       \n\
        }                                                           \n\
    },                                                              \n\
    'yuno': {                                                       \n\
        'yuno_name': '(^^__hostname__^^)',                          \n\
        'trace_levels': {                                           \n\
            'Tcp0': ['connections'],                                \n\
            'TcpS0': ['listen', 'not-accepted', 'accepted'],        \n\
            'Tcp1': ['connections'],                                \n\
            'TcpS1': ['listen', 'not-accepted', 'accepted']         \n\
        }                                                           \n\
    },                                                              \n\
    'global': {                                                     \n\
        'Authz.max_sessions_per_user': 4,                           \n\
        'Authz.initial_load': {                                     \n\
            'roles': [                                              \n\
                {                                                   \n\
                    'id': 'root',                                   \n\
                    'disabled': false,                              \n\
                    'description': 'Super-Owner of system',         \n\
                    'realm_id': '*',                                \n\
                    'service': '*'                                  \n\
                },                                                  \n\
                {                                                   \n\
                    'id': 'owner',                                  \n\
                    'disabled': false,                              \n\
                    'description': 'Owner of system',               \n\
                    'realm_id': '(^^__realm_id__^^)',               \n\
                    'service': '*'                                  \n\
                },                                                  \n\
                {                                                   \n\
                    'id': 'manage-authz',                           \n\
                    'disabled': false,                              \n\
                    'description': 'Management of Authz',           \n\
                    'realm_id': '(^^__realm_id__^^)',               \n\
                    'service': 'treedb_authz'                       \n\
                }                                                   \n\
            ],                                                      \n\
            'users': [                                              \n\
                {                                                   \n\
                    'id': 'yuneta',                                 \n\
                    'roles': [                                      \n\
                        'roles^root^users',                         \n\
                        'roles^owner^users'                         \n\
                    ]                                               \n\
                }                                                   \n\
            ]                                                       \n\
        },                                                          \n\
        'Authz.jwt_public_key': '-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj0ZkOtmWlsDLJiJWXTEJ\\ntyXxlVY7iLseG982eaFgDaAdtE3Z5J+WDvzni7v4MPR55oMyi/oeAvTKIsVOv3aw\\nobRJ/Mr45Qh6I0j4Hn+rFfPW4wbmxRmFeyRrfMzYAZZoibZ3m7EFlj2RINvJFIgE\\npIoTf4UneXmlSDbUU9MTZe1mULfCfEZVa5V9W86BluAAib1mYJU7aJ20KPkbQAvW\\nXqC82AE9ga66HnQ2n56mv1kPyvNGKvvM6vD2IXQeLIYgudYT2KlGKd8isrOEkrno\\nXtPKMSaRhVccO73Wbo7krhjGV5MTpMvvOM+wDprslFkODm0MORsHORVxfcVGWSpU\\ngQIDAQAB\\n-----END PUBLIC KEY-----\\n'  \n\
    },                                                              \n\
    'services': [                                                   \n\
        {                                               \n\
            'name': 'agent',                            \n\
            'gclass': 'Agent',                          \n\
            'default_service': true,                    \n\
            'autostart': true,                          \n\
            'autoplay': false,                          \n\
            'kw': {                                     \n\
            },                                          \n\
            'zchilds': [                                \n\
                {                                               \n\
                    'name': '__input_side__',                   \n\
                    'gclass': 'IOGate',                         \n\
                    'as_service': true,                         \n\
                    'kw': {                                     \n\
                        'persistent_channels': false            \n\
                    },                                          \n\
                    'zchilds': [                                        \n\
                        {                                               \n\
                            'name': 'server_port',                      \n\
                            'gclass': 'TcpS0',                          \n\
                            'as_unique': true,                          \n\
                            'kw': {                                     \n\
                                'url': '(^^__input_url__^^)',           \n\
                                'child_tree_filter': {                  \n\
                                    'op': 'find',                       \n\
                                    'kw': {                                 \n\
                                        '__prefix_gobj_name__': 'wss',      \n\
                                        '__gclass_name__': 'IEvent_srv',    \n\
                                        '__disabled__': false,              \n\
                                        'connected': false                  \n\
                                    }                                       \n\
                                }                                           \n\
                            }                                               \n\
                        },                                                  \n\
                        {                                                   \n\
                            'name': 'secure_port',                          \n\
                            'gclass': 'TcpS1',                              \n\
                            'as_unique': true,                              \n\
                            'kw': {                                         \n\
                                'crypto': {                                 \n\
                                    'library': 'openssl',                   \n\
'ssl_certificate': '/yuneta/store/certs/self-signed/yuneta_agent.crt',      \n\
'ssl_certificate_key': '/yuneta/store/certs/self-signed/yuneta_agent.key',  \n\
                                    'trace': false                          \n\
                                },                                          \n\
                                'url': '(^^__top_url__^^)',                 \n\
                                'child_tree_filter': {                      \n\
                                    'op': 'find',                           \n\
                                    'kw': {                                 \n\
                                        '__prefix_gobj_name__': 'wss',      \n\
                                        '__gclass_name__': 'IEvent_srv',    \n\
                                        '__disabled__': false,              \n\
                                        'connected': false                  \n\
                                    }                                       \n\
                                }                                           \n\
                            }                                               \n\
                        }                                                   \n\
                    ],                                                  \n\
                    '[^^zchilds^^]': {                                  \n\
                        '__range__': [[12000,12099]], #^^ max 100 users \n\
                        '__vars__': {                                   \n\
                        },                                              \n\
                        '__content__': {                                \n\
                            'name': 'wss-(^^__range__^^)',                  \n\
                            'gclass': 'IEvent_srv',                         \n\
                            'kw': {                                         \n\
                            },                                              \n\
                            'zchilds': [                                     \n\
                                {                                               \n\
                                    'name': 'wss-(^^__range__^^)',              \n\
                                    'gclass': 'Channel',                        \n\
                                    'kw': {                                         \n\
                                    },                                              \n\
                                    'zchilds': [                                     \n\
                                        {                                               \n\
                                            'name': 'wss-(^^__range__^^)',              \n\
                                            'gclass': 'GWebSocket',                     \n\
                                            'no_autostart': true,                       \n\
                                            'kw': {                                     \n\
                                                'iamServer': true                       \n\
                                            }                                           \n\
                                        }                                               \n\
                                    ]                                               \n\
                                }                                               \n\
                            ]                                               \n\
                        }                                               \n\
                    }                                                   \n\
                }                                               \n\
            ]                                           \n\
        },                                              \n\
        {                                                           \n\
            'name': 'authz',                                        \n\
            'gclass': 'Authz',                                      \n\
            'default_service': false,                               \n\
            'autostart': true,                                      \n\
            'autoplay': true,                                       \n\
            'kw': {                                                 \n\
            },                                                      \n\
            'zchilds': [                                            \n\
            ]                                                       \n\
        }                                                           \n\
    ]                                                               \n\
}                                                                   \n\
";

/***************************************************************************
 *                      Register
 ***************************************************************************/
static void register_yuno_and_more(void)
{
    /*------------------------*
     *  Register yuneta-tls
     *------------------------*/
    yuneta_register_c_tls();

    /*-------------------*
     *  Register yuno
     *-------------------*/
    register_yuno_yuneta_agent();

    /*--------------------*
     *  Register service
     *--------------------*/
    gobj_register_gclass(GCLASS_AGENT);
}

/***************************************************************************
 *                      Main
 ***************************************************************************/
int main(int argc, char *argv[])
{
    /*------------------------------------------------*
     *  To trace memory
     *------------------------------------------------*/
#ifdef DEBUG
    static uint32_t mem_list[] = {0,0};
    gbmem_trace_alloc_free(1, mem_list);
#endif

    /*
     *  Estas trazas siempre en el agente.
     */
    gobj_set_gclass_trace(GCLASS_IEVENT_SRV, "identity-card", TRUE);
    gobj_set_gclass_trace(GCLASS_IEVENT_CLI, "identity-card", TRUE);

    if(argv[1]) {
        if(strcmp(argv[1], "verbose2")==0) {
            gobj_set_gclass_trace(GCLASS_IEVENT_SRV, "ievents2", TRUE);
            argc = 1;
        } else if(strcmp(argv[1], "verbose3")==0) {
            gobj_set_gclass_trace(GCLASS_IEVENT_SRV, "ievents2", TRUE);
            gobj_set_global_trace("machine", TRUE);
            argc = 1;
        } else if(strcmp(argv[1], "verbose4")==0) {
            gobj_set_gclass_trace(GCLASS_IEVENT_SRV, "ievents2", TRUE);
            gobj_set_global_trace("machine", TRUE);
            gobj_set_global_trace("ev_kw", TRUE);
            argc = 1;
        } else if(strcmp(argv[1], "verbose5")==0) {
            gobj_set_gclass_trace(GCLASS_IEVENT_SRV, "ievents2", TRUE);
            gobj_set_global_trace("", TRUE);
            gobj_set_global_trace("ev_kw", TRUE);
            argc = 1;
        } else if(strcmp(argv[1], "verbose")==0) {
            gobj_set_gclass_trace(GCLASS_IEVENT_SRV, "ievents", TRUE);
            argc = 1;
        }
    }

//     gobj_set_gclass_trace(GCLASS_ROUTER, "machine", TRUE);
//     gobj_set_gclass_trace(GCLASS_ROUTER, "ev_kw", TRUE);
//     gobj_set_gclass_trace(GCLASS_ROUTER, "routing", TRUE);
//     gobj_set_gclass_trace(GCLASS_IOGATE, "machine", TRUE);
//     gobj_set_gclass_trace(GCLASS_IOGATE, "ev_kw", TRUE);
//     gobj_set_gclass_trace(GCLASS_CHANNEL, "machine", TRUE);
//     gobj_set_gclass_trace(GCLASS_CHANNEL, "ev_kw", TRUE);
//     gobj_set_gclass_trace(GCLASS_COUNTER, "debug", TRUE);

//     gobj_set_gclass_trace(GCLASS_AGENT, "machine", TRUE);
//     gobj_set_gclass_trace(GCLASS_AGENT, "ev_kw", TRUE);
//     gobj_set_gclass_trace(GCLASS_COUNTER, "machine", TRUE);
//     gobj_set_gclass_trace(GCLASS_COUNTER, "ev_kw", TRUE);
//     gobj_set_gclass_trace(GCLASS_RESOURCE, "sql", TRUE);

//      gobj_set_gclass_trace(GCLASS_TCP0, "traffic", TRUE);

//     gobj_set_gobj_trace(0, "machine", TRUE, 0);
//     gobj_set_gobj_trace(0, "ev_kw", TRUE, 0);
//     gobj_set_gobj_trace(0, "subscriptions", TRUE, 0);
//     gobj_set_gobj_trace(0, "create_delete", TRUE, 0);
//     gobj_set_gobj_trace(0, "start_stop", TRUE, 0);

    gobj_set_gclass_no_trace(GCLASS_TIMER, "machine", TRUE);

//     set_auto_kill_time(10);

    /*------------------------------------------------*
     *          Start yuneta
     *------------------------------------------------*/
    helper_quote2doublequote(fixed_config);
    helper_quote2doublequote(variable_config);
    yuneta_setup(
        dbattrs_startup,            // dbsimple2
        dbattrs_end,                // dbsimple2
        dbattrs_load_persistent,    // dbsimple2
        dbattrs_save_persistent,    // dbsimple2
        dbattrs_remove_persistent,  // dbsimple2
        dbattrs_list_persistent,    // dbsimple2
        command_parser,
        stats_parser,
        authz_checker,              // Monoclass Authz
        authenticate_parser         // Monoclass Authz
    );
    return yuneta_entry_point(
        argc, argv,
        APP_NAME, APP_VERSION, APP_SUPPORT, APP_DOC, APP_DATETIME,
        fixed_config,
        variable_config,
        register_yuno_and_more
    );
}
