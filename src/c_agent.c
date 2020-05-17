/***********************************************************************
 *          C_AGENT.C
 *          Agent GClass.
 *
 *          Yuneta Agent, the first authority of realms and yunos in a host
 *
 *          Copyright (c) 2016 Niyamaka.
 *          All Rights Reserved.
***********************************************************************/
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <regex.h>
#include <unistd.h>
#include "c_agent.h"
#include "treedb_schema_yuneta_agent.c"

// TODO comando para enviar el json del agente a los nodos
// Y tendrá que rearrancar, no?

// TODO fallo a investigar. Al editar la configuración del emailsender, el servicio ha dejado de funcionar,
// porque no se le pasaban los valores globales __url__, __ip__, __port__
// Reproducción: crea un segundo yuno emailsender con la misma configuración, y luego borralo.
// Deja de funcionar.
/*
{
    "global": {
        "emailsender.__json_config_variables__": {      ESTA PARTE VACIA!!!
            "__yuno_name__": "gpss",
            "__yuno_role__": "emailsender",
            "__yuno_service__": "emailsender",
            "__ip__": "127.0.0.1",
            "__port__": "3100",
            "__url__": "ws://127.0.0.1:3100"
        }
    },
    "environment": {
        "work_dir": "/yuneta",
        "domain_dir": "/realms/sfs/gpss/utils/utils/emailsender^gpss"
    },
    "yuno": {
        "realm_name": "utils",
        "yuno_name": "gpss",
        "yuno_release": "2.4.0-1",
        "realm_id": 1,
        "bind_ip": "0.0.0.0",
        "multiple": false,
        "launch_id": 97770288644108
    }
}
*/
/***************************************************************************
 *              Constants
 ***************************************************************************/
#define NEXT_ERROR 210

// HACK this resource only works with primary key being integer type!
#define SDATA_GET_ID(hs)  sdata_read_uint64((hs), "id")

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE char * build_yuno_private_domain(hgobj gobj, hsdata hs_yuno, char *bf, int bfsize, BOOL create_dir);
PRIVATE char * build_yuno_public_domain(hgobj gobj, hsdata hs_yuno, char *subdomain, char *bf, int bfsize, BOOL create_dir);
PRIVATE int build_role_plus_name(char *bf, int bf_len, hsdata hs_yuno);
PRIVATE char * build_yuno_bin_path(hgobj gobj, hsdata hs_yuno, char *bf, int bfsize, BOOL create_dir);
PRIVATE char * build_yuno_log_path(hgobj gobj, hsdata hs_yuno, char *bf, int bfsize, BOOL create_dir);
PRIVATE GBUFFER* build_yuno_running_script(
    hgobj gobj,
    GBUFFER* gbuf_script,
    hsdata hs_yuno,
    char *bfbinary,
    int bfbinary_size
);
PRIVATE int enable_yuno(hgobj gobj, hsdata hs_yuno);
PRIVATE int disable_yuno(hgobj gobj, hsdata hs_yuno);
PRIVATE int run_yuno(hgobj gobj, hsdata hs_yuno, hgobj src);
PRIVATE int kill_yuno(hgobj gobj, hsdata hs_yuno);
PRIVATE int play_yuno(hgobj gobj, hsdata hs_yuno, json_t *kw, hgobj src);
PRIVATE int pause_yuno(hgobj gobj, hsdata hs_yuno, json_t *kw, hgobj src);
PRIVATE int trace_on_yuno(hgobj gobj, hsdata hs_yuno, json_t *kw, hgobj src);
PRIVATE int trace_off_yuno(hgobj gobj, hsdata hs_yuno, json_t *kw, hgobj src);
PRIVATE int command_to_yuno(
    hgobj gobj, hsdata hs_yuno, const char* command, json_t* kw, hgobj src
);
PRIVATE int stats_to_yuno(
    hgobj gobj, hsdata hs_yuno, const char* stats, json_t* kw, hgobj src
);
PRIVATE int total_yunos_in_realm(hgobj gobj, json_int_t realm_id);
PRIVATE int total_binary_in_yunos(hgobj gobj, json_int_t binary_id);
PRIVATE int total_config_in_yunos(hgobj gobj, json_int_t config_id);
PRIVATE int audit_command_cb(const char *command, json_t *kw, void *user_data);

PRIVATE hsdata get_hs_by_id(hgobj gobj, const char *resource, json_int_t parent_id, json_int_t id);
PRIVATE json_int_t find_last_id_by_name(hgobj gobj, const char *resource, const char *key, const char *value);
PRIVATE hsdata find_binary_version(hgobj gobj, const char *role, const char *version);
PRIVATE hsdata find_configuration_version(hgobj gobj, const char *role, const char *name, const char *version);
PRIVATE int build_release_name(char *bf, int bfsize, hsdata hs_binary, dl_list_t *iter_configs);

PRIVATE int register_public_services(hgobj gobj, hsdata hs_yuno);

/***************************************************************************
 *              Resources
 ***************************************************************************/
/*

                        Agent resource schema
                        =====================


                        ┌───────────────┐
                        │     realms    │
                        └───────────────┘
                                ▲ n (dl 'yunos')
                                ┃
                                ┃
                                ▼ 1 ('realm_id')
                ┌───────────────────────────────────────┐
                │               yunos                   │
                └───────────────────────────────────────┘
                        ▲ 1 ('binary_id')       ▲ n (dl 'configurations')
                        ┃                       ┃
                        ┃                       ┃
                        ▼ n (dl 'yunos')        ▼ n (dl 'yunos')
                ┌────────────────┐      ┌────────────────┐
                │   binaries     │      │ configurations │
                └────────────────┘      └────────────────┘

*/


PRIVATE sdata_desc_t tb_binaries[] = {
/*-FIELD-type-----------name----------------flag------------------------resource--------header----------fillsp--description---------*/
SDATADF (ASN_JSON,      "ids",              SDF_NOTACCESS,              0,              0,              0,      "List of id's to match."),
SDATADF (ASN_COUNTER64, "id",               SDF_PERSIST|SDF_PKEY,       0,              "Id",           8,      "Id."),
SDATADF (ASN_OCTET_STR, "role",             SDF_PERSIST|SDF_REQUIRED,   0,              "Binary Role",  18,     "Role extracted from binary."),
SDATADF (ASN_OCTET_STR, "version",          SDF_PERSIST|SDF_REQUIRED,   0,              "Binary Version",14,    "Version extracted from binary."),
SDATADF (ASN_UNSIGNED,  "size",             SDF_PERSIST,                0,              "Size",         10,     "Size of binary file."),
SDATADF (ASN_OCTET_STR, "date",             SDF_PERSIST,                0,              "Date",         22,     "Compilation date extracted from binary."),
SDATADF (ASN_OCTET_STR, "description",      SDF_PERSIST,                0,              "Description",  22,     "Description extracted from binary."),
SDATADF (ASN_JSON,      "classifiers",      SDF_PERSIST,                0,              "Classifiers",  22,     "Domain of the binary."),
SDATADF (ASN_JSON,      "required_services",SDF_PERSIST,                0,              "Required Services",22, "Services required."),
SDATADF (ASN_JSON,      "public_services",  SDF_PERSIST,                0,              "Public Services",22,   "Public services offered."),
SDATADF (ASN_JSON,      "service_descriptor",SDF_PERSIST,               0,              "Service Descriptor",22,"Public service descriptor."),
SDATADF (ASN_OCTET_STR, "binary",           SDF_PERSIST|SDF_REQUIRED,   0,              "Binary",       22,     "Path to the binary in the file system."),
SDATADF (ASN_JSON,      "source",           SDF_PERSIST|SDF_WR,         0,              "Source",       0,      "Optional auto-update from external source. FUTURE"),
SDATA_END()
};

PRIVATE sdata_desc_t tb_configs[] = {
/*-FIELD-type-----------name----------------flag------------------------resource--------header----------fillsp--description---------*/
SDATADF (ASN_JSON,      "ids",              SDF_NOTACCESS,              0,              0,              0,      "List of id's to match."),
SDATADF (ASN_COUNTER64, "id",               SDF_PERSIST|SDF_PKEY,       0,              "Id",           8,      "Id."),
SDATADF (ASN_OCTET_STR, "name",             SDF_PERSIST|SDF_REQUIRED,   0,              "Configuration Name", 30, "Configuration name."),
SDATADF (ASN_OCTET_STR, "version",          SDF_PERSIST|SDF_WR,         0,              "Configuration Version",22, "Configuration version."),
SDATADF (ASN_OCTET_STR, "description",      SDF_PERSIST|SDF_WR,         0,              "Description",  30,     "Description."),
SDATADF (ASN_OCTET_STR, "type",             SDF_PERSIST|SDF_WR,         0,              "Type",         20,     "Type of file: .json, .tar.gz, etc. Default or empty: json"),
SDATADF (ASN_OCTET_STR, "destination",      SDF_PERSIST|SDF_WR,         0,              "Destination",  30,     "Directory to install. Default or empty: json in running dir."),
SDATADF (ASN_OCTET_STR, "date",             SDF_PERSIST,                0,              "Date",         21,     "Date last modification."),
SDATADF (ASN_JSON,      "zcontent",         SDF_PERSIST|SDF_WR,         0,              "Content",      35,     "Content configuration."),
SDATADF (ASN_JSON,      "source",           SDF_PERSIST|SDF_WR,         0,              "Source",       0,      "Optional auto-update from external source. FUTURE"),
SDATA_END()
};

PRIVATE sdata_desc_t tb_yunos[] = {
/*-FIELD-type-----------name----------------flag------------------------resource--------header----------fillsp--description---------*/
SDATADF (ASN_JSON,      "ids",              SDF_NOTACCESS,              0,              0,              0,      "List of id's to match."),

SDATADF (ASN_COUNTER64, "id",               SDF_PERSIST|SDF_PKEY,       0,              "Id",           8,      "Id."),

SDATADF (ASN_OCTET_STR, "realm_name",       SDF_PERSIST,                0,              "Realm Name",   16,     "Realm of yuno"),
SDATADF (ASN_OCTET_STR, "yuno_role",        SDF_PERSIST,                0,              "Yuno Role",    16,     "Yuno *role*"),
SDATADF (ASN_OCTET_STR, "yuno_name",        SDF_PERSIST,                0,              "Yuno Name",    16,     "Yuno *name*"),
SDATADF (ASN_OCTET_STR, "yuno_release",     SDF_PERSIST,                0,              "Yuno Release", 16,     "Yuno *release*"),
SDATADF (ASN_OCTET_STR, "yuno_alias",       SDF_PERSIST,                0,              "Yuno Alias",   16,     "Yuno *alias*"),

SDATADF (ASN_BOOLEAN,   "yuno_running",     SDF_VOLATIL,                0,              "Running",      7,      "True if the yuno is running."),
SDATADF (ASN_BOOLEAN,   "yuno_playing",     SDF_VOLATIL,                0,              "Playing",      7,      "True if the yuno is playing."),
SDATADF (ASN_UNSIGNED,  "yuno_pid",         SDF_VOLATIL,                0,              "Pid",          7,      "Linux Process ID of the running yuno."),

SDATADF (ASN_BOOLEAN,   "disabled",         SDF_PERSIST|SDF_WR,         0,              "Disabled",     8,      "True if the yuno is disabled and therefore cannot be running."),
SDATADF (ASN_BOOLEAN,   "must_play",        SDF_PERSIST|SDF_WR,         0,              "MustPlay",     8,      "If true the agent will play the yuno automatically after be set running."),
SDATADF (ASN_BOOLEAN,   "traced",           SDF_PERSIST|SDF_WR,         0,              "Traced",       6,      "True if the yuno is tracing."),
SDATADF (ASN_BOOLEAN,   "multiple",         SDF_PERSIST,                0,              "Multiple",     6,      "True if yuno can have multiple instances with same name."),
SDATADF (ASN_BOOLEAN,   "global",           SDF_PERSIST,                0,              "Global",       6,      "Yuno with global service (False: bind to 127.0.0.1, True: bind to realm ip)."),

// Importante marcar el campo con SDF_PARENTID, para que el sistema conozca al grand_parent or parent.
SDATADF (ASN_COUNTER64, "realm_id",         SDF_PERSIST|SDF_PARENTID,   "realms", "Realm Id",     8,      "The Realm (parent) of the yuno. Cannot be changed once created."),
SDATADF (ASN_COUNTER64, "binary_id",        SDF_PERSIST|SDF_FKEY,       "binaries",     "Binary Id",    8,      "Binary (child) of the yuno."),

/*-CHILD-type-----------name----------------flag------------------------resource------------free_fn---------header----------fillsp---description--*/
SDATADC (ASN_ITER,      "config_ids",       SDF_RESOURCE,               "configurations",   sdata_destroy,  "Config. Ids",  15,     "Configurations associated to the yuno. Order is important! The last has prevalence over the previous."),

/*-FIELD-type-----------name----------------flag------------------------resource--------header----------fillsp--description---------*/
SDATADF (ASN_OCTET_STR, "yuno_startdate",   SDF_PERSIST,                0,              "Start Date",   10,     "Last start date of the yuno."),
SDATADF (ASN_POINTER,   "channel_gobj",     SDF_NOTACCESS,              0,              "Channel gobj", 0,      "Channel gobj"),
SDATADF (ASN_OCTET_STR, "solicitante",      SDF_NOTACCESS,              0,              "Solicitante",  0,      "Solicitante."),
SDATADF (ASN_COUNTER64, "launch_id",        SDF_NOTACCESS,              0,              "Launch Id",    0,      "time_t + counter."),

SDATA_END()
};


PRIVATE sdata_desc_t tb_realms[] = {
/*-FIELD-type-----------name----------------flag------------------------resource--------header----------fillsp--description---------*/
SDATADF (ASN_JSON,      "ids",              SDF_NOTACCESS,              0,              0,              0,      "List of id's to match."),
SDATADF (ASN_COUNTER64, "id",               SDF_PERSIST|SDF_PKEY,       0,              "Id",           8,      "Id."),
SDATADF (ASN_OCTET_STR, "domain",           SDF_PERSIST|SDF_REQUIRED,   0,              "Realm Domain", 22,     "Realm *domain*. It's up to you."),
SDATADF (ASN_JSON,      "range_ports",      SDF_PERSIST|SDF_REQUIRED,   0,              "Range Ports",  22,     "Range of ports (my rule: 9000 dev, 8000 prepro, 2000 prod)."),
SDATADF (ASN_OCTET_STR, "role",             SDF_PERSIST|SDF_REQUIRED,   0,              "Realm Role",   22,     "Realm *role*. It's up to you."),
SDATADF (ASN_OCTET_STR, "name",             SDF_PERSIST,                0,              "Realm Name",   22,     "Realm *name*. It's up to you."),
SDATADF (ASN_OCTET_STR, "bind_ip",          SDF_PERSIST,                0,              "Bind IP",      22,     "Ip to be bind by the Realm."),
SDATADF (ASN_UNSIGNED,  "last_port",        SDF_PERSIST,                0,              "Last Port",    10,     "Last port assigned."),

/*-CHILD-type-----------name----------------flag------------------------resource------------free_fn---------header--------------fillsp---description--*/
// Marca "yunos" con SDF_PURECHILD, es el iter de los child yunos.
// HACK Obligado que el nombre el field sea el del recurso hijo.
SDATADC (ASN_ITER,      "yunos",            SDF_RESOURCE|SDF_PURECHILD, "yunos",            sdata_destroy,  "Yunos",            22,     "Yunos living in the realm."),
SDATA_END()
};

PRIVATE sdata_desc_t tb_public_services[] = {
/*-FIELD-type-----------name----------------flag------------------------resource--------header----------fillsp--description---------*/
SDATADF (ASN_JSON,      "ids",              SDF_NOTACCESS,              0,              0,              0,      "List of id's to match."),
SDATADF (ASN_COUNTER64, "id",               SDF_PERSIST|SDF_PKEY,       0,              "Id",           8,      "Id."),
SDATADF (ASN_OCTET_STR, "service",          SDF_PERSIST|SDF_REQUIRED,   0,              "Service",      18,     "Service name."),
SDATADF (ASN_OCTET_STR, "description",      SDF_PERSIST,                0,              "Description",  18,     "Service description."),
SDATADF (ASN_OCTET_STR, "yuno_role",        SDF_PERSIST|SDF_REQUIRED,   0,              "Yuno Role",    18,     "Yuno Role of service."),
SDATADF (ASN_OCTET_STR, "yuno_name",        SDF_PERSIST,                0,              "Yuno Name",    18,     "Yuno Name of service."),
SDATADF (ASN_COUNTER64, "realm_id",         SDF_PERSIST,                0,              "Realm Id",     8,      "The Realm of the service's yuno."),
SDATADF (ASN_COUNTER64, "yuno_id",          SDF_PERSIST,                0,              "Yuno Id",      8,      "Yuno id."),
SDATADF (ASN_OCTET_STR, "ip",               SDF_PERSIST|SDF_WR,         0,              "Ip",           16,     "Service Ip assigned."),
SDATADF (ASN_UNSIGNED,  "port",             SDF_PERSIST|SDF_WR,         0,              "Port",         5,      "Service Port assigned."),
SDATADF (ASN_OCTET_STR, "schema",           SDF_PERSIST,                0,              "Schema",       6,      "schema for service url."),
SDATADF (ASN_OCTET_STR, "url",              SDF_PERSIST|SDF_WR,         0,              "Url",          22,      "Service Url assigned."),
SDATADF (ASN_JSON,      "connector",        SDF_PERSIST,                0,              "Connector",    12,     "The client configuration to connect the service."),
SDATA_END()
};

/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/
PRIVATE char agent_filter_chain_config[]= "\
{                                                                   \n\
    'services': [                                                   \n\
        {                                   \n\
            'name': 'agent_client',         \n\
            'gclass': 'IEvent_cli',         \n\
            'autostart': true,              \n\
            'kw': {                         \n\
                'remote_yuno_name': '',                 \n\
                'remote_yuno_role': 'yuneta_agent',     \n\
                'remote_yuno_service': 'agent',         \n\
                'extra_info': {                             \n\
                    'realm_name': '%s',                     \n\
                    'realm_id': %d,                         \n\
                    'yuno_id': %d                           \n\
                }                                           \n\
            },                                          \n\
            'zchilds': [                                 \n\
                {                                       \n\
                    'name': 'agent_client',             \n\
                    'gclass': 'IOGate',                 \n\
                    'kw': {                             \n\
                    },                                  \n\
                    'zchilds': [                         \n\
                        {                                   \n\
                            'name': 'agent_client',         \n\
                            'gclass': 'Channel',            \n\
                            'kw': {                         \n\
                            },                              \n\
                            'zchilds': [                         \n\
                                {                               \n\
                                    'name': 'agent_client',         \n\
                                    'gclass': 'GWebSocket',         \n\
                                    'kw': {                         \n\
                                        'resource': '/',            \n\
                                        'iamServer': 0,             \n\
                                        'kw_connex': {              \n\
                                            'timeout_inactivity': -1,               \n\
                                            'timeout_between_connections': 2000,    \n\
                                            'urls':[                                \n\
                                                'ws://127.0.0.1:1991'               \n\
                                            ]                                       \n\
                                        }    \n\
                                    }    \n\
                                }    \n\
                            ]    \n\
                        }    \n\
                    ]    \n\
                }    \n\
            ]    \n\
        }    \n\
    ]    \n\
}    \n\
";

PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE json_t *cmd_run_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_kill_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_play_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_pause_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_enable_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_disable_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_trace_on_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_trace_off_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE json_t *cmd_dir_public(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_dir_realms(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_dir_logs(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_dir_repos(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_dir_store(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_sumdir(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_list_persistent_attrs(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_launch_scripts(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_replicate_node(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_replicate_binaries(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE json_t *cmd_list_public_services(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_update_public_service(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_delete_public_service(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE json_t *cmd_list_realms(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_create_realm(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_update_realm(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_delete_realm(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE json_t *cmd_list_binaries(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_install_binary(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_update_binary(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_delete_binary(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE json_t *cmd_list_configs(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_create_config(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_update_config(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_upgrade_config(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_delete_config(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE json_t *cmd_top_yunos(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_list_yunos(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_create_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_delete_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_set_alias(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_top_last_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE json_t *cmd_command_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_stats_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_command_agent(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_stats_agent(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_set_okill(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_set_qkill(hgobj gobj, const char *cmd, json_t *kw, hgobj src);



PRIVATE sdata_desc_t pm_help[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "cmd",          0,              0,          "command about you want help."),
SDATAPM (ASN_UNSIGNED,  "level",        0,              0,          "command search level in childs"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_command_agent[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "command",      0,              0,          "Command to be executed in agent."),
SDATAPM (ASN_OCTET_STR, "service",      0,              0,          "Service of agent where execute the command."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_stats_agent[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "stats",        0,              0,          "Statistic to be executed in agent."),
SDATAPM (ASN_OCTET_STR, "service",      0,              0,          "Service of agent where execute the statistic."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_running_keys[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_run_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_kill_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATAPM (ASN_BOOLEAN,   "app",          0,              0,          "Kill app yunos (id>=1000)"),
SDATAPM (ASN_BOOLEAN,   "force",        0,              0,          "kill with SIGKILL instead of SIGQUIT"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_play_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_pause_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_enable_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_disable_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_trace_on_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_trace_off_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_command_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATAPM (ASN_OCTET_STR, "command",      0,              0,          "Command to be executed in matched yunos."),
SDATAPM (ASN_OCTET_STR, "service",      0,              0,          "Service of yuno where execute the command."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_stats_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id of yuno."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATAPM (ASN_OCTET_STR, "stats",        0,              0,          "Statistic to be executed in matched yunos."),
SDATAPM (ASN_OCTET_STR, "service",      0,              0,          "Service of yuno where execute the statistic."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_set_alias[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of yuno's id to match."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATAPM (ASN_OCTET_STR, "alias",        0,              0,          "New Yuno alias."),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno Alias."),
SDATAPM (ASN_BOOLEAN,   "yuno_running", 0,              0,          "Yuno running."),
SDATAPM (ASN_BOOLEAN,   "disabled",     0,              0,          "Yuno disabled"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_top_last_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm Id."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm Name."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno Role."),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno Name."),
SDATAPM (ASN_OCTET_STR, "yuno_release", 0,              0,          "Yuno Release."),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno alias."),
SDATA_END()
};



PRIVATE sdata_desc_t pm_read_json[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "filename",      0,              0,         "Filename to read"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_read_file[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "filename",      0,              0,         "Filename to read"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_read_binary_file[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "filename",      0,              0,         "Filename to read"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_dir[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "subdirectory", 0,              0,          "Subdirectory wanted."),
SDATAPM (ASN_OCTET_STR, "match",        0,              0,          "Pattern to match"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_logs[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Yuno Id to get logs."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_sumdir[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "directory",    0,              0,          "Display files with sizes of 'directory'."),
SDATAPM (ASN_OCTET_STR, "match",        0,              0,          "Filter files by match"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_launch_scripts[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "directory",    0,              0,          "Directory with the scripts."),
SDATAPM (ASN_OCTET_STR, "filter",       0,              0,          "Fiter the scripts by RE filename."),
SDATAPM (ASN_OCTET_STR, "arg1",         0,              0,          "Argument 1 for scripts"),
SDATAPM (ASN_OCTET_STR, "arg2",         0,              0,          "Argument 2 for scripts"),
SDATAPM (ASN_OCTET_STR, "arg3",         0,              0,          "Argument 3 for scripts"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_replicate_node[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of realms' id to replicate/upgrade."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Realm Id you want replicate/upgrade."),
SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Realm name you want replicate/upgrade."),
SDATAPM (ASN_OCTET_STR, "url",          0,              0,          "Url of node where replicate/upgrade."),
SDATAPM (ASN_OCTET_STR, "filename",     0,              0,          "Filename where save replicate/upgrade."),
SDATA_END()
};

PRIVATE sdata_desc_t pm_replicate_binaries[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "ids",          0,              0,          "List of binaries' id to replicate."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Binary Id to replicate."),
SDATAPM (ASN_OCTET_STR, "role",         0,              0,          "Binary role you want replicate."),
SDATAPM (ASN_OCTET_STR, "url",          0,              0,          "Url of node where replicate binaries."),
SDATAPM (ASN_OCTET_STR, "filename",     0,              0,          "Filename where save the replicate."),
SDATA_END()
};

PRIVATE sdata_desc_t pm_update_realm[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATAPM (ASN_OCTET_STR, "bind_ip",      0,              0,          "Ip to be bind by the Realm."),
SDATAPM (ASN_UNSIGNED,  "last_port",    0,              0,          "Last port assigned."),

SDATA_END()
};
PRIVATE sdata_desc_t pm_del_realm[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_update_service[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATAPM (ASN_OCTET_STR, "ip",           0,              0,          "Ip assigned."),
SDATAPM (ASN_UNSIGNED,  "port",         0,              0,          "Port assigned."),
SDATAPM (ASN_OCTET_STR, "url",          0,              0,          "Url assigned."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_del_service[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_install_binary[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "role",         SDF_REQUIRED,   0,          "role to install."),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATAPM (ASN_OCTET_STR, "content64",    0,              0,          "yuno binary content in base64. Use content64=$$(role) or content64=full-path."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_update_binary[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATAPM (ASN_OCTET_STR, "content64",    0,              0,          "yuno binary content in base64. Use content64=$$(role) or content64=full-path."),
SDATA_END()
};
PRIVATE sdata_desc_t pm_delete_binary[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATA_END()
};


PRIVATE sdata_desc_t pm_create_config[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "name",         SDF_REQUIRED,   0,          "Configuration name"),
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATAPM (ASN_OCTET_STR, "version",      0,              0,          "Configuration version"),
SDATAPM (ASN_OCTET_STR, "description",  0,              0,          "Description"),
SDATAPM (ASN_OCTET_STR, "content64",    0,              0,          "Content in base64"),
SDATAPM (ASN_OCTET_STR, "type",         0,              0,          "Type of file: .json, .tar.gz, etc. Default or empty: json"),
SDATAPM (ASN_OCTET_STR, "destination",  0,              0,          "Directory to install. Default or empty: json in running dir"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_edit_config[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "id",           0,              0,          "Id"),
SDATAPM (ASN_OCTET_STR, "name",         0,              0,          "configuration name"),
SDATAPM (ASN_OCTET_STR, "version",      0,              0,          "configuration version"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_view_config[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "id",           0,              0,          "Id"),
SDATAPM (ASN_OCTET_STR, "name",         0,              0,          "configuration name"),
SDATAPM (ASN_OCTET_STR, "version",      0,              0,          "configuration version"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_update_config[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "id",           0,              0,          "id"),
SDATAPM (ASN_OCTET_STR, "version",      0,              0,          "configuration version"),
SDATAPM (ASN_OCTET_STR, "description",  0,              0,          "description"),
SDATAPM (ASN_OCTET_STR, "content64",    0,              0,          "content in base64"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_upgrade_config[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_JSON,      "id",           0,              0,          "id"),
SDATAPM (ASN_OCTET_STR, "name",         0,              0,          "configuration name"),
SDATAPM (ASN_OCTET_STR, "version",      0,              0,          "configuration version"),
SDATAPM (ASN_OCTET_STR, "description",  0,              0,          "description"),
SDATAPM (ASN_OCTET_STR, "content64",    0,              0,          "content in base64"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_delete_config[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_create_yuno[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_COUNTER64, "id",           0,              0,          "Id"),

SDATAPM (ASN_OCTET_STR, "realm_name",   0,              0,          "Yuno realm."),
SDATAPM (ASN_OCTET_STR, "yuno_role",    0,              0,          "Yuno role"),
SDATAPM (ASN_OCTET_STR, "role_version", 0,              0,          "Role version"),
SDATAPM (ASN_OCTET_STR, "yuno_name",    0,              0,          "Yuno name"),
SDATAPM (ASN_OCTET_STR, "name_version", 0,              0,          "Name version"),
SDATAPM (ASN_OCTET_STR, "yuno_alias",   0,              0,          "Yuno alias"),

SDATAPM (ASN_COUNTER64, "realm_id",     0,              0,          "Realm"),
SDATAPM (ASN_COUNTER64, "binary_id",    0,              0,          "Binary"),
SDATAPM (ASN_BOOLEAN,   "create-config",0,              0,          "Create configuration if not exist."),
SDATAPM (ASN_JSON,      "config_ids",   0,              0,          "Configurations"),

SDATAPM (ASN_BOOLEAN,   "disabled",     0,              0,          "True if yuno is disabled."),
SDATAPM (ASN_BOOLEAN,   "must_play",    0,              0,          "True if yuno must play."),
SDATAPM (ASN_BOOLEAN,   "multiple",     0,              0,          "True if yuno can have multiple instances with same name."),
SDATAPM (ASN_BOOLEAN,   "global",       0,              0,          "Yuno with public service (False: bind to 127.0.0.1, True: bind to realm ip)"),
SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};
PRIVATE const char *a_edit_config[] = {"EV_EDIT_CONFIG", 0};
PRIVATE const char *a_view_config[] = {"EV_VIEW_CONFIG", 0};
PRIVATE const char *a_edit_yuno_config[] = {"EV_EDIT_YUNO_CONFIG", 0};
PRIVATE const char *a_view_yuno_config[] = {"EV_VIEW_YUNO_CONFIG", 0};
PRIVATE const char *a_read_json[] = {"EV_READ_JSON", 0};
PRIVATE const char *a_read_file[] = {"EV_READ_FILE", 0};
PRIVATE const char *a_read_binary_file[] = {"EV_READ_BINARY_FILE", 0};
PRIVATE const char *a_read_running_keys[] = {"EV_READ_RUNNING_KEYS", 0};
PRIVATE const char *a_read_running_bin[] = {"EV_READ_RUNNING_BIN", 0};

PRIVATE const char *a_top_yunos[] = {"t", 0};
PRIVATE const char *a_list_yunos[] = {"1", 0};
PRIVATE const char *a_list_binaries[] = {"2", 0};
PRIVATE const char *a_list_configs[] = {"3", 0};
PRIVATE const char *a_list_realms[] = {"4", 0};
PRIVATE const char *a_list_public_services[] = {"5", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD2--type-----------name----------------flag----------------alias---------------items-----------json_fn---------description---------- */
SDATACM2 (ASN_SCHEMA,   "help",             0,                  a_help,             pm_help,        cmd_help,       "Command's help"),
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              "\nAgent\n-----------"),
SDATACM2 (ASN_SCHEMA,   "command-agent",    SDF_WILD_CMD,       0,                  pm_command_agent,cmd_command_agent,"Command to agent. WARNING: parameter's keys are not checked."),
SDATACM2 (ASN_SCHEMA,   "stats-agent",      SDF_WILD_CMD,       0,                  pm_stats_agent, cmd_stats_agent, "Get statistics of agent."),
SDATACM2 (ASN_SCHEMA,   "set-ordered-kill", 0,                  0,                  0,              cmd_set_okill,  "Kill yunos with SIGQUIT, ordered kill."),
SDATACM2 (ASN_SCHEMA,   "set-quick-kill",   0,                  0,                  0,              cmd_set_qkill,  "Kill yunos with SIGKILL, quick kill."),
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              "\nYuneta tree\n-----------"),
SDATACM2 (ASN_SCHEMA,   "dir-logs",         0,                  0,                  pm_logs,        cmd_dir_logs,   "List log filenames of yuno."),
SDATACM2 (ASN_SCHEMA,   "dir-public",       0,                  0,                  pm_dir,         cmd_dir_public, "List /yuneta/public directory."),
SDATACM2 (ASN_SCHEMA,   "dir-realms",       0,                  0,                  pm_dir,         cmd_dir_realms, "List /yuneta/realms directory."),
SDATACM2 (ASN_SCHEMA,   "dir-repos",        0,                  0,                  pm_dir,         cmd_dir_repos,  "List /yuneta/repos directory."),
SDATACM2 (ASN_SCHEMA,   "dir-store",        0,                  0,                  pm_dir,         cmd_dir_store,  "List /yuenta/store directory."),
SDATACM2 (ASN_SCHEMA,   "sumdir",           0,                  0,                  pm_sumdir,      cmd_sumdir,     "List /yuneta directory with file sizes."),
SDATACM2 (ASN_SCHEMA,   "list-persistent-attrs", 0,             0,                  0,              cmd_list_persistent_attrs, "List persistent attributes in /yuneta/realm directory."),
SDATACM2 (ASN_SCHEMA,   "launch-scripts",   0,                  0,                  pm_launch_scripts, cmd_launch_scripts, "Launch scripts found in specified path."),
SDATACM2 (ASN_SCHEMA,   "read-json",        0,                  a_read_json,        pm_read_json,   0,              "Read json file."),
SDATACM2 (ASN_SCHEMA,   "read-file",        0,                  a_read_file,        pm_read_file,   0,              "Read a text file."),
SDATACM2 (ASN_SCHEMA,   "read-binary-file", 0,                  a_read_binary_file, pm_read_binary_file, 0,         "Read a binary file (encoded in base64)."),
SDATACM2 (ASN_SCHEMA,   "running-keys",     0,                  a_read_running_keys,pm_running_keys,0,              "Read yuno running parameters."),
SDATACM2 (ASN_SCHEMA,   "running-bin",      0,                  a_read_running_bin, pm_running_keys,0,              "Read yuno running bin path."),
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              "\nDeploy\n------"),
SDATACM2 (ASN_SCHEMA,   "replicate-node",   0,                  0,                  pm_replicate_node, cmd_replicate_node, "Replicate realms' yunos in other node or in file."),
SDATACM2 (ASN_SCHEMA,   "upgrade-node",     0,                  0,                  pm_replicate_node, cmd_replicate_node, "Upgrade realms' yunos in other node or in file."),
SDATACM2 (ASN_SCHEMA,   "replicate-binaries", 0,                0,                  pm_replicate_binaries, cmd_replicate_binaries, "Replicate binaries in other node or in file."),
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              ""),
SDATACM2 (ASN_SCHEMA,   "list-public-services", 0,              a_list_public_services,tb_public_services, cmd_list_public_services,"List public services."),
SDATACM2 (ASN_SCHEMA,   "update-public-service", 0,             0,                  pm_update_service, cmd_update_public_service,"Update a public service."),
SDATACM2 (ASN_SCHEMA,   "delete-public-service", 0,             0,                  pm_del_service, cmd_delete_public_service,"Remove a public service."),
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              ""),
SDATACM2 (ASN_SCHEMA,   "create-realm",     0,                  0,                  tb_realms,      cmd_create_realm,"Create a new realm."),
SDATACM2 (ASN_SCHEMA,   "update-realm",     0,                  0,                  pm_update_realm,cmd_update_realm,"Update a realm."),
SDATACM2 (ASN_SCHEMA,   "delete-realm",     0,                  0,                  pm_del_realm,   cmd_delete_realm,"Remove a realm."),
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              ""),
SDATACM2 (ASN_SCHEMA,   "install-binary",   0,                  0,                  pm_install_binary,cmd_install_binary, "Install yuno binary. Use 'role content64=$$(role)'."),
SDATACM2 (ASN_SCHEMA,   "update-binary",    0,                  0,                  pm_update_binary,cmd_update_binary, "Update yuno binary. WARNING: Don't use in production!"),
SDATACM2 (ASN_SCHEMA,   "delete-binary",    0,                  0,                  pm_delete_binary,cmd_delete_binary, "Delete binary."),
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              ""),
SDATACM2 (ASN_SCHEMA,   "create-config",    0,                  0,                  pm_create_config,cmd_create_config, "Create configuration."),
SDATACM2 (ASN_SCHEMA,   "edit-config",      0,                  a_edit_config,      pm_edit_config, 0,              "Edit configuration."),
SDATACM2 (ASN_SCHEMA,   "view-config",      0,                  a_view_config,      pm_view_config, 0,              "View configuration."),
SDATACM2 (ASN_SCHEMA,   "update-config",    0,                  0,                  pm_update_config,cmd_update_config, "Update configuration."),
SDATACM2 (ASN_SCHEMA,   "upgrade-config",   0,                  0,                  pm_upgrade_config,cmd_upgrade_config, "Upgrade configuration (create a new id)."),
SDATACM2 (ASN_SCHEMA,   "delete-config",    0,                  0,                  pm_delete_config,cmd_delete_config, "Delete configuration."),
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              ""),
SDATACM2 (ASN_SCHEMA,   "create-yuno",      0,                  0,                  pm_create_yuno, cmd_create_yuno, "Create yuno."),
SDATACM2 (ASN_SCHEMA,   "delete-yuno",      0,                  0,                  tb_yunos,       cmd_delete_yuno, "Delete yuno."),
SDATACM2 (ASN_SCHEMA,   "set-alias",        0,                  0,                  pm_set_alias,   cmd_set_alias,  "Set yuno alias."),
SDATACM2 (ASN_SCHEMA,   "edit-yuno-config", 0,                  a_edit_yuno_config, tb_yunos,       0,              "Edit yuno configuration."),
SDATACM2 (ASN_SCHEMA,   "view-yuno-config", 0,                  a_view_yuno_config, tb_yunos,       0,              "View yuno configuration."),
SDATACM2 (ASN_SCHEMA,   "top-last-yuno",    0,                  0,                  pm_top_last_yuno,cmd_top_last_yuno,"Enable the last yuno's release, disable the others found."),

/*-CMD2--type-----------name----------------flag----------------alias---------------items-----------json_fn---------description---------- */
SDATACM2 (ASN_SCHEMA,   "",                 0,                  0,                  0,              0,              "\nOperation\n---------"),
SDATACM2 (ASN_SCHEMA,   "top",              0,                  a_top_yunos,        tb_yunos,       cmd_top_yunos,  "List only enabled yunos."),
SDATACM2 (ASN_SCHEMA,   "list-yunos",       0,                  a_list_yunos,       tb_yunos,       cmd_list_yunos, "List all yunos."),
SDATACM2 (ASN_SCHEMA,   "list-binaries",    0,                  a_list_binaries,    tb_binaries,    cmd_list_binaries,"List binaries."),
SDATACM2 (ASN_SCHEMA,   "list-configs",     0,                  a_list_configs,     tb_configs,     cmd_list_configs,"List configurations."),
SDATACM2 (ASN_SCHEMA,   "list-realms",      0,                  a_list_realms,      tb_realms,      cmd_list_realms,"List realms."),
SDATACM2 (ASN_SCHEMA,   "run-yuno",         0,                  0,                  pm_run_yuno,    cmd_run_yuno,   "Run yuno."),
SDATACM2 (ASN_SCHEMA,   "kill-yuno",        0,                  0,                  pm_kill_yuno,   cmd_kill_yuno,  "Kill yuno."),
SDATACM2 (ASN_SCHEMA,   "play-yuno",        0,                  0,                  pm_play_yuno,   cmd_play_yuno,  "Play yuno."),
SDATACM2 (ASN_SCHEMA,   "pause-yuno",       0,                  0,                  pm_pause_yuno,  cmd_pause_yuno, "Pause yuno."),
SDATACM2 (ASN_SCHEMA,   "enable-yuno",      0,                  0,                  pm_enable_yuno, cmd_enable_yuno,"Enable yuno."),
SDATACM2 (ASN_SCHEMA,   "disable-yuno",     0,                  0,                  pm_disable_yuno,cmd_disable_yuno,"Disable yuno."),
SDATACM2 (ASN_SCHEMA,   "trace-on-yuno",    SDF_WILD_CMD,       0,                  pm_trace_on_yuno,cmd_trace_on_yuno,"Trace on yuno."),
SDATACM2 (ASN_SCHEMA,   "trace-off-yuno",   SDF_WILD_CMD,       0,                  pm_trace_off_yuno,cmd_trace_off_yuno,"Trace off yuno."),
SDATACM2 (ASN_SCHEMA,   "command-yuno",     SDF_WILD_CMD,       0,                  pm_command_yuno,cmd_command_yuno,"Command to yuno. WARNING: parameter's keys are not checked."),
SDATACM2 (ASN_SCHEMA,   "stats-yuno",       SDF_WILD_CMD,       0,                  pm_stats_yuno,  cmd_stats_yuno, "Get statistics of yuno."),

SDATA_END()
};

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag----------------default---------description---------- */
SDATA (ASN_OCTET_STR,   "database",         SDF_RD|SDF_REQUIRED,"agent_treedb", "Database name"),
SDATA (ASN_OCTET_STR,   "startup_command",  SDF_RD,             0,              "Command to execute at startup"),
SDATA (ASN_JSON,        "agent_environment",SDF_RD,             0,              "Agent environment. Override the yuno environment."),
SDATA (ASN_JSON,        "node_variables",   SDF_RD,             0,              "Global to Node json config variables."),
SDATA (ASN_INTEGER,     "timerStBoot",      SDF_RD,             6*1000,         "Timer to run yunos on boot"),
SDATA (ASN_INTEGER,     "signal2kill",      SDF_RD,             SIGQUIT,        "Signal to kill yunos"),
SDATA (ASN_POINTER,     "user_data",        0,                  0,              "User data"),
SDATA (ASN_POINTER,     "user_data2",       0,                  0,              "More user data"),
SDATA (ASN_POINTER,     "subscriber",       0,                  0,              "Subscriber of output-events. Not a child gobj."),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_USER = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"trace_user",        "Trace user description"},
{0, 0},
};


/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t timerStBoot;
    BOOL enabled_yunos_running;

    hgobj resource;
    hgobj timer;
    hrotatory_t audit_file;
} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    helper_quote2doublequote(treedb_schema_yuneta_agent);

    /*
     *  Chequea schema fichador, exit si falla.
     */
    json_t *jn_treedb_schema_yuneta_agent;
    jn_treedb_schema_yuneta_agent = legalstring2json(treedb_schema_yuneta_agent, TRUE);
    if(!jn_treedb_schema_yuneta_agent) {
        exit(-1);
    }

    priv->timer = gobj_create("agent", GCLASS_TIMER, 0, gobj);
    const char *database = gobj_read_str_attr(gobj, "database");

    FILE *file = fopen("/yuneta/realms/agent/yuneta_agent.pid", "w");
    if(file) {
        fprintf(file, "%d\n", getpid());
        fclose(file);
    }

    json_t *kw_resource = json_pack("{s:s, s:s, s:o}",
        "service", "yuneta_agent",
        "database", database,
        "treedb_schema", jn_treedb_schema_yuneta_agent
    );

    priv->resource = gobj_create_unique(
        "agent_resources",
        GCLASS_NODE,
        kw_resource,
        gobj
    );

    char audit_path[NAME_MAX];
    yuneta_realm_file(audit_path, sizeof(audit_path), "audit", "ZZZ-DD_MM_CCYY.log", TRUE);
    priv->audit_file = rotatory_open(
        audit_path,
        0,                      // 0 = default 64K
        0,                      // 0 = default 8
        0,                      // 0 = default 10
        yuneta_xpermission(),   // permission for directories and executable files. 0 = default 02775
        0660,                   // permission for regular files. 0 = default 0664
        TRUE
    );
    if(priv->audit_file) {
        gobj_audit_commands(audit_command_cb, gobj);
    }

    /*
     *  SERVICE subscription model
     */
    hgobj subscriber = (hgobj)gobj_read_pointer_attr(gobj, "subscriber");
    if(subscriber) {
        gobj_subscribe_event(gobj, NULL, NULL, subscriber);
    }

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(timerStBoot,             gobj_read_int32_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
//     PRIVATE_DATA *priv = gobj_priv_data(gobj);
//
//     IF_EQ_SET_PRIV(timeout,             gobj_read_int32_attr)
//     END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->audit_file) {
        rotatory_close(priv->audit_file);
        priv->audit_file = 0;
    }
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->resource) {
        gobj_start(priv->resource);
    }
    gobj_start(priv->timer);
    set_timeout(priv->timer, priv->timerStBoot);
    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->resource) {
        gobj_stop(priv->resource);
    }
    clear_timeout(priv->timer);
    gobj_stop(priv->timer);
    gobj_stop_childs(gobj);
    return 0;
}

/***************************************************************************
 *      Framework Method mt_authenticate
 ***************************************************************************/
PRIVATE json_t *mt_authenticate(hgobj gobj, const char *service, json_t *kw, hgobj src)
{
    const char *user = kw_get_str(kw, "user", 0, 0);
    const char *password = kw_get_str(kw, "password", 0, 0);
    if(!user || !password) {
        // TODO implement authentication
    }

    /*
     *  Autoriza
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        0,
        0,
        0,
        kw  // owned
    );

    return webix;
}




            /***************************
             *      Commands
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    KW_INCREF(kw);
    json_t *jn_resp = gobj_build_cmds_doc(gobj, kw);
    return msg_iev_build_webix(
        gobj,
        0,
        jn_resp,
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_dir_public(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *match = kw_get_str(kw, "match", 0, 0);
    if(!match) {
        match = ".*";
    }
    const char *subdirectory = kw_get_str(kw, "subdirectory", 0, 0);
    char directory[NAME_MAX];
    if(!empty_string(subdirectory)) {
        if(*subdirectory=='/') {
            subdirectory++;
        }
        snprintf(directory, sizeof(directory), "/yuneta/public/%s", subdirectory);
    } else {
        snprintf(directory, sizeof(directory), "/yuneta/public");
    }

    int size;
    char **tree = get_ordered_filename_array(
        directory,
        match,
        WD_RECURSIVE|WD_MATCH_DIRECTORY|WD_MATCH_REGULAR_FILE|WD_MATCH_SYMBOLIC_LINK|WD_HIDDENFILES,
        &size
    );
    json_t *jn_array = json_array();
    for(int i=0; i<size; i++) {
        char *fullpath = tree[i];
        json_array_append_new(jn_array, json_string(fullpath));
    }
    free_ordered_filename_array(tree, size);

    return msg_iev_build_webix(
        gobj,
        0,
        0,
        0,
        jn_array,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_dir_realms(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *match = kw_get_str(kw, "match", 0, 0);
    if(!match) {
        match = ".*";
    }
    const char *subdirectory = kw_get_str(kw, "subdirectory", 0, 0);
    char directory[NAME_MAX];
    if(!empty_string(subdirectory)) {
        if(*subdirectory=='/') {
            subdirectory++;
        }
        snprintf(directory, sizeof(directory), "/yuneta/realms/%s", subdirectory);
    } else {
        snprintf(directory, sizeof(directory), "/yuneta/realms");
    }

    int size;
    char **tree = get_ordered_filename_array(
        directory,
        match,
        WD_RECURSIVE|WD_MATCH_DIRECTORY|WD_MATCH_REGULAR_FILE|WD_MATCH_SYMBOLIC_LINK|WD_HIDDENFILES,
        &size
    );
    json_t *jn_array = json_array();
    for(int i=0; i<size; i++) {
        char *fullpath = tree[i];
        json_array_append_new(jn_array, json_string(fullpath));
    }
    free_ordered_filename_array(tree, size);

    return msg_iev_build_webix(
        gobj,
        0,
        0,
        0,
        jn_array,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_dir_repos(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *match = kw_get_str(kw, "match", 0, 0);
    if(!match) {
        match = ".*";
    }
    const char *subdirectory = kw_get_str(kw, "subdirectory", 0, 0);
    char directory[NAME_MAX];
    if(!empty_string(subdirectory)) {
        if(*subdirectory=='/') {
            subdirectory++;
        }
        snprintf(directory, sizeof(directory), "/yuneta/repos/%s", subdirectory);
    } else {
        snprintf(directory, sizeof(directory), "/yuneta/repos");
    }

    int size;
    char **tree = get_ordered_filename_array(
        directory,
        match,
        WD_RECURSIVE|WD_MATCH_DIRECTORY|WD_MATCH_REGULAR_FILE|WD_MATCH_SYMBOLIC_LINK|WD_HIDDENFILES,
        &size
    );
    json_t *jn_array = json_array();
    for(int i=0; i<size; i++) {
        char *fullpath = tree[i];
        json_array_append_new(jn_array, json_string(fullpath));
    }
    free_ordered_filename_array(tree, size);

    return msg_iev_build_webix(
        gobj,
        0,
        0,
        0,
        jn_array,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_dir_store(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *match = kw_get_str(kw, "match", 0, 0);
    if(!match) {
        match = ".*";
    }
    const char *subdirectory = kw_get_str(kw, "subdirectory", 0, 0);
    char directory[NAME_MAX];
    if(!empty_string(subdirectory)) {
        if(*subdirectory=='/') {
            subdirectory++;
        }
        snprintf(directory, sizeof(directory), "/yuneta/store/%s", subdirectory);
    } else {
        snprintf(directory, sizeof(directory), "/yuneta/store");
    }

    int size;
    char **tree = get_ordered_filename_array(
        directory,
        match,
        WD_RECURSIVE|WD_MATCH_DIRECTORY|WD_MATCH_REGULAR_FILE|WD_MATCH_SYMBOLIC_LINK|WD_HIDDENFILES,
        &size
    );
    json_t *jn_array = json_array();
    for(int i=0; i<size; i++) {
        char *fullpath = tree[i];
        json_array_append_new(jn_array, json_string(fullpath));
    }
    free_ordered_filename_array(tree, size);

    return msg_iev_build_webix(
        gobj,
        0,
        0,
        0,
        jn_array,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_dir_logs(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *realm_id = kw_get_str(kw, "realm_id", 0, 0);
    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!id) {
        return msg_iev_build_webix(
            gobj,
            -197,
            json_local_sprintf("'id' required."),
            0,
            0,
            kw  // owned
        );
    }

    hsdata hs = gobj_get_resource(priv->resource, "yunos", realm_id, id);
    if(!hs) {
        return msg_iev_build_webix(gobj,
            -198,
            json_local_sprintf("Yuno not found."),
            0,
            0,
            kw  // owned
        );
    }

    char yuno_log_path[NAME_MAX];
    build_yuno_log_path(gobj, hs, yuno_log_path, sizeof(yuno_log_path), FALSE);

    int size;
    char **tree = get_ordered_filename_array(
        yuno_log_path,
        ".*",
        WD_RECURSIVE|WD_MATCH_DIRECTORY|WD_MATCH_REGULAR_FILE|WD_MATCH_SYMBOLIC_LINK|WD_HIDDENFILES,
        &size
    );
    json_t *jn_array = json_array();
    for(int i=0; i<size; i++) {
        char *fullpath = tree[i];
        json_array_append_new(jn_array, json_string(fullpath));
    }
    free_ordered_filename_array(tree, size);

    return msg_iev_build_webix(
        gobj,
        0,
        0,
        0,
        jn_array,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE BOOL sumdir_cb(
    void *user_data,
    wd_found_type type,
    char *fullpath,
    const char *directory,
    char *name,             // dname[255]
    int level,
    int index)
{
    if(!(type == WD_TYPE_DIRECTORY || type == WD_TYPE_REGULAR_FILE)) {
        return TRUE; // continue traverse tree
    }

    json_t *jn_data = user_data;

    uint64_t size = filesize(fullpath);

    if(kw_has_key(jn_data, directory)) {
        json_int_t total_size = kw_get_int(jn_data, directory, 0, 0);
        total_size += size;
        json_object_set_new(jn_data, directory, json_integer(total_size));
    } else {
        json_object_set_new(jn_data, directory, json_integer(size));
    }
    // TODO para pintar con puntos "%'d\n", 1123456789
    return TRUE; // continue traverse tree
}
PRIVATE json_t *cmd_sumdir(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *directory = kw_get_str(kw, "directory", 0, 0);
    if(!directory) {
        directory = "/yuneta";
    }
    const char *match = kw_get_str(kw, "match", 0, 0);
    if(!match) {
        match = ".*";
    }
    json_t *jn_data = json_object();

    walk_dir_tree(
        directory,
        match,
        WD_RECURSIVE|WD_MATCH_DIRECTORY|WD_MATCH_REGULAR_FILE|WD_MATCH_SYMBOLIC_LINK|WD_HIDDENFILES,
        sumdir_cb,
        jn_data
    );

    return msg_iev_build_webix(
        gobj,
        0,
        0,
        0,
        jn_data,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE BOOL read_json_cb(
    void *user_data,
    wd_found_type type,     // type found
    char *fullpath,         // directory+filename found
    const char *directory,  // directory of found filename
    char *name,             // dname[255]
    int level,              // level of tree where file found
    int index               // index of file inside of directory, relative to 0
)
{
    json_t *jn_dict = user_data;
    size_t flags = 0;
    json_error_t error;
    json_t *jn_attr = json_load_file(fullpath, flags, &error);
    if(jn_attr) {
        json_object_set_new(jn_dict, fullpath, jn_attr);
    } else {
        jn_attr = json_local_sprintf("Invalid json in '%s' file, error '%s'", fullpath, error.text);
        json_object_set_new(jn_dict, fullpath, jn_attr);
    }
    return TRUE; // to continue
}
/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t* cmd_list_persistent_attrs(hgobj gobj, const char* cmd, json_t* kw, hgobj src)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/realms", yuneta_work_dir());
    json_t *jn_dict = json_object();

    walk_dir_tree(
        path,
        ".*persistent-attrs.json",
        WD_RECURSIVE|WD_MATCH_REGULAR_FILE,
        read_json_cb,
        jn_dict
    );

    /*
     *  Inform
     */
    return msg_iev_build_webix(gobj,
        0,
        0,
        0,
        jn_dict, // owned
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE BOOL launch_sh_cb(
    void *user_data,
    wd_found_type type,
    char *fullpath,
    const char *directory,
    char *name,             // dname[255]
    int level,
    int index)
{
    if(!(type == WD_TYPE_REGULAR_FILE)) {
        return TRUE; // continue traverse tree
    }
    json_t *kw = user_data;
    char *arg1 = (char *)kw_get_str(kw, "arg1", 0, 0);
    char *arg2 = (char *)kw_get_str(kw, "arg2", 0, 0);
    char *arg3 = (char *)kw_get_str(kw, "arg3", 0, 0);
    size_t response_size = 32*1024;
    char *response = gbmem_malloc(response_size);

    char command[1024];
    snprintf(command, sizeof(command), "%s %s %s %s",
        fullpath,
        !empty_string(arg1)?arg1:"",
        !empty_string(arg2)?arg2:"",
        !empty_string(arg3)?arg3:""
    );
    if(run_command(command, response, response_size)<0) {
        log_error(0,
            "gobj",         "%s", __FILE__,
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "run_command() FAILED",
            "command",      "%s", command,
            "output",       "%s", response,
            NULL
        );
    }
    gbmem_free(response);

    return TRUE; // continue traverse tree
}
PRIVATE json_t *cmd_launch_scripts(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *directory = kw_get_str(kw, "directory", 0, 0);
    if(empty_string(directory)) {
        return msg_iev_build_webix(
            gobj,
            -199,
            json_local_sprintf("What directory?"),
            0,
            0,
            kw  // owned
        );
    }
    const char *filter = kw_get_str(kw, "filter", 0, 0);
    const char *match = ".*\\.sh";
    char temp[NAME_MAX];
    if(!empty_string(filter)) {
        snprintf(temp, sizeof(temp), ".*%s.*\\.sh", filter);
        match = temp;
    }

    walk_dir_tree(
        directory,
        match,
        WD_MATCH_REGULAR_FILE,
        launch_sh_cb,
        kw
    );

    return msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf("Done!"),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_replicate_node(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    BOOL upgrade = strstr(cmd, "upgrade")?1:0;
    int realm_replicates = 0;
    json_t *kw_ids = 0;

    const char *realm_name = kw_get_str(kw, "realm_name", 0, 0);
    if(!empty_string(realm_name)) {
        json_int_t realm_id = find_last_id_by_name(gobj, "realms", "name", realm_name);
        if(!realm_id) {
            return msg_iev_build_webix(
                gobj,
                -196,
                json_local_sprintf("Realm %s not found.", realm_name),
                0,
                0,
                kw  // owned
            );
        }
        kw_ids = kwids_id2kwids(realm_id);
    } else {
        kw_ids = kwids_extract_and_expand_ids(kw);
    }

    KW_INCREF(kw_ids); // use later with yunos
    dl_list_t *iter_realms = gobj_list_resource(priv->resource, "realms", kw_ids);
    realm_replicates = dl_size(iter_realms);
    if(realm_replicates==0) {
        KW_DECREF(kw_ids);
        return msg_iev_build_webix(
            gobj,
            -195,
            json_local_sprintf("No realms found."),
            0,
            0,
            kw  // owned
        );
    }

    const char *filename = kw_get_str(kw, "filename", 0, 0);
    const char *url = kw_get_str(kw, "url", 0, 0);

    /*----------------------------------*
     *      Build destination file
     *----------------------------------*/
    char fecha[32];
    char source_[NAME_MAX];
    if(empty_string(filename)) {
        /*
        *  Mask "DD/MM/CCYY-hh:mm:ss-w-ddd"
        */
        time_t t;
        time(&t);
        strftime(fecha, sizeof(fecha), "%Y-%m-%d", localtime(&t));

        if(!empty_string(realm_name)) {
            snprintf(source_, sizeof(source_), "%s-%s-realm-%s.json",
                upgrade?"upgrade":"replicate",
                fecha,
                realm_name
            );
        } else {
            GBUFFER *gbuf_ids = gbuf_create((size_t)4*1024, (size_t)32*1024, 0, 0);

            hsdata hs_realm; rc_instance_t *i_hs;
            i_hs = rc_first_instance(iter_realms, (rc_resource_t **)&hs_realm);
            while(i_hs) {
                json_int_t realm_id = SDATA_GET_ID(hs_realm);
                gbuf_printf(gbuf_ids, "-%d", (int)realm_id);

                /*
                *  Next realm
                */
                i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_realm);
            }

            char *realms_ids = gbuf_cur_rd_pointer(gbuf_ids);
            snprintf(source_, sizeof(source_), "%s-%s-realms%s.json",
                upgrade?"upgrade":"replicate",
                fecha,
                realms_ids
            );
            gbuf_decref(gbuf_ids);
        }
        filename = source_;
    }
    char path[NAME_MAX];
    yuneta_store_file(path, sizeof(path), "replicates", "", filename, TRUE);

    /*----------------------------------*
     *      Create json script file
     *----------------------------------*/
    FILE *file = fopen(path, "w");
    if(!file) {
        KW_DECREF(kw_ids);
        rc_free_iter(iter_realms, TRUE, 0);
        return msg_iev_build_webix(
            gobj,
            -194,
            json_local_sprintf("Cannot create '%s' file.", path),
            0,
            0,
            kw  // owned
        );
    }

    /*----------------------------------*
     *      Fill realms
     *----------------------------------*/
    hsdata hs_realm; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_realms, (rc_resource_t **)&hs_realm);
    while(i_hs) {
        json_t *jn_range_ports = sdata_read_json(hs_realm, "range_ports");
        char *range_ports = json2uglystr(jn_range_ports);
        fprintf(file, "{\"command\": \"%screate-realm domain='%s' range_ports=%s role='%s' name='%s' bind_ip='%s'\"}\n",
            upgrade?"-":"",
            sdata_read_str(hs_realm, "domain"),
            range_ports,
            sdata_read_str(hs_realm, "role"),
            sdata_read_str(hs_realm, "name"),
            sdata_read_str(hs_realm, "bind_ip")
        );
        gbmem_free(range_ports);

        /*
         *  Next realm
         */
        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_realm);
    }
    fprintf(file, "\n");
    rc_free_iter(iter_realms, TRUE, 0);

    /*---------------------------------------------------------------*
     *      Fill top yunos with his binaries and configurations
     *---------------------------------------------------------------*/
    /*
     *  Control repeated binaries/configurations
     */
    json_t *jn_added_binaries = json_array();
    json_t *jn_added_configs = json_array();

    dl_list_t *iter_yunos = gobj_list_resource(priv->resource, "yunos", 0); // Select all yunos
    hsdata hs_yuno;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        BOOL valid_yuno = TRUE;
        /*
         *  The rule: only enabled yunos and aliased yunos are replicated.
         */
        BOOL yuno_disabled = sdata_read_bool(hs_yuno, "disabled");
        const char *alias = sdata_read_str(hs_yuno, "yuno_alias");
        if(empty_string(alias)) {
            if(yuno_disabled) {
                // Sin alias y disabled, ignora en cualquier caso.
                valid_yuno = FALSE;
            }
        } else {
            // NEW Version 2.2.5
            if(yuno_disabled && upgrade) {
                // Con alias y disabled, ignora en upgrade, no en replicate.
                valid_yuno = FALSE;
            }
        }
        if(!valid_yuno) {
            /*
             *  Next
             */
            i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
            continue;
        }
        /*
         *  Check if yuno belongs to some realm to replicate.
         */
        if(json_array_size(json_object_get(kw_ids, "ids"))>0) {
            json_int_t realm_id = sdata_read_uint64(hs_yuno, "realm_id");
            if(!int_in_dict_list(realm_id, kw_ids, "ids")) {
                valid_yuno = FALSE;
            }
        }
        if(!valid_yuno) {
            /*
             *  Next
             */
            i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
            continue;
        }

        /*
         *  Valid yuno to replicate.
         */
        const char *realm_name = sdata_read_str(hs_yuno, "realm_name");
        if(!realm_name) {
            realm_name = "";
        }
        const char *yuno_role = sdata_read_str(hs_yuno, "yuno_role");
        const char *yuno_name = sdata_read_str(hs_yuno, "yuno_name");
        if(!yuno_name) {
            yuno_name = "";
        }
        const char *yuno_alias = sdata_read_str(hs_yuno, "yuno_alias");
        if(!yuno_alias) {
            yuno_alias = "";
        }

        /*
         *  Order: kill-yuno.
         */
        fprintf(file,
            "{\"command\": \"-kill-yuno realm_name='%s' yuno_role='%s' yuno_name='%s'\"}\n",
            realm_name,
            yuno_role,
            yuno_name
        );

        /*
         *  Save yuno's configurations.
         */
        dl_list_t *iter_config_ids = sdata_read_iter(hs_yuno, "config_ids");
        if(rc_iter_size(iter_config_ids)>0) {
            hsdata hs_config; rc_instance_t *i_hs;
            i_hs = rc_first_instance(iter_config_ids, (rc_resource_t **)&hs_config);
            while(i_hs) {
                json_int_t config_id = SDATA_GET_ID(hs_config);
                if(int_in_jn_list(config_id, jn_added_configs)) {
                    /*
                     *  Next config
                     */
                    i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_config);
                    continue;
                }

                const char *name = sdata_read_str(hs_config, "name");
                const char *version = sdata_read_str(hs_config, "version");
                const char *description = sdata_read_str(hs_config, "description");
                json_t *jn_content = sdata_read_json(hs_config, "zcontent");
                char *content = json2uglystr(jn_content);
                GBUFFER *gbuf_base64 = gbuf_string2base64(content, (size_t)strlen(content));
                const char *p = gbuf_cur_rd_pointer(gbuf_base64);

                fprintf(file,
                    "{\"command\": \"%screate-config '%s' version='%s' description='%s' content64=%s\"}\n",
                    upgrade?"-":"",
                    name,
                    version,
                    description,
                    p
                );
                gbmem_free(content);
                gbuf_decref(gbuf_base64);

                json_array_append_new(jn_added_configs, json_integer(config_id));

                /*
                 *  Next config
                 */
                i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_config);
            }
        }

        /*
         *  Save yuno's binary.
         */
        json_int_t binary_id = sdata_read_uint64(hs_yuno, "binary_id");
        hsdata hs_binary = gobj_get_resource(priv->resource, "binaries", 0, binary_id);
        if(hs_binary) {
            if(!int_in_jn_list(binary_id, jn_added_binaries)) {
                const char *role = sdata_read_str(hs_binary, "role");
                char temp[NAME_MAX];
                snprintf(temp, sizeof(temp), "/yuneta/development/output/yunos/%s", role);
                if(access(temp, 0)==0) {
                    fprintf(file,
                        "{\"command\": \"%sinstall-binary '%s' content64=$$(%s)\"}\n",
                        upgrade?"-":"",
                        role,
                        role
                    );
                } else {
                    const char *binary = sdata_read_str(hs_binary, "binary");
                    GBUFFER *gbuf_base64 = gbuf_file2base64(binary);
                    char *p = gbuf_cur_rd_pointer(gbuf_base64);

                    fprintf(file,
                        "{\"command\": \"%sinstall-binary '%s' content64=%s\"}\n",
                        upgrade?"-":"",
                        role,
                        p
                    );
                    gbuf_decref(gbuf_base64);
                }

                json_array_append_new(jn_added_binaries, json_integer(binary_id));
            }
        }

        /*
         *  Order: create-yuno.
         */
        fprintf(file,
            "{\"command\": \"%screate-yuno realm_name='%s' yuno_role='%s' yuno_name='%s' yuno_alias='%s' disabled=%d\"}\n",
            upgrade?"-":"",
            realm_name,
            yuno_role,
            yuno_name,
            yuno_alias,
            yuno_disabled?1:0
        );

        if(upgrade) {
            /*
             *  Order: top-last con filtro.
             */
            json_t *jn_filter = json_pack("{s:s, s:s, s:s, s:b, s:b}",
                "realm_name", realm_name,
                "yuno_role", yuno_role,
                "yuno_name", yuno_name,
                "yuno_running", 1,
                "yuno_playing", 1
            );
            char *filter = json2uglystr(jn_filter);
            fprintf(file,
                "{\"command\": \"-top-last-yuno realm_name='%s' yuno_role='%s' yuno_name='%s'\", \"response_filter\":%s}\n\n",
                realm_name,
                yuno_role,
                yuno_name,
                filter
            );
            json_decref(jn_filter);
            gbmem_free(filter);
        } else {
            fprintf(file,
                "{\"command\": \"-run-yuno realm_name='%s' yuno_role='%s' yuno_name='%s'\"}\n\n",
                realm_name,
                yuno_role,
                yuno_name
            );
        }

        /*
         *  Next
         */
        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    fprintf(file, "\n\n");
    rc_free_iter(iter_yunos, TRUE, 0);

    /*----------------------------------*
     *      Close
     *----------------------------------*/
    json_decref(jn_added_binaries);
    json_decref(jn_added_configs);

    fclose(file);
    KW_DECREF(kw_ids);

    /*----------------------------------*
     *      Execute the file
     *----------------------------------*/
    if(!empty_string(url)) {
        //ybatch_json_command_file(gobj, url, path);
        // TODO exec json command
    }

    return msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf("%d realms replicated in '%s' filename", realm_replicates, path),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_replicate_binaries(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    int binary_replicates = 0;
    json_t *kw_ids = 0;

    const char *role = kw_get_str(kw, "role", 0, 0);
    if(!empty_string(role)) {
        json_int_t binary_id = find_last_id_by_name(gobj, "binaries", "role", role);
        if(!binary_id) {
            return msg_iev_build_webix(
                gobj,
                -196,
                json_local_sprintf("Binary %s not found.", role),
                0,
                0,
                kw  // owned
            );
        }
        kw_ids = kwids_id2kwids(binary_id);
    } else {
        kw_ids = kwids_extract_and_expand_ids(kw);
    }

    dl_list_t *iter_binaries = gobj_list_resource(priv->resource, "binaries", kw_ids);
    binary_replicates = dl_size(iter_binaries);
    if(binary_replicates==0) {
        return msg_iev_build_webix(
            gobj,
            -195,
            json_local_sprintf("No binary found."),
            0,
            0,
            kw  // owned
        );
    }

    const char *filename = kw_get_str(kw, "filename", 0, 0);
    const char *url = kw_get_str(kw, "url", 0, 0);

    /*----------------------------------*
     *      Build destination file
     *----------------------------------*/
    char fecha[32];
    char source_[NAME_MAX];
    if(empty_string(filename)) {
        /*
        *  Mask "DD/MM/CCYY-hh:mm:ss-w-ddd"
        */
        time_t t;
        time(&t);
        strftime(fecha, sizeof(fecha), "%Y-%m-%d", localtime(&t));

        if(!empty_string(role)) {
            snprintf(source_, sizeof(source_), "%s-%s-binary-%s.json",
                "replicate",
                fecha,
                role
            );
        } else {
            GBUFFER *gbuf_ids = gbuf_create(4*1024, 32*1024, 0, 0);

            hsdata hs_binary; rc_instance_t *i_hs;
            i_hs = rc_first_instance(iter_binaries, (rc_resource_t **)&hs_binary);
            while(i_hs) {
                json_int_t binary_id = SDATA_GET_ID(hs_binary);
                gbuf_printf(gbuf_ids, "-%d", (int)binary_id);

                /*
                 *  Next binary
                 */
                i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_binary);
            }

            char *binary_ids = gbuf_cur_rd_pointer(gbuf_ids);
            snprintf(source_, sizeof(source_), "%s-%s-binaries%s.json",
                "replicate",
                fecha,
                binary_ids
            );
            gbuf_decref(gbuf_ids);
        }
        filename = source_;
    }
    char path[NAME_MAX];
    yuneta_store_file(path, sizeof(path), "replicates", "", filename, TRUE);

    /*----------------------------------*
     *      Create json script file
     *----------------------------------*/
    FILE *file = fopen(path, "w");
    if(!file) {
        rc_free_iter(iter_binaries, TRUE, 0);
        return msg_iev_build_webix(
            gobj,
            -194,
            json_local_sprintf("Cannot create '%s' file.", path),
            0,
            0,
            kw  // owned
        );
    }

    /*----------------------------*
     *      Fill binaries
     *----------------------------*/
    hsdata hs_binary; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_binaries, (rc_resource_t **)&hs_binary);
    while(i_hs) {
        json_int_t binary_id = SDATA_GET_ID(hs_binary);
        /*
         *  Save yuno's binary.
         */
        hsdata hs_binary = gobj_get_resource(priv->resource, "binaries", 0, binary_id);
        if(hs_binary) {
            const char *role = sdata_read_str(hs_binary, "role");
            char temp[NAME_MAX];
            snprintf(temp, sizeof(temp), "/yuneta/development/output/yunos/%s", role);
            if(access(temp, 0)==0) {
                fprintf(file,
                    "{\"command\": \"install-binary '%s' content64=$$(%s)\"}\n",
                    role,
                    role
                );
            } else {
                const char *binary = sdata_read_str(hs_binary, "binary");
                GBUFFER *gbuf_base64 = gbuf_file2base64(binary);
                char *p = gbuf_cur_rd_pointer(gbuf_base64);

                fprintf(file,
                    "{\"command\": \"install-binary '%s' content64=%s\"}\n",
                    role,
                    p
                );
                gbuf_decref(gbuf_base64);
            }
        }

        /*
         *  Next binary
         */
        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_binary);
    }

    fprintf(file, "\n\n");

    /*----------------------------------*
     *      Close
     *----------------------------------*/

    fclose(file);

    /*----------------------------------*
     *      Execute the file
     *----------------------------------*/
    if(!empty_string(url)) {
        //ybatch_json_command_file(gobj, url, path);
        // TODO exec json command
    }

    return msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf("%d binaries replicated in '%s' filename", binary_replicates, path),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_list_public_services(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "public_services";

    /*
     *  Get a iter of matched resources
     */
    KW_INCREF(kw);
    dl_list_t *iter = gobj_list_resource(priv->resource, resource, kw);
//     iter = sdata_sort_iter_by_id(iter);

    /*
     *  Convert hsdata to json
     */
    json_t *jn_data = sdata_iter2json(iter, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf(cmd),
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    rc_free_iter(iter, TRUE, 0);

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_delete_public_service(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "public_services";

    /*
     *  Get resources to delete.
     *  Search is restricted to id only
     */
    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!id) {
        return msg_iev_build_webix(
            gobj,
            -104,
            json_local_sprintf("'id' required."),
            0,
            0,
            kw  // owned
        );
    }
    hsdata hs = gobj_get_resource(priv->resource, resource, 0, id);
    if(!hs) {
        return msg_iev_build_webix(
            gobj,
            -105,
            json_local_sprintf("Service not found."),
            0,
            0,
            kw  // owned
        );
    }
    if(gobj_delete_resource(priv->resource, hs)<0) {
        return msg_iev_build_webix(
            gobj,
            -106,
            json_local_sprintf("Cannot delete the service."),
            0,
            0,
            kw  // owned
        );
    }

    return msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf("Service deleted."),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_update_public_service(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "public_services";

    /*
     *  Get a iter of matched resources.
     *  Search is restricted to ids only
     */
    json_t *kw_ids = kwids_extract_and_expand_ids(kw);
    if(!kw_ids) {
        return msg_iev_build_webix(
            gobj,
            -107,
            json_local_sprintf("'id' or 'ids' are required."),
            0,
            0,
            kw  // owned
        );
    }
    dl_list_t *iter = gobj_list_resource(priv->resource, resource, kw_ids);
    if(dl_size(iter)==0) {
        return msg_iev_build_webix(
            gobj,
            -108,
            json_local_sprintf("No resource found."),
            0,
            0,
            kw  // owned
        );
    }

    /*
     *  Convert json in hsdata
     */
    json2sdata_iter(iter, kw, SDF_PERSIST, 0, 0);

    /*
     *  Update database
     */
    hsdata hs; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter, (rc_resource_t **)&hs);
    while(i_hs) {
        gobj_update_resource(
            priv->resource,
            hs
        );
        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs);
    }

    /*
     *  Convert result in json
     */
    json_t *jn_data = sdata_iter2json(iter, SDF_PERSIST, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );
    rc_free_iter(iter, TRUE, 0);

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_list_realms(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "realms";

    /*
     *  Get a iter of matched resources
     */
    json_t *jn_data = gobj_list_nodes(
        priv->resource,
        resource,
        0, // ids
        kw_filter_metadata(kw_incref(kw)), // filter
        0
    );

    /*
     *  Inform
     */
    return msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf(cmd),
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_create_realm(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "realms";

    const char *domain = kw_get_str(kw, "domain", "", 0);
    const char *role = kw_get_str(kw, "role", "", 0);
    const char *name = kw_get_str(kw, "name", "", 0);

    if(empty_string(domain)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_local_sprintf("What domain?"),
            0,
            0,
            kw  // owned
        );
    }
    if(empty_string(role)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_local_sprintf("What role?"),
            0,
            0,
            kw  // owned
        );
    }
    if(empty_string(name)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_local_sprintf("What name?"),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Check if already exists
     *------------------------------------------------*/
    json_t *kw_find = json_pack("{s:s, s:s, s:s}",
        "domain", domain,
        "role", role,
        "name", name
    );

    json_t *jn_data = gobj_list_nodes(
        priv->resource,
        resource,
        0, // ids
        kw_find, // filter
        0
    );
    if(json_array_size(jn_data)) {
        /*
         *  1 o more records, yuno already stored and without overwrite.
         */
        return msg_iev_build_webix(
            gobj,
            -109,
            json_local_sprintf(
                "Realm already exists"
            ),
            tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
            jn_data,
            kw  // owned
        );
    }
    JSON_DECREF(jn_data);

    /*
     *  Add to database
     */
    KW_INCREF(kw);
    json_t *node = gobj_create_node(priv->resource, resource, kw, "");
    if(!node) {
        return msg_iev_build_webix(
            gobj,
            -110,
            json_local_sprintf("Cannot create node"),
            0,
            0,
            kw  // owned
        );
    }

    /*
     *  Convert result in json
     */
    jn_data = json_array();
    json_array_append(jn_data, node);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_update_realm(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "realms";

   /*
     *  Get a iter of matched resources.
     *  Search is restricted to ids only
     */
    json_t *kw_ids = kwids_extract_and_expand_ids(kw);
    if(!kw_ids) {
        return msg_iev_build_webix(
            gobj,
            -111,
            json_local_sprintf("'id' or 'ids' are required."),
            0,
            0,
            kw  // owned
        );
    }
    json_t *iter = gobj_list_nodes(
        priv->resource,
        resource,
        kw_incref(kw_ids), // ids
        0,  // filter
        0
    );

    if(json_array_size(iter)==0) {
        JSON_DECREF(iter);
        JSON_DECREF(kw_ids);
        return msg_iev_build_webix(
            gobj,
            -112,
            json_local_sprintf("Select one realm please"),
            0,
            0,
            kw  // owned
        );
    }

    /*
     *  Update database
     */
    int idx; json_t *node;
    json_array_foreach(iter, idx, node) {
        json_t *update = kw_duplicate(kw);
        json_object_set(update, "id", kw_get_dict_value(node, "id",0,KW_REQUIRED));
        gobj_update_node(priv->resource, resource, update, "");
    }
    JSON_DECREF(iter);

    /*
     *  Inform
     */
    json_t *jn_data = gobj_list_nodes(
        priv->resource,
        resource,
        kw_ids, // ids
        0,  // filter
        0
    );

    return msg_iev_build_webix(
        gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_delete_realm(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "realms";

    /*
     *  Get resources to delete.
     *  Search is restricted to id only
     */
    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!id) {
        return msg_iev_build_webix(
            gobj,
            -113,
            json_local_sprintf("'id' required."),
            0,
            0,
            kw  // owned
        );
    }
    json_t *node = gobj_get_node(priv->resource, resource, id);
    if(!node) {
        return msg_iev_build_webix(
            gobj,
            -114,
            json_local_sprintf("Realm not found."),
            0,
            0,
            kw  // owned
        );
    }
    int use = total_yunos_in_realm(gobj, id);
    if(use > 0) {
        return msg_iev_build_webix(
            gobj,
            -115,
            json_local_sprintf("Cannot delete realm. It has %d yunos.", use),
            0,
            0,
            kw  // owned
        );
    }

    if(gobj_delete_resource(priv->resource, node)<0) {
        return msg_iev_build_webix(
            gobj,
            -116,
            json_local_sprintf("Cannot delete the realm."),
            0,
            0,
            kw  // owned
        );
    }

    return msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf("Realm deleted."),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_list_binaries(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "binaries";

    /*
     *  Get a iter of matched resources
     */
    KW_INCREF(kw);
    dl_list_t *iter = gobj_list_resource(priv->resource, resource, kw);
//     iter = sdata_sort_iter_by_id(iter);

    /*
     *  Convert hsdata to json
     */
    json_t *jn_data = sdata_iter2json(iter, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf(cmd),
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    rc_free_iter(iter, TRUE, 0);

    return webix;
}

/***************************************************************************
 *  Get the information returned of executing  ``yuno --role``
 ***************************************************************************/
PRIVATE json_t *yuno_basic_information(hgobj gobj, const char *cmd)
{
    /*
     *  Execute cmd --role
     */
    size_t size = gbmem_get_maximum_block();
    char *cmd_output = gbmem_malloc(gbmem_get_maximum_block());
    if(!cmd_output) {
        // Error already logged
        return 0;
    }
    char command[NAME_MAX];
    snprintf(command, sizeof(command), "%s --print-role  2>&1", cmd);
    if(run_command(command, cmd_output, size)<0 || !*cmd_output) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "Incorrect role bin path",
            "command",      "%s", command,
            "output",       "%s", cmd_output,
            NULL
        );
        gbmem_free(cmd_output);
        return 0;
    }

    /*
     *  Parse output
     */
    char *p = strchr(cmd_output, '{');
    if(!p) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "Dict not found",
            "command",      "%s", command,
            "output",       "%s", cmd_output,
            NULL
        );
        gbmem_free(cmd_output);
        return 0;
    }
    json_t *jn_basic_info = legalstring2json(p, TRUE);
    gbmem_free(cmd_output);
    return jn_basic_info;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_install_binary(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "binaries";

    const char *id = kw_get_str(kw, "id", 0, 0);
    const char *role = kw_get_str(kw, "role", "", 0);

    const char *content64 = kw_get_str(kw, "content64", "", 0);
    if(empty_string(content64)) {
        return msg_iev_build_webix(
            gobj,
            -117,
            json_local_sprintf("No data in content64"),
            0,
            0,
            kw  // owned
        );
    }
    GBUFFER *gbuf_content = gbuf_decodebase64string(content64);
    char path[NAME_MAX];
    yuneta_realm_file(path, sizeof(path), "temp", role, TRUE);
    gbuf2file(
        gbuf_content, // owned
        path,
        yuneta_xpermission(),
        TRUE
    );

    json_t *jn_basic_info = yuno_basic_information(gobj, path);
    if(!jn_basic_info) {
        return msg_iev_build_webix(
            gobj,
            -118,
            json_local_sprintf(
                "It seems a wrong yuno binary."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Binary received.
     *------------------------------------------------*/
    const char *binary_role = kw_get_str(jn_basic_info, "role", 0, 0);
    const char *binary_version = kw_get_str(jn_basic_info, "version", "", 0);
    json_t *jn_classifiers = kw_get_dict_value(jn_basic_info, "classifiers", 0, 0);

    /*------------------------------------------------*
     *      Check if already exists
     *------------------------------------------------*/
    json_t *kw_find = json_pack("{s:s, s:s}",
        "role", binary_role,
        "version", binary_version
    );
    dl_list_t * iter_find = gobj_list_resource(priv->resource, resource, kw_find);
    if(dl_size(iter_find)) {
        /*
         *  1 o more records, yuno already stored and without overwrite.
         */
        json_t *jn_data = sdata_iter2json(iter_find, SDF_PERSIST, 0);
        json_t *webix = msg_iev_build_webix(
            gobj,
            -119,
            json_local_sprintf(
                "Yuno already exists."
            ),
            tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
            jn_data,
            kw  // owned
        );
        JSON_DECREF(jn_basic_info);
        rc_free_iter(iter_find, TRUE, 0);
        return webix;
    }
    rc_free_iter(iter_find, TRUE, 0);

    /*------------------------------------------------*
     *      Store in filesystem
     *------------------------------------------------*/
    /*
     *  Destination: inside of /yuneta/repos
     *      {{classifiers}}/{{role}}/{{version}}/binary.exe
     */
    char destination[NAME_MAX];
    yuneta_repos_yuno_dir(
        destination,
        sizeof(destination),
        jn_classifiers,
        binary_role,
        binary_version,
        TRUE
    );
    if(access(destination,0)!=0) {
        JSON_DECREF(jn_basic_info);
        return msg_iev_build_webix(
            gobj,
            -120,
            json_local_sprintf(
                "Cannot create '%s' directory.",
                destination
            ),
            0,
            0,
            kw  // owned
        );
    }
    yuneta_repos_yuno_file(
        destination,
        sizeof(destination),
        jn_classifiers,
        binary_role,
        binary_version,
        binary_role,
        TRUE
    );
    /*
     *  Overwrite, the overwrite filter was above.
     */
    if(copyfile(path, destination, yuneta_xpermission(), TRUE)<0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "copyfile() FAILED",
            "path",         "%s", path,
            "destination",  "%s", destination,
            NULL
        );
        JSON_DECREF(jn_basic_info);
        return msg_iev_build_webix(
            gobj,
            -121,
            json_local_sprintf(
                "Cannot copy '%s' to '%s'.",
                path,
                destination
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Store in db
     *------------------------------------------------*/
    json_object_set_new(
        jn_basic_info,
        "size",
        json_integer(
            (json_int_t)filesize(destination)
        )
    );
    json_object_set_new(
        jn_basic_info,
        "binary",
        json_string(destination)
    );
    if(id) {
        json_object_set_new(
            jn_basic_info,
            "id",
            json_integer(id)
        );
    }

    /*
     *  Create the resource
     */
    hsdata hs = gobj_create_resource(priv->resource, resource, jn_basic_info);
    if(!hs) {
        return msg_iev_build_webix(
            gobj,
            -122,
            json_local_sprintf("Cannot create resource."),
            0,
            0,
            kw  // owned
        );
    }

    /*
     *  Convert result in json
     */
    json_t *jn_data = json_array();
    json_array_append_new(jn_data, sdata2json(hs, SDF_PERSIST, 0));

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_update_binary(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "binaries";

    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!id) {
        return msg_iev_build_webix(
            gobj,
            -123,
            json_local_sprintf("'id' required."),
            0,
            0,
            kw  // owned
        );
    }
    hsdata hs = gobj_get_resource(priv->resource, resource, 0, id);
    if(!hs) {
        return msg_iev_build_webix(
            gobj,
            -124,
            json_local_sprintf("Binary not found."),
            0,
            0,
            kw  // owned
        );
    }
    const char *role = sdata_read_str(hs, "role");

    const char *content64 = kw_get_str(kw, "content64", "", 0);
    if(empty_string(content64)) {
        return msg_iev_build_webix(
            gobj,
            -125,
            json_local_sprintf("No data in content64"),
            0,
            0,
            kw  // owned
        );
    }
    GBUFFER *gbuf_content = gbuf_decodebase64string(content64);
    char path[NAME_MAX];
    yuneta_realm_file(path, sizeof(path), "temp", role, TRUE);
    gbuf2file(
        gbuf_content, // owned
        path,
        yuneta_xpermission(),
        TRUE
    );

    json_t *jn_basic_info = yuno_basic_information(gobj, path);
    if(!jn_basic_info) {
        return msg_iev_build_webix(
            gobj,
            -126,
            json_local_sprintf(
                "It seems a wrong yuno binary."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Binary received.
     *------------------------------------------------*/
    const char *binary_role = kw_get_str(jn_basic_info, "role", 0, 0);
    const char *binary_version = kw_get_str(jn_basic_info, "version", "", 0);
    json_t *jn_classifiers = kw_get_dict_value(jn_basic_info, "classifiers", 0, 0);

    /*------------------------------------------------*
     *      Store in filesystem
     *------------------------------------------------*/
    /*
     *  Destination: inside of /yuneta/repos
     *      {{classifiers}}/{{role}/{{version}}/binary.exe
     */
    char destination[NAME_MAX];
    yuneta_repos_yuno_dir(
        destination,
        sizeof(destination),
        jn_classifiers,
        binary_role,
        binary_version,
        TRUE
    );
    if(access(destination,0)!=0) {
        JSON_DECREF(jn_basic_info);
        return msg_iev_build_webix(
            gobj,
            -127,
            json_local_sprintf(
                "Cannot create '%s' directory.",
                destination
            ),
            0,
            0,
            kw  // owned
        );
    }
    yuneta_repos_yuno_file(
        destination,
        sizeof(destination),
        jn_classifiers,
        binary_role,
        binary_version,
        binary_role,
        TRUE
    );
    /*
     *  Overwrite, the overwrite filter was above.
     */
    if(copyfile(path, destination, yuneta_xpermission(), TRUE)<0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "copyfile() FAILED",
            "path",         "%s", path,
            "destination",  "%s", destination,
            NULL
        );
        JSON_DECREF(jn_basic_info);
        return msg_iev_build_webix(
            gobj,
            -128,
            json_local_sprintf(
                "Cannot copy '%s' to '%s'.",
                path,
                destination
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *  Update the resource
     *------------------------------------------------*/
    json_object_set_new(
        jn_basic_info,
        "size",
        json_integer(
            (json_int_t)filesize(destination)
        )
    );
    json_object_set_new(
        jn_basic_info,
        "binary",
        json_string(destination)
    );
    //"classifiers"
    json2sdata(hs, jn_basic_info, SDF_PERSIST, 0, 0);
    JSON_DECREF(jn_basic_info);

    gobj_update_resource(priv->resource, hs);

    /*
     *  Convert result in json
     */
    json_t *jn_data = json_array();
    json_array_append_new(jn_data, sdata2json(hs, SDF_PERSIST, 0));

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_delete_binary(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "binaries";

    /*
     *  Get resources to delete.
     *  Search is restricted to id only
     */
    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!id) {
        return msg_iev_build_webix(
            gobj,
            -129,
            json_local_sprintf("'id' required."),
            0,
            0,
            kw  // owned
        );
    }
    hsdata hs = gobj_get_resource(priv->resource, resource, 0, id);
    if(!hs) {
        return msg_iev_build_webix(
            gobj,
            -130,
            json_local_sprintf("Binary not found."),
            0,
            0,
            kw  // owned
        );
    }

    if(total_binary_in_yunos(gobj, id)>0) {
        return msg_iev_build_webix(
        gobj,
            -131,
            json_local_sprintf("Binary used in some yuno."),
            0,
            0,
            kw  // owned
        );
    }

    json_t *jn_classifiers = sdata_read_json(hs, "classifiers");
    const char *role = sdata_read_str(hs, "role");
    const char *version = sdata_read_str(hs, "version");
    char destination[NAME_MAX];
    yuneta_repos_yuno_dir(
        destination,
        sizeof(destination),
        jn_classifiers,
        role,
        version,
        FALSE
    );

    if(gobj_delete_resource(priv->resource, hs)<0) {
        return msg_iev_build_webix(
            gobj,
            -132,
            json_local_sprintf("Cannot delete the binary."),
            0,
            0,
            kw  // owned
        );

    }
    /*
     *  Remove from store in filesystem
     */
    if(access(destination,0)==0) {
        rmrdir(destination);
    }

    return msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf("Binary deleted."),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_list_configs(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "configurations";

    /*
     *  Get a iter of matched resources
     */
    KW_INCREF(kw);
    dl_list_t *iter = gobj_list_resource(priv->resource, resource, kw);
//     iter = sdata_sort_iter_by_id(iter);

    /*
     *  Convert hsdata to json
     */
    json_t *jn_data = sdata_iter2json(iter, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        json_local_sprintf(cmd),
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    rc_free_iter(iter, TRUE, 0);

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_create_config(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "configurations";

    const char *id = kw_get_str(kw, "id", 0, 0);
    const char *name = kw_get_str(kw, "name", "", 0);
    const char *version = kw_get_str(kw, "version", "", 0);
    const char *description = kw_get_str(kw, "description", "", 0);
    const char *source= kw_get_str(kw, "source", "", 0);
    const char *autoupdate= kw_get_str(kw, "autoupdate", "", 0);

    /*------------------------------------------------*
     *      Check if already exists
     *------------------------------------------------*/
    json_t *kw_find = json_pack("{s:s, s:s}",
        "name", name,
        "version", version
    );
    dl_list_t * iter_find = gobj_list_resource(priv->resource, resource, kw_find);
    if(dl_size(iter_find)) {
        /*
         *  1 o more records, yuno already stored and without overwrite.
         */
        json_t *jn_data = sdata_iter2json(iter_find, SDF_PERSIST, 0);
        json_t *webix = msg_iev_build_webix(
            gobj,
            -133,
            json_local_sprintf(
                "Configuration already exists."
            ),
            tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
            jn_data,
            kw  // owned
        );
        rc_free_iter(iter_find, TRUE, 0);
        return webix;
    }
    rc_free_iter(iter_find, TRUE, 0);

    /*
     *  Get content in base64 and decode
     */
    json_t *jn_config;
    const char *content64 = kw_get_str(kw, "content64", "", 0);
    if(!empty_string(content64)) {
        GBUFFER *gbuf_content = gbuf_decodebase64string(content64);
        jn_config = gbuf2json(
            gbuf_content,  // owned
            1
        );
        if(!jn_config) {
            return msg_iev_build_webix(
                gobj,
                -134,
                json_local_sprintf("Bad json in content64"),
                0,
                0,
                kw  // owned
            );
        }
    } else {
        jn_config = json_object();
    }

    /*------------------------------------------------*
     *      Create record
     *------------------------------------------------*/
    json_t *kw_configuration = json_pack("{s:s, s:s, s:s, s:s, s:s}",
        "name", name,
        "version", version,
        "description", description,
        "source", source,
        "autoupdate", autoupdate
    );

    char current_date[22];
    current_timestamp(current_date, sizeof(current_date));  // "CCYY/MM/DD hh:mm:ss"
    json_object_set_new(
        kw_configuration,
        "date",
        json_string(current_date)
    );
    json_object_set_new(
        kw_configuration,
        "zcontent",
        jn_config // owned
    );
    if(id) {
        json_object_set_new(
            kw_configuration,
            "id",
            json_integer(id)
        );
    }

    /*------------------------------------------------*
     *      Store in db
     *------------------------------------------------*/
    hsdata hs = gobj_create_resource(priv->resource, resource, kw_configuration);
    if(!hs) {
        return msg_iev_build_webix(
            gobj,
            -135,
            json_local_sprintf("Cannot create resource."),
            0,
            0,
            kw  // owned
        );
    }

    /*
     *  Convert result in json
     */
    json_t *jn_data = json_array();
    json_array_append_new(jn_data, sdata2json(hs, SDF_PERSIST, 0));

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_update_config(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "configurations";

    /*
     *  Get resources to delete.
     *  Search is restricted to id only
     */
    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!id) {
        return msg_iev_build_webix(
            gobj,
            -136,
            json_local_sprintf("'id' required."),
            0,
            0,
            kw  // owned
        );
    }
    hsdata hs = gobj_get_resource(priv->resource, resource, 0, id);
    if(!hs) {
        return msg_iev_build_webix(
            gobj,
            -137,
            json_local_sprintf("Configuration not found."),
            0,
            0,
            kw  // owned
        );
    }

    /*
     *  Get new config (or not)
     */
    const char *content64 = kw_get_str(kw, "content64", "", 0);
    if(!empty_string(content64)) {
        json_t *jn_config = 0;
        if(!empty_string(content64)) {
            GBUFFER *gbuf_content = gbuf_decodebase64string(content64);
            jn_config = gbuf2json(
                gbuf_content,  // owned
                1
            );
        }
        if(!jn_config) {
            return msg_iev_build_webix(
                gobj,
                -138,
                json_local_sprintf("Bad json in content64"),
                0,
                0,
                kw  // owned
            );
        }
        sdata_write_json(hs, "zcontent", jn_config);
        JSON_DECREF(jn_config);
    }

    /*
     *  Update config
     */
    json2sdata(hs, kw, SDF_PERSIST, 0, 0);

    gobj_update_resource(
        priv->resource,
        hs
    );

    /*
     *  Convert result in json
     */
    json_t *jn_data = json_array();
    json_array_append_new(jn_data, sdata2json(hs, SDF_PERSIST, 0));

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_upgrade_config(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    return cmd_create_config(gobj, cmd, kw, src);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_delete_config(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "configurations";

    /*
     *  Get resources to delete.
     *  Search is restricted to id only
     */
    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!id) {
        return msg_iev_build_webix(gobj,
            -139,
            json_local_sprintf("'id' required."),
            0,
            0,
            kw  // owned
        );
    }
    hsdata hs = gobj_get_resource(priv->resource, resource, 0, id);
    if(!hs) {
        return msg_iev_build_webix(gobj,
            -140,
            json_local_sprintf("Configuration not found."),
            0,
            0,
            kw  // owned
        );
    }
    int use = total_config_in_yunos(gobj, id);
    if(use > 0) {
        return msg_iev_build_webix(gobj,
            -141,
            json_local_sprintf("Cannot delete configuration. It's using in %d yunos.", use),
            0,
            0,
            kw  // owned
        );
    }

    if(gobj_delete_resource(priv->resource, hs)<0) {
        return msg_iev_build_webix(gobj,
            -142,
            json_local_sprintf("Cannot delete the configuration."),
            0,
            0,
            kw  // owned
        );
    }

    return msg_iev_build_webix(gobj,
        0,
        json_local_sprintf("Configuration deleted."),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_top_yunos(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    // TODO serí así con Regular expressions:
    //json_object_set_new(kw, "yuno_alias", json_string("^(?!\s*$).+"));
    // Aunque obligaría a usar re siempre en todas las búsquedas.
    // Porqué no hacer una nueva API que use re? (Suma en vez de sustituir!).

    //json_object_set_new(kw, "disabled", json_false()); A pelo todo de momento.

    /*
     *  Get a iter of matched resources
     */
    KW_INCREF(kw);
    dl_list_t *iter = gobj_list_resource(priv->resource, resource, kw);

    dl_list_t *top_iter = rc_init_iter(0);


    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        BOOL disabled = sdata_read_bool(hs_yuno, "disabled");
        const char *yuno_alias = sdata_read_str(hs_yuno, "yuno_alias");
        if(!disabled || !empty_string(yuno_alias)) {
            rc_add_instance(top_iter, hs_yuno, 0);
        }
        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    rc_free_iter(iter, TRUE, 0);

    /*
     *  Convert hsdata to json
     */
    json_t *jn_data = sdata_iter2json(top_iter, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        json_local_sprintf(cmd),
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    rc_free_iter(top_iter, TRUE, 0);

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_list_yunos(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*
     *  Get a iter of matched resources
     */
    KW_INCREF(kw);
    dl_list_t *iter = gobj_list_resource(priv->resource, resource, kw);
//     iter = sdata_sort_iter_by_id(iter);

    /*
     *  Convert hsdata to json
     */
    json_t *jn_data = sdata_iter2json(iter, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        json_local_sprintf(cmd),
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    rc_free_iter(iter, TRUE, 0);

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
json_t* cmd_create_yuno(hgobj gobj, const char* cmd, json_t* kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*-----------------------------*
     *      Parameter's filter
     *-----------------------------*/
    const char *realm_name = kw_get_str(kw, "realm_name", 0, 0);
    const char *yuno_role = kw_get_str(kw, "yuno_role", 0, 0);
    const char *yuno_name = kw_get_str(kw, "yuno_name", 0, 0);
    const char *role_version = kw_get_str(kw, "role_version", 0, 0);
    const char *name_version = kw_get_str(kw, "name_version", 0, 0);
    BOOL create_config = kw_get_bool(kw, "create-config", 0, 0);

    /*
     *  Fuerza que no sean nulos
     */
    if(!realm_name) {
        json_object_set_new(kw, "realm_name", json_string(""));
        realm_name = kw_get_str(kw, "realm_name", 0, 0);
    }
    if(!yuno_role) {
        json_object_set_new(kw, "yuno_role", json_string(""));
        yuno_role = kw_get_str(kw, "yuno_role", 0, 0);
    }
    if(!yuno_name) {
        json_object_set_new(kw, "yuno_name", json_string(""));
        yuno_name = kw_get_str(kw, "yuno_name", 0, 0);
    }
    if(!role_version) {
        json_object_set_new(kw, "role_version", json_string(""));
        role_version = kw_get_str(kw, "role_version", 0, 0);
    }
    if(!name_version) {
        json_object_set_new(kw, "name_version", json_string("1"));
        name_version = kw_get_str(kw, "name_version", 0, 0);
    }

    const char *realm_id = kw_get_str(kw, "realm_id", 0, 0);
    json_int_t binary_id = kw_get_int(kw, "binary_id", 0, 0);

    if(empty_string(yuno_role) && binary_id==0) {
        return msg_iev_build_webix(gobj,
            -144,
            json_local_sprintf(
                "Role required."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*---------------------------------------------*
     *      Check Realm
     *      realm_id prioritary.
     *---------------------------------------------*/
    if(realm_id) {
        hsdata hs_realm = get_hs_by_id(gobj, "realms", 0, realm_id);
        if(!hs_realm) {
            return msg_iev_build_webix(gobj,
                -145,
                json_local_sprintf(
                    "Realm with id %d not found.", (int)realm_id
                ),
                0,
                0,
                kw  // owned
            );
        }
        json_object_set_new(kw, "realm_name", json_string(sdata_read_str(hs_realm, "name")));

    } else {
        realm_id = find_last_id_by_name(gobj, "realms", "name", realm_name);
        if(!realm_id) {
            return msg_iev_build_webix(gobj,
                -146,
                json_local_sprintf(
                    "Realm '%s' not found.", realm_name
                ),
                0,
                0,
                kw  // owned
            );
        }
        json_object_set_new(kw, "realm_id", json_integer(realm_id));
    }

    /*---------------------------------------------*
     *      Role
     *      binary_id prioritary.
     *---------------------------------------------*/
    hsdata hs_binary = 0;
    if(binary_id) {
        hs_binary = get_hs_by_id(gobj, "binaries", 0, binary_id);
        if(!hs_binary) {
            return msg_iev_build_webix(gobj,
                -147,
                json_local_sprintf(
                    "Binary with id %d not found.", (int)binary_id
                ),
                0,
                0,
                kw  // owned
            );
        }
        json_object_set_new(kw, "yuno_role", json_string(sdata_read_str(hs_binary, "role")));

    } else {
        hs_binary = find_binary_version(gobj, yuno_role, role_version);
        if(!hs_binary) {
            /*
             *  Can be any version, but must exists
             */
            return msg_iev_build_webix(gobj,
                -148,
                json_local_sprintf(
                    "Binary '%s%s%s' not found.",
                    yuno_role,
                    empty_string(role_version)?"":"-",
                    empty_string(role_version)?"":role_version
                ),
                0,
                0,
                kw  // owned
            );
        }
        binary_id = sdata_read_uint64(hs_binary, "id");
        json_object_set_new(kw, "binary_id", json_integer(binary_id));
    }

    /*---------------------------------------------*
     *      Name
     *      config_ids prioritary.
     *---------------------------------------------*/
    json_t *kw_config_ids = kwids_json2kwids(kw_get_dict_value(kw, "config_ids", 0, 0));
    dl_list_t *iter_configs = 0;
    hsdata hs_configuration = 0;

    if(kw_config_ids) {
        iter_configs = gobj_list_resource(
            priv->resource,
            "configurations",
            kw_config_ids // owned
        );

        /*
         *  Configurations can be none or multiple.
         */
        int configurations_to_find = json_array_size(kw_get_dict_value(kw_config_ids, "ids", 0, 0));
        int n_configs = dl_size(iter_configs);
        if(configurations_to_find) {
            if(configurations_to_find != n_configs) {
                rc_free_iter(iter_configs, TRUE, 0);
                return msg_iev_build_webix(gobj,
                    -149,
                    json_local_sprintf(
                        "Some configuration not found."
                    ),
                    0,
                    0,
                    kw  // owned
                );
            }
        }

    } else if(!empty_string(yuno_name)) {
        /*
         *  By name configurations can be none or one.
         */
        hs_configuration = find_configuration_version(
            gobj,
            sdata_read_str(hs_binary, "role"),
            yuno_name,
            name_version
        );
        if(!hs_configuration) {
            if(!create_config) {
                return msg_iev_build_webix(gobj,
                    -150,
                    json_local_sprintf(
                        "Yuno '%s.%s': configuration '%s%s%s' not found.",
                        yuno_role, yuno_name,
                        yuno_name,
                        empty_string(name_version)?"":"-",
                        empty_string(name_version)?"":name_version
                    ),
                    0,
                    0,
                    kw  // owned
                );
            } else {
                /*------------------------------------------------*
                 *      Create record
                 *------------------------------------------------*/
                char some_doc[256];
                snprintf(some_doc, sizeof(some_doc), "Yuno %s", yuno_role);
                json_t *kw_configuration = json_pack("{s:s, s:s, s:s, s:s, s:s}",
                    "name", yuno_name,
                    "version", name_version,
                    "description", some_doc,
                    "source", "",
                    "autoupdate", ""
                );

                char current_date[22];
                current_timestamp(current_date, sizeof(current_date));  // "CCYY/MM/DD hh:mm:ss"
                json_object_set_new(
                    kw_configuration,
                    "date",
                    json_string(current_date)
                );
                json_object_set_new(
                    kw_configuration,
                    "zcontent",
                    json_object() // owned
                );

                /*------------------------------------------------*
                 *      Store in db
                 *------------------------------------------------*/
                hs_configuration = gobj_create_resource(priv->resource, "configurations", kw_configuration);
                if(!hs_configuration) {
                    return msg_iev_build_webix(
                        gobj,
                        -135,
                        json_local_sprintf("Cannot create configuration."),
                        0,
                        0,
                        kw  // owned
                    );
                }
            }
        }
        json_int_t configuration_id = sdata_read_uint64(hs_configuration, "id");
        json_t *jn_array = json_array();
        json_array_append_new(jn_array, json_integer(configuration_id));
        json_object_set_new(kw, "config_ids", jn_array);

        kw_config_ids = kwids_json2kwids(jn_array);
        iter_configs = gobj_list_resource(
            priv->resource,
            "configurations",
            kw_config_ids // owned
        );
    }

    char yuno_release[120];
    build_release_name(yuno_release, sizeof(yuno_release), hs_binary, iter_configs);
    json_object_set_new(kw, "yuno_release", json_string(yuno_release));
    rc_free_iter(iter_configs, TRUE, 0);

    /*---------------------------------------------*
     *      Check multiple yuno
     *---------------------------------------------*/
    BOOL multiple = kw_get_bool(kw, "multiple", 0, 0);
    if(!multiple) {
        /*
         *  Check if already exists
         */
        json_t *kw_find = json_pack("{s:s, s:s, s:s, s:s}",
            "realm_name", realm_name,
            "yuno_role", yuno_role,
            "yuno_name", yuno_name,
            "yuno_release", yuno_release
        );
        dl_list_t * iter_find = gobj_list_resource(priv->resource, resource, kw_find);
        if(dl_size(iter_find)) {
            /*
             *  1 o more records, yuno already stored and without overwrite.
             */
            json_t *jn_data = sdata_iter2json(iter_find, SDF_PERSIST|SDF_VOLATIL, 0);
            json_t *webix = msg_iev_build_webix(
                gobj,
                -151,
                json_local_sprintf(
                    "Yuno already exists."
                ),
                tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
                jn_data,
                kw  // owned
            );
            rc_free_iter(iter_find, TRUE, 0);
            return webix;
        }
        rc_free_iter(iter_find, TRUE, 0);
    }

    /*---------------------------------------------*
     *      Create the yuno
     *---------------------------------------------*/
    const char *keys[] = {
        "realm_name",
        "yuno_role",
        "yuno_name",
        "yuno_release",
        "yuno_alias",

        "realm_id",
        "binary_id",
        "config_ids",

        "disabled",
        "must_play",
        "multiple",
        "global",
        0
    };
    json_t *kw_yuno = kw_duplicate_with_only_keys(kw, keys);
    json_int_t yuno_id = kw_get_int(kw, "id", 0, 0);
    if(yuno_id) {
        // Cannot be done in kw_duplicate_with_only_keys(). The 'id' key must not exist if is 0.
        json_object_set_new(kw_yuno, "id", json_integer(yuno_id));
    }

    hsdata hs_yuno = gobj_create_resource(
        priv->resource,
        resource,
        kw_yuno
    );
    if(!hs_yuno) {
        return msg_iev_build_webix(
            gobj,
            -152,
            json_local_sprintf("Cannot create resource."),
            0,
            0,
            kw  // owned
        );
    }

    /*-----------------------------*
     *  Register public services
     *-----------------------------*/
    register_public_services(gobj, hs_yuno);

    /*
     *  Convert result in json
     */
    json_t *jn_data = json_array();
    json_array_append_new(jn_data, sdata2json(hs_yuno, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0));

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
json_t* cmd_delete_yuno(hgobj gobj, const char* cmd, json_t* kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*
     *  Get resources to delete.
     *  Search is restricted to ids only
     */
    json_t *kw_ids = kwids_extract_and_expand_ids(kw);
    if(!kw_ids) {
        return msg_iev_build_webix(gobj,
            -153,
            json_local_sprintf("'id' or 'ids' are required."),
            0,
            0,
            kw  // owned
        );
    }

    /*---------------------------------------------*
     *      Check Realm
     *---------------------------------------------*/
    const char *realm_name = kw_get_str(kw, "realm_name", "", 0);
    const char *realm_id = kw_get_str(kw, "realm_id", 0, 0);
    if(!realm_id) {
        realm_id = find_last_id_by_name(gobj, "realms", "name", realm_name);
        if(!realm_id) {
            json_decref(kw_ids);
            return msg_iev_build_webix(gobj,
                -146,
                json_local_sprintf(
                    "Realm '%s' not found.", realm_name
                ),
                0,
                0,
                kw  // owned
            );
        }
        json_object_set_new(kw, "realm_id", json_integer(realm_id));
    }

    int deleted = 0;
    int failed = 0;
    json_int_t *ids_list = jsonlist2c(kw_get_dict_value(kw_ids, "ids", 0, 0));
    json_int_t *p_id = ids_list;
    while(*p_id) {
        json_int_t id = *p_id;
        if(id != (json_int_t)-1) {
            hsdata hs = gobj_get_resource(priv->resource, resource, realm_id, id);
            if(hs) {
                BOOL running = sdata_read_bool(hs, "yuno_running");
                if(running) {
                    failed++;
                    p_id++;
                    continue;
                }
                char yuno_bin_path[NAME_MAX];
                build_yuno_bin_path(gobj, hs, yuno_bin_path, sizeof(yuno_bin_path), FALSE);
                if(gobj_delete_resource(priv->resource, hs)==0) {
                    /*
                     *  remove run script
                     */
                    rmrdir(yuno_bin_path);
                    deleted++;
                } else {
                    failed++;
                }
            }
        }
        p_id++;
    }
    if(!deleted) {
        failed = 1;
    }
    gbmem_free(ids_list);
    json_decref(kw_ids);

    /*
     *  Inform
     */
    json_t *webix;
    if(failed) {
        webix = msg_iev_build_webix(gobj,
            -155,
            json_local_sprintf("%d %s deleted. Some yuno not found or it's running.", deleted, resource),
            0,
            0,
            kw  // owned
        );

    } else {
        webix = msg_iev_build_webix(gobj,
            0,
            json_local_sprintf("%d %s deleted.", deleted, resource),
            0,
            0,
            kw  // owned
        );
    }
    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_set_alias(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    const char *yuno_alias = kw_get_str(kw, "alias", 0, 0);
    if(!yuno_alias) {
        return msg_iev_build_webix(gobj,
            -159,
            json_local_sprintf("What alias?"),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -158,
            json_local_sprintf(
                "No yuno found to set alias."
            ),
            0,
            0,
            kw  // owned
        );
    }

    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Set alias
         */
        sdata_write_str(hs_yuno, "yuno_alias", yuno_alias);
        gobj_update_resource(priv->resource, hs_yuno);

        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }

    /*
     *  Convert result in json
     */
    json_t *jn_data = sdata_iter2json(iter_yunos, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);
    rc_free_iter(iter_yunos, TRUE, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return webix;
}

/***************************************************************************
 *  Enable and run/play the last yuno's release
 *  disable the remains found
 ***************************************************************************/
PRIVATE json_t *cmd_top_last_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *realm_name = kw_get_str(kw, "realm_name", "", 0);
    const char *realm_id = kw_get_str(kw, "realm_id", 0, 0);

    /*---------------------------------------------*
     *      Check Realm
     *---------------------------------------------*/
    if(!realm_id) {
        realm_id = find_last_id_by_name(gobj, "realms", "name", realm_name);
        if(!realm_id) {
            return msg_iev_build_webix(gobj,
                -146,
                json_local_sprintf(
                    "Realm '%s' not found.", realm_name
                ),
                0,
                0,
                kw  // owned
            );
        }
        json_object_set_new(kw, "realm_id", json_integer(realm_id));
    }

    /*---------------------------------------------*
     *      Check required attrs
     *---------------------------------------------*/
    const char *yuno_role = kw_get_str(kw, "yuno_role", "", 0);
    const char *yuno_name = kw_get_str(kw, "yuno_name", 0, 0);
    const char *yuno_release = kw_get_str(kw, "yuno_release", 0, 0);
    const char *alias = kw_get_str(kw, "yuno_alias", 0, 0);
    if(empty_string(yuno_role)) {
        return msg_iev_build_webix(gobj,
            -187,
            json_local_sprintf(
                "Yuno role required."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*---------------------------------------------*
     *      Find yuno to top
     *---------------------------------------------*/
    hsdata hs_yuno;
    json_t *kw_find;
    dl_list_t * iter_to_top;
    rc_instance_t *i_hs;
    int found;
    kw_find = json_pack("{s:I, s:s}",
        "realm_id", realm_id,
        "yuno_role", yuno_role
    );
    if(yuno_name) {
        json_object_set_new(kw_find, "yuno_name", json_string(yuno_name));
    }
    if(yuno_release) {
        json_object_set_new(kw_find, "yuno_release", json_string(yuno_release));
    }
    if(alias) {
        json_object_set_new(kw_find, "yuno_alias", json_string(alias));
    }

    KW_INCREF(kw_find);
    iter_to_top = gobj_list_resource(priv->resource, "yunos", kw_find);
    found = dl_size(iter_to_top);
    if(!found) {
        rc_free_iter(iter_to_top, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -191,
            json_local_sprintf(
                "Select one yuno to top."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*---------------------------------------------*
     *      Kill yunos
     *---------------------------------------------*/
    int prev_signal2kill = gobj_read_int32_attr(gobj, "signal2kill");
    gobj_write_int32_attr(gobj, "signal2kill", SIGKILL);

    i_hs = rc_last_instance(iter_to_top, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        BOOL running = sdata_read_bool(hs_yuno, "yuno_running");
        if(running) {
            kill_yuno(gobj, hs_yuno);
        }

        i_hs = rc_prev_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    gobj_write_int32_attr(gobj, "signal2kill", prev_signal2kill);
    rc_free_iter(iter_to_top, TRUE, 0);

    exit(-1); // TODO de momento fuerza la muerte del agente para recargar nueva config.

    /*---------------------------------------------*
     *      Run yunos
     *---------------------------------------------*/
    iter_to_top = gobj_list_resource(priv->resource, "yunos", kw_find);
    i_hs = rc_last_instance(iter_to_top, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        json_int_t yuno_id_to = SDATA_GET_ID(hs_yuno);
        json_t *kw_run = json_pack("{s:I, s:I}",
            "realm_id", realm_id,
            "id", yuno_id_to
        );
        cmd_run_yuno(gobj, "run-yuno", kw_run, src);

        i_hs = rc_prev_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    gobj_write_int32_attr(gobj, "signal2kill", prev_signal2kill);

    /*
     *  Inform
     */
    json_t *jn_data = sdata_iter2json(iter_to_top, SDF_PERSIST, 0);
    rc_free_iter(iter_to_top, TRUE, 0);

    json_t *webix = msg_iev_build_webix(
        gobj,
        0,
        0,
        RESOURCE_WEBIX_SCHEMA(priv->resource, "yunos"),
        jn_data, // owned
        kw  // owned
    );

    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_run_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    json_object_set_new(kw, "disabled", json_false());
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    int found = rc_iter_size(iter_yunos);
    if(found == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -161,
            json_local_sprintf(
                "No yuno found to run."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *  Walk over yunos iter:
     *      run
     *      add filter for future counter.
     *------------------------------------------------*/
    json_t *filterlist = json_array();
    int total_run = 0;
    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Run the yuno
         */
        BOOL disabled = sdata_read_bool(hs_yuno, "disabled");
        BOOL yuno_running = sdata_read_bool(hs_yuno, "yuno_running");
        if(!disabled && !yuno_running) {
            int r = run_yuno(gobj, hs_yuno, src);
            if(r==0) {
                json_int_t id = SDATA_GET_ID(hs_yuno);
                json_t *jn_EvChkItem = json_pack("{s:s, s:{s:I, s:I, s:I}}",
                    "event", "EV_ON_OPEN",
                    "filters",
                        "identity_card`realm_id", sdata_read_uint64(hs_yuno, "realm_id"),
                        "identity_card`yuno_id", id,
                        "identity_card`launch_id", sdata_read_uint64(hs_yuno, "launch_id")
                );
                json_array_append_new(filterlist, jn_EvChkItem);
                if(src != gobj) {
                    sdata_write_str(hs_yuno, "solicitante", gobj_name(src));
                } else {
                    sdata_write_str(hs_yuno, "solicitante", "");
                }
                total_run++;
            } else {
                // TODO por aquí se escapa algo.
                log_error(0,
                    "gobj",             "%s", gobj_full_name(gobj),
                    "function",         "%s", __FUNCTION__,
                    "msgset",           "%s", MSGSET_INTERNAL_ERROR,
                    "msg",              "%s", "run_yuno() FAILED",
                    "ret",              "%d", r,
                    NULL
                );
            }

        }
        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }

    if(!total_run) {
        rc_free_iter(iter_yunos, TRUE, 0);
        JSON_DECREF(filterlist);
        return msg_iev_build_webix(gobj,
            -162,
            json_local_sprintf(
                "No yuno found to run."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*--------------------------------------*
     *  Crea con counter un futuro
     *  que nos indique cuando han arrancado
     *  all yunos arrancados.
     *--------------------------------------*/
    KW_INCREF(kw);
    json_t *kw_answer = kw;

    char info[80];
    snprintf(info, sizeof(info), "%d yunos found to run", total_run);
    json_t *kw_counter = json_pack("{s:s, s:i, s:i, s:o, s:I, s:I}",
        "info", info,
        "max_count", total_run,
        "expiration_timeout", 10*1000,
        "input_schema", filterlist, // owned
        "user_data", (json_int_t)(size_t)iter_yunos,    // HACK free en diferido, en ac_final_count()
        "user_data2", (json_int_t)(size_t)kw_answer     // HACK free en diferido, ac_final_count()
    );

    hgobj gobj_counter = gobj_create("", GCLASS_COUNTER, kw_counter, gobj);

    /*
     *  Subcribe al objeto counter a los eventos del router
     */
    json_t *kw_sub = json_pack("{s:{s:s}}",
        "__config__", "__rename_event_name__", "EV_COUNT"
    );
    gobj_subscribe_event(gobj_child_by_name(gobj, "__input_side__", 0), "EV_ON_OPEN", kw_sub, gobj_counter);

// KKK
    /*
     *  Subcribeme a mí al evento final del counter, con msg_id
     *  msg_id: con que me diga quien es el requester de este comando me vale
     *  HACK: Meto un msg_id en la subscripción al counter.
     *  Así en la publicación recibida recuperamos el msg_id que contiene el 'requester'
     *  que pusimos.
     *  Además le decimos al counter que se suscriba al evento EV_ON_OPEN del router,
     *  pero diciendo que reciba un rename, EV_COUNT, que es el que está definido en la máquina.
     *  Con los filtros le decimos que cuente los eventos recibidos que además
     *  cumplan con los filtros pasados. Es decir, identificamos, entre los posible multiples
     *  eventos recibidos en la publicación, justo al evento que queremos.
     */
    json_t *kw_final_count = json_object();
    if(src != gobj) {
        // Si la petición no viene del propio agente, guarda al requester
        json_t *global = json_object();
        json_object_set_new(kw_final_count, "__global__", global);
        json_t *jn_msg_id = json_pack("{s:s}",
            "requester", gobj_name(src)
        );
        msg_iev_push_stack(
            global,
            "requester_stack",
            jn_msg_id
        );
    }

    gobj_subscribe_event(gobj_counter, "EV_FINAL_COUNT", kw_final_count, gobj);

    gobj_start(gobj_counter);

    KW_DECREF(kw);
    return 0;   // Asynchronous response
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_kill_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    BOOL app = kw_get_bool(kw, "app", 0, 0);
    BOOL force = kw_get_bool(kw, "force", 0, 0);

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    json_object_set_new(kw, "yuno_running", json_true());
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    int total_to_kill = rc_iter_size(iter_yunos);
    if(total_to_kill == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -164,
            json_local_sprintf(
                "No yuno found to kill."
            ),
            0,
            0,
            kw  // owned
        );
    }

    int prev_signal2kill = 0;
    if(force) {
        prev_signal2kill = gobj_read_int32_attr(gobj, "signal2kill");
        gobj_write_int32_attr(gobj, "signal2kill", SIGKILL);
    }

    /*------------------------------------------------*
     *  Walk over yunos iter:
     *      kill
     *      add filter for future counter.
     *------------------------------------------------*/
    json_t *filterlist = json_array();
    int total_killed = 0;
    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_last_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Kill the yuno
         */
        BOOL yuno_running = sdata_read_bool(hs_yuno, "yuno_running");
        json_int_t id = SDATA_GET_ID(hs_yuno);
        if(app && id < 1000) {
            i_hs = rc_prev_instance(i_hs, (rc_resource_t **)&hs_yuno);
            continue;
        }
        if(yuno_running) {
            if(kill_yuno(gobj, hs_yuno)==0) {
                json_int_t channel_gobj = (json_int_t)(size_t)sdata_read_pointer(hs_yuno, "channel_gobj");
                json_t *jn_EvChkItem = json_pack("{s:s, s:{s:I}}",
                    "event", "EV_ON_CLOSE",
                    "filters",
                        "__temp__`channel_gobj", channel_gobj
                );
                json_array_append_new(filterlist, jn_EvChkItem);
                total_killed++;
            } else {
                if(force) {
                    gobj_write_int32_attr(gobj, "signal2kill", prev_signal2kill);
                }
                rc_free_iter(iter_yunos, TRUE, 0);
                JSON_DECREF(filterlist);
                return msg_iev_build_webix(gobj,
                    -165,
                    json_local_sprintf(
                        "Can't kill yuno: %s.", gobj_get_message_error(gobj)
                    ),
                    0,
                    0,
                    kw  // owned
                );
            }
        }
        i_hs = rc_prev_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }

    if(force) {
        gobj_write_int32_attr(gobj, "signal2kill", prev_signal2kill);
    }

    if(!total_killed) {
        rc_free_iter(iter_yunos, TRUE, 0);
        JSON_DECREF(filterlist);
        return msg_iev_build_webix(gobj,
            -166,
            json_local_sprintf(
                "No yuno found to kill."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*--------------------------------------*
     *  Crea con counter un futuro
     *  que nos indique cuando han arrancado
     *  all yunos arrancados.
     *--------------------------------------*/
    KW_INCREF(kw);
    json_t *kw_answer = kw;

    char info[80];
    snprintf(info, sizeof(info), "%d yunos found to kill", total_killed);
    json_t *kw_counter = json_pack("{s:s, s:i, s:i, s:o, s:I, s:I}",
        "info", info,
        "max_count", total_killed,
        "expiration_timeout", 10*1000,
        "input_schema", filterlist, // owned
        "user_data", (json_int_t)(size_t)iter_yunos,    // HACK free en diferido, en ac_final_count()
        "user_data2", (json_int_t)(size_t)kw_answer     // HACK free en diferido, ac_final_count()
    );

    hgobj gobj_counter = gobj_create("", GCLASS_COUNTER, kw_counter, gobj);
    json_t *kw_sub = json_pack("{s:{s:s}}",
        "__config__", "__rename_event_name__", "EV_COUNT"
    );

    /*
     *  Subcribe al objeto counter a los eventos del router
     */
    gobj_subscribe_event(gobj_child_by_name(gobj, "__input_side__", 0), "EV_ON_CLOSE", kw_sub, gobj_counter);

// KKK
    /*
     *  Subcribeme a mí al evento final del counter, con msg_id
     *  msg_id: con que me diga quien es el requester de este comando me vale
     */
    json_t *kw_final_count = json_object();
    if(src != gobj) {
        // Si la petición no viene del propio agente, guarda al requester
        json_t *global = json_object();
        json_object_set_new(kw_final_count, "__global__", global);
        json_t *jn_msg_id = json_pack("{s:s}",
            "requester", gobj_name(src)
        );
        msg_iev_push_stack(
            global,
            "requester_stack",
            jn_msg_id
        );
    }

    gobj_subscribe_event(gobj_counter, "EV_FINAL_COUNT", kw_final_count, gobj);

    gobj_start(gobj_counter);

    KW_DECREF(kw);
    return 0;   // Asynchronous response
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_play_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    json_object_set_new(kw, "disabled", json_false());
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -168,
            json_local_sprintf(
                "No yuno found to play."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *  Walk over yunos iter:
     *      play
     *      add filter for future counter.
     *------------------------------------------------*/
    json_t *filterlist = json_array();
    int total_already_playing = 0;
    int total_to_played = 0;
    int total_to_preplayed = 0;
    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Play the yuno
         */
        if(!sdata_read_bool(hs_yuno, "must_play")) {
            sdata_write_bool(hs_yuno, "must_play", TRUE);
            gobj_update_resource(priv->resource, hs_yuno);
            total_to_preplayed++;
        }

        BOOL yuno_running = sdata_read_bool(hs_yuno, "yuno_running");
        if(!yuno_running) {
            i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
            continue;
        }
        BOOL yuno_playing = sdata_read_bool(hs_yuno, "yuno_playing");
        if(!yuno_playing) {
            /*
             *  HACK le meto un id al mensaje de petición PLAY_YUNO
             *  que lo devolverá en el mensaje respuesta PLAY_YUNO_ACK.
             */
            json_int_t filter_ref = (json_int_t)long_reference();
            json_t *jn_msg = json_object();
            kw_set_subdict_value(jn_msg, "__md_iev__", "__id__", json_integer(filter_ref));
            if(play_yuno(gobj, hs_yuno, jn_msg, src)==0) {
                /*
                 *  HACK Guarda el filtro para el counter.
                 *  Realmente solo se necesita para informar al cliente
                 *  solo después de que se hayan ejecutado sus ordenes.
                 */
                json_t *jn_EvChkItem = json_pack("{s:s, s:{s:I}}",
                    "event", "EV_PLAY_YUNO_ACK",
                    "filters",
                        "__md_iev__`__id__", (json_int_t)filter_ref
                );
                json_array_append_new(filterlist, jn_EvChkItem);
                total_to_played++;
            }
        } else {
            total_already_playing++;
        }
        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }

    if(!total_to_played && !total_to_preplayed) {
        json_t *jn_data = 0;
        if(total_already_playing) {
            jn_data = sdata_iter2json(iter_yunos, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);
        }
        rc_free_iter(iter_yunos, TRUE, 0);
        JSON_DECREF(filterlist);
        return msg_iev_build_webix(gobj,
            0,
            json_local_sprintf(
                "No yuno found to play."
            ),
            0,
            jn_data, // owned
            kw  // owned
        );
    }
    if(!total_to_played) {
        rc_free_iter(iter_yunos, TRUE, 0);
        JSON_DECREF(filterlist);
        return msg_iev_build_webix(gobj,
            0,
            json_local_sprintf(
                "%d yunos found to preplay.",
                total_to_preplayed
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*--------------------------------------*
     *  Crea con counter un futuro
     *  que nos indique cuando han arrancado
     *  all yunos arrancados.
     *--------------------------------------*/
    KW_INCREF(kw);
    json_t *kw_answer = kw;

    char info[80];
    snprintf(info, sizeof(info), "%d to preplay, %d to play.",
        total_to_preplayed,
        total_to_played
    );
    json_t *kw_counter = json_pack("{s:s, s:i, s:i, s:o, s:I, s:I}",
        "info", info,
        "max_count", total_to_played,
        "expiration_timeout", 10*1000,
        "input_schema", filterlist, // owned
        "user_data", (json_int_t)(size_t)iter_yunos,    // HACK free en diferido, en ac_final_count()
        "user_data2", (json_int_t)(size_t)kw_answer     // HACK free en diferido, ac_final_count()
    );

    hgobj gobj_counter = gobj_create("", GCLASS_COUNTER, kw_counter, gobj);
    json_t *kw_sub = json_pack("{s:{s:s}}",
        "__config__", "__rename_event_name__", "EV_COUNT"
    );

    /*
     *  Subcribe al objeto counter a los eventos del router
     */
    gobj_subscribe_event(
        gobj,
        "EV_PLAY_YUNO_ACK",
        kw_sub,
        gobj_counter
    );

// KKK
    /*
     *  Subcribeme a mí al evento final del counter, con msg_id
     *  msg_id: con que me diga quien es el requester de este comando me vale
     */
    json_t *kw_final_count = json_object();
    if(src != gobj) {
        // Si la petición no viene del propio agente, guarda al requester
        json_t *global = json_object();
        json_object_set_new(kw_final_count, "__global__", global);
        json_t *jn_msg_id = json_pack("{s:s}",
            "requester", gobj_name(src)
        );
        msg_iev_push_stack(
            global,
            "requester_stack",
            jn_msg_id
        );
    }

    gobj_subscribe_event(gobj_counter, "EV_FINAL_COUNT", kw_final_count, gobj);

    gobj_start(gobj_counter);

    KW_DECREF(kw);
    return 0;   // Asynchronous response
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_pause_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    json_object_set_new(kw, "disabled", json_false());
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -172,
            json_local_sprintf(
                "No yuno found to pause."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *  Walk over yunos iter:
     *      pause
     *      add filter for future counter.
     *------------------------------------------------*/
    json_t *filterlist = json_array();
    int total_already_pausing = 0;
    int total_to_paused = 0;
    int total_to_prepaused = 0;
    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_last_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Pause the yuno
         */
        if(sdata_read_bool(hs_yuno, "must_play")) {
            sdata_write_bool(hs_yuno, "must_play", FALSE);
            gobj_update_resource(priv->resource, hs_yuno);
            total_to_prepaused++;
        }
        BOOL yuno_playing = sdata_read_bool(hs_yuno, "yuno_playing");
        if(yuno_playing) {
            json_int_t filter_ref = (json_int_t)long_reference();
            json_t *jn_msg = json_object();
            kw_set_dict_value(jn_msg, "__md_iev__`__id__", json_integer(filter_ref));
            if(pause_yuno(gobj, hs_yuno, jn_msg, src)==0) {
                json_t *jn_EvChkItem = json_pack("{s:s, s:{s:I}}",
                    "event", "EV_PAUSE_YUNO_ACK",
                    "filters",
                        "__md_iev__`__id__", (json_int_t)filter_ref
                );
                json_array_append_new(filterlist, jn_EvChkItem);
                total_to_paused++;
            }
        } else {
            total_already_pausing++;
        }
        i_hs = rc_prev_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }

    if(!total_to_paused && !total_to_prepaused) {
        json_t *jn_data = 0;
        if(total_already_pausing) {
            jn_data = sdata_iter2json(iter_yunos, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);
        }
        rc_free_iter(iter_yunos, TRUE, 0);
        JSON_DECREF(filterlist);
        return msg_iev_build_webix(gobj,
            0,
            json_local_sprintf(
                "No yuno found to pause."
            ),
            0,
            jn_data,
            kw  // owned
        );
    }
    if(!total_to_paused) {
        rc_free_iter(iter_yunos, TRUE, 0);
        JSON_DECREF(filterlist);
        return msg_iev_build_webix(gobj,
            0,
            json_local_sprintf(
                "%d yunos found to prepause.",
                total_to_prepaused
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*--------------------------------------*
     *  Crea con counter un futuro
     *  que nos indique cuando han arrancado
     *  all yunos arrancados.
     *--------------------------------------*/
    KW_INCREF(kw);
    json_t *kw_answer = kw;

    char info[80];
    snprintf(info, sizeof(info), "%d to prepause, %d to pause.",
        total_to_prepaused,
        total_to_paused
    );
    json_t *kw_counter = json_pack("{s:s, s:i, s:i, s:o, s:I, s:I}",
        "info", info,
        "max_count", total_to_paused,
        "expiration_timeout", 10*1000,
        "input_schema", filterlist, // owned
        "user_data", (json_int_t)(size_t)iter_yunos,    // HACK free en diferido, en ac_final_count()
        "user_data2", (json_int_t)(size_t)kw_answer     // HACK free en diferido, ac_final_count()
    );

    hgobj gobj_counter = gobj_create("", GCLASS_COUNTER, kw_counter, gobj);
    json_t *kw_sub = json_pack("{s:{s:s}}",
        "__config__", "__rename_event_name__", "EV_COUNT"
    );

    /*
     *  Subcribe al objeto counter a los eventos del router
     */
    gobj_subscribe_event(
        gobj,
        "EV_PAUSE_YUNO_ACK",
        kw_sub,
        gobj_counter
    );

// KKK
    /*
     *  Subcribeme a mí al evento final del counter, con msg_id
     *  msg_id: con que me diga quien es el requester de este comando me vale
     */
    json_t *kw_final_count = json_object();
    if(src != gobj) {
        // Si la petición no viene del propio agente, guarda al requester
        json_t *global = json_object();
        json_object_set_new(kw_final_count, "__global__", global);
        json_t *jn_msg_id = json_pack("{s:s}",
            "requester", gobj_name(src)
        );
        msg_iev_push_stack(
            global,
            "requester_stack",
            jn_msg_id
        );
    }

    gobj_subscribe_event(gobj_counter, "EV_FINAL_COUNT", kw_final_count, gobj);

    gobj_start(gobj_counter);

    KW_DECREF(kw);
    return 0;   // Asynchronous response
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t* cmd_enable_yuno(hgobj gobj, const char* cmd, json_t* kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    json_object_set_new(kw, "disabled", json_true());
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -175,
            json_local_sprintf(
                "No yuno found to enable."
            ),
            0,
            0,
            kw  // owned
        );
    }

    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Enable yuno
         */
        BOOL disabled = sdata_read_bool(hs_yuno, "disabled");
        if(disabled) {
            enable_yuno(gobj, hs_yuno);
        }
        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    rc_free_iter(iter_yunos, TRUE, 0);

    json_object_set_new(kw, "disabled", json_false()); // Show enabled!
    return cmd_list_yunos(
        gobj,
        cmd,
        kw,  // owned
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t* cmd_disable_yuno(hgobj gobj, const char* cmd, json_t* kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    json_object_set_new(kw, "disabled", json_false());
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -177,
            json_local_sprintf(
                "No yuno found to disable."
            ),
            0,
            0,
            kw  // owned
        );
    }

    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Disable yuno
         */
        BOOL disabled = sdata_read_bool(hs_yuno, "disabled");
        if(!disabled) {
            BOOL playing = sdata_read_bool(hs_yuno, "yuno_playing");
            if(playing) {
                pause_yuno(gobj, hs_yuno, 0, src);
            }
            BOOL running = sdata_read_bool(hs_yuno, "yuno_running");
            if(running) {
                kill_yuno(gobj, hs_yuno);
            }
            disable_yuno(gobj, hs_yuno);
        }

        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    rc_free_iter(iter_yunos, TRUE, 0);

    json_object_set_new(kw, "disabled", json_true()); // Show disabled!
    return cmd_list_yunos(
        gobj,
        cmd,
        kw,  // owned
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t* cmd_trace_on_yuno(hgobj gobj, const char* cmd, json_t* kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -208,
            json_local_sprintf(
                "No yuno found to trace-on."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Remove properties of this
     *------------------------------------------------*/
    if(kw_has_key(kw, "id")) {
        json_object_del(kw, "id");
    }
    if(kw_has_key(kw, "ids")) {
        json_object_del(kw, "ids");
    }
    if(kw_has_key(kw, "reaml_id")) {
        json_object_del(kw, "realm_id");
    }

    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Trace on yuno
         */
        sdata_write_bool(hs_yuno, "traced", TRUE);
        json_t *kw_clone = msg_iev_pure_clone(kw);
        trace_on_yuno(gobj, hs_yuno, kw_clone, src);
        gobj_update_resource(priv->resource, hs_yuno);

        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    rc_free_iter(iter_yunos, TRUE, 0);

    json_object_set_new(kw, "traced", json_true()); // Show trace!
    return cmd_list_yunos(
        gobj,
        cmd,
        kw,  // owned
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t* cmd_trace_off_yuno(hgobj gobj, const char* cmd, json_t* kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -209,
            json_local_sprintf(
                "No yuno found to trace-off."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Remove properties of this
     *------------------------------------------------*/
    if(kw_has_key(kw, "id")) {
        json_object_del(kw, "id");
    }
    if(kw_has_key(kw, "ids")) {
        json_object_del(kw, "ids");
    }
    if(kw_has_key(kw, "reaml_id")) {
        json_object_del(kw, "realm_id");
    }

    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Trace on yuno
         */
        sdata_write_bool(hs_yuno, "traced", FALSE);
        json_t *kw_clone = msg_iev_pure_clone(kw);
        trace_off_yuno(gobj, hs_yuno, kw_clone, src);
        gobj_update_resource(priv->resource, hs_yuno);

        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    rc_free_iter(iter_yunos, TRUE, 0);

    json_object_set_new(kw, "traced", json_false()); // Show trace!
    return cmd_list_yunos(
        gobj,
        cmd,
        kw,  // owned
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_command_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    const char *command = kw_get_str(kw, "command", 0, 0);
    if(empty_string(command)) {
        return msg_iev_build_webix(gobj,
            -178,
            json_local_sprintf(
                "What command?"
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    KW_INCREF(kw);
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -180,
            json_local_sprintf(
                "No yuno found."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Remove properties of this
     *------------------------------------------------*/
    if(kw_has_key(kw, "id")) {
        json_object_del(kw, "id");
    }
    if(kw_has_key(kw, "ids")) {
        json_object_del(kw, "ids");
    }
    if(kw_has_key(kw, "reaml_id")) {
        json_object_del(kw, "realm_id");
    }

    /*------------------------------------------------*
     *      Send command
     *------------------------------------------------*/
    int raised = 0;
    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Command to yuno
         */
        BOOL running = sdata_read_bool(hs_yuno, "yuno_running");
        if(running) {
            json_t *kw_yuno = json_deep_copy(kw);
            command_to_yuno(gobj, hs_yuno, command, kw_yuno, src);
            raised++;
        }

        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    rc_free_iter(iter_yunos, TRUE, 0);

    if(!raised) {
        return msg_iev_build_webix(gobj,
            -181,
            json_local_sprintf(
                "Yuno not running."
            ),
            0,
            0,
            kw  // owned
        );
    }

    KW_DECREF(kw);
    return 0;   /* Asynchronous response */
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_stats_yuno(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    const char *stats = kw_get_str(kw, "stats", "", 0);

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    KW_INCREF(kw);
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    if(rc_iter_size(iter_yunos) == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return msg_iev_build_webix(gobj,
            -183,
            json_local_sprintf(
                "No yuno found."
            ),
            0,
            0,
            kw  // owned
        );
    }

    /*------------------------------------------------*
     *      Remove properties of this
     *------------------------------------------------*/
    if(kw_has_key(kw, "id")) {
        json_object_del(kw, "id");
    }
    if(kw_has_key(kw, "ids")) {
        json_object_del(kw, "ids");
    }
    if(kw_has_key(kw, "reaml_id")) {
        json_object_del(kw, "realm_id");
    }

    /*------------------------------------------------*
     *      Send stats
     *------------------------------------------------*/
    int raised = 0;
    hsdata hs_yuno; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    while(i_hs) {
        /*
         *  Stats of yuno
         */
        BOOL running = sdata_read_bool(hs_yuno, "yuno_running");
        if(running) {
            json_t *kw_yuno = json_deep_copy(kw);
            stats_to_yuno(gobj, hs_yuno, stats, kw_yuno, src);
            raised++;
        }

        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_yuno);
    }
    rc_free_iter(iter_yunos, TRUE, 0);

    if(!raised) {
        return msg_iev_build_webix(gobj,
            -184,
            json_local_sprintf(
                "Yuno not running."
            ),
            0,
            0,
            kw  // owned
        );
    }

    KW_DECREF(kw);
    return 0;   /* Asynchronous response */
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_command_agent(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *command = kw_get_str(kw, "command", 0, 0);
    if(empty_string(command)) {
        return msg_iev_build_webix(gobj,
            -178,
            json_local_sprintf(
                "What command?"
            ),
            0,
            0,
            kw  // owned
        );
    }
    const char *service = kw_get_str(kw, "service", "", 0);

    hgobj service_gobj;
    if(empty_string(service)) {
        service_gobj = gobj_default_service();
    } else {
        service_gobj = gobj_find_service(service, FALSE);
        if(!service_gobj) {
            return msg_iev_build_webix(gobj,
                -178,
                json_local_sprintf("Service '%s' not found.", service),
                0,
                0,
                kw  // owned
            );
        }
    }

    json_t *webix = gobj_command(
        service_gobj,
        command,
        kw, // owned
        src
    );
    return webix;

}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_stats_agent(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *stats = kw_get_str(kw, "stats", "", 0);
    const char *service = kw_get_str(kw, "service", "", 0);

    hgobj service_gobj;
    if(empty_string(service)) {
        service_gobj = gobj_default_service();
    } else {
        service_gobj = gobj_find_service(service, FALSE);
        if(!service_gobj) {
            return msg_iev_build_webix(gobj,
                -178,
                json_local_sprintf("Service '%s' not found.", service),
                0,
                0,
                kw  // owned
            );
        }
    }

    json_t *webix = gobj_stats(
        service_gobj,
        stats,
        kw, // owned
        src
    );
    return webix;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_set_okill(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    gobj_write_int32_attr(gobj, "signal2kill", SIGQUIT);
    return msg_iev_build_webix(gobj,
        0,
        json_local_sprintf("Set kill mode = ordered (with SIGQUIT)."),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_set_qkill(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    gobj_write_int32_attr(gobj, "signal2kill", SIGKILL);
    return msg_iev_build_webix(gobj,
        0,
        json_local_sprintf("Set kill mode = quick (with SIGKILL)."),
        0,
        0,
        kw  // owned
    );
}



            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *      Execute command
 ***************************************************************************/
PRIVATE int exec_startup_command(hgobj gobj)
{
    const char *startup_command = gobj_read_str_attr(gobj, "startup_command");
    if(!empty_string(startup_command)) {
        log_debug(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_STARTUP,
            "msg",          "%s", "exec_startup_command",
            "cmd",          "%s", startup_command,
            NULL
        );
        if(system(startup_command)!=0) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                "msg",          "%s", "system() FAILED",
                "script",       "%s", startup_command,
                "errno",        "%d", errno,
                "strerror",     "%s", strerror(errno),
                NULL
            );
        }
    }
    return 0;
}

/***************************************************************************
 *  Build the private domain of yuno (defined by his realm)
 ***************************************************************************/
PRIVATE char * build_yuno_private_domain(hgobj gobj, hsdata hs_yuno, char *bf, int bfsize, BOOL create_dir)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *p;
    *bf = 0;

    json_int_t realm_id = sdata_read_uint64(hs_yuno, "realm_id");
    hsdata hs_realm = gobj_get_resource(priv->resource, "realms", 0, realm_id);
    if(!hs_realm) {
        return 0;
    }

    p = bf + strlen(bf);
    snprintf(p, bfsize - strlen(bf), "/realms");

    const char *domain = sdata_read_str(hs_realm, "domain");
    const char *role = sdata_read_str(hs_realm, "role");
    const char *name = sdata_read_str(hs_realm, "name");
    if(!empty_string(domain)) {
        p = bf + strlen(bf);
        if(*domain == '/') {
            snprintf(p, bfsize - strlen(bf), "%s", domain);
        } else {
            snprintf(p, bfsize - strlen(bf), "/%s", domain);
        }
    }
    if(!empty_string(role)) {
        p = bf + strlen(bf);
        snprintf(p, bfsize - strlen(bf), "/%s", role);
    }
    if(!empty_string(name)) {
        p = bf + strlen(bf);
        snprintf(p, bfsize - strlen(bf), "/%s", name);
    }
    strtolower(bf); // domain in lower case

    char role_plus_name[NAME_MAX];
    build_role_plus_name(role_plus_name, sizeof(role_plus_name), hs_yuno);

    p = bf + strlen(bf);
    snprintf(p, bfsize - strlen(bf), "/%s",
        role_plus_name
    );

    if(create_dir) {
        mkrdir(bf, 0, yuneta_xpermission());
    }
    return bf;
}

/***************************************************************************
 *  Build the public domain of yuno (defined by his realm)
 ***************************************************************************/
PRIVATE char * build_yuno_public_domain(
    hgobj gobj,
    hsdata hs_yuno,
    char *subdomain,
    char *bf,
    int bfsize,
    BOOL create_dir)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *p;
    *bf = 0;

    json_int_t realm_id = sdata_read_uint64(hs_yuno, "realm_id");
    hsdata hs_realm = gobj_get_resource(priv->resource, "realms", 0, realm_id);
    if(!hs_realm) {
        return 0;
    }

    p = bf + strlen(bf);
    snprintf(p, bfsize - strlen(bf), "/public/%s/realms", subdomain);

    const char *domain = sdata_read_str(hs_realm, "domain");
    const char *role = sdata_read_str(hs_realm, "role");
    const char *name = sdata_read_str(hs_realm, "name");
    if(!empty_string(domain)) {
        p = bf + strlen(bf);
        if(*domain == '/') {
            snprintf(p, bfsize - strlen(bf), "%s", domain);
        } else {
            snprintf(p, bfsize - strlen(bf), "/%s", domain);
        }
    }
    if(!empty_string(role)) {
        p = bf + strlen(bf);
        snprintf(p, bfsize - strlen(bf), "/%s", role);
    }
    if(!empty_string(name)) {
        p = bf + strlen(bf);
        snprintf(p, bfsize - strlen(bf), "/%s", name);
    }
    strtolower(bf); // domain in lower case

    char role_plus_name[NAME_MAX];
    build_role_plus_name(role_plus_name, sizeof(role_plus_name), hs_yuno);

    p = bf + strlen(bf);
    snprintf(p, bfsize - strlen(bf), "/%s",
        role_plus_name
    );

    if(create_dir) {
        mkrdir(bf, 0, yuneta_xpermission());
    }
    return bf;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int build_role_plus_name(char *bf, int bf_len, hsdata hs_yuno)
{
    const char *yuno_role = sdata_read_str(hs_yuno, "yuno_role");
    const char *yuno_name = sdata_read_str(hs_yuno, "yuno_name");

    if(empty_string(yuno_name)) {
        snprintf(bf, bf_len, "%s",
            yuno_role
        );
    } else {
        snprintf(bf, bf_len, "%s^%s",
            yuno_role,
            yuno_name
        );
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE char * build_yuno_bin_path(hgobj gobj, hsdata hs_yuno, char *bf, int bfsize, BOOL create_dir)
{
    char *p;

    *bf = 0;

    const char *work_dir = yuneta_work_dir();
    p = bf + strlen(bf);
    snprintf(p, bfsize - strlen(bf), "%s", work_dir);

    p = bf + strlen(bf);
    build_yuno_private_domain(gobj, hs_yuno, p, bfsize - strlen(bf), create_dir);
    p = bf + strlen(bf);
    snprintf(p, bfsize - strlen(bf), "/bin");

    json_int_t yuno_id = SDATA_GET_ID(hs_yuno);
    p = bf + strlen(bf);
    snprintf(p, bfsize - strlen(bf), "/%03"JSON_INTEGER_FORMAT,
        yuno_id
    );

    if(create_dir) {
        mkrdir(bf, 0, yuneta_xpermission());
    }
    return bf;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE char * build_yuno_log_path(hgobj gobj, hsdata hs_yuno, char *bf, int bfsize, BOOL create_dir)
{
    char *p;

    *bf = 0;

    const char *work_dir = yuneta_work_dir();
    p = bf + strlen(bf);
    snprintf(p, bfsize - strlen(bf), "%s", work_dir);

    p = bf + strlen(bf);
    build_yuno_public_domain(gobj, hs_yuno, "logs", p, bfsize - strlen(bf), create_dir);

    if(create_dir) {
        mkrdir(bf, 0, yuneta_xpermission());
    }
    return bf;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int save_pid_in_file(hgobj gobj, hsdata hs_yuno, uint32_t pid)
{
    char yuno_bin_path[NAME_MAX];
    char filename_pid_path[NAME_MAX];
    /*
     *  Let it create the bin_path. Can exist some zombi yuno.
     */
    build_yuno_bin_path(gobj, hs_yuno, yuno_bin_path, sizeof(yuno_bin_path), TRUE);
    snprintf(filename_pid_path, sizeof(filename_pid_path), "%s/yuno.pid", yuno_bin_path);
    FILE *file = fopen(filename_pid_path, "w");
    fprintf(file, "%d\n", pid);
    fclose(file);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int enable_yuno(hgobj gobj, hsdata hs_yuno)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    sdata_write_bool(hs_yuno, "disabled", FALSE);

    return gobj_update_resource(
        priv->resource,
        hs_yuno
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int disable_yuno(hgobj gobj, hsdata hs_yuno)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    sdata_write_bool(hs_yuno, "disabled", TRUE);

    return gobj_update_resource(
        priv->resource,
        hs_yuno
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int find_required_services_size(hgobj gobj, json_int_t binary_id)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    hsdata hs_binary = gobj_get_resource(priv->resource, "binaries", 0, binary_id);
    if(!hs_binary) {
        return 0;
    }
    json_t *jn_required_services = sdata_read_json(hs_binary, "required_services");
    return json_array_size(jn_required_services);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE const char *find_bind_ip(hgobj gobj, json_int_t realm_id)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    hsdata hs_realm = gobj_get_resource(priv->resource, "realms", 0, realm_id);
    if(!hs_realm) {
        return "";
    }
    const char *bind_ip = sdata_read_str(hs_realm, "bind_ip");
    if(!bind_ip) {
        return "";
    }
    return bind_ip;
}

/***************************************************************************
 *  Find a service for client
 ***************************************************************************/
PRIVATE hsdata find_service_for_client(hgobj gobj, const char *service_, hsdata hs_yuno)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "public_services";

    char *service = gbmem_strdup(service_);

    json_int_t realm_id = sdata_read_uint64(hs_yuno, "realm_id");
    char *service_yuno_name = strchr(service, '.');
    if(service_yuno_name) {
        *service_yuno_name = 0;
        service_yuno_name++; // yuno_name of service required
    }

    /*
     *  llamando igual al yuno servicio y al yuno cliente
     */
    json_t *kw_find = json_pack("{s:I, s:s}",
        "realm_id", realm_id,
        "service", service
    );
    if(service_yuno_name) {
        json_object_set_new(kw_find, "yuno_name", json_string(service_yuno_name));
    }

    dl_list_t * iter_find = gobj_list_resource(priv->resource, resource, kw_find);

    hsdata hs=0;
    rc_last_instance(iter_find, (rc_resource_t **)&hs);
    rc_free_iter(iter_find, TRUE, 0);
    if(hs) {
        gbmem_free(service);
        return hs;
    }

    /*
     *  Busca sin reino
     */
    kw_find = json_pack("{s:s}",
        "service", service
    );
    if(service_yuno_name) {
        json_object_set_new(kw_find, "yuno_name", json_string(service_yuno_name));
    }

    iter_find = gobj_list_resource(priv->resource, resource, kw_find);
    rc_last_instance(iter_find, (rc_resource_t **)&hs);
    rc_free_iter(iter_find, TRUE, 0);

    gbmem_free(service);

    return hs;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int write_service_client_connectors(
    hgobj gobj,
    hsdata hs_yuno,
    const char *config_path
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    const char *realm_name_ = sdata_read_str(hs_yuno, "realm_name");
    const char *yuno_role_ = sdata_read_str(hs_yuno, "yuno_role");
    const char *yuno_name_ = sdata_read_str(hs_yuno, "yuno_name");
    json_int_t binary_id = sdata_read_uint64(hs_yuno, "binary_id");
    hsdata hs_binary = gobj_get_resource(priv->resource, "binaries", 0, binary_id);
    json_t *jn_required_services = sdata_read_json(hs_binary, "required_services");
    if(json_array_size(jn_required_services)==0) {
        return 0;
    }
    json_t *jn_services = json_array();
    json_t *jn_yuno_services = json_pack("{s:o}",
        "services", jn_services
    );
    GBUFFER *gbuf_config = gbuf_create((size_t)4*1024, (size_t)256*1024, 0, 0);
    size_t index;
    json_t *jn_service;
    json_array_foreach(jn_required_services, index, jn_service) {
        const char *yuno_service = json_string_value(jn_service);
        if(empty_string(yuno_service)) {
            continue;
        }
        hsdata hs_service = find_service_for_client(gobj, yuno_service, hs_yuno);
        if(!hs_service) {
            log_error(0,
                "gobj",             "%s", gobj_full_name(gobj),
                "function",         "%s", __FUNCTION__,
                "msgset",           "%s", MSGSET_SERVICE_ERROR,
                "msg",              "%s", "required service NOT FOUND",
                "required service", "%s", yuno_service,
                "realm_name",       "%s", realm_name_?realm_name_:"",
                "yuno_role",        "%s", yuno_role_?yuno_role_:"",
                "yuno_name",        "%s", yuno_name_?yuno_name_:"",
                NULL
            );
            continue;
        }
        json_t *jn_connector = sdata_read_json(hs_service, "connector");
        if(!jn_connector) {
            log_error(0,
                "gobj",             "%s", gobj_full_name(gobj),
                "function",         "%s", __FUNCTION__,
                "msgset",           "%s", MSGSET_SERVICE_ERROR,
                "msg",              "%s", "service connector NULL",
                "required service", "%s", yuno_service,
                "realm_name",       "%s", realm_name_?realm_name_:"",
                "yuno_role",        "%s", yuno_role_?yuno_role_:"",
                "yuno_name",        "%s", yuno_name_?yuno_name_:"",
                NULL
            );
            continue;
        }
        const char *url = sdata_read_str(hs_service, "url");
        const char *yuno_role = sdata_read_str(hs_service, "yuno_role");
        const char *yuno_name = sdata_read_str(hs_service, "yuno_name");
        const char *schema = sdata_read_str(hs_service, "schema");
        const char *ip =  sdata_read_str(hs_service, "ip");
        uint32_t port_ =  sdata_read_uint32(hs_service, "port");
        char port[32];
        snprintf(port, sizeof(port), "%d", port_);
        json_t * jn_config_variables = json_pack("{s:{s:s, s:s, s:s, s:s, s:s, s:s, s:s}}",
            "__json_config_variables__",
                "__yuno_name__", yuno_name,
                "__yuno_role__", yuno_role,
                "__yuno_service__", yuno_service,
                "__ip__", ip,
                "__port__", port,
                "__schema__", schema,
                "__url__", url
        );

        json_t *kw_connector = kw_apply_json_config_variables(jn_connector, jn_config_variables);
        json_decref(jn_config_variables);
        json_array_append_new(jn_services, kw_connector);
    }

    json_append2gbuf(
        gbuf_config,
        jn_yuno_services // owned
    );

    gbuf2file( // save: service connectors
        gbuf_config, // owned
        config_path,
        yuneta_rpermission(),
        TRUE
    );

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *assigned_yuno_global_service_variables(
    hgobj gobj,
    json_int_t realm_id,
    json_int_t yuno_id,
    const char *yuno_name,
    const char *yuno_role
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    json_t *jn_global_content = json_object();

    /*
     *  Busca los servicios públicos de este yuno.
     */

    /*
     *  Crea una entrada en global por servicio: "__service__`__json_config_variables__"
     *  con
     *      __yuno_name__
     *      __yuno_role__
     *      __yuno_service__
     *      __url__
     *      __port__
     *      __ip__
     *
     */
    json_t *kw_find = json_pack("{s:I, s:I}",
        "realm_id", realm_id,
        "yuno_id", yuno_id
    );
    dl_list_t *iter = gobj_list_resource(priv->resource, "public_services", kw_find);

    hsdata hs; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter, (rc_resource_t **)&hs);
    while(i_hs) {
        /*
         *  Add the service variables
         */
        const char *service = sdata_read_str(hs, "service");
        char key[256];
        snprintf(key, sizeof(key), "%s.__json_config_variables__", service);
        json_t *jn_variables = json_object();
        json_object_set_new(jn_global_content, key, jn_variables);

        const char *ip = sdata_read_str(hs, "ip");
        uint32_t port_ = sdata_read_uint32(hs, "port");
        char port[32];
        snprintf(port, sizeof(port), "%d", port_);
        const char *url = sdata_read_str(hs, "url");

        json_object_set_new(jn_variables, "__yuno_name__", json_string(yuno_name));
        json_object_set_new(jn_variables, "__yuno_role__", json_string(yuno_role));
        json_object_set_new(jn_variables, "__yuno_service__", json_string(service));
        json_object_set_new(jn_variables, "__ip__", json_string(ip));
        json_object_set_new(jn_variables, "__port__", json_string(port));
        json_object_set_new(jn_variables, "__url__", json_string(url));

        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs);
    }
    rc_free_iter(iter, TRUE, 0);

    return jn_global_content;
}

/***************************************************************************
 *
 ***************************************************************************/
GBUFFER *build_yuno_running_script(
    hgobj gobj,
    GBUFFER* gbuf_script,
    hsdata hs_yuno,
    char *bfbinary,
    int bfbinary_size
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    const char *work_dir = yuneta_work_dir();
    json_int_t yuno_id = SDATA_GET_ID(hs_yuno);

    /*
     *  Build the domain of yuno (defined by his realm)
     */
    char domain_dir[NAME_MAX];
    build_yuno_private_domain(gobj, hs_yuno, domain_dir, sizeof(domain_dir), TRUE);

    char yuno_bin_path[NAME_MAX];
    build_yuno_bin_path(gobj, hs_yuno, yuno_bin_path, sizeof(yuno_bin_path), TRUE);

    /*
     *  Get the binary
     */
    json_int_t binary_id = sdata_read_uint64(hs_yuno, "binary_id");
    json_int_t realm_id = sdata_read_uint64(hs_yuno, "realm_id");
    BOOL multiple = sdata_read_bool(hs_yuno, "multiple");
    const char *bind_ip = find_bind_ip(gobj, realm_id);
    const char *realm_name = sdata_read_str(hs_yuno, "realm_name");
    const char *yuno_role = sdata_read_str(hs_yuno, "yuno_role");
    const char *yuno_name = sdata_read_str(hs_yuno, "yuno_name");
    const char *yuno_alias = sdata_read_str(hs_yuno, "yuno_alias");
    const char *yuno_release = sdata_read_str(hs_yuno, "yuno_release");
    uint64_t launch_id = sdata_read_uint64(hs_yuno, "launch_id");

    hsdata hs_binary = gobj_get_resource(priv->resource, "binaries", 0, binary_id);
    if(!hs_binary) {
        return 0;
    }
    const char *binary = sdata_read_str(hs_binary, "binary");
    char role_plus_name[NAME_MAX];
    build_role_plus_name(role_plus_name, sizeof(role_plus_name), hs_yuno);

    /*
     *  Build the run script
     */
//     gbuf_printf(gbuf_script, "%s", binary);
    snprintf(bfbinary, bfbinary_size, "%s", binary);

    char config_file_name[NAME_MAX];
    char config_path[NAME_MAX];
    int n_config = 0;
    gbuf_printf(gbuf_script, "[");
    if(1) {
        /*------------------------------------*
         *      Put agent client service
         *------------------------------------*/
        snprintf(config_file_name, sizeof(config_file_name), "%d-%s",
            n_config+1,
            role_plus_name
        );
        snprintf(config_path, sizeof(config_path), "%s/%s.json", yuno_bin_path, config_file_name);

        GBUFFER *gbuf_config = gbuf_create((size_t)4*1024, 256*1024, 0, 0);
        char *client_agent_config = gbmem_strdup(agent_filter_chain_config);
        helper_quote2doublequote(client_agent_config);

        gbuf_printf(
            gbuf_config,
            client_agent_config,
            realm_name,
            (int)realm_id,
            (int)yuno_id
        );

        gbuf2file( // save: agent connector
            gbuf_config, // owned
            config_path,
            yuneta_rpermission(),
            TRUE
        );
        if(n_config > 0) {
            gbuf_printf(gbuf_script, ",");
        }
        gbuf_printf(gbuf_script, "\"%s\"", config_path);

        n_config++;

        gbmem_free(client_agent_config);

        /*--------------------------------------*
         *      Put required service clients
         *--------------------------------------*/
        int required_services = find_required_services_size(gobj, binary_id);
        if(required_services) {
            snprintf(config_file_name, sizeof(config_file_name), "%d-%s",
                n_config+1,
                role_plus_name
            );
            snprintf(config_path, sizeof(config_path), "%s/%s.json", yuno_bin_path, config_file_name);
            write_service_client_connectors( // save: service connectors
                gobj,
                hs_yuno,
                config_path
            );
            if(n_config > 0) {
                gbuf_printf(gbuf_script, ",");
            }
            gbuf_printf(gbuf_script, "\"%s\"", config_path);
            n_config++;
        }

        /*--------------------------------------*
         *      Put yuno configuration
         *--------------------------------------*/
        dl_list_t *iter_config_ids = sdata_read_iter(hs_yuno, "config_ids");
        if(rc_iter_size(iter_config_ids)>0) {
            hsdata hs_config; rc_instance_t *i_hs;
            i_hs = rc_first_instance(iter_config_ids, (rc_resource_t **)&hs_config);
            while(i_hs) {
                GBUFFER *gbuf_config = gbuf_create(4*1024, 256*1024, 0, 0);
                snprintf(config_file_name, sizeof(config_file_name), "%d-%s",
                    n_config+1,
                    role_plus_name
                );
                snprintf(config_path, sizeof(config_path), "%s/%s.json", yuno_bin_path, config_file_name);

                json_t *content = sdata_read_json(hs_config, "zcontent");
                JSON_INCREF(content);
                json_append2gbuf(
                    gbuf_config,
                    content // owned
                );

                gbuf2file( // save: user configurations
                    gbuf_config, // owned
                    config_path,
                    yuneta_rpermission(),
                    TRUE
                );
                if(n_config > 0) {
                    gbuf_printf(gbuf_script, ",");
                }
                gbuf_printf(gbuf_script, "\"%s\"", config_path);
                n_config++;
                i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs_config);
            }
        }
    }
    if(1) {
        /*-------------------------------------------*
         *      Put environment and yuno variables
         *-------------------------------------------*/
        snprintf(config_file_name, sizeof(config_file_name), "%d-%s",
            n_config+1,
            role_plus_name
        );
        snprintf(config_path, sizeof(config_path), "%s/%s.json", yuno_bin_path, config_file_name);

        GBUFFER *gbuf_config = gbuf_create(4*1024, 256*1024, 0, 0);

        json_t *jn_global = assigned_yuno_global_service_variables(
            gobj,
            realm_id,
            yuno_id,
            yuno_name,
            yuno_role
        );
        json_t *jn_node_variables = gobj_read_json_attr(gobj, "node_variables");
        if(jn_node_variables) {
            json_object_update(jn_global, jn_node_variables);
        }

        json_t *jn_environment = json_pack("{s:s, s:s}",
            "work_dir", work_dir,
            "domain_dir", domain_dir
        );
        json_t *jn_content = json_pack("{s:o, s:o, s:{s:s, s:s, s:s, s:s, s:I, s:s, s:b, s:I}}",
            "global", jn_global,
            "environment", jn_environment,
            "yuno",
                "realm_name", realm_name?realm_name:"",
                "yuno_name", yuno_name?yuno_name:"",
                "yuno_alias", yuno_alias?yuno_alias:"",
                "yuno_release", yuno_release?yuno_release:"",
                "realm_id", realm_id,
                "bind_ip", bind_ip?bind_ip:"",
                "multiple", multiple,
                "launch_id", (json_int_t)launch_id
        );
        json_t *jn_agent_environment = gobj_read_json_attr(gobj, "agent_environment");
        if(jn_agent_environment) {
            // HACK Override the yuno environment by agent environment.
            json_object_update(jn_environment, jn_agent_environment);
        }

        json_append2gbuf(
            gbuf_config,
            jn_content  //owned
        );

        gbuf2file( // save: environment and yuno variables
            gbuf_config, // owned
            config_path,
            yuneta_rpermission(),
            TRUE
        );
        if(n_config > 0) {
            gbuf_printf(gbuf_script, ",");
        }
        gbuf_printf(gbuf_script, "\"%s\"", config_path);
        n_config++;
    }
    gbuf_printf(gbuf_script, "]");

    return gbuf_script;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int run_yuno(hgobj gobj, hsdata hs_yuno, hgobj src)
{
    /*
     *  Launch id
     *  TODO cuando un yuno no arranca y no encuentra una .so, aparece como running al agente
     */
    static uint16_t counter = 0;
    uint64_t t;
    time((time_t*)&t);
    t = t<<(sizeof(uint16_t)*8);
    t += ++counter;
    sdata_write_uint64(hs_yuno, "launch_id", t);

    char bfbinary[NAME_MAX];
    GBUFFER *gbuf_sh = gbuf_create(4*1024, 32*1024, 0, 0);
    build_yuno_running_script(gobj, gbuf_sh, hs_yuno, bfbinary, sizeof(bfbinary));

    json_int_t realm_id = sdata_read_uint64(hs_yuno, "realm_id");
    json_int_t yuno_id = sdata_read_uint64(hs_yuno, "id");
    const char *realm_name = sdata_read_str(hs_yuno, "realm_name");
    const char *yuno_role = sdata_read_str(hs_yuno, "yuno_role");
    const char *yuno_name = sdata_read_str(hs_yuno, "yuno_name");
    const char *yuno_alias = sdata_read_str(hs_yuno, "yuno_alias");
    const char *yuno_release = sdata_read_str(hs_yuno, "yuno_release");

    char yuno_bin_path[NAME_MAX];
    build_yuno_bin_path(gobj, hs_yuno, yuno_bin_path, sizeof(yuno_bin_path), TRUE);

    char role_plus_name[NAME_MAX];
    build_role_plus_name(role_plus_name, sizeof(role_plus_name), hs_yuno);

    char script_path[NAME_MAX];
    snprintf(script_path, sizeof(script_path), "%s/%s.sh", yuno_bin_path, role_plus_name);

    char exec_cmd[PATH_MAX];
    snprintf(exec_cmd, sizeof(exec_cmd), "%s --start", script_path);

    log_debug(0,
        "gobj",         "%s", gobj_full_name(gobj),
        "function",     "%s", __FUNCTION__,
        "msgset",       "%s", MSGSET_STARTUP,
        "msg",          "%s", "running yuno",
        "realm_id",     "%d", (int)realm_id,
        "yuno_id",      "%d", (int)yuno_id,
        "realm_name",   "%s", realm_name?realm_name:"",
        "yuno_role",    "%s", yuno_role,
        "yuno_name",    "%s", yuno_name?yuno_name:"",
        "yuno_alias",   "%s", yuno_name?yuno_alias:"",
        "yuno_release", "%s", yuno_release?yuno_release:"",
        "exec_cmd",     "%s", exec_cmd,
        NULL
    );

    char *bfarg = gbuf_cur_rd_pointer(gbuf_sh);
    //     int ret = system(exec_cmd);
    char *const argv[]={(char *)yuno_role, "-f", bfarg, "--start", 0};

    int ret = run_process2(bfbinary, argv);
    if(ret != 0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "Cannot run the yuno",
            "realm_id",     "%d", (int)realm_id,
            "yuno_id",      "%d", (int)yuno_id,
            "yuno_role",    "%s", yuno_role,
            "yuno_name",    "%s", yuno_name?yuno_name:"",
            "yuno_alias",   "%s", yuno_name?yuno_alias:"",
            "yuno_release", "%s", yuno_release?yuno_release:"",
            "ret",          "%d", ret,
            NULL
        );
    }

    int fd = newfile(script_path, yuneta_xpermission(), TRUE);
    if(fd<0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "newfile() FAILED",
            "path",         "%s", script_path,
            "errno",        "%d", errno,
            "strerror",     "%s", strerror(errno),
            NULL
        );
    } else {
        write(fd, bfbinary, strlen(bfbinary));
        write(fd, " --config-file='", strlen(" --config-file='"));
        write(fd, bfarg, strlen(bfarg));
        write(fd, "' $1\n", strlen("' $1\n"));
        close(fd);
    }
    gbuf_decref(gbuf_sh);
    return ret;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int kill_yuno(hgobj gobj, hsdata hs_yuno)
{
    /*
     *  Get some yuno data
     */
    int signal2kill = gobj_read_int32_attr(gobj, "signal2kill");
    if(!signal2kill) {
        signal2kill = SIGQUIT;
    }

    json_int_t yuno_id = sdata_read_uint64(hs_yuno, "id");
    json_int_t realm_id = sdata_read_uint64(hs_yuno, "realm_id");
    const char *yuno_role = sdata_read_str(hs_yuno, "yuno_role");
    const char *yuno_name = sdata_read_str(hs_yuno, "yuno_name");
    const char *yuno_release = sdata_read_str(hs_yuno, "yuno_release");
    uint32_t pid = sdata_read_uint32(hs_yuno, "yuno_pid");
    if(!pid) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "yuno PID NULL",

            "realm_id",     "%d", (int)realm_id,
            "yuno_id",      "%d", (int)yuno_id,
            "pid",          "%d", (int)pid,
            "yuno_role",    "%s", yuno_role,
            "yuno_name",    "%s", yuno_name?yuno_name:"",
            "yuno_release", "%s", yuno_release?yuno_release:"",

            NULL
        );
        return -1;
    }
    log_debug(0,
        "gobj",         "%s", gobj_full_name(gobj),
        "function",     "%s", __FUNCTION__,
        "msgset",       "%s", MSGSET_STARTUP,
        "msg",          "%s", "killing yuno",
        "realm_id",     "%d", (int)realm_id,
        "yuno_id",      "%d", (int)yuno_id,
        "pid",          "%d", (int)pid,
        "yuno_role",    "%s", yuno_role,
        "yuno_name",    "%s", yuno_name?yuno_name:"",
        "yuno_release", "%s", yuno_release?yuno_release:"",
        NULL
    );
    if(kill(pid, signal2kill)<0) { //  TODO remove pidfile on kill successful
        int last_errno = errno;
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "Cannot kill yuno",
            "realm_id",     "%d", (int)realm_id,
            "yuno_id",      "%d", (int)yuno_id,
            "pid",          "%d", (int)pid,
            "yuno_role",    "%s", yuno_role,
            "yuno_name",    "%s", yuno_name?yuno_name:"",
            "yuno_release", "%s", yuno_release?yuno_release:"",
            "error",        "%d", last_errno,
            "strerror",     "%s", strerror(last_errno),
            NULL
        );
        gobj_set_message_error(gobj, strerror(last_errno));
        if(last_errno == ESRCH) { // No such process
            return 0; // Wait ev_on_close is nosense.
        }
        return -1;
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int play_yuno(hgobj gobj, hsdata hs_yuno, json_t *kw, hgobj src)
{
    hgobj channel_gobj = sdata_read_pointer(hs_yuno, "channel_gobj");
    if(!channel_gobj) {
        KW_DECREF(kw);
        return -1;
    }
    return gobj_send_event(
        channel_gobj,
        "EV_PLAY_YUNO",
        kw,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int pause_yuno(hgobj gobj, hsdata hs_yuno, json_t *kw, hgobj src)
{
    hgobj channel_gobj = sdata_read_pointer(hs_yuno, "channel_gobj");
    if(!channel_gobj) {
        KW_DECREF(kw);
        return -1;
    }
    return gobj_send_event(
        channel_gobj,
        "EV_PAUSE_YUNO",
        kw,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int trace_on_yuno(hgobj gobj, hsdata hs_yuno, json_t *kw,  hgobj src)
{
    hgobj channel_gobj = sdata_read_pointer(hs_yuno, "channel_gobj");
    if(!channel_gobj) {
        return -1;
    }
    json_object_set_new(kw, "service", json_string("__yuno__"));

    char command[256];
    snprintf(
        command,
        sizeof(command),
        "set-gobj-trace "
        "level=%d set=1",
        TRACE_USER_LEVEL
    );
    json_t *webix = gobj_command( // debe retornar siempre 0.
        channel_gobj,
        command,
        kw,
        gobj
    );
    JSON_DECREF(webix);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int trace_off_yuno(hgobj gobj, hsdata hs_yuno, json_t *kw,  hgobj src)
{
    hgobj channel_gobj = sdata_read_pointer(hs_yuno, "channel_gobj");
    if(!channel_gobj) {
        return -1;
    }
    json_object_set_new(kw, "service", json_string("__yuno__"));

    char command[256];
    snprintf(
        command,
        sizeof(command),
        "set-gobj-trace "
        "level=%d set=0",
        TRACE_USER_LEVEL
    );
    json_t *webix = gobj_command( // debe retornar siempre 0.
        channel_gobj,
        command,
        kw,
        src //gobj
    );
    JSON_DECREF(webix);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int command_to_yuno(hgobj gobj, hsdata hs_yuno, const char *command, json_t *kw, hgobj src)
{
    hgobj channel_gobj = sdata_read_pointer(hs_yuno, "channel_gobj");
    if(!channel_gobj) {
        KW_DECREF(kw);
        return -1;
    }
    json_t *webix = gobj_command( // debe retornar siempre 0.
        channel_gobj,
        command,
        kw,
        src //gobj
    );
    JSON_DECREF(webix);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int stats_to_yuno(hgobj gobj, hsdata hs_yuno, const char* stats, json_t* kw, hgobj src)
{
    hgobj channel_gobj = sdata_read_pointer(hs_yuno, "channel_gobj");
    if(!channel_gobj) {
        KW_DECREF(kw);
        return -1;
    }
    json_t *webix =  gobj_stats(  // debe retornar siempre 0.
        channel_gobj,
        stats,
        kw,
        src // gobj
    );
    JSON_DECREF(webix);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int total_yunos_in_realm(hgobj gobj, json_int_t realm_id)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *kw_find = json_pack("{s:I}",
        "realm_id", realm_id
    );
    dl_list_t *iter = gobj_list_resource(priv->resource, "yunos", kw_find);
    int yunos = rc_iter_size(iter);
    rc_free_iter(iter, TRUE, 0);
    return yunos;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int total_binary_in_yunos(hgobj gobj, json_int_t binary_id)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *kw_find = json_pack("{s:I}",
        "binary_id", binary_id
    );
    /*
     *  Esta bien así, no le paso realm_id porque los quiero all.
     */
    dl_list_t *iter = gobj_list_resource(priv->resource, "yunos", kw_find);
    int binaries = rc_iter_size(iter);
    rc_free_iter(iter, TRUE, 0);
    return binaries;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int total_config_in_yunos(hgobj gobj, json_int_t config_id)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *kw_find = json_pack("{s:[I]}",
        "config_ids", config_id
    );
    /*
     *  Esta bien así, no le paso realm_id porque los quiero all.
     */
    dl_list_t *iter = gobj_list_resource(priv->resource, "yunos", kw_find);
    int binaries = rc_iter_size(iter);
    rc_free_iter(iter, TRUE, 0);
    return binaries;
}

/***************************************************************************
 *  Try to run the activated yunos.
 *  This function is periodically called by timer
 ***************************************************************************/
PRIVATE int run_enabled_yunos(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    log_debug(0,
        "gobj",         "%s", gobj_full_name(gobj),
        "function",     "%s", __FUNCTION__,
        "msgset",       "%s", MSGSET_STARTUP,
        "msg",          "%s", "run_enabled_yunos",
        NULL
    );
    /*
     *  Esta bien así, no le paso nada, que devuelva all yunos de all reinos.
     */
    json_t *iter_yunos = gobj_list_nodes(priv->resource, resource, 0, 0, 0);
    int idx; json_t *yuno;
    json_array_foreach(iter_yunos, idx, yuno) {
        /*
         *  Activate the yuno
         */
        BOOL disabled = kw_get_bool(yuno, "disabled", 0, KW_REQUIRED);
        if(!disabled) {
            BOOL running = kw_get_bool(yuno, "yuno_running", 0, KW_REQUIRED);
            if(!running) {
                run_yuno(gobj, yuno, 0);
            }
        }
    }
    JSON_DECREF(iter_yunos);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int audit_command_cb(const char *command, json_t *kw, void *user_data)
{
    hgobj gobj = user_data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->audit_file) {
        if(!kw) {
            kw = json_object();
        } else {
            KW_INCREF(kw);
        }
        char fecha[32];
        current_timestamp(fecha, sizeof(fecha));
        json_t *jn_cmd = json_pack("{s:s, s:s, s:o}",
            "command", command,
            "date", fecha,
            "kw", kw
        );
        if(jn_cmd) {
            char *audit = json2str(jn_cmd);
            if(audit) {
                rotatory_write(priv->audit_file, LOG_AUDIT, audit, strlen(audit));
                rotatory_write(priv->audit_file, LOG_AUDIT, "\n", 1);  // double new line: the separator field
                gbmem_free(audit);
            }
            json_decref(jn_cmd);
        }
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE hsdata get_hs_by_id(hgobj gobj, const char* resource, json_int_t parent_id, json_int_t id)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    return gobj_get_resource(priv->resource, resource, parent_id, id);
}

/***************************************************************************
 *  Comprueba si existe al menos un recurso con ese nombre
 ***************************************************************************/
PRIVATE json_int_t find_last_id_by_name(hgobj gobj, const char *resource, const char *key, const char *value)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *kw_find = json_pack("{s:s}",
        key, value
    );

    json_int_t id = 0;
    dl_list_t * iter_find = gobj_list_resource(priv->resource, resource, kw_find);
    if(dl_size(iter_find)) {
        /*
         *  1 o more records
         */
        hsdata hs; rc_instance_t *i_hs;
        i_hs = rc_last_instance(iter_find, (rc_resource_t **)&hs);
        if(i_hs) {
            id = sdata_read_uint64(hs, "id");
        }
    }
    rc_free_iter(iter_find, TRUE, 0);
    return id;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE hsdata find_binary_version(hgobj gobj, const char *role, const char *version)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *kw_find = json_pack("{s:s}",
        "role", role
    );

    dl_list_t * iter_find = gobj_list_resource(priv->resource, "binaries", kw_find);

    hsdata hs=0; rc_instance_t *i_hs;
    i_hs = rc_last_instance(iter_find, (rc_resource_t **)&hs);
    while(i_hs) {
        const char *version_ = sdata_read_str(hs, "version");
        if(empty_string(version)) {
            // Get the last if no version wanted.
            break;
        }
        if(strcmp(version, version_)==0) {
            /*
             *  Found the wanted version.
             *  FUTURE we can manage operators like python (>=, =, <=)
             */
            break;
        }
        i_hs = rc_prev_instance(i_hs, (rc_resource_t **)&hs);
    }

    rc_free_iter(iter_find, TRUE, 0);

    return hs;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE hsdata find_configuration_version(hgobj gobj, const char *role, const char *name, const char *version)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *kw_find = json_pack("{s:s}",
        "name", name
    );
    dl_list_t * iter_find = gobj_list_resource(priv->resource, "configurations", kw_find);

    hsdata hs=0; rc_instance_t *i_hs;
    i_hs = rc_last_instance(iter_find, (rc_resource_t **)&hs);
    while(i_hs) {
        const char *version_ = sdata_read_str(hs, "version");
        if(empty_string(version)) {
            // Get the last if no version wanted.
            break;
        }
        if(strcmp(version, version_)==0) {
            /*
             *  Found the wanted version.
             *  FUTURE we can manage operators like python (>=, =, <=)
             */
            break;
        }
        i_hs = rc_prev_instance(i_hs, (rc_resource_t **)&hs);
    }
    rc_free_iter(iter_find, TRUE, 0);

    /*
     *  Search with role prefix.
     */
    char with_prefix[120];
    snprintf(with_prefix, sizeof(with_prefix), "%s.%s", role, name);
    kw_find = json_pack("{s:s}",
        "name", with_prefix
    );
    iter_find = gobj_list_resource(priv->resource, "configurations", kw_find);

    i_hs = rc_last_instance(iter_find, (rc_resource_t **)&hs);
    while(i_hs) {
        const char *version_ = sdata_read_str(hs, "version");
        if(empty_string(version)) {
            // Get the last if no version wanted.
            break;
        }
        if(strcmp(version, version_)==0) {
            /*
             *  Found the wanted version.
             *  FUTURE we can manage operators like python (>=, =, <=)
             */
            break;
        }
        i_hs = rc_prev_instance(i_hs, (rc_resource_t **)&hs);
    }
    rc_free_iter(iter_find, TRUE, 0);

    return hs;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int build_release_name(char *bf, int bfsize, hsdata hs_binary, dl_list_t *iter_configs)
{
    int len;
    char *p = bf;

    const char *binary_version = sdata_read_str(hs_binary, "version");
    snprintf(p, bfsize, "%s", binary_version);
    len = strlen(p); p += len; bfsize -= len;

    hsdata hs=0; rc_instance_t *i_hs;
    i_hs = rc_first_instance(iter_configs, (rc_resource_t **)&hs);
    while(i_hs) {
        const char *version_ = sdata_read_str(hs, "version");

        snprintf(p, bfsize, "-%s", version_);
        len = strlen(p); p += len; bfsize -= len;

        i_hs = rc_next_instance(i_hs, (rc_resource_t **)&hs);
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE hsdata find_public_service(
    hgobj gobj,
    json_int_t realm_id,
    const char *yuno_role,
    const char *yuno_name,
    const char *service)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "public_services";

    json_t *kw_find = json_pack("{s:I, s:s, s:s, s:s}",
        "realm_id", realm_id,
        "yuno_role", yuno_role,
        "yuno_name", yuno_name,
        "service", service
    );

    dl_list_t * iter_find = gobj_list_resource(priv->resource, resource, kw_find);

    hsdata hs=0;
    rc_last_instance(iter_find, (rc_resource_t **)&hs);
    rc_free_iter(iter_find, TRUE, 0);

    return hs;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int get_new_service_port(hgobj gobj, hsdata hs_realm)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    uint32_t new_port = 0;
    json_t *jn_range_ports = sdata_read_json(hs_realm, "range_ports");
    json_t *jn_port_list = json_expand_integer_list(jn_range_ports);

    uint32_t last_port = sdata_read_uint32(hs_realm, "last_port");
    if(!last_port) {
        new_port = json_list_int(jn_port_list, 0);
    } else {
        int idx = json_list_int_index(jn_port_list, last_port);
        if(idx < 0) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "integer not in list",
                "realm_id",     "%d", (int)SDATA_GET_ID(hs_realm),
                NULL
            );
            JSON_DECREF(jn_port_list);
            return 0;
        }
        idx ++;
        if(idx >= json_array_size(jn_port_list)) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_SERVICE_ERROR,
                "msg",          "%s", "Range of ports are exhausted",
                "realm_id",     "%d", (int)SDATA_GET_ID(hs_realm),
                NULL
            );
            JSON_DECREF(jn_port_list);
            return 0;
        }
        new_port = json_list_int(jn_port_list, idx);
    }
    sdata_write_uint32(hs_realm, "last_port", new_port);
    gobj_update_resource(priv->resource, hs_realm);

    JSON_DECREF(jn_port_list);
    return new_port;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int register_public_services(hgobj gobj, hsdata hs_yuno)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "public_services";

    json_int_t yuno_id = SDATA_GET_ID(hs_yuno);
    const char *yuno_role = sdata_read_str(hs_yuno, "yuno_role");
    const char *yuno_name = sdata_read_str(hs_yuno, "yuno_name");
    json_int_t binary_id = sdata_read_uint64(hs_yuno, "binary_id");
    json_int_t realm_id = sdata_read_uint64(hs_yuno, "realm_id");
    hsdata hs_binary = get_hs_by_id(gobj, "binaries", 0, binary_id);
    hsdata hs_realm = get_hs_by_id(gobj, "realms", 0, realm_id);

    json_t *jn_public_services = sdata_read_json(hs_binary, "public_services");
    json_t *jn_service_descriptor = sdata_read_json(hs_binary, "service_descriptor");
    if(jn_public_services) {
        size_t index;
        json_t *jn_service;
        json_array_foreach(jn_public_services, index, jn_service) {
            const char *service = json_string_value(jn_service);
            if(empty_string(service)) {
                continue;
            }

            json_t *jn_descriptor = kw_get_dict_value(jn_service_descriptor, service, 0, 0);
            const char *description = kw_get_str(jn_descriptor, "description", "", 0);
            const char *schema = kw_get_str(jn_descriptor, "schema", "", 0);
            json_t *jn_connector = kw_get_dict_value(jn_descriptor, "connector", 0, 0);

            int port = 0;

            /*
             *  Check if already exists the service
             */
            hsdata hs_service = find_public_service(
                gobj,
                realm_id,
                yuno_role,
                yuno_name,
                service
            );
            if(hs_service) {
                sdata_write_str(hs_service, "description", description);
                sdata_write_str(hs_service, "schema", schema);
                sdata_write_json(hs_service, "connector", jn_connector);
                port = sdata_read_uint32(hs_service, "port");

            } else {
                json_t *kw_write_service = json_pack("{s:s, s:s, s:s, s:s, s:s, s:I}",
                    "service", service,
                    "description", description,
                    "schema", schema,
                    "yuno_role", yuno_role,
                    "yuno_name", yuno_name,
                    "realm_id", (json_int_t) realm_id
                );
                if(jn_connector) {
                    json_object_set(kw_write_service, "connector", jn_connector);
                } else {
                    json_object_set_new(kw_write_service, "connector", json_object());
                }

                hs_service = gobj_create_resource(
                    priv->resource,
                    resource,
                    kw_write_service
                );
                if(!hs_service) {
                    log_error(0,
                        "gobj",         "%s", gobj_full_name(gobj),
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_SERVICE_ERROR,
                        "msg",          "%s", "Cannot create service",
                        "realm_id",     "%d", (int)realm_id,
                        "yuno_role",    "%s", yuno_role,
                        "yuno_name",    "%s", yuno_name,
                        "service",      "%s", service,
                        NULL
                    );
                    continue;
                }
                port = get_new_service_port(gobj, hs_realm);
            }

            /*
             *  Write calculated fields: ip, port (__service_ip__, __service_port__)
             */
            const char *ip;
            BOOL public_ = sdata_read_bool(hs_yuno, "global");
            if(public_) {
                ip = sdata_read_str(hs_realm, "bind_ip");
            } else {
                ip = "127.0.0.1";
            }

            sdata_write_str(hs_service, "ip", ip);
            sdata_write_uint32(hs_service, "port", port);
            char url[128];
            snprintf(url, sizeof(url), "%s://%s:%d", schema, ip, port);
            sdata_write_str(hs_service, "url", url);

            /*
             *  yuno_id will change with each new yuno release
             */
            sdata_write_uint64(hs_service, "yuno_id", yuno_id);
            gobj_update_resource(priv->resource, hs_service);
        }
    }

    return 0;
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_edit_config(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "configurations";

    const char *name = kw_get_str(kw, "name", 0, 0);
    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!name && id==0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("'name' or 'id' required."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    KW_INCREF(kw);
    dl_list_t *iter = gobj_list_resource(priv->resource, resource, kw);
    int found = rc_iter_size(iter);
    if(found != 1) {
        rc_free_iter(iter, TRUE, 0);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -186,
                found==0?json_local_sprintf("Configuration not found."):json_local_sprintf("Too many configurations. Select only one."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    /*
     *  Convert result in json
     */
    json_t *jn_data = sdata_iter2json(iter, SDF_PERSIST, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );
    rc_free_iter(iter, TRUE, 0);

    return gobj_send_event(
        src,
        event,
        webix,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_view_config(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "configurations";

    const char *name = kw_get_str(kw, "name", 0, 0);
    const char *id = kw_get_str(kw, "id", 0, 0);
    if(!name && id==0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("'name' or 'id' required."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    KW_INCREF(kw);
    dl_list_t *iter = gobj_list_resource(priv->resource, resource, kw);
    int found = rc_iter_size(iter);
    if(found != 1) {
        rc_free_iter(iter, TRUE, 0);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -186,
                found==0?json_local_sprintf("Configuration not found."):json_local_sprintf("Too many configurations. Select only one."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    /*
     *  Convert result in json
     */
    json_t *jn_data = sdata_iter2json(iter, SDF_PERSIST, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        0,
        0,
        jn_data, // owned
        kw  // owned
    );
    rc_free_iter(iter, TRUE, 0);

    return gobj_send_event(
        src,
        event,
        webix,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_edit_yuno_config(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    KW_INCREF(kw);
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    int found = rc_iter_size(iter_yunos);
    if(found == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("No yuno found."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    if(found != 1) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -186,
                json_local_sprintf("Select only one yuno please."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    hsdata hs_yuno;
    rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    rc_free_iter(iter_yunos, TRUE, 0);

    /*------------------------------------------*
     *  Found the yuno, now get his config
     *------------------------------------------*/
    resource = "configurations";

    dl_list_t *iter_config_ids = sdata_read_iter(hs_yuno, "config_ids");
    found = rc_iter_size(iter_config_ids);
    if(found == 0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("Yuno without configuration."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    if(found > 1) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("Yuno with too much configurations. Not supported."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    /*
     *  Convert result in json
     */
    json_t *jn_data = sdata_iter2json(iter_config_ids, SDF_PERSIST, 0);
    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return gobj_send_event(
        src,
        event,
        webix,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_view_yuno_config(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    KW_INCREF(kw);
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    int found = rc_iter_size(iter_yunos);
    if(found == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("No yuno found."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    if(found != 1) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -186,
                json_local_sprintf("Select only one yuno please."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    hsdata hs_yuno;
    rc_first_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    rc_free_iter(iter_yunos, TRUE, 0);

    /*------------------------------------------*
     *  Found the yuno, now get his config
     *------------------------------------------*/
    resource = "configurations";

    dl_list_t *iter_config_ids = sdata_read_iter(hs_yuno, "config_ids");
    found = rc_iter_size(iter_config_ids);
    if(found == 0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("Yuno without configuration."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    if(found > 1) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("Yuno with too much configurations. Not supported."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    /*
     *  Convert result in json
     */
    json_t *jn_data = sdata_iter2json(iter_config_ids, SDF_PERSIST, 0);
    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        0,
        0,
        tranger_list_topic_desc(gobj_read_json_attr(priv->resource, "tranger"), resource),
        jn_data, // owned
        kw  // owned
    );

    return gobj_send_event(
        src,
        event,
        webix,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_read_json(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    const char *filename = kw_get_str(kw, "filename", 0, 0);
    if(!filename) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -187,
                json_local_sprintf("filename required."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    if(access(filename, 0)!=0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -188,
                json_local_sprintf("File '%s' not found.", filename),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    int fp = open(filename, 0);
    if(fp<0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -189,
                json_local_sprintf("Cannot open '%s', %s.", filename, strerror(errno)),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    // TODO optimiza preguntando el tamaño del fichero
    size_t len = gbmem_get_maximum_block();
    char *s = gbmem_malloc(len);
    if(!s) {
        close(fp);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -190,
                json_local_sprintf("No memory."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    int readed = read(fp, s, len-1);
    if(!readed) {
        int err = errno;
        close(fp);
        gbmem_free(s);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -191,
                json_local_sprintf("Error with file '%s': %s.", filename, strerror(err)),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    close(fp);

    char *p = strrchr(filename, '/');
    if(!p) {
        p = (char *)filename;
    } else {
        p++;
    }
    json_t *jn_s = nonlegalstring2json(s, TRUE);
    json_t *jn_data = json_pack("{s:s, s:o}",
        "name", p,
        "zcontent", jn_s?jn_s:json_string("Invalid json in filename")
    );
    gbmem_free(s);

    /*
     *  Inform
     */
    return gobj_send_event(
        src,
        event,
        msg_iev_build_webix(gobj,
            0,
            0,
            0,
            jn_data, // owned
            kw  // owned
        ),
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_read_file(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    const char *filename = kw_get_str(kw, "filename", 0, 0);
    if(!filename) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -192,
                json_local_sprintf("filename required."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    if(access(filename, 0)!=0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -193,
                json_local_sprintf("File '%s' not found.", filename),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    int fp = open(filename, 0);
    if(fp<0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -194,
                json_local_sprintf("Cannot open '%s', %s.", filename, strerror(errno)),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    // TODO optimiza preguntando el tamaño del fichero
    size_t len = gbmem_get_maximum_block();
    char *s = gbmem_malloc(len);
    if(!s) {
        close(fp);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -195,
                json_local_sprintf("No memory."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    int readed = read(fp, s, len-1);
    if(!readed) {
        int err = errno;
        close(fp);
        gbmem_free(s);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -196,
                json_local_sprintf("Error with file '%s': %s.", filename, strerror(err)),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    close(fp);

    char *p = strrchr(filename, '/');
    if(!p) {
        p = (char *)filename;
    } else {
        p++;
    }
    json_t *jn_s = json_string(s);
    json_t *jn_data = json_pack("{s:s, s:o}",
        "name", p,
        "zcontent", jn_s?jn_s:json_string("Invalid content in filename")
    );
    gbmem_free(s);

    /*
     *  Inform
     */
    return gobj_send_event(
        src,
        event,
        msg_iev_build_webix(gobj,
            0,
            0,
            0,
            jn_data, // owned
            kw  // owned
        ),
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_read_binary_file(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    const char *filename = kw_get_str(kw, "filename", 0, 0);
    if(!filename) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -200,
                json_local_sprintf("filename required."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    if(access(filename, 0)!=0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -201,
                json_local_sprintf("File '%s' not found.", filename),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    size_t max_size = gbmem_get_maximum_block();
    uint64_t size = filesize(filename);
    if(size > max_size) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -205,
                json_local_sprintf("File '%s' too large. Maximum supported size is %ld", filename, max_size),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    int fp = open(filename, 0);
    if(fp<0) {
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -202,
                json_local_sprintf("Cannot open '%s', %s.", filename, strerror(errno)),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    char *s = gbmem_malloc(size);
    if(!s) {
        close(fp);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -203,
                json_local_sprintf("No memory."),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    int readed = read(fp, s, size);
    if(readed!=size) {
        int err = errno;
        close(fp);
        gbmem_free(s);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -204,
                json_local_sprintf("Error with file '%s': %s.", filename, strerror(err)),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }
    close(fp);

    char *p = strrchr(filename, '/');
    if(!p) {
        p = (char *)filename;
    } else {
        p++;
    }

    GBUFFER *gbuf_base64 = gbuf_string2base64(s, size);

    json_t *jn_s = json_string(gbuf_cur_rd_pointer(gbuf_base64));
    json_t *jn_data = json_pack("{s:s, s:o}",
        "name", p,
        "content64", jn_s?jn_s:json_string("Invalid content64")
    );
    gbmem_free(s);
    gbuf_decref(gbuf_base64);

    /*
     *  Inform
     */
    return gobj_send_event(
        src,
        event,
        msg_iev_build_webix(gobj,
            0,
            0,
            0,
            jn_data, // owned
            kw  // owned
        ),
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_read_running_keys(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    int found = rc_iter_size(iter_yunos);
    if(found == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -161,
                json_local_sprintf(
                    "No yuno found."
                ),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    /*------------------------------------------------*
     *  Walk over yunos iter:
     *------------------------------------------------*/
    hsdata hs_yuno;
    rc_last_instance(iter_yunos, (rc_resource_t **)&hs_yuno);

    char bfbinary[NAME_MAX];
    GBUFFER *gbuf_sh = gbuf_create(4*1024, 32*1024, 0, 0);
    build_yuno_running_script(gobj, gbuf_sh, hs_yuno, bfbinary, sizeof(bfbinary));
    char *s = gbuf_cur_rd_pointer(gbuf_sh);

    char temp[4*1024];
    snprintf(temp, sizeof(temp), "--config-file='%s'", s);
    json_t *jn_s = json_string(temp);
    json_t *jn_data = json_pack("{s:s, s:o}",
        "name", "running-keys",
        "zcontent", jn_s?jn_s:json_string("Invalid content in filename")
    );
    gbuf_decref(gbuf_sh);
    rc_free_iter(iter_yunos, TRUE, 0);

    /*
     *  Inform
     */
    return gobj_send_event(
        src,
        "EV_READ_FILE",
        msg_iev_build_webix(gobj,
            0,
            0,
            0,
            jn_data, // owned
            kw  // owned
        ),
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_read_running_bin(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char *resource = "yunos";

    /*------------------------------------------------*
     *      Get the yunos
     *------------------------------------------------*/
    if(kw) {
        KW_INCREF(kw);
    } else {
        kw = json_object();
    }
    dl_list_t * iter_yunos = gobj_list_resource(priv->resource, resource, kw);
    int found = rc_iter_size(iter_yunos);
    if(found == 0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        return gobj_send_event(
            src,
            event,
            msg_iev_build_webix(gobj,
                -161,
                json_local_sprintf(
                    "No yuno found."
                ),
                0,
                0,
                kw  // owned
            ),
            gobj
        );
    }

    /*------------------------------------------------*
     *  Walk over yunos iter:
     *------------------------------------------------*/
    hsdata hs_yuno;
    rc_last_instance(iter_yunos, (rc_resource_t **)&hs_yuno);

    char bfbinary[NAME_MAX];
    GBUFFER *gbuf_sh = gbuf_create(4*1024, 32*1024, 0, 0);
    build_yuno_running_script(gobj, gbuf_sh, hs_yuno, bfbinary, sizeof(bfbinary));

    json_t *jn_s = json_string(bfbinary);
    json_t *jn_data = json_pack("{s:s, s:o}",
        "name", "running-keys",
        "zcontent", jn_s?jn_s:json_string("Invalid content in filename")
    );
    gbuf_decref(gbuf_sh);
    rc_free_iter(iter_yunos, TRUE, 0);

    /*
     *  Inform
     */
    return gobj_send_event(
        src,
        "EV_READ_FILE",
        msg_iev_build_webix(gobj,
            0,
            0,
            0,
            jn_data, // owned
            kw  // owned
        ),
        gobj
    );
}

/***************************************************************************
 *  Este mensaje llega directamente del channel superior (ievent_srv)
 ***************************************************************************/
PRIVATE int ac_play_yuno_ack(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int action_return = kw_get_int(kw, "result", -1, 0);
    if(action_return == 0) {
        /*
         *  Saco al originante por el user_data del canal.
         *  HACK aquí nos viene directamente el evento del canal,
         *  sin pasar por IOGate (spiderden), y por lo tanto sin "channel_gobj"
         *  porque el iev_srv no eleva ON_MESSAGE como los gossamer a spiderden,
         *  se lo queda, y procesa el inter-evento.
         *  Los mensajes ON_OPEN y ON_CLOSE del iogate:route nos llegan porque estamos
         *  suscritos a all ellos.
         */
        hgobj channel_gobj = (hgobj)(size_t)kw_get_int(kw, "__temp__`channel_gobj", 0, KW_REQUIRED);
        hsdata hs_yuno = gobj_read_pointer_attr(channel_gobj, "user_data");
        if(!hs_yuno) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "hs_yuno NULL",
                NULL
            );
            KW_DECREF(kw);
            return 0;
        }
        sdata_write_bool(hs_yuno, "yuno_playing", TRUE);
        gobj_publish_event(
            gobj,
            event,
            kw // own kw
        );
    } else {
        KW_DECREF(kw);
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_pause_yuno_ack(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int action_return = kw_get_int(kw, "result", -1, 0);
    if(action_return == 0) {
        /*
         *  Saco al originante por el user_data del canal.
         */
        hgobj channel_gobj = (hgobj)(size_t)kw_get_int(kw, "__temp__`channel_gobj", 0, KW_REQUIRED);
        hsdata hs_yuno = gobj_read_pointer_attr(channel_gobj, "user_data");
        if(!hs_yuno) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "hs_yuno NULL",
                NULL
            );
            KW_DECREF(kw);
            return 0;
        }
        sdata_write_bool(hs_yuno, "yuno_playing", FALSE);
        gobj_publish_event(
            gobj,
            event,
            kw // own kw
        );
    } else {
        KW_DECREF(kw);
    }
    return 0;
}

/***************************************************************************
 *  HACK nodo intermedio
 ***************************************************************************/
PRIVATE int ac_stats_yuno_answer(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    json_t *jn_ievent_id = msg_iev_pop_stack(kw, IEVENT_MESSAGE_AREA_ID);

    const char *dst_service = kw_get_str(jn_ievent_id, "dst_service", "", 0);

    hgobj gobj_requester = gobj_child_by_name(
        gobj_child_by_name(gobj, "__input_side__", 0),
        dst_service,
        0
    );
    if(!gobj_requester) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "child not found",
            "child",        "%s", dst_service,
            NULL
        );
        JSON_DECREF(jn_ievent_id);
        KW_DECREF(kw);
        return 0;
    }
    JSON_DECREF(jn_ievent_id);

    KW_INCREF(kw);
    json_t *kw_redirect = msg_iev_answer(gobj, kw, kw, 0);

    return gobj_send_event(
        gobj_requester,
        event,
        kw_redirect,
        gobj
    );
}

/***************************************************************************
 *  HACK nodo intermedio
 ***************************************************************************/
PRIVATE int ac_command_yuno_answer(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    json_t *jn_ievent_id = msg_iev_pop_stack(kw, IEVENT_MESSAGE_AREA_ID);

    const char *dst_service = kw_get_str(jn_ievent_id, "dst_service", "", 0);
    if(strcmp(dst_service, gobj_name(gobj))==0) {
        // Comando directo del agente
        JSON_DECREF(jn_ievent_id);
        KW_DECREF(kw);
        return 0;
    }

    hgobj gobj_requester = gobj_child_by_name(
        gobj_child_by_name(gobj, "__input_side__", 0),
        dst_service,
        0
    );
    if(!gobj_requester) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "child not found",
            "child",        "%s", dst_service,
            NULL
        );
        JSON_DECREF(jn_ievent_id);
        KW_DECREF(kw);
        return 0;
    }
    JSON_DECREF(jn_ievent_id);

    KW_INCREF(kw);
    json_t *kw_redirect = msg_iev_answer(gobj, kw, kw, 0);

    return gobj_send_event(
        gobj_requester,
        event,
        kw_redirect,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_on_open(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *client_yuno_role = kw_get_str(kw, "client_yuno_role", "", 0);
    if(strcasecmp(client_yuno_role, "yuneta_cli")==0 ||
            strcasecmp(client_yuno_role, "yuneta_agent")==0 ||
            strcasecmp(client_yuno_role, "ybatch")==0 ||
            strcasecmp(client_yuno_role, "ystats")==0 ||
            strcasecmp(client_yuno_role, "ycommand")==0 ||
            strcasecmp(client_yuno_role, "GUI")==0 ||
            strcasecmp(client_yuno_role, "yuneta_gui")==0) {
        // let it.
        KW_DECREF(kw);
        return 0;
    }

    json_int_t realm_id = kw_get_int(kw, "identity_card`realm_id", 0, KW_REQUIRED);
    json_int_t yuno_id = kw_get_int(kw, "identity_card`yuno_id", 0, KW_REQUIRED);
    json_int_t pid = kw_get_int(kw, "identity_card`pid", 0, KW_REQUIRED);
    BOOL playing = kw_get_bool(kw, "identity_card`playing", 0, KW_REQUIRED);
    const char *yuno_role = kw_get_str(kw, "identity_card`yuno_role", "", KW_REQUIRED);
    const char *yuno_name = kw_get_str(kw, "identity_card`yuno_name", "", KW_REQUIRED);
    const char *yuno_release = kw_get_str(kw, "identity_card`yuno_release", "", KW_REQUIRED);
    const char *yuno_startdate= kw_get_str(kw, "identity_card`yuno_startdate", "", KW_REQUIRED);
    hgobj channel_gobj = (hgobj)(size_t)kw_get_int(kw, "__temp__`channel_gobj", 0, KW_REQUIRED);

    json_t *kw_find = json_pack("{s:s, s:s, s:b, s:I, s:I}",
        "yuno_role", yuno_role,     // WARNING NEW 6-Feb-2019 efecto colateral?
        "yuno_name", yuno_name,     // WARNING NEW
        "disabled", 0,
        "realm_id", realm_id,
        "id", yuno_id
    );
    dl_list_t * iter_yunos;
    iter_yunos = gobj_list_resource(priv->resource, "yunos", kw_find);
    int found = dl_size(iter_yunos);
    if(found==0) {
        rc_free_iter(iter_yunos, TRUE, 0);
        KW_DECREF(kw);
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "yuno NOT FOUND",
            "realm_id",     "%d", (int)realm_id,
            "yuno_id",      "%d", (int)yuno_id,
            NULL
        );
        if(pid) {
            kill(pid, SIGKILL);
        }
        return -1;
    }

    hsdata hs_yuno;
    rc_last_instance(iter_yunos, (rc_resource_t **)&hs_yuno);
    rc_free_iter(iter_yunos, TRUE, 0);

    /*
     *  Check if it's already live.
     */
    uint32_t _pid = sdata_read_uint32(hs_yuno, "yuno_pid");
    if(_pid && getpgid(_pid) >= 0) {
        KW_DECREF(kw);
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "yuno ALREADY living, killing new yuno",
            "realm_id",     "%d", (int)realm_id,
            "yuno_id",      "%d", (int)yuno_id,
            "current pid",  "%d", (int)_pid,
            "new pid",      "%d", (int)pid,
            "yuno_role",    "%s", yuno_role,
            "yuno_name",    "%s", yuno_name,
            "yuno_release", "%s", yuno_release,
            NULL
        );
        if(pid) {
            kill(pid, SIGKILL);
        }
        return -1;
    }

    save_pid_in_file(gobj, hs_yuno, pid);

    if(strcmp(yuno_role, sdata_read_str(hs_yuno, "yuno_role"))!=0) {
        KW_DECREF(kw);
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "yuno_role not match",
            "yuno_role registered",     "%s", sdata_read_str(hs_yuno, "yuno_role"),
            "yuno_role incoming",       "%s", yuno_role,
            "realm_id",     "%d", (int)realm_id,
            "yuno_id",      "%d", (int)yuno_id,
            "current pid",  "%d", (int)_pid,
            "new pid",      "%d", (int)pid,
            NULL
        );
        if(pid) {
            kill(pid, SIGKILL);
        }
        return -1;
    }
    if(strcmp(yuno_name, sdata_read_str(hs_yuno, "yuno_name"))!=0) {
        KW_DECREF(kw);
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "yuno_name not match",
            "yuno_name registered",    "%s", sdata_read_str(hs_yuno, "yuno_name"),
            "yuno_name incoming",   "%s", yuno_name,
            "yuno_role",    "%s", yuno_role,
            "realm_id",     "%d", (int)realm_id,
            "yuno_id",      "%d", (int)yuno_id,
            "current pid",  "%d", (int)_pid,
            "new pid",      "%d", (int)pid,
            NULL
        );
        if(pid) {
            kill(pid, SIGKILL);
        }
        return -1;
    }
    if(strcmp(yuno_release, sdata_read_str(hs_yuno, "yuno_release"))!=0) {
        KW_DECREF(kw);
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "yuno_release not match",
            "yuno_release registered", "%s", sdata_read_str(hs_yuno, "yuno_release"),
            "yuno_release incoming","%s", yuno_release,
            "yuno_role",    "%s", yuno_role,
            "yuno_name",    "%s", yuno_name,
            "realm_id",     "%d", (int)realm_id,
            "yuno_id",      "%d", (int)yuno_id,
            "current pid",  "%d", (int)_pid,
            "new pid",      "%d", (int)pid,
            NULL
        );
        if(pid) {
            kill(pid, SIGKILL);
        }
        return -1;
    }
    if(realm_id != sdata_read_uint64(hs_yuno, "realm_id")) {
        KW_DECREF(kw);
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "realm_id not match",
            "yuno_release", "%s", yuno_release,
            "yuno_role",    "%s", yuno_role,
            "yuno_name",    "%s", yuno_name,
            "realm_id incoming",     "%d", (int)realm_id,
            "realm_id registered",    "%d", (int)sdata_read_uint64(hs_yuno, "realm_id"),
            "yuno_id",      "%d", (int)yuno_id,
            "current pid",  "%d", (int)_pid,
            "new pid",      "%d", (int)pid,
            NULL
        );
        if(pid) {
            kill(pid, SIGKILL);
        }
        return -1;
    }

    sdata_write_str(hs_yuno, "yuno_startdate", yuno_startdate);
    sdata_write_bool(hs_yuno, "yuno_running", TRUE);
    sdata_write_bool(hs_yuno, "yuno_playing", playing);
    sdata_write_uint32(hs_yuno, "yuno_pid", pid);
    sdata_write_pointer(hs_yuno, "channel_gobj", channel_gobj);
    if(channel_gobj) {
        gobj_write_pointer_attr(channel_gobj, "user_data", hs_yuno);
    } else {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "channel_gobj NULL",
            NULL
        );
    }

    log_debug(0,
        "gobj",         "%s", gobj_full_name(gobj),
        "function",     "%s", __FUNCTION__,
        "msgset",       "%s", MSGSET_STARTUP,
        "msg",          "%s", "yuno up",
        "realm_id",     "%d", (int)realm_id,
        "yuno_id",      "%d", (int)yuno_id,
        "pid",          "%d", (int)pid,
        "yuno_role",    "%s", yuno_role,
        "yuno_name",    "%s", yuno_name?yuno_name:"",
        "yuno_release", "%s", yuno_release?yuno_release:"",
        NULL
    );

    /*---------------*
     *  Check play
     *---------------*/
    if(!playing) {
        const char *solicitante = sdata_read_str(hs_yuno, "solicitante");
        BOOL must_play = sdata_read_bool(hs_yuno, "must_play");
        if(must_play) {
            hgobj gobj_requester = 0;
            if(!empty_string(solicitante)) {
                gobj_requester = gobj_child_by_name(
                    gobj_child_by_name(gobj, "__input_side__", 0),
                    solicitante,
                    0
                );
            }
            if(!gobj_requester) {
                play_yuno(gobj, hs_yuno, 0, src);
            } else {
                json_t *kw_play = json_pack("{s:I, s:I}",
                    "realm_id", (json_int_t)realm_id,
                    "id", (json_int_t)yuno_id
                );
                cmd_play_yuno(gobj, "play-yuno", kw_play, gobj_requester);
            }
        }
        sdata_write_str(hs_yuno, "solicitante", "");
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_on_close(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    if(gobj_is_shutdowning()) {
        KW_DECREF(kw);
        return 0;
    }
    hgobj channel_gobj = (hgobj)(size_t)kw_get_int(kw, "__temp__`channel_gobj", 0, KW_REQUIRED);
    if(!channel_gobj) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "channel_gobj NULL",
            NULL
        );
        KW_DECREF(kw);
        return 0;
    }
    hsdata hs_yuno = gobj_read_pointer_attr(channel_gobj, "user_data");
    if(!hs_yuno) {
        // Must be yuneta_cli or a yuno refused!.
        KW_DECREF(kw);
        return 0;
    }
    gobj_write_pointer_attr(channel_gobj, "user_data", 0); // HACK release yuno info connection

    const char *realm_name = sdata_read_str(hs_yuno, "realm_name");
    if(!realm_name) {
        realm_name = "";
    }
    const char *yuno_role = sdata_read_str(hs_yuno, "yuno_role");
    const char *yuno_name = sdata_read_str(hs_yuno, "yuno_name");
    const char *yuno_release = sdata_read_str(hs_yuno, "yuno_release");
    log_debug(0,
        "gobj",         "%s", gobj_full_name(gobj),
        "function",     "%s", __FUNCTION__,
        "msgset",       "%s", MSGSET_STARTUP,
        "msg",          "%s", "yuno down",
        "realm_id",     "%d", (int)sdata_read_uint64(hs_yuno, "realm_id"),
        "yuno_id",      "%d", (int)sdata_read_uint64(hs_yuno, "id"),
        "pid",          "%d", (int)sdata_read_uint32(hs_yuno, "yuno_pid"),
        "yuno_role",    "%s", yuno_role,
        "yuno_name",    "%s", yuno_name?yuno_name:"",
        "yuno_release", "%s", yuno_release?yuno_release:"",
        NULL
    );

    sdata_write_bool(hs_yuno, "yuno_running", FALSE);
    sdata_write_bool(hs_yuno, "yuno_playing", FALSE);
    sdata_write_uint32(hs_yuno, "yuno_pid", 0);
    sdata_write_pointer(hs_yuno, "channel_gobj", 0);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_final_count(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    const char *info = kw_get_str(kw, "info", "", 0);
    int max_count = kw_get_int(kw, "max_count", 0, 0);
    int cur_count = kw_get_int(kw, "cur_count", 0, 0);

// KKK

    dl_list_t * iter_yunos = gobj_read_pointer_attr(src, "user_data");
    json_t *kw_answer = gobj_read_pointer_attr(src, "user_data2");

    json_t *jn_request = msg_iev_pop_stack(kw, "requester_stack");
    if(!jn_request) {
        rc_free_iter(iter_yunos, TRUE, 0);
        KW_DECREF(kw_answer);
        KW_DECREF(kw);
        return -1;
    }

    const char *requester = kw_get_str(jn_request, "requester", 0, 0);
    hgobj gobj_requester = gobj_child_by_name(
        gobj_child_by_name(gobj, "__input_side__", 0),
        requester,
        0
    );
    if(!gobj_requester) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "child not found",
            "child",        "%s", requester,
            NULL
        );
        rc_free_iter(iter_yunos, TRUE, 0);
        JSON_DECREF(jn_request);
        KW_DECREF(kw_answer);
        KW_DECREF(kw);
        return 0;
    }
    JSON_DECREF(jn_request);

    BOOL ok = (max_count>0 && max_count==cur_count);

    json_t *jn_comment = json_local_sprintf("%s%s (%d raised, %d reached)\n",
        ok?"OK: ":"",
        info,
        max_count,
        cur_count
    );

    json_t *jn_data = sdata_iter2json(iter_yunos, SDF_PERSIST|SDF_RESOURCE|SDF_VOLATIL, 0);

    rc_free_iter(iter_yunos, TRUE, 0);

    /*
     *  Inform
     */
    json_t *webix = msg_iev_build_webix(gobj,
        ok?0:-197,
        jn_comment, // owned
        RESOURCE_WEBIX_SCHEMA(priv->resource, "yunos"),
        jn_data,
        kw_answer  // owned
    );

    KW_DECREF(kw);

    return gobj_send_event(
        gobj_requester,
        "EV_MT_COMMAND_ANSWER",
        webix,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    if(!priv->enabled_yunos_running) {
        priv->enabled_yunos_running = 1;
        run_enabled_yunos(gobj);
        exec_startup_command(gobj);
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input

    /*
     *  Deploy - Repository
     */
    {"EV_EDIT_CONFIG",          EVF_PUBLIC_EVENT,  0,  "Edit configuration"},
    {"EV_VIEW_CONFIG",          EVF_PUBLIC_EVENT,  0,  "View configuration"},
    {"EV_EDIT_YUNO_CONFIG",     EVF_PUBLIC_EVENT,  0,  "Edit yuno configuration"},
    {"EV_VIEW_YUNO_CONFIG",     EVF_PUBLIC_EVENT,  0,  "View yuno configuration"},
    {"EV_READ_JSON",            EVF_PUBLIC_EVENT,  0,  "Read json filename"},
    {"EV_READ_FILE",            EVF_PUBLIC_EVENT,  0,  "Read text filename"},
    {"EV_READ_BINARY_FILE",     EVF_PUBLIC_EVENT,  0,  "Read binary filename"},
    {"EV_READ_RUNNING_KEYS",    EVF_PUBLIC_EVENT,  0,  "Read running-keys"},
    {"EV_READ_RUNNING_BIN",     EVF_PUBLIC_EVENT,  0,  "Read running-bin path"},

    {"EV_PLAY_YUNO_ACK",        EVF_PUBLIC_EVENT,  0,  0},
    {"EV_PAUSE_YUNO_ACK",       EVF_PUBLIC_EVENT,  0,  0},
    {"EV_MT_STATS_ANSWER",      EVF_PUBLIC_EVENT,  0,  0},
    {"EV_MT_COMMAND_ANSWER",    EVF_PUBLIC_EVENT,  0,  0},
    {"EV_ON_COMMAND",           EVF_PUBLIC_EVENT,  0,  0},

    // bottom input
    {"EV_ON_OPEN",          0,  0,  0},
    {"EV_ON_CLOSE",         0,  0,  0},
    {"EV_TIMEOUT",          0,  0,  0},
    {"EV_FINAL_COUNT",      0,  0,  0},
    {"EV_STOPPED",          0,  0,  0},
    // internal
    {NULL, 0, 0, 0}
};
PRIVATE const EVENT output_events[] = {
    {"EV_PLAY_YUNO_ACK",        EVF_NO_WARN_SUBS,  0,  0},
    {"EV_PAUSE_YUNO_ACK",       EVF_NO_WARN_SUBS,  0,  0},
    {"EV_MT_STATS_ANSWER",      0,  0,  0},
    {"EV_MT_COMMAND_ANSWER",    0,  0,  0},
    {NULL, 0, 0, 0}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_EDIT_CONFIG",          ac_edit_config,         0},
    {"EV_VIEW_CONFIG",          ac_view_config,         0},
    {"EV_EDIT_YUNO_CONFIG",     ac_edit_yuno_config,    0},
    {"EV_VIEW_YUNO_CONFIG",     ac_view_yuno_config,    0},
    {"EV_READ_JSON",            ac_read_json,           0},
    {"EV_READ_FILE",            ac_read_file,           0},
    {"EV_READ_BINARY_FILE",     ac_read_binary_file,    0},
    {"EV_READ_RUNNING_KEYS",    ac_read_running_keys,   0},
    {"EV_READ_RUNNING_BIN",     ac_read_running_bin,    0},

    {"EV_PLAY_YUNO_ACK",        ac_play_yuno_ack,       0},
    {"EV_PAUSE_YUNO_ACK",       ac_pause_yuno_ack,      0},
    {"EV_MT_STATS_ANSWER",      ac_stats_yuno_answer,   0},
    {"EV_MT_COMMAND_ANSWER",    ac_command_yuno_answer, 0},
    {"EV_ON_COMMAND",           ac_command_yuno_answer, 0},

    {"EV_ON_OPEN",              ac_on_open,             0},
    {"EV_ON_CLOSE",             ac_on_close,            0},
    {"EV_FINAL_COUNT",          ac_final_count,         0},
    {"EV_TIMEOUT",              ac_timeout,             0},
    {"EV_STOPPED",              0,                      0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_IDLE,
    NULL
};

PRIVATE FSM fsm = {
    input_events,
    output_events,
    state_names,
    states,
};

/***************************************************************************
 *              GClass
 ***************************************************************************/
/*---------------------------------------------*
 *              Local methods table
 *---------------------------------------------*/
PRIVATE LMETHOD lmt[] = {
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_AGENT_NAME,      // CHANGE WITH each gclass
    &fsm,
    {
        mt_create,
        0, //mt_create2,
        mt_destroy,
        mt_start,
        mt_stop,
        0, //mt_play,
        0, //mt_pause,
        mt_writing,
        0, //mt_reading,
        0, //mt_subscription_added,
        0, //mt_subscription_deleted,
        0, //mt_child_added,
        0, //mt_child_removed,
        0, //mt_stats,
        0, //mt_command,
        0, //mt_inject_event,
        0, //mt_create_resource,
        0, //mt_list_resource,
        0, //mt_update_resource,
        0, //mt_delete_resource,
        0, //mt_add_child_resource_link
        0, //mt_delete_child_resource_link
        0, //mt_get_resource
        0, //mt_future24,
        mt_authenticate,
        0, //mt_list_childs,
        0, //mt_stats_updated,
        0, //mt_disable,
        0, //mt_enable,
        0, //mt_trace_on,
        0, //mt_trace_off,
        0, //mt_gobj_created,
        0, //mt_future33,
        0, //mt_future34,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_future38,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_link_nodes2,
        0, //mt_unlink_nodes,
        0, //mt_unlink_nodes2,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_snap_nodes,
        0, //mt_set_nodes_snap,
        0, //mt_list_nodes_snaps,
        0, //mt_future52,
        0, //mt_future53,
        0, //mt_future54,
        0, //mt_future55,
        0, //mt_future56,
        0, //mt_future57,
        0, //mt_future58,
        0, //mt_future59,
        0, //mt_future60,
        0, //mt_future61,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    0,  // acl
    s_user_trace_level,
    command_table,  // command_table
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_agent(void)
{
    return &_gclass;
}
