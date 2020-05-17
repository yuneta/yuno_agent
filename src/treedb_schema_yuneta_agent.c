#pragma once

/*

tb_resources    NOT recursive (no tree), all tables must be defined in this table
------------
    realms:         ASN_ITER,       SDF_RESOURCE
    binaries,       ASN_ITER,       SDF_RESOURCE
    configurations: ASN_ITER,       SDF_RESOURCE
    yunos:          ASN_ITER,       SDF_RESOURCE|SDF_PURECHILD
                                                            ▲
                                                            |
                        HACK PureChild: mark SDF_PURECHILD in own table and in parent's field!
                                                            | and mark SDF_PARENTID the own field pointing to parent
                        ┌───────────────┐                   |     |
                        │     realms    │                   |     |
                        └───────────────┘                   |     |
                                ▲ n (dl 'yunos')            |     |
                                ┃                           |     |
                                ┃                           |     |
                                ▼ 1 ('realm_id')            |     |
                ┌───────────────────────────────────────┐   |     |
                │               yunos                   │   |     |
                └───────────────────────────────────────┘   |     |
                        ▲ 1 ('binary_id')       ▲ n (dl 'configurations')
                        ┃                       ┃           |     |
                        ┃                       ┃           |     |
                        ▼ n (dl 'yunos')        ▼ n (dl 'yunos')  |
                ┌────────────────┐      ┌────────────────┐  |     |
                │   binaries     │      │ configurations │  |     |
                └────────────────┘      └────────────────┘  |     |
                                                            |     |
Realms                                                      |     |
------                                                      |     |
    id:             ASN_COUNTER64,  SDF_PERSIST|SDF_PKEY    ▼     |
    yunos:          ASN_ITER,       SDF_RESOURCE|SDF_PURECHILD,   |     "yunos"
                                                                  |
Yunos                                                             |
-----                                                             |
    id:             ASN_COUNTER64,  SDF_PERSIST|SDF_PKEY          ▼
    realm_id:       ASN_COUNTER64,  SDF_PERSIST|SDF_PARENTID,           "realms"
    binary_id:      ASN_COUNTER64,  SDF_PERSIST,                        "binaries"
    config_ids:     ASN_ITER,       SDF_RESOURCE,                       "configurations"

Binaries
--------
    id:             ASN_COUNTER64,  SDF_PERSIST|SDF_PKEY

configurations
--------------
    id:             ASN_COUNTER64,  SDF_PERSIST|SDF_PKEY

*/

static char treedb_schema_yuneta_agent[]= "\
{                                                                   \n\
    'schema_version': '1',                                          \n\
    'topics': [                                                     \n\
        {                                                           \n\
            'topic_name': 'realms',                                 \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'domain': {                                         \n\
                    'header': 'Realm Domain',                       \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'range_ports': {                                    \n\
                    'header': 'Range Ports',                        \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'role': {                                           \n\
                    'header': 'Realm Role',                         \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'name': {                                           \n\
                    'header': 'Realm Name',                         \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'bind_ip': {                                        \n\
                    'header': 'Bind IP',                            \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'last_port': {                                      \n\
                    'header': 'Last Port',                          \n\
                    'fillspace': 10,                                \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'yunos': {                                          \n\
                    'header': 'Yunos',                              \n\
                    'fillspace': 22,                                \n\
                    'type': 'array',                                \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'yunos': 'realm_id'                         \n\
                    }                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
                                                                    \n\
        {                                                           \n\
            'topic_name': 'yunos',                                  \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'realm_name': {                                     \n\
                    'header': 'Realm Name',                         \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_role': {                                      \n\
                    'header': 'Yuno Role',                          \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_name': {                                      \n\
                    'header': 'Yuno Name',                          \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_release': {                                   \n\
                    'header': 'Yuno Release',                       \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_alias': {                                     \n\
                    'header': 'Yuno Alias',                         \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_running': {                                   \n\
                    'header': 'Running',                            \n\
                    'fillspace': 7,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_playing': {                                   \n\
                    'header': 'Playing',                            \n\
                    'fillspace': 7,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_pid': {                                       \n\
                    'header': 'Pid',                                \n\
                    'fillspace': 7,                                 \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'disabled': {                                       \n\
                    'header': 'Disabled',                           \n\
                    'fillspace': 8,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'must_play': {                                      \n\
                    'header': 'MustPlay',                           \n\
                    'fillspace': 8,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'traced': {                                         \n\
                    'header': 'Traced',                             \n\
                    'fillspace': 6,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'multiple': {                                       \n\
                    'header': 'Multiple',                           \n\
                    'fillspace': 6,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'global': {                                         \n\
                    'header': 'Global',                             \n\
                    'fillspace': 6,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'realm_id': {                                       \n\
                    'header': 'Realm Id',                           \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                'binary_id': {                                      \n\
                    'header': 'Binary Id',                          \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                'configurations': {                                 \n\
                    'header': 'Configurations',                     \n\
                    'fillspace': 15,                                \n\
                    'type': 'array',                                \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'configurations': 'yunos'                   \n\
                    }                                               \n\
                },                                                  \n\
                'yuno_startdate': {                                 \n\
                    'header': 'Start Date',                         \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
                                                                    \n\
        {                                                           \n\
            'topic_name': 'configurations',                         \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'name': {                                           \n\
                    'header': 'Configuration Name',                 \n\
                    'fillspace': 30,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'version': {                                        \n\
                    'header': 'Configuration Version',              \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'Description',                        \n\
                    'fillspace': 30,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'type': {                                           \n\
                    'header': 'Type',                               \n\
                    'fillspace': 20,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'destination': {                                    \n\
                    'header': 'Destination',                        \n\
                    'fillspace': 30,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'date': {                                           \n\
                    'header': 'Date',                               \n\
                    'fillspace': 21,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yunos': {                                          \n\
                    'header': 'Yunos',                              \n\
                    'fillspace': 22,                                \n\
                    'type': 'array',                                \n\
                    'flag': ['fkey']                                \n\
                },                                                  \n\
                'zcontent': {                                       \n\
                    'header': 'Content',                            \n\
                    'fillspace': 35,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'source': {                                         \n\
                    'header': 'Source',                             \n\
                    'fillspace': 0,                                 \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
                                                                    \n\
        {                                                           \n\
            'topic_name': 'binaries',                               \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'role': {                                           \n\
                    'header': 'Binary Role',                        \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'version': {                                        \n\
                    'header': 'Binary Version',                     \n\
                    'fillspace': 14,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'size': {                                           \n\
                    'header': 'Size',                               \n\
                    'fillspace': 10,                                \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'date': {                                           \n\
                    'header': 'Date',                               \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'Description',                        \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'classifiers': {                                    \n\
                    'header': 'Classifiers',                        \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'required_services': {                              \n\
                    'header': 'Required Services',                  \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'public_services': {                                \n\
                    'header': 'Public Services',                    \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'service_descriptor': {                             \n\
                    'header': 'Service Descriptor',                 \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'binary': {                                         \n\
                    'header': 'Binary',                             \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yunos': {                                          \n\
                    'header': 'Yunos',                              \n\
                    'fillspace': 22,                                \n\
                    'type': 'array',                                \n\
                    'flag': ['fkey']                                \n\
                },                                                  \n\
                'source': {                                         \n\
                    'header': 'Source',                             \n\
                    'fillspace': 0,                                 \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
                                                                    \n\
        {                                                           \n\
            'topic_name': 'public_services',                        \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'service': {                                        \n\
                    'header': 'Service',                            \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'Description',                        \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_role': {                                      \n\
                    'header': 'Yuno Role',                          \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_name': {                                      \n\
                    'header': 'Yuno Name',                          \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'realm_id': {                                       \n\
                    'header': 'Realm Id',                           \n\
                    'fillspace': 8,                                 \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_id': {                                        \n\
                    'header': 'Yuno Id',                            \n\
                    'fillspace': 8,                                 \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'ip': {                                             \n\
                    'header': 'Ip',                                 \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'port': {                                           \n\
                    'header': 'Port',                               \n\
                    'fillspace': 5,                                 \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'schema': {                                         \n\
                    'header': 'Schema',                             \n\
                    'fillspace': 6,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'url': {                                            \n\
                    'header': 'Url',                                \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'connector': {                                      \n\
                    'header': 'Connector',                          \n\
                    'fillspace': 12,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        }                                                           \n\
                                                                    \n\
    ]                                                               \n\
}                                                                   \n\
";

