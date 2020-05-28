#pragma once

/*

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
                        ▲ 1 ('binary')          ▲ n (dl 'configurations')
                        ┃                       ┃
                        ┃                       ┃
                        ▼ n (dl 'yunos')        ▼ n (dl 'yunos')
                ┌────────────────┐      ┌────────────────┐
                │   binaries     │      │ configurations │
                └────────────────┘      └────────────────┘

*/

static char treedb_schema_yuneta_agent[]= "\
{                                                                   \n\
    'id': 'yuneta_agent',                                           \n\
    'schema_version': '5',                                          \n\
    'topics': [                                                     \n\
        {                                                           \n\
            'topic_name': 'realms',                                 \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'domain': {                                         \n\
                    'header': 'domain',                             \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'range_ports': {                                    \n\
                    'header': 'range_ports',                        \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'role': {                                           \n\
                    'header': 'role',                               \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'name': {                                           \n\
                    'header': 'name',                               \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'bind_ip': {                                        \n\
                    'header': 'bind_ip',                            \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'last_port': {                                      \n\
                    'header': 'last_port',                          \n\
                    'fillspace': 10,                                \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'yunos': {                                          \n\
                    'header': 'yunos',                              \n\
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
            'topic_version': '3',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'realm_name': {                                     \n\
                    'header': 'realm_name',                         \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_role': {                                      \n\
                    'header': 'yuno_role',                          \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_name': {                                      \n\
                    'header': 'yuno_name',                          \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_release': {                                   \n\
                    'header': 'yuno_release',                       \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_alias': {                                     \n\
                    'header': 'yuno_alias',                         \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_running': {                                   \n\
                    'header': 'yuno_running',                       \n\
                    'fillspace': 7,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_playing': {                                   \n\
                    'header': 'yuno_playing',                       \n\
                    'fillspace': 7,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_pid': {                                       \n\
                    'header': 'yuno_pid',                           \n\
                    'fillspace': 7,                                 \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'watcher_pid': {                                    \n\
                    'header': 'watcher_pid',                        \n\
                    'fillspace': 7,                                 \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'disabled': {                                       \n\
                    'header': 'disabled',                           \n\
                    'fillspace': 8,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'must_play': {                                      \n\
                    'header': 'must_play',                          \n\
                    'fillspace': 8,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'traced': {                                         \n\
                    'header': 'traced',                             \n\
                    'fillspace': 6,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'multiple': {                                       \n\
                    'header': 'multiple',                           \n\
                    'fillspace': 6,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'global': {                                         \n\
                    'header': 'global',                             \n\
                    'fillspace': 6,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'realm_id': {                                       \n\
                    'header': 'realm_id',                           \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                'binary': {                                         \n\
                    'header': 'binary',                             \n\
                    'fillspace': 8,                                 \n\
                    'type': 'object',                               \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'binaries': 'yunos'                         \n\
                    }                                               \n\
                },                                                  \n\
                'configurations': {                                 \n\
                    'header': 'configurations',                     \n\
                    'fillspace': 15,                                \n\
                    'type': 'array',                                \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'configurations': 'yunos'                   \n\
                    }                                               \n\
                },                                                  \n\
                'yuno_startdate': {                                 \n\
                    'header': 'yuno_startdate',                     \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                '_channel_gobj': {                                  \n\
                    'header': '_channel_gobj',                      \n\
                    'fillspace': 6,                                 \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'solicitante': {                                    \n\
                    'header': 'solicitante',                        \n\
                    'fillspace': 6,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'global': {                                         \n\
                    'header': 'global',                             \n\
                    'fillspace': 6,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
                                                                    \n\
        {                                                           \n\
            'topic_name': 'configurations',                         \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '2',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'name': {                                           \n\
                    'header': 'name',                               \n\
                    'fillspace': 30,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'version': {                                        \n\
                    'header': 'version',                            \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'description',                        \n\
                    'fillspace': 30,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'type': {                                           \n\
                    'header': 'type',                               \n\
                    'fillspace': 20,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'destination': {                                    \n\
                    'header': 'destination',                        \n\
                    'fillspace': 30,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'date': {                                           \n\
                    'header': 'date',                               \n\
                    'fillspace': 21,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yunos': {                                          \n\
                    'header': 'yunos',                              \n\
                    'fillspace': 22,                                \n\
                    'type': 'array',                                \n\
                    'flag': ['fkey']                                \n\
                },                                                  \n\
                'zcontent': {                                       \n\
                    'header': 'zcontent',                           \n\
                    'fillspace': 35,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'source': {                                         \n\
                    'header': 'source',                             \n\
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
            'topic_version': '2',                                   \n\
            'topic_options': '',                                    \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'role': {                                           \n\
                    'header': 'role',                               \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'version': {                                        \n\
                    'header': 'version',                            \n\
                    'fillspace': 14,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'size': {                                           \n\
                    'header': 'size',                               \n\
                    'fillspace': 10,                                \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'date': {                                           \n\
                    'header': 'date',                               \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'description',                        \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'classifiers': {                                    \n\
                    'header': 'classifiers',                        \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'required_services': {                              \n\
                    'header': 'required_services',                  \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'public_services': {                                \n\
                    'header': 'public_services',                    \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'service_descriptor': {                             \n\
                    'header': 'service_descriptor',                 \n\
                    'fillspace': 22,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'binary': {                                         \n\
                    'header': 'binary',                             \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yunos': {                                          \n\
                    'header': 'yunos',                              \n\
                    'fillspace': 22,                                \n\
                    'type': 'array',                                \n\
                    'flag': ['fkey']                                \n\
                },                                                  \n\
                'source': {                                         \n\
                    'header': 'source',                             \n\
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
                    'header': 'id',                                 \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required',                                 \n\
                        'rowid'                                     \n\
                    ]                                               \n\
                },                                                  \n\
                'service': {                                        \n\
                    'header': 'service',                            \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'description',                        \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_role': {                                      \n\
                    'header': 'yuno_role',                          \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_name': {                                      \n\
                    'header': 'yuno_name',                          \n\
                    'fillspace': 18,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno_id': {                                        \n\
                    'header': 'yuno_id',                            \n\
                    'fillspace': 8,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'ip': {                                             \n\
                    'header': 'ip',                                 \n\
                    'fillspace': 16,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'port': {                                           \n\
                    'header': 'port',                               \n\
                    'fillspace': 5,                                 \n\
                    'type': 'integer',                              \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'schema': {                                         \n\
                    'header': 'schema',                             \n\
                    'fillspace': 6,                                 \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'url': {                                            \n\
                    'header': 'url',                                \n\
                    'fillspace': 22,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'connector': {                                      \n\
                    'header': 'connector',                          \n\
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

