#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SYS_CONFIG_CONFIG_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_SYS_CONFIG_CONFIG_H

DWORD request_sys_config_getenv(Remote *remote, Packet *packet);
DWORD request_sys_config_getuid(Remote *remote, Packet *packet);
DWORD request_sys_config_sysinfo(Remote *remote, Packet *packet);
DWORD request_sys_config_rev2self(Remote *remote, Packet *packet);
DWORD request_sys_config_getprivs(Remote *remote, Packet *packet);
DWORD request_sys_config_steal_token(Remote *remote, Packet *packet);
DWORD request_sys_config_drop_token(Remote *remote, Packet *packet);
#endif
