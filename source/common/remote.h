/*!
 * @file remote.h
 * @brief Declarations of functions and types that interact with a remote endpoint.
 */
#ifndef _METERPRETER_LIB_REMOTE_H
#define _METERPRETER_LIB_REMOTE_H

#include "crypto.h"
#include "thread.h"
#include "config.h"

/*! @brief This is the size of the certificate hash that is validated (sha1) */
#define CERT_HASH_SIZE 20

#ifdef _WIN32
typedef wchar_t CHARTYPE;
typedef CHARTYPE* STRTYPE;
#else
typedef char CHARTYPE;
typedef CHARTYPE* STRTYPE;
#endif

// Forward declarations required to keep compilers happy.
typedef struct _Packet Packet;
typedef struct _PacketRequestCompletion PacketRequestCompletion;
typedef struct _Transport Transport;
typedef struct _Remote Remote;
typedef struct _TimeoutSettings TimeoutSettings;

typedef SOCKET(*PTransportGetSocket)(Transport* transport);
typedef void(*PTransportReset)(Transport* transport, BOOL shuttingDown);
typedef BOOL(*PTransportInit)(Transport* transport);
typedef BOOL(*PTransportDeinit)(Transport* transport);
typedef void(*PTransportDestroy)(Transport* transport);
typedef Transport*(*PTransportCreate)(Remote* remote, MetsrvTransportCommon* config, LPDWORD size);
typedef void(*PConfigCreate)(Remote* remote, MetsrvConfig** config, LPDWORD size);

typedef BOOL(*PServerDispatch)(Remote* remote, THREAD* dispatchThread);
typedef DWORD(*PPacketTransmit)(Remote* remote, Packet* packet, PacketRequestCompletion* completion);

typedef struct _TimeoutSettings
{
	/*! @ brief The total number of seconds to wait for a new packet before killing off the session. */
	int comms;
	/*! @ brief The total number of seconds to keep retrying for before a new session is established. */
	UINT retry_total;
	/*! @ brief The number of seconds to wait between reconnects. */
	UINT retry_wait;
} TimeoutSettings;

typedef struct _TcpTransportContext
{
	SOCKET fd;                            ///! Remote socket file descriptor.
	SOCKET listen;                        ///! Listen socket descriptor, if any.
	SSL_METHOD* meth;                     ///! The current SSL method in use.
	SSL_CTX* ctx;                         ///! SSL-specific context information.
	SSL* ssl;                             ///! Pointer to the SSL detail/version/etc.
} TcpTransportContext;

typedef struct _HttpTransportContext
{
	BOOL ssl;                             ///! Flag indicating whether the connection uses SSL.
	HANDLE internet;                      ///! Handle to the internet module for use with HTTP and HTTPS.
	HANDLE connection;                    ///! Handle to the HTTP or HTTPS connection.
	unsigned char* cert_hash;             ///! Pointer to the 20-byte certificate hash to validate

	STRTYPE ua;                           ///! User agent string.
	STRTYPE uri;                          ///! UUID encoded as a URI.
	STRTYPE proxy;                        ///! Proxy details.
	STRTYPE proxy_user;                   ///! Proxy username.
	STRTYPE proxy_pass;                   ///! Proxy password.
} HttpTransportContext;

typedef struct _Transport
{
	DWORD type;                           ///! The type of transport in use.
	PTransportGetSocket get_socket;       ///! Function to get the socket from the transport.
	PTransportReset transport_reset;      ///! Function to reset/clean the transport ready for restarting.
	PTransportInit transport_init;        ///! Initialises the transport.
	PTransportDeinit transport_deinit;    ///! Deinitialises the transport.
	PTransportDestroy transport_destroy;  ///! Destroy the transport.
	PServerDispatch server_dispatch;      ///! Transport dispatch function.
	PPacketTransmit packet_transmit;      ///! Transmits a packet over the transport.
	STRTYPE url;                          ///! Full URL describing the comms in use.
	VOID* ctx;                            ///! Pointer to the type-specific transport context;
	TimeoutSettings timeouts;             ///! Container for the timeout settings.
	int comms_last_packet;                ///! Unix timestamp of the last packet received.
	struct _Transport* next_transport;    ///! Pointer to the next transport in the list.
	struct _Transport* prev_transport;    ///! Pointer to the previous transport in the list.
	LOCK* lock;                           ///! Shared reference to the lock used in Remote.
} Transport;

/*!
 * @brief Remote context allocation.
 * @details Wraps the initialized file descriptor for extension purposes.
 *          A \c Remote is effectively a pointer to a remote client context
 *          which contains magic pixie dust that identifies the connection
 *          along with a way to interact with it.
 * @remark The `Original` and `Current` members are used to allow for
 *         functionality such as `rev2self` and reverting back to the initial
 *         desktop stations/desktops.
 */
typedef struct _Remote
{
	HMODULE met_srv;                      ///! Reference to the Meterpreter server instance.

	CryptoContext* crypto;                ///! Cryptographic context associated with the connection.

	PConfigCreate config_create;          ///! Pointer to the function that will create a configuration block from the curren setup.

	Transport* transport;                 ///! Pointer to the currently used transport mechanism in a circular list of transports
	Transport* next_transport;            ///! Set externally when transports are requested to be changed.
	DWORD next_transport_wait;            ///! Number of seconds to wait before going to the next transport (used for sleeping).

	MetsrvConfig* orig_config;            ///! Pointer to the original configuration.

	LOCK* lock;                           ///! General transport usage lock (used by SSL, and desktop stuff too).

	HANDLE server_thread;                 ///! Handle to the current server thread.
	HANDLE server_token;                  ///! Handle to the current server security token.
	HANDLE thread_token;                  ///! Handle to the current thread security token.

	DWORD orig_sess_id;                   ///! ID of the original Meterpreter session.
	DWORD curr_sess_id;                   ///! ID of the currently active session.
	char* orig_station_name;              ///! Original station name.
	char* curr_station_name;              ///! Name of the current station.

#ifdef _WIN32
	char* orig_desktop_name;              ///! Original desktop name.
	char* curr_desktop_name;              ///! Name of the current desktop.
#endif

	PTransportCreate trans_create;        ///! Helper to create transports from configuration.

	int sess_expiry_time;                 ///! Number of seconds that the session runs for.
	int sess_expiry_end;                  ///! Unix timestamp for when the server should shut down.
	int sess_start_time;                  ///! Unix timestamp representing the session startup time.
} Remote;

Remote* remote_allocate();
VOID remote_deallocate(Remote *remote);

VOID remote_set_fd(Remote *remote, SOCKET fd);

DWORD remote_set_cipher(Remote *remote, LPCSTR cipher, struct _Packet *initializer);
CryptoContext *remote_get_cipher(Remote *remote);

#endif
