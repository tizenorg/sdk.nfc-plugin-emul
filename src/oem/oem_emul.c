/*
* Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#define _GNU_SOURCE
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <malloc.h>
#include <vconf.h>

#include <pwd.h>
#include <grp.h>
#include <sys/epoll.h>

#ifdef USE_GLIB_MAIN_LOOP
#include <glib.h>
#endif

#include "net_nfc_oem_controller.h"
#include "net_nfc_typedef.h"
#include "nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_ndef_record.h"

#include <netinet/in.h>

/***************************	STRUCTURE DEFINE START	***************************************/

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

typedef enum {
	EMUL_NFC_TAG_DISCOVERED = 100,
	EMUL_NFC_TAG_DETACHED,
	EMUL_NFC_P2P_DISCOVERED,
	EMUL_NFC_P2P_DETACHED,
	EMUL_NFC_P2P_SEND,
	EMUL_NFC_UNKNOWN_MSG
} emul_message_id;

typedef enum {
	EMUL_TAG_TOPAZ_JEWEL =1,
	EMUL_TAG_MIFARE_UL,
	EMUL_TAG_FELICA,
	EMUL_TAG_MIFARE_DESFIRE,
	EMUL_NFC_TARGET,
	EMUL_TARGET_TYPE_MAX
} emul_target_type;

typedef enum {
	EMUL_NDEF_TNF_EMPTY = 0,
	EMUL_NDEF_TNF_WELL_KNOWN,
	EMUL_NDEF_TNF_MIME_MEDIA,
	EMUL_NDEF_TNF_ABSOLUTE_URI,
	EMUL_NDEF_TNF_EXTERNAL,
	EMUL_NDEF_TNF_UNKNOWN
} emul_ndef_name_format;

typedef enum {
	NET_NFC_STATE_EXCHANGER_SERVER = 0x00,
	NET_NFC_STATE_EXCHANGER_SERVER_NPP,

	NET_NFC_STATE_EXCHANGER_CLIENT,
	NET_NFC_STATE_CONN_HANDOVER_REQUEST,
	NET_NFC_STATE_CONN_HANDOVER_SELECT,
	NET_NFC_STATE_UNKNOWN
} llcp_state_e;

typedef enum{
	SNEP_REQ_CONTINUE = 0x00,
	SNEP_REQ_GET = 0x01,
	SNEP_REQ_PUT = 0x02,
	SNEP_REQ_REJECT = 0x7F,
	SNEP_RESP_CONT = 0x80,
	SNEP_RESP_SUCCESS = 0x81,
	SNEP_RESP_NOT_FOUND = 0xC0,
	SNEP_RESP_EXCESS_DATA = 0xC1,
	SNEP_RESP_BAD_REQ = 0xC2,
	SNEP_RESP_NOT_IMPLEMENT = 0xE0,
	SNEP_RESP_UNSUPPORTED_VER = 0xE1,
	SNEP_RESP_REJECT = 0xFF,
}snep_command_field_e;

typedef struct _socket_info_s {
	net_nfc_llcp_socket_t socket_handle;
	bool isValid;
	void* user_context;
}socket_info_s;

typedef struct _net_nfc_oem_llcp_state_t{
	int client_fd;
	unsigned int step;
	unsigned int fragment_offset;
	llcp_state_e state;
	net_nfc_llcp_socket_t socket;
	uint16_t max_capability;
	net_nfc_target_handle_s * handle;
	net_nfc_error_e prev_result;
	net_nfc_llcp_socket_t incomming_socket;
	ndef_message_s *requester;
	ndef_message_s *selector;
	bool low_power;
	void * user_data;
	void * payload;

	llcp_app_protocol_e type_app_protocol;
	net_nfc_conn_handover_carrier_type_e type;

} net_nfc_oem_llcp_state_t;

typedef struct _snep_msg_s{
	data_s *data;
	int offset;
	bool isSegment;

	/* Members below are used for snep msg of client */
	bool firstTime;
	bool RespContinue;
}snep_msg_s;

typedef struct _emulMsg_data_s{
	net_nfc_record_tnf_e tnf;
	data_s typeName;
	data_s id;
	data_s payload;

	bool realRecord;
}emulMsg_data_s;

typedef struct _emulMsg_s{
	emul_message_id message_id;
	emul_target_type target_type;
	int record_count;
	uint8_t* file_data;

	data_s rawdata;
}emulMsg_s;

typedef void * (*emul_Nfc_thread_handler_t)   (void * pParam);

/***************************	STRUCTURE DEFINE START	***************************************/



/******************************             DEFINE START	*******************************************/

/* for emulator management */
#define NET_NFC_EMUL_DATA_PATH				"/opt/nfc/"
#define NET_NFC_EMUL_MESSAGE_FILE_NAME		"sdkMsg"
#define NET_NFC_EMUL_MSG_ID_SEPERATOR			"\n:"
#define NET_NFC_EMUL_MSG_DATA_SEPERATOR		"\n\0"
#define NET_NFC_EMUL_MSG_RECORD_SEPERATOR	"\n,"
#define NET_NFC_EMUL_TAG_DISCOVERED_DATA_FORMAT "%d,%d,%[^\n]"

#ifdef __USE_EPOLL_FOR_FILE__
#define EPOLL_SIZE 128
#endif

/* for llcp functionality */
#define LLCP_NB_SOCKET_MAX 5
#define NET_NFC_EMUL_SNEP_SERVER_SOCKET_NUMBER 0
#define NET_NFC_EMUL_INCOMING_SOCKET_NUMBER 0
#define NET_NFC_EMUL_NPP_SERVER_SOCKET_NUMBER 1
#define NET_NFC_EMUL_CLIENT_SOCKET_NUMBER 2
#define NET_NFC_EMUL_HANDOVER_REQUEST_SOCKET_NUMBER 3
#define NET_NFC_EMUL_HANDOVER_SELECT_SOCKET_NUMBER 4

#define SNEP_MAX_BUFFER	128
#define SNEP_MAJOR_VER 1
#define SNEP_MINOR_VER 0

/* static variable */
#define BUFFER_LENGTH_MAX 4096
#define READ_BUFFER_LENGTH_MAX BUFFER_LENGTH_MAX
#define WRITE_BUFFER_LENGTH_MAX BUFFER_LENGTH_MAX
#define NET_NFC_MAX_LLCP_SOCKET_BUFFER BUFFER_LENGTH_MAX

/******************************             DEFINE END	*******************************************/



/******************************          VARIABLE START	*******************************************/

/* listener callback */
static target_detection_listener_cb	g_emul_controller_target_cb ;
static se_transaction_listener_cb		g_emul_controller_se_cb ;
static llcp_event_listener_cb			g_emul_controller_llcp_cb ;

/* for emulator management */
pthread_t			gEmulThread;
emulMsg_s		gSdkMsg;

/* for stack management */
static net_nfc_target_handle_s * current_working_handle = NULL;
static bool			g_stack_init_successful = 0;
static bool			g_target_attached = 0;

/* for llcp functionality */
snep_msg_s		Snep_Server_msg = {0,};
snep_msg_s		Snep_Client_msg = {0,};
socket_info_s socket_info_array[LLCP_NB_SOCKET_MAX] = {{0,}};
data_s * llcp_server_data = NULL;
data_s * llcp_client_data = NULL;

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/******************************          VARIABLE END	*******************************************/



/***************************	STATIC FUNCTION	DECLARE START	***************************************/

/***************************	INTERFACE START	***************************************/

static bool net_nfc_emul_controller_init (net_nfc_error_e* result);
static bool net_nfc_emul_controller_deinit (void);
static bool net_nfc_emul_controller_register_listener(target_detection_listener_cb target_detection_listener,se_transaction_listener_cb se_transaction_listener, llcp_event_listener_cb llcp_event_listener, net_nfc_error_e* result);
static bool net_nfc_emul_controller_unregister_listener();
static bool net_nfc_emul_controller_get_firmware_version(data_s **data, net_nfc_error_e *result);
static bool net_nfc_emul_controller_check_firmware_version(net_nfc_error_e* result);
static bool net_nfc_emul_controller_update_firmware(net_nfc_error_e* result);
static bool net_nfc_emul_controller_get_stack_information(net_nfc_stack_information_s* stack_info, net_nfc_error_e* result);
static bool net_nfc_emul_controller_configure_discovery (net_nfc_discovery_mode_e mode, net_nfc_event_filter_e config, net_nfc_error_e* result);
static bool net_nfc_emul_controller_get_secure_element_list(net_nfc_secure_element_info_s* list, int* count, net_nfc_error_e* result);
static bool net_nfc_emul_controller_set_secure_element_mode(net_nfc_secure_element_type_e element_type, net_nfc_secure_element_mode_e mode, net_nfc_error_e* result);
static bool net_nfc_emul_controller_connect(net_nfc_target_handle_s* handle, net_nfc_error_e* result);
static bool net_nfc_emul_controller_disconnect(net_nfc_target_handle_s* handle, net_nfc_error_e* result);
static bool net_nfc_emul_controller_check_ndef(net_nfc_target_handle_s* handle, uint8_t *ndef_card_state, int* max_data_size, int* real_data_size, net_nfc_error_e* result);
static bool net_nfc_emul_controller_check_target_presence(net_nfc_target_handle_s* handle, net_nfc_error_e* result);
static bool net_nfc_emul_controller_read_ndef(net_nfc_target_handle_s* handle, data_s** data, net_nfc_error_e* result);
static bool net_nfc_emul_controller_write_ndef(net_nfc_target_handle_s* handle, data_s* data, net_nfc_error_e* result);
static bool net_nfc_emul_controller_make_read_only_ndef(net_nfc_target_handle_s* handle, net_nfc_error_e* result);
static bool net_nfc_emul_controller_transceive (net_nfc_target_handle_s* handle, net_nfc_transceive_info_s* info, data_s** data, net_nfc_error_e* result);
static bool net_nfc_emul_controller_format_ndef(net_nfc_target_handle_s* handle, data_s* secure_key, net_nfc_error_e* result);
static bool net_nfc_emul_controller_exception_handler(void);
static bool net_nfc_emul_controller_is_ready(net_nfc_error_e* error);

static bool net_nfc_emul_controller_llcp_config (net_nfc_llcp_config_info_s * config, net_nfc_error_e * result);
static bool net_nfc_emul_controller_llcp_check_llcp (net_nfc_target_handle_s * handle, net_nfc_error_e* result);
static bool net_nfc_emul_controller_llcp_activate_llcp (net_nfc_target_handle_s * handle, net_nfc_error_e* result);
static bool net_nfc_emul_controller_llcp_create_socket (net_nfc_llcp_socket_t* socket, net_nfc_socket_type_e socketType, uint16_t miu, uint8_t rw,  net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_bind(net_nfc_llcp_socket_t socket, uint8_t service_access_point, net_nfc_error_e* result);
static bool net_nfc_emul_controller_llcp_listen(net_nfc_target_handle_s* handle, uint8_t* service_access_name, net_nfc_llcp_socket_t socket, net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_accept (net_nfc_llcp_socket_t socket, net_nfc_error_e* result);
static bool net_nfc_emul_controller_llcp_connect_by_url( net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, uint8_t* service_access_name, net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_connect(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, uint8_t service_access_point, net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_reject(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, net_nfc_error_e* result);
static bool net_nfc_emul_controller_llcp_disconnect (net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_socket_close (net_nfc_llcp_socket_t socket, net_nfc_error_e* result);
static bool net_nfc_emul_controller_llcp_recv(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, data_s* data, net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_send(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, data_s* data, net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_recv_from(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, data_s * data, net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_send_to(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, data_s* data, uint8_t service_access_point, net_nfc_error_e* result, void * user_param);
static bool net_nfc_emul_controller_llcp_get_remote_config (net_nfc_target_handle_s* handle, net_nfc_llcp_config_info_s *config, net_nfc_error_e* result);
static bool net_nfc_emul_controller_llcp_get_remote_socket_info (net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_s * option, net_nfc_error_e* result);

static bool net_nfc_emul_controller_support_nfc(net_nfc_error_e *result);

/***************************	INTERFACE END	***************************************/



/***************************	ETC Function	***************************************/

/* Memory utils */
/* free memory, after free given memory it set NULL. Before proceed free, this function also check NULL */
void __nfc_emul_util_free_mem(void** mem, char * filename, unsigned int line);
/* allocation memory */
void __nfc_emul_util_alloc_mem(void** mem, int size, char * filename, unsigned int line);
#define	 _nfc_emul_util_alloc_mem(mem,size) __nfc_emul_util_alloc_mem((void **)&mem,size,__FILE__, __LINE__)
#define	 _nfc_emul_util_free_mem(mem) __nfc_emul_util_free_mem((void **)&mem,__FILE__, __LINE__)


static bool __net_nfc_is_valide_target_handle (net_nfc_target_handle_s * handle);
static void __net_nfc_make_valid_target_handle (net_nfc_target_handle_s ** handle);
static void __net_nfc_make_invalid_target_handle ();

/***************************	STATIC FUNCTION	DECLARE END		***************************************/



void __nfc_emul_util_free_mem (void** mem, char * filename, unsigned int line)
{
	if (mem == NULL || *mem == NULL)
	{
		DEBUG_MSG ("FILE: %s, LINE:%d, Invalid parameter in mem free util (pinter is NULL)", filename, line);
		return;
	}
	free(*mem);
	*mem = NULL;
}

void __nfc_emul_util_alloc_mem(void** mem, int size, char * filename, unsigned int line)
{
	if (mem == NULL || size <= 0)
	{
		DEBUG_MSG ("FILE: %s, LINE:%d, Invalid parameter in mem alloc util", filename, line);
		return;
	}

	DEBUG_MSG("size to malloc() = [%d]", size);

	if (*mem != NULL)
	{
		DEBUG_MSG("FILE: %s, LINE:%d, WARNING: Pointer is already allocated or it was not initialized with NULL", filename, line);
	}

	*mem = malloc (size);

	if (*mem != NULL)
	{
		memset (*mem, 0x0, size);
	}
	else
	{
		DEBUG_MSG("FILE: %s, LINE:%d, Allocation is failed", filename, line);
	}
}

static bool __net_nfc_is_valide_target_handle (net_nfc_target_handle_s * handle)
{
	bool result = (current_working_handle == handle);
	if (!result){
		DEBUG_MSG ("[WARNING]: INVALID HANDLE IS DETECTED!");
	}
	return result;
}
static void __net_nfc_make_valid_target_handle (net_nfc_target_handle_s ** handle)
{
	if (current_working_handle != NULL){
		DEBUG_MSG ("[WARNING]: HANDLE WAS ALLOCATED ALREADY!");
	}
	_nfc_emul_util_alloc_mem (*handle, sizeof (net_nfc_target_handle_s));
	if (*handle != NULL) {
		current_working_handle = *handle;
	}
}
static void __net_nfc_make_invalid_target_handle ()
{
	if (current_working_handle != NULL) {
		_nfc_emul_util_free_mem (current_working_handle);
		current_working_handle = NULL;
	}
}

static socket_info_s * _net_nfc_get_available_socket_slot ()
{
	int idx = 0;
	for (; idx < LLCP_NB_SOCKET_MAX; idx++)
	{
		if (socket_info_array [idx].isValid == false)
		{
			memset (&(socket_info_array[idx]), 0x00, sizeof (socket_info_s));
			socket_info_array [idx].isValid = true;
			return &(socket_info_array[idx]);
		}
	}

	DEBUG_ERR_MSG("_net_nfc_get_available_socket_slot is failed");
	return NULL;
}

static void _net_nfc_remove_socket_slot (net_nfc_llcp_socket_t socket)
{
	int idx = 0;

	for (; idx < LLCP_NB_SOCKET_MAX; idx++)
	{
		if (socket_info_array [idx].isValid == true &&
			socket_info_array [idx].socket_handle == socket)
		{
			socket_info_array [idx].isValid = false;
			socket_info_array [idx].socket_handle = 0;
			socket_info_array [idx].user_context= NULL;
		}
	}
}

static socket_info_s * _net_nfc_find_server_socket (net_nfc_llcp_socket_t socket)
{
	int idx = 0;
	for (; idx < LLCP_NB_SOCKET_MAX; idx++)
	{
		if (socket_info_array [idx].socket_handle == socket && socket_info_array [idx].isValid == true)
		{
			return &(socket_info_array[idx]);
		}
	}

	DEBUG_ERR_MSG("_net_nfc_find_server_socket is failed");
	return NULL;
}

////////////// INTERFACE START //////////

NET_NFC_EXPORT_API bool onload(net_nfc_oem_interface_s* emul_interfaces)
{
	DEBUG_EMUL_BEGIN();

	emul_interfaces->init = net_nfc_emul_controller_init;
	emul_interfaces->deinit = net_nfc_emul_controller_deinit;
	emul_interfaces->register_listener = net_nfc_emul_controller_register_listener;
	emul_interfaces->unregister_listener = net_nfc_emul_controller_unregister_listener;
	emul_interfaces->get_firmware_version = net_nfc_emul_controller_get_firmware_version;
	emul_interfaces->check_firmware_version = net_nfc_emul_controller_check_firmware_version;
	emul_interfaces->update_firmeware = net_nfc_emul_controller_update_firmware;
	emul_interfaces->get_stack_information = net_nfc_emul_controller_get_stack_information;
	emul_interfaces->configure_discovery = net_nfc_emul_controller_configure_discovery;
	emul_interfaces->get_secure_element_list = net_nfc_emul_controller_get_secure_element_list;
	emul_interfaces->set_secure_element_mode = net_nfc_emul_controller_set_secure_element_mode;
	emul_interfaces->connect = net_nfc_emul_controller_connect;
	emul_interfaces->disconnect = net_nfc_emul_controller_disconnect;
	emul_interfaces->check_ndef = net_nfc_emul_controller_check_ndef;
	emul_interfaces->check_presence = net_nfc_emul_controller_check_target_presence;
	emul_interfaces->read_ndef = net_nfc_emul_controller_read_ndef;
	emul_interfaces->write_ndef = net_nfc_emul_controller_write_ndef;
	emul_interfaces->make_read_only_ndef = net_nfc_emul_controller_make_read_only_ndef;
	emul_interfaces->transceive = net_nfc_emul_controller_transceive;
	emul_interfaces->format_ndef = net_nfc_emul_controller_format_ndef;
	emul_interfaces->exception_handler = net_nfc_emul_controller_exception_handler;
	emul_interfaces->is_ready = net_nfc_emul_controller_is_ready;

	emul_interfaces->config_llcp = net_nfc_emul_controller_llcp_config;
	emul_interfaces->check_llcp_status = net_nfc_emul_controller_llcp_check_llcp;
	emul_interfaces->activate_llcp = net_nfc_emul_controller_llcp_activate_llcp;
	emul_interfaces->create_llcp_socket = net_nfc_emul_controller_llcp_create_socket;
	emul_interfaces->bind_llcp_socket = net_nfc_emul_controller_llcp_bind;
	emul_interfaces->listen_llcp_socket = net_nfc_emul_controller_llcp_listen;
	emul_interfaces->accept_llcp_socket = net_nfc_emul_controller_llcp_accept;
	emul_interfaces->connect_llcp_by_url = net_nfc_emul_controller_llcp_connect_by_url;
	emul_interfaces->connect_llcp = net_nfc_emul_controller_llcp_connect;
	emul_interfaces->disconnect_llcp = net_nfc_emul_controller_llcp_disconnect;
	emul_interfaces->close_llcp_socket = net_nfc_emul_controller_llcp_socket_close;
	emul_interfaces->recv_llcp = net_nfc_emul_controller_llcp_recv;
	emul_interfaces->send_llcp = net_nfc_emul_controller_llcp_send;
	emul_interfaces->recv_from_llcp = net_nfc_emul_controller_llcp_recv_from;
	emul_interfaces->send_to_llcp = net_nfc_emul_controller_llcp_send_to;
	emul_interfaces->reject_llcp = net_nfc_emul_controller_llcp_reject;
	emul_interfaces->get_remote_config = net_nfc_emul_controller_llcp_get_remote_config;
	emul_interfaces->get_remote_socket_info = net_nfc_emul_controller_llcp_get_remote_socket_info;

	emul_interfaces->support_nfc = net_nfc_emul_controller_support_nfc;

	DEBUG_EMUL_END();

	return true;
}

static void _net_nfc_initialize_llcp(void)
{
	DEBUG_EMUL_BEGIN();

	if (Snep_Server_msg.data != NULL) {
		if (Snep_Server_msg.data->buffer != NULL) {
			free(Snep_Server_msg.data->buffer);
		}
		free(Snep_Server_msg.data);
	}
	memset(&Snep_Server_msg, 0x00, sizeof(snep_msg_s));

	if (Snep_Client_msg.data != NULL) {
		if (Snep_Client_msg.data->buffer != NULL) {
			free(Snep_Client_msg.data->buffer);
		}
		free(Snep_Client_msg.data);
	}
	memset(&Snep_Client_msg, 0x00, sizeof(snep_msg_s));

	llcp_server_data = NULL;
	llcp_client_data = NULL;

	DEBUG_EMUL_END();
}

static void _net_nfc_initialize_emulMsg(void)
{
	DEBUG_EMUL_BEGIN();

	gSdkMsg.message_id = EMUL_NFC_UNKNOWN_MSG;
	gSdkMsg.target_type = EMUL_TARGET_TYPE_MAX;
	gSdkMsg.record_count = 0;

	if (gSdkMsg.file_data != NULL) {
		free(gSdkMsg.file_data);
		gSdkMsg.file_data = NULL;
	}

	if (gSdkMsg.rawdata.buffer != NULL) {
		free(gSdkMsg.rawdata.buffer);
		gSdkMsg.rawdata.buffer = NULL;
	}
	gSdkMsg.rawdata.length = 0;

	DEBUG_EMUL_END();
}

static bool _net_nfc_is_data_emulMsgData(emul_message_id messageId)
{
	DEBUG_EMUL_BEGIN();

	bool retval = false;

	switch (messageId) {
		case EMUL_NFC_TAG_DISCOVERED :{
			retval = true;
		}
		break;

		case EMUL_NFC_P2P_SEND :{
			retval = true;
		}
		break;

		case EMUL_NFC_TAG_DETACHED :
		case EMUL_NFC_P2P_DISCOVERED :
		case EMUL_NFC_P2P_DETACHED :
		default :
		break;

	}

	DEBUG_MSG("retval [%d]", retval);

	DEBUG_EMUL_END();

	return retval;
}

static net_nfc_record_tnf_e _net_nfc_get_tnf_type(int name_format)
{
	DEBUG_EMUL_BEGIN();

	net_nfc_record_tnf_e tnf = NET_NFC_RECORD_EMPTY;

	switch (name_format) {
		case EMUL_NDEF_TNF_EMPTY :
			tnf = NET_NFC_RECORD_EMPTY;
		break;

		case EMUL_NDEF_TNF_WELL_KNOWN :
			tnf = NET_NFC_RECORD_WELL_KNOWN_TYPE;
		break;

		case EMUL_NDEF_TNF_MIME_MEDIA :
			tnf = NET_NFC_RECORD_MIME_TYPE;
		break;

		case EMUL_NDEF_TNF_ABSOLUTE_URI :
			tnf = NET_NFC_RECORD_URI;
		break;

		case EMUL_NDEF_TNF_EXTERNAL :
			tnf = NET_NFC_RECORD_EXTERNAL_RTD;
		break;

		case EMUL_NDEF_TNF_UNKNOWN :
			tnf = NET_NFC_RECORD_UNKNOWN;
		break;

		default :
			tnf = NET_NFC_RECORD_UNKNOWN;
			DEBUG_MSG("data is currupted");
		break;

	}

	DEBUG_MSG("tnf [%d]", tnf);

	DEBUG_EMUL_END();

	return tnf;

}

static bool _net_nfc_set_emulMsg(uint8_t * emulData, long int messageSize)
{
	DEBUG_EMUL_BEGIN();

	char *emulMsgID;
	char *emulMsgData;

	/* emulData => ID : MSG ex) 100:1,1,1,U,samsung,http://www.naver.com */
	emulMsgID = strtok((char *)emulData, NET_NFC_EMUL_MSG_ID_SEPERATOR);
	if (emulMsgID != NULL) {
		gSdkMsg.message_id = (emul_message_id) (atoi(emulMsgID));
	}

	DEBUG_MSG("gSdkMsg.message_id >>>>[%d]", gSdkMsg.message_id);

	if (_net_nfc_is_data_emulMsgData(gSdkMsg.message_id)) {

		emulMsgData = strtok(NULL, NET_NFC_EMUL_MSG_DATA_SEPERATOR);
		DEBUG_MSG("emulMsgData >>>>[%s]", emulMsgData);

		switch (gSdkMsg.message_id) {
			case EMUL_NFC_TAG_DISCOVERED :
			case EMUL_NFC_P2P_SEND :
			{
				/* get message : Tag Type, Record Count, Records */
				int target_type = -1;
				char file_data[BUFFER_LENGTH_MAX]={ 0, };
				int length =0;

				sscanf(emulMsgData, NET_NFC_EMUL_TAG_DISCOVERED_DATA_FORMAT, &target_type, &gSdkMsg.record_count, file_data);

				gSdkMsg.target_type = (emul_target_type) target_type;

				length = strlen(file_data)+1;
				_nfc_emul_util_alloc_mem(gSdkMsg.file_data, length);
				memcpy(gSdkMsg.file_data, file_data, length);

				DEBUG_ERR_MSG("EMUL MESSAGE DATA START >>>>>>>>>>>>>>>>>>>>>>>>");
				DEBUG_MSG("message_id >>>>[%d]", gSdkMsg.message_id);
				DEBUG_MSG("target_type >>>>[%d]", gSdkMsg.target_type);
				DEBUG_MSG("record_count >>>>[%d]", gSdkMsg.record_count);
				DEBUG_MSG("file_data >>>>[%s]", (char *)gSdkMsg.file_data);
				DEBUG_ERR_MSG("EMUL MESSAGE DATA END >>>>>>>>>>>>>>>>>>>>>>>>");
			}
			break;

			default : {
				/* exception case */
				DEBUG_ERR_MSG("_net_nfc_set_emulMsg error. Data is currupted");
				return false;
			}
			break;

		}
	}
	else {

		switch (gSdkMsg.message_id) {
			case EMUL_NFC_P2P_DISCOVERED :{
				gSdkMsg.target_type = EMUL_NFC_TARGET;
			}
			break;

			case EMUL_NFC_TAG_DETACHED :
			case EMUL_NFC_P2P_DETACHED :
				DEBUG_MSG("TAG or TARGET DETACHED");
			break;

			default : {
				/* exception case */
				DEBUG_ERR_MSG("_net_nfc_set_emulMsg error. Data is currupted");
				return false;
			}
			break;
		}
	}

	DEBUG_EMUL_END();

	return true;
}

static int _net_nfc_create_records_from_emulMsg(ndef_message_s **ndef_message, int record_count)
{
	DEBUG_EMUL_BEGIN();

	int index;
	int create_record_count = 0;
	char emulMsg[BUFFER_LENGTH_MAX] = { 0, };

	memcpy(emulMsg, gSdkMsg.file_data, strlen((char*)gSdkMsg.file_data));

	/* parsing data and create record to record structure */
	for (index = 0; index < record_count ; index ++) {
		char *name_format;
		char *type_name;
		char *record_id;
		char *record_payload;

		emulMsg_data_s record = { 0, };
		data_s filePayload;

		/* parse string */
		if (index == 0)
		{
			name_format = strtok((char *) emulMsg, NET_NFC_EMUL_MSG_RECORD_SEPERATOR);
		}
		else
		{
			name_format = strtok(NULL, NET_NFC_EMUL_MSG_RECORD_SEPERATOR);
		}
		type_name = strtok(NULL, NET_NFC_EMUL_MSG_RECORD_SEPERATOR);
		record_id = strtok(NULL, NET_NFC_EMUL_MSG_RECORD_SEPERATOR);
		if (index == record_count-1) {
			/* the last payload : we have to read sentence fully */
			record_payload = strtok(NULL, "\n");
		}
		else {
			record_payload = strtok(NULL, NET_NFC_EMUL_MSG_RECORD_SEPERATOR);
		}

		/* assign data to record structure */
		record.tnf = _net_nfc_get_tnf_type(atoi(name_format));

		if (strcmp(type_name, "Null")) {
			DEBUG_MSG("Data : type_name ");

			record.typeName.length = strlen(type_name);
			_nfc_emul_util_alloc_mem(record.typeName.buffer, record.typeName.length);

			if (record.typeName.buffer == NULL) {
				DEBUG_MSG("_nfc_emul_util_alloc_mem failed");
				goto ERROR;
			}
			memcpy(record.typeName.buffer, type_name, record.typeName.length);
		}

		if (strcmp(record_id, "Null")) {
			DEBUG_MSG("Data : record_id ");

			record.id.length = strlen(record_id);
			_nfc_emul_util_alloc_mem(record.id.buffer, record.id.length);

			if (record.id.buffer == NULL) {
				DEBUG_MSG("_nfc_emul_util_alloc_mem failed");
				goto ERROR;
			}
			memcpy(record.id.buffer, record_id, record.id.length);
		}

		if (strcmp(record_payload, "Null")) {
			DEBUG_MSG("Data : record_payload ");

			record.payload.length = strlen(record_payload);
			_nfc_emul_util_alloc_mem(record.payload.buffer, record.payload.length);

			if (record.payload.buffer == NULL) {
				DEBUG_MSG("_nfc_emul_util_alloc_mem failed");
				goto ERROR;
			}
			memcpy(record.payload.buffer, record_payload, record.payload.length);
		}

#ifndef __EMUL_DEBUG__
		DEBUG_ERR_MSG("RECORD DATA START >>>>>>>>>>>>>>>>>>>>>>>>");
		DEBUG_MSG("TNF >>>>[%d]", record.tnf);
		DEBUG_MSG("type_name >>>>[%s]", type_name);
		DEBUG_MSG("record_id >>>>[%s]", record_id);
		DEBUG_MSG("record_payload >>>>[%s]", record_payload);
		DEBUG_ERR_MSG("RECORD DATA END >>>>>>>>>>>>>>>>>>>>>>>>");
#endif

		/* create record */
		ndef_record_h new_record = NULL;
		net_nfc_error_e result = NET_NFC_OK;

		if (record.tnf == NET_NFC_RECORD_EMPTY) {
			if((result = net_nfc_util_create_record(NET_NFC_RECORD_EMPTY, &record.typeName, &record.id, &record.payload, (ndef_record_s **) &new_record)) != NET_NFC_OK) {
				DEBUG_MSG("net_nfc_create_record failed[%d]", result);
				goto ERROR;;
			}
		}
		else if (record.tnf == NET_NFC_RECORD_UNKNOWN) {
			if((result = net_nfc_util_create_record(NET_NFC_RECORD_UNKNOWN, &record.typeName, &record.id, &record.payload, (ndef_record_s **) &new_record)) != NET_NFC_OK) {
				DEBUG_MSG("net_nfc_create_record failed[%d]", result);
				goto ERROR;;
			}
		}
		else if ((record.tnf == NET_NFC_RECORD_WELL_KNOWN_TYPE)) {
			if (!strncmp((char *)record.typeName.buffer, "U", 1)) {
				DEBUG_MSG("URI Type ");

				data_s payload_data = { NULL, 0 };

				if (record.payload.buffer != NULL )
				{
					payload_data.length = strlen((char *)record_payload) + 1;

					_nfc_emul_util_alloc_mem(payload_data.buffer, payload_data.length);
					if (payload_data.buffer == NULL)
					{
						DEBUG_MSG("_nfc_emul_util_alloc_mem failed");
						goto ERROR;
					}

					payload_data.buffer[0] = NET_NFC_SCHEMA_FULL_URI;	/* first byte of payload is protocol scheme */
					memcpy(payload_data.buffer + 1, record.payload.buffer, payload_data.length - 1);
				}

				if (net_nfc_util_create_record(record.tnf, &record.typeName, &record.id, &payload_data, (ndef_record_s**) &new_record) != NET_NFC_OK){
					DEBUG_ERR_MSG("net_nfc_util_create_record is failed");
					goto ERROR;
				}

				if (payload_data.buffer != NULL )
					_nfc_emul_util_free_mem(payload_data.buffer);
			}
			else if (!strncmp((char *)record.typeName.buffer, "T", 1)) {
				DEBUG_MSG("TEXT Type ");

				data_s payload_data = { NULL, 0 };
				int offset = 0;
				int controll_byte;

				if (record.payload.buffer != NULL )
				{
					payload_data.length = strlen((char *)record_payload) + strlen("en-US") + 1;

					_nfc_emul_util_alloc_mem(payload_data.buffer, payload_data.length);
					if (payload_data.buffer == NULL)
					{
						DEBUG_MSG("_nfc_emul_util_alloc_mem failed");
						goto ERROR;
					}

					controll_byte = strlen("en-US") & 0x3F;

					payload_data.buffer[0] = controll_byte;

					offset = 1;
					memcpy(payload_data.buffer + offset, "en-US", strlen("en-US"));

					offset = offset + strlen("en-US");
					memcpy(payload_data.buffer + offset, record.payload.buffer, strlen(record_payload));

				}

				if (net_nfc_util_create_record(record.tnf, &record.typeName, &record.id, &payload_data, (ndef_record_s**) &new_record) != NET_NFC_OK){
					DEBUG_ERR_MSG("net_nfc_util_create_record is failed");
					goto ERROR;
				}

				if (payload_data.buffer != NULL )
					_nfc_emul_util_free_mem(payload_data.buffer);
			}
			else {
				DEBUG_ERR_MSG("NET_NFC_RECORD_WELL_KNOWN_TYPE >> typeName is wrong");
				goto ERROR;
			}
		}
		else if ((record.tnf == NET_NFC_RECORD_MIME_TYPE)) {

			FILE *file = NULL;

			/* open file : size limit? 10k? */
			file = fopen(record_payload, "r");
			if (file != NULL) {
				long int file_len = 0, read_count = 0, read_total = 0;
				uint8_t *file_data = NULL;

				fseek(file, 0, SEEK_END);
				file_len = ftell(file);
				fseek(file, 0, SEEK_SET);

				_nfc_emul_util_alloc_mem(file_data, file_len);

				if (file_data == NULL)
				{
					DEBUG_MSG("_nfc_emul_util_alloc_mem failed");
					fclose(file);
					goto ERROR;
				}

				/* create payload */
				do
				{
					read_count = fread(file_data + read_total, 1, file_len - read_total, file);
					read_total += read_count;
				}
				while (read_count != 0 && read_total < file_len);

				fclose(file);

				DEBUG_MSG("fread(%s) success, size %ld", record.payload.buffer, file_len);

				filePayload.length= file_len;
				_nfc_emul_util_alloc_mem(filePayload.buffer, filePayload.length);

				if (filePayload.buffer == NULL) {
					DEBUG_MSG("_nfc_emul_util_alloc_mem failed");
					_nfc_emul_util_free_mem(file_data);
					goto ERROR;
				}
				memcpy(filePayload.buffer, file_data, filePayload.length);

				_nfc_emul_util_free_mem(file_data);

				/* set id */
				if (record.id.buffer == NULL) {
					char *file_name = NULL;

					file_name = strrchr(record_payload, '/');
					if (file_name == NULL) {
						file_name = (char *) record_payload;
					}
					else {
						file_name++;
					}

					record.id.length = strlen(file_name);
					_nfc_emul_util_alloc_mem(record.id.buffer, record.id.length);

					if (record.id.buffer == NULL) {
						DEBUG_MSG("_nfc_emul_util_alloc_mem failed");
						_nfc_emul_util_free_mem(filePayload.buffer);
						goto ERROR;
					}
					memcpy(record.id.buffer, file_name, record.id.length);
				}
			}
			else {
				DEBUG_MSG("file open error");
				goto ERROR;;
			}

			/* create record */
			if((result = net_nfc_util_create_record(record.tnf, &record.typeName, &record.id, &filePayload, (ndef_record_s **) &new_record)) != NET_NFC_OK) {
				DEBUG_MSG("net_nfc_create_record failed[%d]", result);
				goto ERROR;;
			}
		}
		else {
			/* NET_NFC_RECORD_URI or NET_NFC_RECORD_EXTERNAL_RTD */
			if((result = net_nfc_util_create_record(record.tnf, &record.typeName, &record.id, &record.payload, (ndef_record_s **) &new_record)) != NET_NFC_OK) {
				DEBUG_MSG("net_nfc_create_record failed[%d]", result);
				goto ERROR;;
			}
		}

		/* append record to ndef msg */
		if((result = net_nfc_util_append_record((ndef_message_s*) *ndef_message, (ndef_record_s *) new_record)) != NET_NFC_OK){
			DEBUG_MSG("net_nfc_util_append_record failed[%d]", result);
			goto ERROR;;
		}

		create_record_count++;
		DEBUG_MSG("Create Record Sucess. Create Record Count[%d]", create_record_count);
ERROR :
		/* To Do : memory issue */
#if 0
		/* free data */
		if (record.typeName.buffer != NULL) {
			_nfc_emul_util_free_mem(record.typeName.buffer);
		}
		if (record.id.buffer != NULL) {
			_nfc_emul_util_free_mem(record.id.buffer);
		}
		if (record.payload.buffer != NULL) {
			_nfc_emul_util_free_mem(record.payload.buffer);
		}
		if(filePayload.buffer != NULL) {
			_nfc_emul_util_free_mem(filePayload.buffer);
		}
#endif
		DEBUG_MSG("Create Record Loop End");

	}

	DEBUG_EMUL_END();

	return create_record_count;
}

static bool _net_nfc_create_ndef_from_emulMsg(void)
{
	DEBUG_EMUL_BEGIN();

	if (gSdkMsg.file_data == NULL) {
		return false;
	}

	int retval = true;
	net_nfc_error_e result = NET_NFC_OK;

	int record_count  = gSdkMsg.record_count;

	if(record_count == 0) {
		return false;
	}


	/* create ndef msg */
	ndef_message_h ndef_message = NULL;
	int ndef_length = 0;

	if((result = net_nfc_util_create_ndef_message ((ndef_message_s **) &ndef_message)) != NET_NFC_OK)
	{
		DEBUG_MSG("failed to create ndef message [%d]", result);
	}

	/* create records and append it to ndef_msg*/
	gSdkMsg.record_count = _net_nfc_create_records_from_emulMsg((ndef_message_s **) &ndef_message, record_count);

	/* convert ndef msg to raw data */
	ndef_length = net_nfc_util_get_ndef_message_length ((ndef_message_s *) ndef_message);

	if (!ndef_length){
		DEBUG_MSG("ndef_message size is zero!");
	}

	gSdkMsg.rawdata.length = ndef_length;
	_nfc_emul_util_alloc_mem(gSdkMsg.rawdata.buffer, ndef_length);

	if((result = net_nfc_util_convert_ndef_message_to_rawdata((ndef_message_s*)ndef_message, (data_s*) & gSdkMsg.rawdata)) != NET_NFC_OK) {
		DEBUG_MSG("net_nfc_util_convert_ndef_message_to_rawdata is failed![%d]", result);

	}

	net_nfc_util_free_ndef_message(ndef_message);
	DEBUG_EMUL_END();

	return retval;
}

static int _net_nfc_emul_convert_target_type(emul_target_type targetType)
{
	DEBUG_EMUL_BEGIN();

	int covert = 0;

	switch (targetType) {
		case EMUL_TAG_TOPAZ_JEWEL :
			covert = NET_NFC_JEWEL_PICC;
		break;

		case EMUL_TAG_MIFARE_UL :
			covert = NET_NFC_MIFARE_ULTRA_PICC;
		break;

		case EMUL_TAG_FELICA :
			covert = NET_NFC_FELICA_PICC;
		break;

		case EMUL_TAG_MIFARE_DESFIRE :
			covert = NET_NFC_MIFARE_DESFIRE_PICC;
		break;

		case EMUL_NFC_TARGET :
			covert = NET_NFC_NFCIP1_TARGET;
		break;

		case EMUL_TARGET_TYPE_MAX :
		default:
			/* exception case */
			DEBUG_ERR_MSG("_net_nfc_emul_convert_target_type error. Target type is unknown");
		break;

	}

	DEBUG_MSG("covert [%d]", covert);

	DEBUG_EMUL_END();

	return covert;
}

static bool _net_nfc_emul_get_is_target_attached(void)
{
	return g_target_attached;
}

static void _net_nfc_emul_set_is_target_attached(bool is_detached)
{
	g_target_attached = is_detached;
	DEBUG_MSG("set g_target_attached [%d]", g_target_attached);
}

static void _net_nfc_target_discovered_cb(void)
{
	DEBUG_EMUL_BEGIN();

	/* make handle */
	net_nfc_target_handle_s* handle = NULL;
	int length = 0;

	__net_nfc_make_valid_target_handle (&handle);
	if(handle == NULL) {
		return;
	}

	/* make msg */
	net_nfc_request_target_detected_t* target_detected = NULL;
	uint8_t device_info[] = { 0x03, 0x55, 0x49, 0x44, 0x07, 0x04, 0x93, 0xB7, 0xD9, 0x5B, 0x02, 0x80, \
		0x08, 0x41, 0x50, 0x50, 0x5F, 0x44, 0x41, 0x54, 0x41, 0x00, 0x03, 0x53, 0x41, 0x4B, \
		0x01, 0x00, 0x04, 0x41, 0x54, 0x51, 0x41, 0x02, 0x44, 0x00, 0x0D, 0x4D, 0x41, 0x58, \
		0x5F, 0x44, 0x41, 0x54, 0x41, 0x5F, 0x52, 0x41, 0x54, 0x45, 0x01, 0x00, 0x08, 0x46, \
		0x57, 0x49, 0x5F, 0x53, 0x46, 0x47, 0x54, 0x01, 0x03, 0x49, 0x44, 0x6D, 0x07, 0x04, \
		0x93, 0xB7, 0xD9, 0x5B, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


	length = sizeof(net_nfc_request_target_detected_t) + sizeof(device_info);
	_nfc_emul_util_alloc_mem(target_detected, length);
	if (target_detected == NULL)
	{
		return;
	}

	target_detected->length = length;
	target_detected->request_type = NET_NFC_MESSAGE_SERVICE_STANDALONE_TARGET_DETECTED;
	target_detected->handle = handle;

	target_detected->devType = _net_nfc_emul_convert_target_type(gSdkMsg.target_type);
	if (!target_detected->devType) {
		DEBUG_MSG("target_detected->devType is unknown");
		return;
	}

	_net_nfc_emul_set_is_target_attached(true);

	if(target_detected->devType == NET_NFC_NFCIP1_TARGET ){
		DEBUG_MSG("set llcp connection  type. remote device is target");
		handle->connection_type = NET_NFC_P2P_CONNECTION_TARGET;
		_net_nfc_initialize_llcp();
	}
	else if ( target_detected->devType == NET_NFC_NFCIP1_INITIATOR){
		DEBUG_MSG("set llcp connection  type. remote device is initiator");
		handle->connection_type = NET_NFC_P2P_CONNECTION_INITIATOR;
		_net_nfc_initialize_llcp();
	}
	else
	{
		DEBUG_MSG("set tag connection");
		handle->connection_type = NET_NFC_TAG_CONNECTION;
	}

	target_detected->number_of_keys = 7;
	target_detected->target_info_values.length = sizeof(device_info);
	memcpy(&target_detected->target_info_values.buffer, device_info, target_detected->target_info_values.length);

	/* call target_cb */
	if(g_emul_controller_target_cb != NULL) {
		DEBUG_MSG("discovered callback is called");
		g_emul_controller_target_cb(target_detected, NULL);
	}
	DEBUG_EMUL_END();
}

static void _net_nfc_tag_detached_cb(void)
{
	DEBUG_EMUL_BEGIN();

	_net_nfc_emul_set_is_target_attached(false);

	DEBUG_EMUL_END();
}

static void _net_nfc_target_detached_cb(void)
{
	DEBUG_EMUL_BEGIN();

	_net_nfc_emul_set_is_target_attached(false);

	/* For P2P, we send msg to manager */
	net_nfc_request_llcp_msg_t *req_msg = NULL;

	_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

	if (req_msg != NULL) {
		req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_DEACTIVATED;

		DEBUG_MSG("deactivated callback is called");
		g_emul_controller_llcp_cb(req_msg, current_working_handle);
	}
}

static void _net_nfc_llcp_data_receive_cb(void* pContext)
{
	DEBUG_EMUL_BEGIN();

	net_nfc_request_llcp_msg_t *req_msg = NULL;

	_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

	if (req_msg != NULL) {
		req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_RECEIVE;
		req_msg->result = NET_NFC_OK;

		DEBUG_MSG("receive callback is called >>");
		g_emul_controller_llcp_cb(req_msg, pContext);
	}

	DEBUG_EMUL_END();
}

static void _net_nfc_llcp_data_receive_from_cb(void* pContext)
{
	DEBUG_EMUL_BEGIN();

	net_nfc_request_llcp_msg_t *req_msg = NULL;

	_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

	if (req_msg != NULL){
		req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_RECEIVE_FROM;
		req_msg->result = NET_NFC_OK;

		DEBUG_MSG("receive_from callback is called >>");
		g_emul_controller_llcp_cb(req_msg, pContext);
	}

	DEBUG_EMUL_END();
}

static data_s* _net_nfc_llcp_snep_create_msg(snep_command_field_e resp_field, data_s* information)
{
	DEBUG_EMUL_BEGIN();

	uint8_t response = (uint8_t)resp_field;
	uint8_t version = 0;
	uint32_t length_field = 0;

	version = SNEP_MAJOR_VER;
	version = (((version << 4) & 0xf0) | (SNEP_MINOR_VER & 0x0f));

	data_s* snep_msg = NULL;

	if(information == NULL){

		length_field = 0;

		if((snep_msg = (data_s*)calloc(1, sizeof(data_s))) == NULL){
			return NULL;
		}

		snep_msg->length = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);
		if((snep_msg->buffer = calloc(snep_msg->length, sizeof(uint8_t))) == NULL){

			_nfc_emul_util_free_mem(snep_msg);
			return NULL;
		}

		uint8_t* temp = snep_msg->buffer;

		/* copy version */
		*temp = version;
		temp++;

		/* copy response */
		*temp = response;
		temp++;
	}
	else
	{

		if((snep_msg = (data_s*)calloc(1, sizeof(data_s))) == NULL)
		{
			return NULL;
		}
							/* version 	  response		length	 	             payload*/
		snep_msg->length = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t) + information->length;

		if((snep_msg->buffer = (uint8_t *)calloc(snep_msg->length, sizeof(uint8_t))) == NULL)
		{
			_nfc_emul_util_free_mem(snep_msg);
			return NULL;
		}

		memset(snep_msg->buffer,  0x00, snep_msg->length);

		uint8_t* temp = snep_msg->buffer;

		/* copy version */
		*temp = version;
		temp++;

		/* copy response */
		*temp = response;
		temp++;

		length_field = htonl(information->length);

		/* length will be se 0. so we don't need to copy value */
		memcpy(temp, &length_field, sizeof(uint32_t));
		temp += sizeof(uint32_t);

		/* copy ndef information to response msg */
		memcpy(temp, information->buffer, information->length);
	}

	DEBUG_EMUL_END();

	return snep_msg;
}

static llcp_state_e _net_nfc_get_llcp_state(void* pContext)
{
	DEBUG_EMUL_BEGIN();
	llcp_state_e state;

	if (pContext == NULL) {
		DEBUG_ERR_MSG("pContext is NULL >>>");
		return NET_NFC_STATE_UNKNOWN;
	}

	net_nfc_oem_llcp_state_t *llcp_state = NULL;

	llcp_state = (net_nfc_oem_llcp_state_t *) pContext;
	state = llcp_state->state;

	DEBUG_EMUL_END();

	return state;
}

static bool _net_nfc_make_llcp_data(void)
{
	DEBUG_EMUL_BEGIN();

	int real_data_size = 0;

	/* create ndef */
	if ( !_net_nfc_create_ndef_from_emulMsg()) {
		DEBUG_ERR_MSG("read ndef_msg is failed >>>");

		return false;
	}

	if (gSdkMsg.record_count == 0)
	{
		DEBUG_ERR_MSG("record_count is zero >>>");
		return false;
	}
	else
	{
		real_data_size = gSdkMsg.rawdata.length;

		if(real_data_size == 0)
		{
			DEBUG_ERR_MSG("real_data_size is zero >>>");
			return false;
		}

		/* For SNEP, we should create snep msg, and then copy it to llcp_server_data */
		Snep_Server_msg.data = _net_nfc_llcp_snep_create_msg(SNEP_REQ_PUT, &gSdkMsg.rawdata);
		if (Snep_Server_msg.data == NULL) {
			DEBUG_ERR_MSG("create snep msg is failed >>>");
			return false;
		}

		/* copy rawdata to llcp_server_data->buffer */
		if (Snep_Server_msg.data->length <= SNEP_MAX_BUFFER) {
			DEBUG_MSG("The snep msg size is small than SNEP_MAX_BUFFER >>>");

			if (llcp_server_data == NULL)
				return false;

			llcp_server_data->length = Snep_Server_msg.data->length;
			memcpy(llcp_server_data->buffer, Snep_Server_msg.data->buffer, Snep_Server_msg.data->length);
		}
		else {
			DEBUG_MSG("send first segment >>>");

			if (llcp_server_data == NULL) {
				return false;
			}

			llcp_server_data->length = SNEP_MAX_BUFFER;
			memcpy(llcp_server_data->buffer, Snep_Server_msg.data->buffer, SNEP_MAX_BUFFER);

			Snep_Server_msg.isSegment = true;
			Snep_Server_msg.offset = SNEP_MAX_BUFFER;
		}
	}

	DEBUG_EMUL_END();

	return true;
}

static bool _net_nfc_send_emulMsg_to_nfc_manager(void)
{
	DEBUG_EMUL_BEGIN();

	switch (gSdkMsg.message_id) {
		case EMUL_NFC_TAG_DISCOVERED :{
			/* create ndef */
			if ( !_net_nfc_create_ndef_from_emulMsg()) {
				DEBUG_ERR_MSG("create ndef_msg is failed >>>");
				return false;
			}

			_net_nfc_target_discovered_cb();
		}
		break;

		case EMUL_NFC_TAG_DETACHED :{
			_net_nfc_tag_detached_cb();
		}
		break;

		case EMUL_NFC_P2P_DISCOVERED : {
			_net_nfc_target_discovered_cb();
		}
		break;

		case EMUL_NFC_P2P_SEND : {
			if(_net_nfc_make_llcp_data()) {

				/* find snep server*/
				socket_info_s *socket_info = _net_nfc_find_server_socket((net_nfc_llcp_socket_t)NET_NFC_EMUL_SNEP_SERVER_SOCKET_NUMBER);
				if (socket_info == NULL) {
					DEBUG_ERR_MSG ("socket_info is NULL");
					return false;
				}

				llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
				llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
				if (llcp_state == NET_NFC_STATE_UNKNOWN) {
					DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
					return false;
				}

				if (llcp_state == NET_NFC_STATE_EXCHANGER_SERVER) {
					_net_nfc_llcp_data_receive_cb(socket_info->user_context); /* call callback */
				}
				else {
					DEBUG_ERR_MSG("getting snep server handle is failed.");
					return false;
				}
			}
			else {
				DEBUG_ERR_MSG("make_p2p_data is fail!!");
				return false;
			}
		}
		break;

		case EMUL_NFC_P2P_DETACHED : {
			_net_nfc_target_detached_cb();
		}
		break;

		default :
			DEBUG_ERR_MSG("message_id is wrong!!");
		break;
	}

	DEBUG_EMUL_END();

	return false;
}

#ifdef USE_GLIB_MAIN_LOOP
static void _net_nfc_call_dispatcher_in_g_main_loop(void)
{
	DEBUG_EMUL_BEGIN();

	if(g_idle_add_full(G_PRIORITY_HIGH_IDLE, (GSourceFunc)_net_nfc_send_emulMsg_to_nfc_manager, NULL, NULL))
	{
		g_main_context_wakeup(g_main_context_default()) ;
	}

	DEBUG_EMUL_END();
}
#endif

static void _net_nfc_process_emulMsg(uint8_t * data, long int size)
{
	DEBUG_EMUL_BEGIN();

	uint8_t * emulData = data;
	long int messageSize = size;

	/* initialize gSdkMsg */
	_net_nfc_initialize_emulMsg();

	/* parse data and set it to gSdkMsg */
	if(!_net_nfc_set_emulMsg(emulData, messageSize)) {
		DEBUG_MSG("data is currupted");
		return;
	}

	/* send message to nfc-manager */
#ifdef USE_GLIB_MAIN_LOOP
	_net_nfc_call_dispatcher_in_g_main_loop();
#else
	_net_nfc_send_emulMsg_to_nfc_manager();
#endif
	DEBUG_EMUL_END();
}

#ifdef __USE_EPOLL_FOR_FILE__
static void emul_ReaderThread(void * pArg)
{
	DEBUG_MSG("emul_ReaderThread START >>>>");

	char file_name[1024] = { 0, };
	bool condition = true;

	int emulMsg_file_fd = -1;
	int emulMsg_poll_fd = -1;
	struct epoll_event *emulMsg_poll_events = NULL;

	/* make file name */
	snprintf(file_name, sizeof(file_name), "%s/%s", NET_NFC_EMUL_DATA_PATH, NET_NFC_EMUL_MESSAGE_FILE_NAME );
	DEBUG_MSG("file path : %s", file_name);

	/* open file for poll */
	emulMsg_file_fd = open(file_name, O_RDONLY|O_NONBLOCK);
	if (emulMsg_file_fd < 0) {
		DEBUG_MSG("file open error !!!!");
		return;
	}

	/* create epoll */
	if((emulMsg_poll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1)
	{
		DEBUG_MSG("epoll_create1 is occured");
	}

	if((emulMsg_poll_events = (struct epoll_event *)calloc(1, sizeof(struct epoll_event) * EPOLL_SIZE)) == NULL)
	{
		DEBUG_MSG("calloc is occured");
	}

	/* set event */
	struct epoll_event ev;

	ev.events = EPOLLIN | EPOLLET | EPOLLHUP | EPOLLERR;
	ev.data.fd = emulMsg_file_fd;

	/* add file fd to epoll */
	epoll_ctl(emulMsg_poll_fd, EPOLL_CTL_ADD, emulMsg_file_fd, &ev);

	while (condition == true) {

		int num_of_files = 0;
		int index =0 ;

		/* to do : I will add mutex in the future */
		/* lock mutex */

		DEBUG_MSG("epoll wait >>>>");

		if(emulMsg_poll_fd == -1 || emulMsg_file_fd == -1)
		{
			DEBUG_MSG("client is deinitialized. ");
			condition = 0;
		}

		while((num_of_files = epoll_wait(emulMsg_poll_fd, emulMsg_poll_events, EPOLL_SIZE, 300)) == 0){
			if(emulMsg_poll_fd == -1){
				DEBUG_MSG("client ipc thread is terminated");
				condition = 0;
			}
			else{
				DEBUG_MSG("no data is changed ");
			}

		}

		for(index = 0; index < num_of_files; index++)
		{
			if( (emulMsg_poll_events[index].events & (EPOLLHUP)) || (emulMsg_poll_events[index].events & (EPOLLERR)))
			{
				DEBUG_MSG("connection is closed");

				condition = 0;
			}
			else if(emulMsg_poll_events[index].events & EPOLLIN)
			{
				if(emulMsg_poll_events[index].data.fd == emulMsg_file_fd)
				{
					char readbuffer[READ_BUFFER_LENGTH_MAX];
					int readcnt = 0;

					DEBUG_MSG("precess POLLIN ");

					memset(readbuffer, 0x00, sizeof(READ_BUFFER_LENGTH_MAX));

					readcnt = read(emulMsg_file_fd, readbuffer, READ_BUFFER_LENGTH_MAX);

					DEBUG_MSG("message readcnt= [%d] ", readcnt);
					DEBUG_MSG("message = [%s] ", readbuffer);

					_net_nfc_process_emulMsg(readbuffer, readcnt);
				}
				else
				{
					DEBUG_MSG("not expected socket connection");
					condition = 0;
				}
			}
			else
			{
				if(num_of_files == index)
				{
					DEBUG_MSG("unknown event");
					condition = 0;
				}
			}


		}

		/* unlock mutex */

	}

	close(emulMsg_file_fd);

	DEBUG_MSG("emul_ReaderThread END >>>>");
}

#else

static void emul_ReaderThread(void * pArg)
{
	DEBUG_MSG("emul_ReaderThread START >>>>");

	FILE *fp = NULL;
	char file_name[1024] = { 0, };
	char *buf;
	struct stat st;
	time_t last_mtime = 0;
	bool condition = true;

	/* make file name */
	snprintf(file_name, sizeof(file_name), "%s/%s", NET_NFC_EMUL_DATA_PATH, NET_NFC_EMUL_MESSAGE_FILE_NAME );
	DEBUG_MSG("file path : %s", file_name);

	/* polling 500 ms */

	while (condition != 0) {

		usleep(500 * 1000);

		/* open file */
		fp = fopen(file_name, "r");
		if (NULL == fp)
		{
			DEBUG_MSG("file open error");
			condition = false;
			break;
		}

		/* get the modified time of the file */
		if (stat(file_name, &st) == 0) {
			if (st.st_mtime == last_mtime) {
				fclose(fp);
				continue;
			}
		} else {
			DEBUG_MSG("stat error");
			fclose(fp);
			continue;
		}

		/* read data */
		if (fscanf(fp, "%a[^\n]", &buf))
		{
			if (buf)
			{
				DEBUG_MSG("get DATA >>>> buf [%s]", buf);

				if (last_mtime)
				{
					_net_nfc_process_emulMsg((uint8_t*) buf, (long int) strlen(buf));
				}
				else
				{
					// EMUL_NFC_TAG_DISCOVERED, EMUL_NFC_P2P_DISCOVERED
					if ('1'==buf[0] && '0'==buf[1] && ('0'==buf[2] || '2'==buf[2]))
						_net_nfc_process_emulMsg((uint8_t*)buf, (long int) strlen(buf));
				}

				/* process message */
				free(buf);
			}
		}

		DEBUG_MSG("FILE Modified Time [%ld]", (unsigned long) st.st_mtime);
		DEBUG_MSG("Last FILE Modified Time [%ld]", (unsigned long) last_mtime);
		last_mtime = st.st_mtime;

		fclose(fp);

		DEBUG_MSG("LOOP END >>>>");

	}

	DEBUG_MSG("emul_ReaderThread END >>>>");
}
#endif

static bool _net_nfc_emul_controller_start_thread (void)
{
	bool ret = true;

	DEBUG_EMUL_BEGIN();

	ret = pthread_create(&gEmulThread, NULL,  (emul_Nfc_thread_handler_t)emul_ReaderThread,  (void*) "emul_read_thread");

	if(ret != 0)
		return false;

	DEBUG_EMUL_END();

	return true;
}

static void _net_nfc_emul_controller_stop_thread (void)
{
	DEBUG_EMUL_BEGIN();

	pthread_cancel(gEmulThread);

	usleep(500 * 1000);

	pthread_cond_signal(&cond);

	pthread_join(gEmulThread, NULL);

	DEBUG_EMUL_END();
}

static bool _net_nfc_emul_controller_create_interfaceFile (void)
{
	char file_name[1024] = { 0, };
	FILE *fp = NULL;
	struct stat st;
	bool retval = false;

	DEBUG_EMUL_BEGIN();

	/* create file */
	snprintf(file_name, sizeof(file_name), "%s/%s", NET_NFC_EMUL_DATA_PATH, NET_NFC_EMUL_MESSAGE_FILE_NAME );
	DEBUG_MSG("file path : %s", file_name);

	if (stat(file_name, &st) == 0) {
		DEBUG_MSG("file is already created");
		return true;
	}

	if ((fp = fopen(file_name, "w")) != NULL)
	{
		struct passwd *pw_root = NULL;
		struct group *gr_root = NULL;

		fchmod(fileno(fp), 0755);

		pw_root = getpwnam("root");
		gr_root = getgrnam("root");

		if ((pw_root != NULL) && (gr_root != NULL))
		{
			if (fchown(fileno(fp), pw_root->pw_uid, gr_root->gr_gid) < 0)
			{
				DEBUG_ERR_MSG("failed to change owner");
			}
			else {
				retval = true;
			}
		}
		else {
			DEBUG_ERR_MSG("failed to get privilege");
		}

		fclose(fp);

	}
	else {
		DEBUG_ERR_MSG("failed to create file");
	}

	DEBUG_EMUL_END();

	return retval;
}

static bool net_nfc_emul_controller_init (net_nfc_error_e* result)
{
	bool ret = true;

	if (result == NULL) {
		return false;
	}

	DEBUG_EMUL_BEGIN();

	DEBUG_MSG("start stack init ");

	if (g_stack_init_successful == true)
	{
		DEBUG_MSG("Already statck is initialized");
		return true;
	}

	/* file create for testing */
	if (!_net_nfc_emul_controller_create_interfaceFile()) {
		DEBUG_ERR_MSG("Failed to create interfaceFile");
		return false;
	}

	/* start reader thread : to get event from Inject */
	if (!_net_nfc_emul_controller_start_thread()) {
		DEBUG_ERR_MSG("Failed to create emul thread");
		return false;
	}

	DEBUG_MSG("Stack init finished");

	g_stack_init_successful = true;

	DEBUG_EMUL_END();

	return ret;
}

static bool net_nfc_emul_controller_deinit (void)
{
	DEBUG_EMUL_BEGIN();

	/* End thread */
	if (g_stack_init_successful == false)
	{
		DEBUG_MSG("Already statck is deinitialized");
		return true;
	}

	_net_nfc_emul_controller_stop_thread();

	g_stack_init_successful = false;

	DEBUG_EMUL_END();

	return true;
}
static bool net_nfc_emul_controller_register_listener(target_detection_listener_cb target_detection_listener,se_transaction_listener_cb se_transaction_listener, llcp_event_listener_cb llcp_event_listener, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	g_emul_controller_target_cb = target_detection_listener;
	g_emul_controller_se_cb = se_transaction_listener;
	g_emul_controller_llcp_cb = llcp_event_listener;

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_unregister_listener()
{
	DEBUG_EMUL_BEGIN();

	g_emul_controller_target_cb = NULL;
	g_emul_controller_se_cb = NULL;
	g_emul_controller_llcp_cb = NULL;

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_get_firmware_version(data_s **data, net_nfc_error_e *result)
{
	if (data == NULL || result == NULL)
	{
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	*data = (data_s *)calloc(1, sizeof(data_s));
	(*data)->length = 10;
	(*data)->buffer = (uint8_t *)calloc(1, (*data)->length);

	snprintf((char *)(*data)->buffer, (*data)->length, "%d.%d", 1, 0);

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_check_firmware_version(net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_update_firmware(net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_get_stack_information(net_nfc_stack_information_s* stack_info, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_configure_discovery (net_nfc_discovery_mode_e mode, net_nfc_event_filter_e config, net_nfc_error_e* result)
{
	int idx;
	bool ret = true;

	if (result == NULL)
	{
		return false;
	}

	*result = NET_NFC_OK;


	DEBUG_EMUL_BEGIN();

	if ((mode == NET_NFC_DISCOVERY_MODE_CONFIG))
	{
		if (config == NET_NFC_ALL_DISABLE)
		{
			/* This handle is not useful anymore */
			__net_nfc_make_invalid_target_handle ();

			/* reset socket_info */
			for (idx = 0; idx < LLCP_NB_SOCKET_MAX; idx++)
			{
				_net_nfc_remove_socket_slot((net_nfc_llcp_socket_t) idx);
			}

			DEBUG_MSG("Kill Thread");

			ret = net_nfc_emul_controller_deinit();
		}
		else if(config == NET_NFC_ALL_ENABLE)
		{
			net_nfc_error_e err;

			DEBUG_MSG("Create Thread");
			ret = net_nfc_emul_controller_init(&err);
		}
	}

	DEBUG_EMUL_END();

	return ret;
}

static bool net_nfc_emul_controller_get_secure_element_list(net_nfc_secure_element_info_s* list, int* count, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_set_secure_element_mode(net_nfc_secure_element_type_e element_type, net_nfc_secure_element_mode_e mode, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_check_target_presence(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	usleep(300*1000);

	if (_net_nfc_emul_get_is_target_attached()) {
		return true;
	}
	else {
		DEBUG_MSG("TARGET Detached");
		return false;
	}
}

static bool net_nfc_emul_controller_connect(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_disconnect(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	// This handle is not useful anymore
	__net_nfc_make_invalid_target_handle ();

	/* reset socket_info */
	int idx = 0;
	for (; idx < LLCP_NB_SOCKET_MAX; idx++)
	{
		_net_nfc_remove_socket_slot((net_nfc_llcp_socket_t) idx);
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_check_ndef(net_nfc_target_handle_s* handle, uint8_t *ndef_card_state, int* max_data_size, int* real_data_size, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (handle == NULL || ndef_card_state == NULL || max_data_size == NULL || real_data_size == NULL || result == NULL)
	{
		*result = NET_NFC_NULL_PARAMETER;
		return false;
	}

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	if (_net_nfc_emul_get_is_target_attached())
	{
		*ndef_card_state = NET_NFC_NDEF_CARD_READ_WRITE;
		*max_data_size = BUFFER_LENGTH_MAX;
		*real_data_size = gSdkMsg.rawdata.length;
		DEBUG_MSG("Card State : [%d] MAX data size :[%d] actual data size = [%d]", *ndef_card_state, *max_data_size, *real_data_size);
	}
	else
	{
		DEBUG_MSG("target detached");
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_make_read_only_ndef(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_read_ndef(net_nfc_target_handle_s* handle, data_s** data, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if(handle == NULL || data == NULL || result == NULL)
	{
		DEBUG_ERR_MSG("NET_NFC_NULL_PARAMETER >>>");
		*result = NET_NFC_NULL_PARAMETER;
		return false;
	}

	if (!__net_nfc_is_valide_target_handle(handle)) {
		DEBUG_ERR_MSG("NET_NFC_INVALID_HANDLE >>>");
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	if(gSdkMsg.message_id != EMUL_NFC_TAG_DISCOVERED) {
		DEBUG_ERR_MSG("NET_NFC_NOT_ALLOWED_OPERATION >>>");
		*result = NET_NFC_NOT_ALLOWED_OPERATION;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	int real_data_size = 0;

	if (gSdkMsg.record_count == 0)
	{
		*result = NET_NFC_NO_NDEF_SUPPORT;
		return false;
	}
	else
	{
		real_data_size = gSdkMsg.rawdata.length;

		if(real_data_size == 0)
		{
			DEBUG_ERR_MSG("read ndef_msg is failed >>> real_data_size is zero");
			*result = NET_NFC_NO_NDEF_MESSAGE;
			return false;
		}

		*data = (data_s*) calloc(1, sizeof(data_s));

		if(*data == NULL)
		{
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		(*data)->length = real_data_size;
		(*data)->buffer = (uint8_t *)calloc(1, real_data_size);

		if((*data)->buffer == NULL)
		{
			free(*data);
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		/* copy rawdata to data->buffer */
		memcpy((*data)->buffer, gSdkMsg.rawdata.buffer, real_data_size);
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_write_ndef(net_nfc_target_handle_s* handle, data_s* data, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	usleep(300 * 1000);
	DEBUG_MSG("net_nfc_emul_controller_write_ndef success >>>");

	DEBUG_EMUL_END();

	return true;
}


static bool net_nfc_emul_controller_transceive(net_nfc_target_handle_s *handle,
	net_nfc_transceive_info_s *info, data_s **data, net_nfc_error_e *result)
{
	bool ret = false;

	if (result == NULL) {
		return ret;
	}

	if (info == NULL || info->trans_data.buffer == NULL ||
		info->trans_data.length == 0) {
		*result = NET_NFC_INVALID_PARAM;
		return ret;
	}

	*result = NET_NFC_OK;
	*data = NULL;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return ret;
	}

	DEBUG_EMUL_BEGIN();

	if (info->dev_type == NET_NFC_MIFARE_DESFIRE_PICC) {
		DEBUG_MSG("NET_NFC_MIFARE_DESFIRE_PICC");

		/* check ISO-DEP formatable in DesFire */
		if (info->trans_data.buffer[0] == (uint8_t)0x90 &&
			info->trans_data.buffer[1] == (uint8_t)0x60) {

			data_s *temp;

			_net_nfc_util_alloc_mem(temp, sizeof(data_s));
			if (temp != NULL) {
				temp->length = 9;

				_net_nfc_util_alloc_mem(temp->buffer, temp->length);
				if (temp->buffer != NULL) {
					temp->buffer[7] = (uint8_t)0x91;
					temp->buffer[8] = (uint8_t)0xAF;

					*data = temp;
					ret = true;
				} else {
					*result = NET_NFC_ALLOC_FAIL;
					_net_nfc_util_free_mem(temp);
				}
			} else {
				*result = NET_NFC_ALLOC_FAIL;
			}
		} else {
			*result = NET_NFC_NOT_SUPPORTED;
		}

	} else {
		*result = NET_NFC_NOT_SUPPORTED;
	}

	DEBUG_EMUL_END();

	return ret;
}

static bool net_nfc_emul_controller_format_ndef(net_nfc_target_handle_s* handle, data_s* secure_key, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_exception_handler(void)
{
	DEBUG_EMUL_BEGIN();

	net_nfc_error_e error;

	if(net_nfc_emul_controller_init(&error) == false)
	{
		DEBUG_ERR_MSG("exception handler is failed!!");
		exit(0xff);
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_is_ready(net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return g_stack_init_successful;
}


/*******************
*	LLCP definition     *
********************/

static bool net_nfc_emul_controller_llcp_config (net_nfc_llcp_config_info_s * config, net_nfc_error_e * result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_check_llcp(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_activate_llcp(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_create_socket(net_nfc_llcp_socket_t* socket, net_nfc_socket_type_e socketType, uint16_t miu, uint8_t rw,  net_nfc_error_e* result, void * user_param)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	/* get available socket */
	socket_info_s* socket_info = _net_nfc_get_available_socket_slot();
	if(socket_info == NULL) {
		DEBUG_ERR_MSG("The available socket is nothing!!");
		return false;
	}

	/* get llcp state */
	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(user_param);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG("llcp_state is NET_NFC_STATE_UNKNOWN!!");
		return false;
	}

	if (llcp_state == NET_NFC_STATE_EXCHANGER_SERVER) {
		DEBUG_MSG("NET_NFC_STATE_EXCHANGER_SERVER");

		*socket = NET_NFC_EMUL_SNEP_SERVER_SOCKET_NUMBER;
	}
	else if (llcp_state == NET_NFC_STATE_EXCHANGER_SERVER_NPP) {
		DEBUG_MSG("NET_NFC_STATE_EXCHANGER_SERVER_NPP");

		*socket  = NET_NFC_EMUL_NPP_SERVER_SOCKET_NUMBER;
	}
	else if (llcp_state == NET_NFC_STATE_EXCHANGER_CLIENT) {
		DEBUG_MSG("NET_NFC_STATE_EXCHANGER_CLIENT");

		*socket  = NET_NFC_EMUL_CLIENT_SOCKET_NUMBER;
	}
	else if (llcp_state == NET_NFC_STATE_CONN_HANDOVER_REQUEST) {
		DEBUG_MSG("NET_NFC_STATE_CONN_HANDOVER_REQUEST");

		*socket  = NET_NFC_EMUL_HANDOVER_REQUEST_SOCKET_NUMBER;
	}
	else if (llcp_state == NET_NFC_STATE_CONN_HANDOVER_SELECT) {
		DEBUG_MSG("NET_NFC_STATE_CONN_HANDOVER_SELECT");

		*socket  = NET_NFC_EMUL_HANDOVER_SELECT_SOCKET_NUMBER;
	}
	else {
		DEBUG_MSG("we doesn't support..");

		return false;
	}

	DEBUG_MSG("socket is created = [0x%x]", *socket);

	socket_info->socket_handle = *socket;
	socket_info->user_context = (void *) user_param;

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_bind(net_nfc_llcp_socket_t socket, uint8_t service_access_point, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_listen(net_nfc_target_handle_s* handle, uint8_t* service_access_name, net_nfc_llcp_socket_t socket, net_nfc_error_e* result, void * user_param)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	/* Emul don't create real socket. So, we don't need to wait accept from remote socket */
	/* In here, send accept event for only snep */
	net_nfc_request_accept_socket_t * detail = NULL;

	socket_info_s *socket_info = _net_nfc_find_server_socket(socket);
	if (socket_info == NULL) {
		DEBUG_ERR_MSG ("socket_info is NULL");
		return false;
	}

	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
		return false;
	}

	if (llcp_state == NET_NFC_STATE_EXCHANGER_SERVER) {
		_nfc_emul_util_alloc_mem(detail, sizeof(net_nfc_request_accept_socket_t));

		if(detail != NULL)
		{
			detail->length = sizeof(net_nfc_request_accept_socket_t);
			detail->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_ACCEPT;

			socket_info->user_context = user_param;

			detail->handle = handle;
			detail->incomming_socket = NET_NFC_EMUL_INCOMING_SOCKET_NUMBER;
			detail->trans_param = socket_info->user_context;
			detail->result = NET_NFC_OK;

			DEBUG_MSG("accept callback is called");
			g_emul_controller_llcp_cb(detail, socket_info->user_context);
		}
	}
	else {
		DEBUG_MSG("llcp_state is [%d]", llcp_state);
	}

	DEBUG_EMUL_END();

	return true;
}

/* below accept function does not used. */
static bool net_nfc_emul_controller_llcp_accept(net_nfc_llcp_socket_t	socket, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_connect(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, uint8_t service_access_point, net_nfc_error_e* result, void * user_param)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	socket_info_s *socket_info = _net_nfc_find_server_socket(socket);
	if (socket_info == NULL) {
		DEBUG_ERR_MSG ("socket_info is NULL");
		return false;
	}

	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
		return false;
	}

	if (llcp_state == NET_NFC_STATE_EXCHANGER_CLIENT) {
		net_nfc_request_llcp_msg_t *req_msg = NULL;

		_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

		socket_info->user_context = user_param;

		if (req_msg == NULL){
			DEBUG_MSG("Allocation is failed\n");
			return false;
		}
		req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_CONNECT_SAP;
		req_msg->result = NET_NFC_OK;

		DEBUG_MSG("connect_sap callback is called");
		g_emul_controller_llcp_cb(req_msg, socket_info->user_context);

		/* set variable */
		Snep_Server_msg.firstTime = true;
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_connect_by_url( net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, uint8_t* service_access_name, net_nfc_error_e* result, void * user_param)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	socket_info_s *socket_info = _net_nfc_find_server_socket(socket);
	if (socket_info == NULL) {
		DEBUG_ERR_MSG ("socket_info is NULL");
		return false;
	}

	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
		return false;
	}

	if (llcp_state == NET_NFC_STATE_EXCHANGER_CLIENT) {
		net_nfc_request_llcp_msg_t *req_msg = NULL;

		_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

		socket_info->user_context = user_param;

		if (req_msg == NULL){
			DEBUG_MSG("Allocation is failed\n");
			return false;
		}

		req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_CONNECT ;
		req_msg->result = NET_NFC_OK;

		DEBUG_MSG("connect callback is called");
		g_emul_controller_llcp_cb(req_msg, socket_info->user_context);

		/* set variable */
		Snep_Server_msg.firstTime = true;
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_send(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, data_s* data, net_nfc_error_e* result, void * user_param)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	socket_info_s *socket_info = _net_nfc_find_server_socket(socket);
	if (socket_info == NULL) {
		DEBUG_ERR_MSG ("socket_info is NULL");
		return false;
	}

	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
		return false;
	}

	if(llcp_state == NET_NFC_STATE_EXCHANGER_SERVER) {
		net_nfc_request_llcp_msg_t *req_msg = NULL;

		_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

		socket_info->user_context = user_param;

		if (req_msg != NULL){
			req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
			req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_SEND;
			req_msg->result = NET_NFC_OK;

			DEBUG_MSG("send callback is called");
			g_emul_controller_llcp_cb(req_msg, socket_info->user_context);
		}
	}
	else if (llcp_state == NET_NFC_STATE_EXCHANGER_CLIENT) {

		if (Snep_Client_msg.firstTime) {

			DEBUG_MSG("LLCP client send data on first time. We should get data size to know whether it exceeds SNEP_MAX_BUFFER");

			/* get data size */
			int length = 0;
			uint8_t* temp = NULL;

			temp = data->buffer;
			temp += 2;

			memcpy(&length, temp, sizeof(uint32_t));

			if (length+6 > SNEP_MAX_BUFFER) {
				Snep_Client_msg.RespContinue= true;
			}
			Snep_Client_msg.firstTime = false;
		}

		net_nfc_request_llcp_msg_t *req_msg = NULL;

		_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

		socket_info->user_context = user_param;

		if (req_msg != NULL){
			req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
			req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_SEND;
			req_msg->result = NET_NFC_OK;

			DEBUG_MSG("send callback is called");
			g_emul_controller_llcp_cb(req_msg, socket_info->user_context);
		}
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_send_to(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, data_s* data, uint8_t service_access_point, net_nfc_error_e* result, void * user_param)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	socket_info_s *socket_info = _net_nfc_find_server_socket(socket);
	if (socket_info == NULL) {
		DEBUG_ERR_MSG ("socket_info is NULL");
		return false;
	}

	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
		return false;
	}

	if(llcp_state == NET_NFC_STATE_EXCHANGER_SERVER) {
		net_nfc_request_llcp_msg_t *req_msg = NULL;

		_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

		socket_info->user_context = user_param;

		if (req_msg != NULL){
			req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
			req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_SEND_TO;
			req_msg->result = NET_NFC_OK;

			DEBUG_MSG("send_to callback is called");
			g_emul_controller_llcp_cb(req_msg, socket_info->user_context);
		}
	}
	else if (llcp_state == NET_NFC_STATE_EXCHANGER_CLIENT) {

		if (Snep_Client_msg.firstTime) {

			DEBUG_MSG("LLCP client send to data on first time. We should get data size to know whether it exceeds SNEP_MAX_BUFFER");

			/* get data size */
			int length = 0;
			uint8_t* temp = NULL;

			temp = data->buffer;
			temp += 2;

			memcpy(&length, temp, sizeof(uint32_t));

			if (length+6 > SNEP_MAX_BUFFER) {
				Snep_Client_msg.RespContinue= true;
			}
			Snep_Client_msg.firstTime = false;
		}

		net_nfc_request_llcp_msg_t *req_msg = NULL;

		_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

		socket_info->user_context = user_param;

		if (req_msg != NULL){
			req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
			req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_SEND_TO;
			req_msg->result = NET_NFC_OK;

			DEBUG_MSG("send_to callback is called");
			g_emul_controller_llcp_cb(req_msg, socket_info->user_context);
		}
	}

	DEBUG_EMUL_END();

	return true;
}


static bool net_nfc_emul_controller_llcp_recv(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, data_s * data, net_nfc_error_e* result, void * user_param)
{
	if (result == NULL || data == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	socket_info_s *socket_info = _net_nfc_find_server_socket(socket);
	if (socket_info == NULL) {
		DEBUG_ERR_MSG ("socket_info is NULL");
		return false;
	}

	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
		return false;
	}

	if (llcp_state == NET_NFC_STATE_EXCHANGER_SERVER) {

		DEBUG_MSG("NET_NFC_STATE_EXCHANGER_SERVER");
		socket_info->user_context = user_param;

		if(Snep_Server_msg.isSegment) {
			/* send snep msg continueosly  ..*/
			DEBUG_MSG("send segments for snep msg");

			int remained_size = 0;

			remained_size = Snep_Server_msg.data->length - Snep_Server_msg.offset;
			DEBUG_MSG("remained_size[%d]", remained_size);

			/* copy rawdata to llcp_server_data->buffer */
			if (remained_size <= SNEP_MAX_BUFFER) {
				DEBUG_MSG("send last segment >>>");

				llcp_server_data->length = remained_size;
				memcpy(llcp_server_data->buffer, Snep_Server_msg.data->buffer+Snep_Server_msg.offset , remained_size);

				Snep_Server_msg.isSegment = false;
			}
			else {
				DEBUG_MSG("send continue segment >>>");

				llcp_server_data->length = SNEP_MAX_BUFFER;
				memcpy(llcp_server_data->buffer, Snep_Server_msg.data->buffer+Snep_Server_msg.offset, SNEP_MAX_BUFFER);

				Snep_Server_msg.offset += SNEP_MAX_BUFFER;
			}

			_net_nfc_llcp_data_receive_cb(socket_info->user_context); /* call callback */
		}
		else {
			/* In here, we dosen't call _net_nfc_llcp_data_receive_cb. just wait event from emulator */
			/*After copying data address, we will return it, immediately */
			DEBUG_MSG("data address is set");
			llcp_server_data = data;
		}
	}
	else if (llcp_state == NET_NFC_STATE_EXCHANGER_CLIENT) {

		data_s* resp_msg = NULL;

		DEBUG_MSG("NET_NFC_STATE_EXCHANGER_CLIENT");

		llcp_client_data = data;

		/* make snep msg : SNEP_RESP_CONT or SNEP_RESP_SUCCESS */
		if (Snep_Client_msg.RespContinue) {
			DEBUG_MSG("Make SNEP_RESP_CONT");

			resp_msg = _net_nfc_llcp_snep_create_msg(SNEP_RESP_CONT, NULL);
			if (resp_msg == NULL) {
				DEBUG_ERR_MSG("create snep msg is failed >>>");
				return false;
			}

			Snep_Client_msg.RespContinue = false;
		}
		else {
			DEBUG_MSG("Make SNEP_RESP_SUCCESS");

			resp_msg = _net_nfc_llcp_snep_create_msg(SNEP_RESP_SUCCESS, NULL);
			if (resp_msg == NULL) {
				DEBUG_ERR_MSG("create snep msg is failed >>>");
				return false;
			}
		}

		llcp_client_data->length = resp_msg->length;
		memcpy(llcp_client_data->buffer, resp_msg->buffer, resp_msg->length);

		/* free data */
		free(resp_msg->buffer);
		free(resp_msg);

		_net_nfc_llcp_data_receive_cb(socket_info->user_context); /* call callback */
	}
	else {
		DEBUG_MSG("we don't support..");
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_recv_from(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, data_s * data, net_nfc_error_e* result, void * user_param)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	socket_info_s *socket_info = _net_nfc_find_server_socket(socket);
	if (socket_info == NULL) {
		DEBUG_ERR_MSG ("socket_info is NULL");
		return false;
	}

	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
		return false;
	}

	if (llcp_state == NET_NFC_STATE_EXCHANGER_SERVER) {

		DEBUG_MSG("NET_NFC_STATE_EXCHANGER_SERVER");
		socket_info->user_context = user_param;

		if(Snep_Server_msg.isSegment) {
			/* send snep msg continueosly  ..*/
			DEBUG_MSG("send segments for snep msg");

			int remained_size = 0;

			remained_size = Snep_Server_msg.data->length - Snep_Server_msg.offset;
			DEBUG_MSG("remained_size[%d]", remained_size);

			/* copy rawdata to llcp_server_data->buffer */
			if (remained_size <= SNEP_MAX_BUFFER) {
				DEBUG_MSG("send last segment >>>");

				llcp_server_data->length = remained_size;
				memcpy(llcp_server_data->buffer, Snep_Server_msg.data->buffer+Snep_Server_msg.offset , remained_size);

				Snep_Server_msg.isSegment = false;
			}
			else {
				DEBUG_MSG("send continue segment >>>");

				llcp_server_data->length = SNEP_MAX_BUFFER;
				memcpy(llcp_server_data->buffer, Snep_Server_msg.data->buffer+Snep_Server_msg.offset, SNEP_MAX_BUFFER);

				Snep_Server_msg.offset += SNEP_MAX_BUFFER;
			}

			_net_nfc_llcp_data_receive_from_cb(socket_info->user_context); /* call callback */
		}
		else {
			/* In here, we dosen't call _net_nfc_llcp_data_receive_cb. just wait event from emulator */
			/*After copying data address, we will return it, immediately */
			if(data != NULL) {
				DEBUG_MSG("data address is set");
				llcp_server_data = data;
			}
			else {
				DEBUG_ERR_MSG("data address is NULL");
				return false;
			}
		}
	}
	else if (llcp_state == NET_NFC_STATE_EXCHANGER_CLIENT) {

		DEBUG_MSG("NET_NFC_STATE_EXCHANGER_CLIENT");

		llcp_client_data = data;

		data_s* resp_msg = NULL;

		/* make snep msg : SNEP_RESP_CONT or SNEP_RESP_SUCCESS */
		if (Snep_Client_msg.RespContinue) {
			DEBUG_MSG("Make SNEP_RESP_CONT");

			resp_msg = _net_nfc_llcp_snep_create_msg(SNEP_RESP_CONT, NULL);
			if (resp_msg == NULL || resp_msg->buffer == NULL) {
				DEBUG_ERR_MSG("create snep msg is failed >>>");
				return false;
			}

			llcp_client_data->length = resp_msg->length;
			memcpy(llcp_client_data->buffer, resp_msg->buffer, resp_msg->length);

			Snep_Client_msg.RespContinue = false;
		}
		else {
			DEBUG_MSG("Make SNEP_RESP_SUCCESS");

			resp_msg = _net_nfc_llcp_snep_create_msg(SNEP_RESP_SUCCESS, NULL);
			if (resp_msg == NULL || resp_msg->buffer == NULL) {
				DEBUG_ERR_MSG("create snep msg is failed >>>");
				return false;
			}

			llcp_client_data->length = resp_msg->length;
			memcpy(llcp_client_data->buffer, resp_msg->buffer, resp_msg->length);
		}

		/* free data */
		if (resp_msg->buffer != NULL) {
			free(resp_msg->buffer);
		}
		free(resp_msg);

		_net_nfc_llcp_data_receive_from_cb(socket_info->user_context); /* call callback */

	}
	else {
		DEBUG_MSG("we donen't support..");
	}

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_disconnect(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, net_nfc_error_e* result, void * user_param)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	socket_info_s *socket_info = _net_nfc_find_server_socket(socket);
	if (socket_info == NULL) {
		DEBUG_ERR_MSG ("socket_info is NULL");
		return false;
	}

	llcp_state_e llcp_state = NET_NFC_STATE_UNKNOWN;
	llcp_state = _net_nfc_get_llcp_state(socket_info->user_context);
	if (llcp_state == NET_NFC_STATE_UNKNOWN) {
		DEBUG_ERR_MSG ("llcp_state is NET_NFC_STATE_UNKNOWN");
		return false;
	}

	/* send msg to framework */
	net_nfc_request_llcp_msg_t *req_msg = NULL;

	_nfc_emul_util_alloc_mem(req_msg, sizeof(net_nfc_request_llcp_msg_t));

	socket_info->user_context = user_param;

	if (req_msg != NULL){
		req_msg->length = sizeof(net_nfc_request_llcp_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_LLCP_DISCONNECT;
		req_msg->result = NET_NFC_OK;

		DEBUG_MSG("disconnect callback is called");
		g_emul_controller_llcp_cb(req_msg, user_param);
	}

	/* reset socket_info */
	_net_nfc_remove_socket_slot((net_nfc_llcp_socket_t) socket);

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_socket_close(net_nfc_llcp_socket_t socket, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_reject(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t	socket, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_get_remote_config (net_nfc_target_handle_s* handle, net_nfc_llcp_config_info_s *config, net_nfc_error_e* result)
{
	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	DEBUG_EMUL_END();

	return true;
}

static bool net_nfc_emul_controller_llcp_get_remote_socket_info (net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_s * option, net_nfc_error_e* result)
{
	/* In llcp specification ver 1.1, default miu size is 128 */
	const uint16_t default_miu = 128;

	if (result == NULL) {
		return false;
	}

	*result = NET_NFC_OK;

	if (!__net_nfc_is_valide_target_handle(handle)) {
		*result = NET_NFC_INVALID_HANDLE;
		return false;
	}

	DEBUG_EMUL_BEGIN();

	option->miu = default_miu;

	DEBUG_EMUL_END();

	return true;
}


static bool net_nfc_emul_controller_support_nfc(net_nfc_error_e *result)
{
	bool ret = false;
	struct stat st = { 0, };

	if (result == NULL)
	{
		return ret;
	}

	if (stat("/opt/nfc/sdkMsg", &st) == 0)
	{
		*result = NET_NFC_OK;
		ret = true;
	}
	else
	{
		*result = NET_NFC_NOT_SUPPORTED;
	}

	return ret;
}

////////////// INTERFACE END //////////

