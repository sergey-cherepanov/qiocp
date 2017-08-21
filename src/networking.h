/*
 * Copyright 2014 Sergey Cherepanov (sergtchj@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETWORKING_H_
#define NETWORKING_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <WinSock2.h>
#include <fileapi.h>
#include <windows.h>
#include <WS2tcpip.h>
#include <Mswsock.h>
#include <wchar.h>

/* 0 can be a valid file descriptor so use -1 for "no fd" situation */
#define FD_INVALID -1
typedef short in_port_t;
typedef unsigned  in_addr_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

extern LPFN_TRANSMITFILE lpfnTransmitFile;

#define ChkExit(func,...) if (!(func)) \
do{ \
	WCHAR *sErr = NULL; \
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
	NULL, errno, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (WCHAR*)&sErr, 0, NULL); \
	print_error("in %s func %s line %d "#func" returns error %d %S" \
		, __FILE__, __FUNCTION__, __LINE__, errno, sErr); \
	LocalFree(sErr); {__VA_ARGS__; } \
	exit(EXIT_FAILURE); \
} while (0)

#define crBegin switch(ss->state){case 0:
#define crReturn do{ss->state=__LINE__;goto labelCrFinish;case __LINE__:;}while(0)
#define crFinish }{ss->state=0;}labelCrFinish:;
#define crBreak do{ss->state=0;goto labelCrFinish;}while(0)

#define p_ii(i1,i2) {print_debug(#i1"=%lld "#i2"=%lld\n",(__int64)(i1),(__int64)(i2));}
#define p_xi(i1,i2) {print_debug(#i1"=%p "#i2"=%lld\n",(LPVOID)(i1),(__int64)(i2));}

#undef errno
#define errno (WSAGetLastError())

#define CMD_SEND_BUF_SIZE 512

enum INT_CONSTANTS{
	LISTEN_BACKLOG = 50, RECV_BUFLEN = 4096
};

struct connection_t;
struct AcceptReq;

typedef struct AcceptReq
{
	struct connection_t *ss;
	IN_ADDR peer;
	USHORT port;
	struct AcceptReq *nextReq;
}AcceptReq;

struct buf_list {
    size_t len;
    struct buf_list *next;
    void *buf;
};

typedef struct OVX
{
	OVERLAPPED ov;
	void(*ev_callback)(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped);
	SOCKET fd;
	struct connection_t *conn;
	WSABUF wb;
}OVX;

extern OVX ovListen;
extern OVX ovListen2;

extern AcceptReq *sessionList;

struct Session;

typedef struct connection_t
{
	OVX ox;
	OVX ovs;
	struct Session *session;

	DWORD recvLen;
	DWORD BytesSEND;

    struct buf_list *write_list;
    size_t wbuf_offset;
	union {
		struct {
			ULONG read_bufsize;
			void *read_buf;
		};
		WSABUF wb;
	};
	WSABUF wbs;

	SOCKADDR_IN local;
	char dummy1[16];
	SOCKADDR_IN remote;
	char dummy2[16];
} connection_t;

typedef struct Session
{
	connection_t *conn, *sdt;
	OVX ovAcc;

	struct
	{
		int state;
		HANDLE handle;
		unsigned opts;
		ULARGE_INTEGER fileSize;
		ULARGE_INTEGER readBytes;
		char cmnd_[5];
		char u8opts[2 * MAX_PATH];
		WCHAR file_name[MAX_PATH];
		WCHAR sCurrPath[MAX_PATH];
		char *pCh;
		__int64 ir;
		WSABUF *wBufs;
	};

	struct
	{
		OVERLAPPED fov;
		WSABUF fwb;
		DWORD read_len1;
		HANDLE hMap;
	};
}Session;

extern HANDLE ep_fd;
void event_init(void);
void event_dispatch(void);

void set_error_handler(void(*new_error_handler)(SOCKET, int));

void async_accept(OVX *poL, in_port_t port);
void PrepareNextAcceptEx(OVX *poL);

/* Can be hidden but may be useful as public */
void accept_event_handler(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped);
void send_cplt_handler(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped);
void send_msg_cplt_handler(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped);

void read_event_handler(connection_t *pConn);

void async_send(connection_t **connection, in_addr_t ip, in_port_t port, void *buf, int len);

/* Implemented in oerte_daemon.c but called by accept event handler */
void notify_about_connection(connection_t *connection);

/* print data about socket */
void print_socket(char* comment, SOCKET fd);

void close_conn(connection_t *connection);

void check_error(int ret, char *msg);

void handler(Session* s_session);
void send_msg(connection_t *ss, const char *format, ...);

#endif /* NETWORKING_H_ */