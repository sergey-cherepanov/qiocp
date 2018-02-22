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

#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>           /* For mode constants */
#include <fcntl.h>              /* For O_* constants */
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Mswsock.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

#include "oelog.h"
#include "networking.h"

HANDLE ep_fd = NULL;

OVX ovListen = { { 0 }, accept_event_handler, INVALID_SOCKET };

LPFN_ACCEPTEX lpfnAcceptEx;
LPFN_GETACCEPTEXSOCKADDRS lpfnGetAcceptExSockaddrs;
LPFN_TRANSMITFILE lpfnTransmitFile;

void initLpFns(SOCKET s)
{
	DWORD dwBytes;

#define GET_EXT_PTR(fun, guid) {GUID g=guid; \
		ChkExit(!WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &lpfn##fun, sizeof lpfn##fun, &dwBytes, NULL, NULL));}

	GET_EXT_PTR(AcceptEx,WSAID_ACCEPTEX);
	GET_EXT_PTR(GetAcceptExSockaddrs,WSAID_GETACCEPTEXSOCKADDRS);
	GET_EXT_PTR(TransmitFile,WSAID_TRANSMITFILE);

}

void do_cmplt(ULONG_PTR completionKey, OVX *pox)
{
	pox->ev_callback((Session*)completionKey, pox);
}

void event_dispatch(void)
{
	ULONGLONG t1=0, t2=0, tMax = 0;
		DWORD cbTransferred=0;
		ULONG_PTR completionKey=0;
		OVX *pox = NULL; 

	for (;;){

		ChkExit(GetQueuedCompletionStatus(
			ep_fd,
			&cbTransferred,
			(PULONG_PTR)&completionKey,
			(LPOVERLAPPED*)&pox,
			INFINITE), assert(cbTransferred == pox->ov.InternalHigh);goto Next);
		p_xi(pox->ev_callback, cbTransferred);
		p_xx(completionKey, pox);
		assert(cbTransferred == pox->ov.InternalHigh);
		t1 = GetTickCount();
		do_cmplt(completionKey, pox);
		t2 = GetTickCount();
		tMax = max(tMax, t2 - t1);
		Next:
		print_debug("//// %llu tMax=%llu ////\n", t2 - t1, tMax);
	}
}

void print_socket ( char* comment, SOCKET fd) 
{
	struct sockaddr_in addr = { 0 };
	socklen_t len = sizeof(struct sockaddr_in);
	ChkExit(!getsockname(fd, (struct sockaddr*)&addr, &len)
		, print_info("fd=%p", (void*)fd); return);
	if (AF_INET == addr.sin_family) 
	{
		struct sockaddr_in addr_peer = { 0 };
		char ipLocal[20];
		ChkExit(!getpeername(fd, (struct sockaddr*)&addr_peer, &len)
			, print_info("fd=%p", (void*)fd); return);
		strcpy(ipLocal, inet_ntoa(addr.sin_addr));
		print_info("%s fd=%p local=%s:%d remote=%s:%d \n", comment, (void*)fd,
				ipLocal, ntohs(addr.sin_port),
				inet_ntoa(addr_peer.sin_addr), ntohs(addr_peer.sin_port));
	}
	else
	{
		print_info("%s  fd=%p is not socket addr.sin_family=%d\n", comment, (void*)fd, addr.sin_family);
	}
}

void send_msg_cplt_handler(Session*ss, OVX*ovs)
{
	p_xx(ss, ovs);
	if (ss->sdt){
		if ((ss->state) && (ss->sdt->ovs.fd == ovs->fd))
		{
			handler(ss, ovs);
		}
	}
	free(ovs);
}

void send_cplt_handler(Session*ss, OVX*ovs)
{
	p_xx(ss, ovs);
	if (ss->state && ss->sdt->ox.fd == ovs->fd){
		handler(ss, ovs);
	}
}

void launchRecv(connection_t *pConn)
{
	DWORD Flags = 0;
	pConn->recvLen = 0;
	pConn->wb.buf[0] = '\0';
	if (SOCKET_ERROR == WSARecv(pConn->ox.fd, &pConn->wb, 1, &pConn->recvLen,
		&Flags, &pConn->ox.ov, NULL))
	{
		ChkExit(ERROR_IO_PENDING == WSAGetLastError(), { close_conn(pConn); break; });
	}
	else
	{
		pConn->wb.buf[pConn->recvLen] = '\0';
		print_debug("received2 %d bytes %s\n", pConn->recvLen, pConn->wb.buf);
	}
}

void recv_cplt_handler(Session *ss, OVX* pox)
{
	connection_t* pConn=ss->conn;
	static char delim[] = " \t\r\n";
	char *pEnd;
	char* token;
	static char buf[MAX_PATH * 2];
	char *pbuf = buf;

	memmove(buf, pConn->wb.buf,pConn->recvLen);
	buf[pConn->recvLen] = 0;

	for (; (pEnd = strstr(pbuf, "\r\n")); pbuf = pEnd+2)
	{
		*pEnd = 0;
		token = strtok(pbuf, delim);
		if (token)
		{
			strcpy_s(ss->cmnd_, 5, token);
			token = strtok(NULL, delim + 2);
			if (token)
			{
				strcpy_s(ss->u8opts, 2*MAX_PATH, token);
			}
			ss->state = 0;
			handler(ss,pox);
		}
	}
	launchRecv(pConn);
}

void recv_data_cplt(Session *ss, OVX* pox)
{
	connection_t *pConn = (connection_t *)((char*)pox - offsetof(connection_t, ox));

	p_xx(ss, pox->ov.InternalHigh);
	pConn->recvLen = (DWORD)pox->ov.InternalHigh;

	print_debug("data received %d bytes\n", pConn->recvLen);
	if (ss->sdt){
		if (ss->state && ss->sdt->ox.fd == pox->fd){
			handler(ss, pox);
		}
	}

	/*Socket has closed after QUIT command*/
	pConn = ss->conn;
	if (NULL == pConn
		|| INVALID_SOCKET == pConn->ox.fd)
	{
		free(ss);
		return;
	}
}

void rwc_cplt_handler(Session *ss, OVX* pox)
{
	connection_t *pConn = (connection_t *)((char*)pox - offsetof(connection_t, ox));

	p_xx(ss, pox);
	if (0 == pox->ov.InternalHigh){
		free(pConn);
		free(ss);
		return;
	}

	pConn->recvLen = (DWORD)pox->ov.InternalHigh;
	pConn->wb.buf[pConn->recvLen] = '\0';

	print_debug("received %d bytes %s\n", pConn->recvLen, pConn->wb.buf);
	recv_cplt_handler(ss, pox);

	/*Socket has closed after QUIT command*/
	pConn = ss->conn;
	if (NULL == pConn
		|| INVALID_SOCKET == pConn->ox.fd)
	{
		free(ss);
		return;
	}
}

void accept_dt_cplt(Session* ss, OVX *poL)
{
	p_xx(ss, poL);
	connection_t *sdt = (connection_t*)poL->conn;
	LPSOCKADDR_IN pLocalSock, pRemoteSock;
	int LocalSockLen = 0, RemoteSockLen = 0;
	/*ChkExit(WSAResetEvent(poL->ov.hEvent));*/

	ChkExit(!setsockopt(sdt->ox.fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
		(char *)&poL->fd, sizeof(poL->fd)));
	lpfnGetAcceptExSockaddrs(&sdt->local, (DWORD)poL->ov.InternalHigh
		, sizeof(SOCKADDR_IN)+16, sizeof(SOCKADDR_IN)+16
		, (LPSOCKADDR*)&pLocalSock, &LocalSockLen
		, (LPSOCKADDR*)&pRemoteSock, &RemoteSockLen);


	print_info("!!!!!!!!!!!!!!!!!!!!!!got accept sdt=%llx sdt->ox.fd=%llx\n", sdt, sdt->ox.fd);
	print_socket("AcceptEx Socket", sdt->ox.fd);

	PrepareNextAcceptEx(ss, poL);
	{
		ss->sdt = sdt;
		sdt->session = ss;
		sdt->ox.ev_callback = recv_data_cplt;
		sdt->ovs.ev_callback = send_cplt_handler;
		sdt->ovs.fd = sdt->ox.fd;
		ChkExit(CreateIoCompletionPort((HANDLE)sdt->ox.fd, ep_fd, (ULONG_PTR)ss, 0));
	}

	p_xx(ss, poL);
	if (ss->state){
		handler(ss, poL);
	}
}

void NewSession(Session *ss, connection_t *pConn)
{
	wcscpy(ss->sCurrPath, L"\\");

	p_xx(ss, pConn->ox.fd);

	pConn->ox.ev_callback = rwc_cplt_handler;
	pConn->ovs.ev_callback = send_cplt_handler;
	pConn->ovs.fd = pConn->ox.fd;
	ChkExit(CreateIoCompletionPort((HANDLE)pConn->ox.fd, ep_fd, (ULONG_PTR)ss, 0));
	/*ChkExit(WSA_INVALID_EVENT != (pConn->ox.ov.hEvent = WSACreateEvent()));
	ChkExit(SOCKET_ERROR != WSAEventSelect(pConn->ox.fd, pConn->ox.ov.hEvent
		, FD_READ | FD_WRITE | FD_CLOSE));*/

	send_msg(pConn, "220 IOCP FTP Server\r\n");

	pConn->wb.len = RECV_BUFLEN;
	ChkExit(pConn->wb.buf = malloc(pConn->wb.len));
	launchRecv(pConn);
	{
		ss->ovAcc.conn = ss->conn;
		ss->ovAcc.ev_callback = accept_dt_cplt;
		ss->ovAcc.fd = INVALID_SOCKET;
		async_accept(ss, &ss->ovAcc, 0);
	}

}

void PrepareNextAcceptEx(Session *ss, OVX *poL)
{
	DWORD Bytes = 0;
	connection_t *conn;
	SOCKET peer_fd;
	ChkExit(INVALID_SOCKET != (peer_fd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED)));
	/*ChkExit(CreateIoCompletionPort((HANDLE)peer_fd, ep_fd, (ULONG_PTR)ss, 0));*/

	ChkExit(conn = calloc(1, sizeof *conn), closesocket(peer_fd));
	conn->session = ss;
	conn->ox.fd = peer_fd;
	poL->conn = conn;

	if (!lpfnAcceptEx(poL->fd, peer_fd, (PVOID)&conn->local, 0,
		sizeof(SOCKADDR_IN)+16, sizeof(SOCKADDR_IN)+16, &Bytes, &poL->ov))
	{
		ChkExit(ERROR_IO_PENDING == WSAGetLastError());
	}
	p_xx(conn, peer_fd);
	p_xx(&conn->ox, poL->conn);
}

void accept_event_handler(Session* completionKey, OVX *poL)
{
	p_xx(completionKey, poL);
	connection_t *sdt = (connection_t*)poL->conn;
	LPSOCKADDR_IN pLocalSock, pRemoteSock;
	int LocalSockLen = 0, RemoteSockLen = 0;
	/*ChkExit(WSAResetEvent(poL->ov.hEvent));*/

	ChkExit(!setsockopt(sdt->ox.fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
		(char *)&poL->fd, sizeof(poL->fd)));
	lpfnGetAcceptExSockaddrs(&sdt->local, (DWORD)poL->ov.InternalHigh
		, sizeof(SOCKADDR_IN)+16, sizeof(SOCKADDR_IN)+16
		, (LPSOCKADDR*)&pLocalSock, &LocalSockLen
		, (LPSOCKADDR*)&pRemoteSock, &RemoteSockLen);

	print_info("!!!!!!!!!!!!!!!!!!!!!!got accept sdt=%llx sdt->ox.fd=%llx\n", sdt, sdt->ox.fd);
	print_socket("AcceptEx Socket", sdt->ox.fd);

	PrepareNextAcceptEx(NULL, poL);
	{
		Session* ss;

		ChkExit(ss = calloc(1, sizeof *ss));
		ss->conn = sdt;
		sdt->session = ss;
		NewSession(ss, sdt);
	}
}

void async_accept(Session *ss, OVX *poL, in_port_t port)
{
	struct sockaddr_in addr = {0};

	ChkExit(INVALID_SOCKET != (poL->fd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED)));
	print_debug("WSASocket() is OK!\n","");
	initLpFns(poL->fd);
	ChkExit(CreateIoCompletionPort((HANDLE)poL->fd, ep_fd, (ULONG_PTR)ss, 1));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ChkExit(!bind(poL->fd, (struct sockaddr*)&addr, sizeof(addr)));
	ChkExit(!listen(poL->fd, LISTEN_BACKLOG));
	PrepareNextAcceptEx(ss, poL);
}

void close_conn(connection_t *pConn){
	if (!pConn)
		return;
	{
		SOCKET fd = pConn->ox.fd;

		if (pConn->read_buf)
			free(pConn->read_buf);
		pConn->read_buf = NULL;
		pConn->read_bufsize = 0;

		if (INVALID_SOCKET != fd){
			print_socket("close_conn", fd);
			ChkExit(!closesocket(fd));
		}
		pConn->ox.fd = INVALID_SOCKET;
	}
}
