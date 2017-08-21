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
OVX ovListen2 = { { 0 }, accept_event_handler, INVALID_SOCKET };

AcceptReq *sessionList = NULL;

void event_init(void)
{
	ChkExit(ep_fd = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1));
}

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
			INFINITE), goto Next);
		/*pConn = (struct OvListen*)pOverlapped;*/
		p_xi(pox->ev_callback, cbTransferred);
		p_xx(completionKey, pox);
		t1 = GetTickCount();
		pox->ev_callback(cbTransferred, completionKey, &pox->ov);
		t2 = GetTickCount();
		tMax = max(tMax, t2 - t1);
		Next:
		print_debug("//// %llu tMax=%llu ////", t2 - t1, tMax);
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

static void empty_error_handler(SOCKET fd, int ierr) {
	char str[100];
	sprintf(str, "!!! errno=%d(%s) on", ierr, strerror(ierr));
	print_socket(str, fd);
	exit(EXIT_FAILURE);
}

static void(*error_handler)(SOCKET fd, int err) = empty_error_handler;

void set_error_handler(void(*new_error_handler)(SOCKET, int)) {
	error_handler = new_error_handler;
}


void async_send(connection_t **pp_conn, in_addr_t ip, in_port_t port,
		void *buf, int len) 
{
	struct buf_list *last_list;
	struct buf_list *new_list;
	connection_t *pConn;
	int isConnected=0;

	if (NULL == *pp_conn ) {
		pConn=malloc(sizeof(connection_t));
		*pp_conn=pConn;
	}else{
		pConn=*pp_conn;
		if(FD_INVALID != pConn->ox.fd){
			isConnected=1;
		}
	}
	if (0==isConnected) {
		/* make new connection */
		struct sockaddr_in saddr;
		int ret;
		memset(pConn, 0, sizeof(connection_t));
		ChkExit(pConn->ox.fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP));
		saddr.sin_addr.s_addr = ip;
		saddr.sin_family = AF_INET;
		saddr.sin_port = port;
		ret = connect(pConn->ox.fd, (struct sockaddr *) &saddr,
				sizeof(saddr));
		if ((-1 == ret) && (errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
			error_handler(pConn->ox.fd, errno);
			return;
		}
		print_socket("connect", pConn->ox.fd);
	}

	/* Add data to send queue */
	if( len > 0 ){
		if (NULL == pConn->write_list) {
			int ret;
			do {
				/*errno = 0;*/
				ret = send(pConn->ox.fd, buf, len,0);
			} while(EINTR == errno);
			if(len==ret){
				free(buf);
				return;
			}else if(ret<0){
				if (errno == EWOULDBLOCK || errno == EAGAIN) {
					ret = 0;
				} else {
					error_handler(pConn->ox.fd, errno);
				}
			}
			pConn->wbuf_offset += ret;
		}

		new_list = malloc(sizeof(*new_list));
		if (NULL == new_list) {
			error_handler(pConn->ox.fd, ENOMEM);
			return;
		}
		new_list->buf = buf;
		new_list->len = len;
		new_list->next = NULL;
		if (NULL == pConn->write_list) {
			pConn->write_list = new_list;
		} else {
			last_list = pConn->write_list;
			while (last_list->next != NULL) {
				last_list = last_list->next;
			}
			last_list->next = new_list;
		}
	}

	{
		/*
		short eventsBits=(NULL == pConn->write_list)?
			EV_READ:
			EV_READ | EV_WRITE;

		if(0==pConn->rw_event.ev_events)
		{
			event_set(&pConn->rw_event, pConn->fd,
				eventsBits, rw_event_handler, pConn);
			ChkExit(event_add(&pConn->rw_event,NULL));
		}else{
			if(eventsBits != pConn->rw_event.ev_events){
				event_set(&pConn->rw_event, pConn->fd,
					eventsBits, rw_event_handler, pConn);
				ChkExit(event_mod(&pConn->rw_event));
			}
		}*/
	}
}

void send_msg_cplt_handler(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped)
{
	OVX *ovs = (OVX *)lpOverlapped;
	Session *ss = (Session *)completionKey;


	p_xx(ss, ovs);
#if 0
	{
		WSANETWORKEVENTS ne = { 0 };
	ChkExit(!WSAEnumNetworkEvents(pConn->ox.fd, 0/*ss->ov.hEvent*/, &ne), break);
	print_debug("ne.lNetworkEvents %x\n", ne.lNetworkEvents);
	}
#endif
	ChkExit(WSAResetEvent(lpOverlapped->hEvent), break);
	if (ss->sdt){
		if ((ss->state)
			&& (ss->sdt->ovs.fd == ovs->fd)){
			handler(ss);
		}
	}
	free(ovs);
}

void send_cplt_handler(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped)
{
	OVX *ovs = (OVX *)lpOverlapped;
	Session *ss = (Session *)completionKey;

	p_xx(ss, ovs);
#if 0
	{
		WSANETWORKEVENTS ne = { 0 };
	ChkExit(!WSAEnumNetworkEvents(pConn->ox.fd, 0/*ss->ov.hEvent*/, &ne), break);
	print_debug("ne.lNetworkEvents %x\n", ne.lNetworkEvents);
	}
#endif
	ChkExit(WSAResetEvent(lpOverlapped->hEvent), break);
	if (ss->state && ss->sdt->ox.fd == ovs->fd){
		handler(ss);
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
			ChkExit(ERROR_IO_PENDING == errno, { close_conn(pConn); break; });
		}
		else
		{
			pConn->wb.buf[pConn->recvLen] = '\0';
			print_debug("received2 %d bytes %s\n", pConn->recvLen, pConn->wb.buf);
	}
}

void recv_cplt_handler(Session *ss)
{
	connection_t* pConn=ss->conn;
	char delim[] = " \t\r\n";
	char *pEnd;
	char* token;
	static char buf[MAX_PATH * 2];
	char *pbuf = buf;

	memmove(buf, pConn->wb.buf,pConn->recvLen);
	buf[pConn->recvLen] = 0;

	launchRecv(pConn);

	for (; (pEnd = strstr(pbuf, "\r\n")); pbuf = pEnd+2)
	{
		*pEnd = 0;
		token = strtok(pbuf, delim);
		if (token)
		{
			strcpy(ss->cmnd_, token);
			token = strtok(NULL, delim + 2);
			if (token)
			{
				strcpy(ss->u8opts, token);
			}
			ss->state = 0;
			handler(ss);
		}
	}
}

void recv_data_cplt(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped)
{
	Session *ss = (Session *)completionKey;
	connection_t *pConn = (connection_t *)((char*)lpOverlapped - offsetof(connection_t, ox));

	p_xx(completionKey, lpOverlapped);
	ChkExit(WSAResetEvent(pConn->ox.ov.hEvent));
	pConn->recvLen = cbTransferred;

	print_debug("data received %d bytes\n", pConn->recvLen);
	if (ss->sdt){
		if (ss->state && ss->sdt->ox.fd == ((OVX*)lpOverlapped)->fd){
			handler(ss);
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

void rwc_cplt_handler(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped)
{
	Session *ss = (Session *)completionKey;
	connection_t *pConn = (connection_t *)((char*)lpOverlapped - offsetof(connection_t, ox));

	p_xx(completionKey, lpOverlapped);
	if (0 == cbTransferred){
		WSANETWORKEVENTS ne = { 0 };
		ChkExit(!WSAEnumNetworkEvents(pConn->ox.fd, 0, &ne));
		print_debug("ne.lNetworkEvents %x\n", ne.lNetworkEvents);
		if (FD_CLOSE & ne.lNetworkEvents){
				ChkExit(!ne.iErrorCode[FD_CLOSE_BIT]);
				close_conn(pConn);
			free(ss);
			return;
		}		
	}
	ChkExit(WSAResetEvent(pConn->ox.ov.hEvent));


	pConn->recvLen = cbTransferred;
	pConn->wb.buf[pConn->recvLen] = '\0';

	print_debug("received %d bytes %s\n", pConn->recvLen, pConn->wb.buf);
	recv_cplt_handler(ss);

	/*Socket has closed after QUIT command*/
	pConn = ss->conn;
	if (NULL == pConn
		|| INVALID_SOCKET == pConn->ox.fd)
	{
		free(ss);
		return;
	}
}

void accept_dt_cplt(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped)
{
	OVX *poL = (OVX*)lpOverlapped;
	connection_t *sdt = (connection_t*)poL->conn;

#if 0
	{
		WSANETWORKEVENTS ne = { 0 };
		ChkExit(!WSAEnumNetworkEvents(pConn->ox.fd, 0/*ss->ov.hEvent*/, &ne), break);
		print_debug("ne.lNetworkEvents %x\n", ne.lNetworkEvents);
	}
#endif
	ChkExit(WSAResetEvent(lpOverlapped->hEvent), break);
	accept_event_handler(cbTransferred, completionKey, lpOverlapped);
	{
		Session *ss = sdt->session;
		p_xx(ss, poL);
		if (ss->state){
			handler(ss);
		}
	}
}

void NewSession(connection_t *pConn)
{
	Session *ss;

	ChkExit(ss = calloc(1, sizeof *ss), close_conn(pConn));
	ss->conn = pConn;
	pConn->session = ss;
	wcscpy(ss->sCurrPath, L"\\");

	p_xx(ss, pConn->ox.fd);

	pConn->ox.ev_callback = rwc_cplt_handler;
	pConn->ovs.ev_callback = send_cplt_handler;
	pConn->ovs.fd = pConn->ox.fd;
	ChkExit(CreateIoCompletionPort((HANDLE)pConn->ox.fd, ep_fd, (ULONG_PTR)ss, 0));
	ChkExit(WSA_INVALID_EVENT != (pConn->ox.ov.hEvent = WSACreateEvent()));
	ChkExit(SOCKET_ERROR != WSAEventSelect(pConn->ox.fd, pConn->ox.ov.hEvent, FD_READ | FD_WRITE | FD_CLOSE));


	send_msg(pConn, "220 IOCP FTP Server\r\n");

	pConn->wb.len = RECV_BUFLEN;
	ChkExit(pConn->wb.buf = malloc(pConn->wb.len));
	launchRecv(pConn);
	{
		ss->ovAcc.conn = ss->conn;
		ss->ovAcc.ev_callback = accept_dt_cplt;
		ss->ovAcc.fd = INVALID_SOCKET;
		async_accept(&ss->ovAcc, 0);
	}

}

void PrepareNextAcceptEx(OVX *poL)
{
	DWORD Bytes = 0;
	connection_t *conn;
	SOCKET peer_fd;
	/*ChkExit(peer_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP));*/
	ChkExit(INVALID_SOCKET != (peer_fd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED)));

	ChkExit(conn = calloc(1, sizeof *conn), closesocket(peer_fd));
	/*conn->handle = INVALID_HANDLE_VALUE;*/

	if (!lpfnAcceptEx(poL->fd, peer_fd, (PVOID)&conn->local, 0,
		sizeof(SOCKADDR_IN)+16, sizeof(SOCKADDR_IN)+16, &Bytes, &poL->ov))
	{
		ChkExit(ERROR_IO_PENDING == WSAGetLastError());
	}
	/*poL->ev_callback = accept_event_handler;*/
	poL->conn = conn;
	conn->ox.fd = peer_fd;
	p_xx(conn, peer_fd);
	p_xx(&conn->ox, poL->conn);
}

void accept_event_handler(DWORD cbTransferred, ULONG_PTR completionKey, LPOVERLAPPED lpOverlapped)
{
	p_xx(completionKey, lpOverlapped);
	OVX *poL = (OVX*)lpOverlapped;
	connection_t *sdt = (connection_t*)poL->conn;
	connection_t *connCtrl = NULL;
	LPSOCKADDR_IN pLocalSock, pRemoteSock;
	int LocalSockLen = 0, RemoteSockLen = 0;
	ChkExit(WSAResetEvent(poL->ov.hEvent));

	ChkExit(!setsockopt(sdt->ox.fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
		(char *)&poL->fd, sizeof(poL->fd)));
	lpfnGetAcceptExSockaddrs(&sdt->local, cbTransferred
		, sizeof(SOCKADDR_IN)+16, sizeof(SOCKADDR_IN)+16
		, (LPSOCKADDR*)&pLocalSock, &LocalSockLen
		, (LPSOCKADDR*)&pRemoteSock, &RemoteSockLen);

	{	
		/*
			Is accepted socket for data or session?
			Data socket are in a list, session aren't in the list. 
		*/
		AcceptReq*req, *reqPrev=sessionList;
		for (req = sessionList; NULL != req; req = req->nextReq)
		{
			if (req->peer.s_addr == pRemoteSock->sin_addr.s_addr
				&& req->port == pLocalSock->sin_port)
			{
				if (sessionList == req){
					sessionList = req->nextReq;
				}
				else{
					reqPrev->nextReq = req->nextReq;
				}
				connCtrl = req->ss;
				free(req);
				goto Found;
			}
			reqPrev = req;
		}
		print_socket("Control Socket", sdt->ox.fd);
		Found:;
	}

	print_info("!!!!!!!!!!!!!!!!!!!!!!got accept connCtrl=%llx sdt->ox.fd=%llx\n", connCtrl, sdt->ox.fd);
	print_socket("AcceptEx Socket", sdt->ox.fd);

	PrepareNextAcceptEx(poL);
	if (connCtrl){
		connCtrl->session->sdt = sdt;
		sdt->session = connCtrl->session;
		sdt->ox.ev_callback = recv_data_cplt;
		sdt->ovs.ev_callback = send_cplt_handler;
		sdt->ovs.fd = sdt->ox.fd;
		ChkExit(CreateIoCompletionPort((HANDLE)sdt->ox.fd, ep_fd, (ULONG_PTR)connCtrl->session, 0));
		ChkExit(WSA_INVALID_EVENT != (sdt->ox.ov.hEvent = WSACreateEvent()));
		ChkExit(SOCKET_ERROR != WSAEventSelect(sdt->ox.fd, sdt->ox.ov.hEvent, FD_READ | FD_WRITE | FD_CLOSE));
		sdt->ovs.ov.hEvent = sdt->ox.ov.hEvent;
		/*NewDataSocket(session, sdt->oa.fd);*/
	}else{
		NewSession(sdt);
	}
}

void async_accept(OVX *poL, in_port_t port)
{
	struct sockaddr_in addr = {0};

	/*ChkExit(poL->fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP));*/

	ChkExit(INVALID_SOCKET != (poL->fd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED)));
	print_debug("WSASocket() is OK!\n","");
	initLpFns(poL->fd);
	ChkExit(CreateIoCompletionPort((HANDLE)poL->fd, ep_fd, (ULONG_PTR)poL, 1));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ChkExit(!bind(poL->fd, (struct sockaddr*)&addr, sizeof(addr)));

	ChkExit(!listen(poL->fd, LISTEN_BACKLOG));

	ChkExit(WSA_INVALID_EVENT != (poL->ov.hEvent = WSACreateEvent()));
	ChkExit(SOCKET_ERROR != WSAEventSelect(poL->fd, poL->ov.hEvent, FD_ACCEPT));
	PrepareNextAcceptEx(poL);
}

void close_conn(connection_t *pConn){
	if (!pConn)
		return;
	{
		SOCKET fd = pConn->ox.fd;
		struct buf_list *el_buf = pConn->write_list;

		for (; el_buf != NULL;) {
			struct buf_list *el = el_buf;
			el_buf = el_buf->next;
			free(el->buf);
			free(el);
		}
		pConn->write_list = NULL;
		if (pConn->read_buf)
			free(pConn->read_buf);
		pConn->read_buf = NULL;
		pConn->read_bufsize = 0;

		/*if (INVALID_HANDLE_VALUE != pConn->handle){
			ChkExit(CloseHandle(pConn->handle));
			pConn->handle = INVALID_HANDLE_VALUE;
			}*/
		if (INVALID_SOCKET != fd){
			/*event_del(&pConn->rw_event);*/
			ChkExit(WSAResetEvent(pConn->ox.ov.hEvent));
			ChkExit(CloseHandle(pConn->ox.ov.hEvent));
			print_socket("close_conn", fd);
			ChkExit(!closesocket(fd));
		}
		/*memset(pConn, 0, sizeof*pConn);*/
		pConn->ox.fd = INVALID_SOCKET;
		free(pConn);
		pConn = 0;
	}
}