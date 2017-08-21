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
#include <WinSock2.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <conio.h>

#include "oelog.h"
#include "networking.h"

static const int PORT = 5001;

void handle_cmd_overall(uint8_t *recv_buf, uint32_t buf_len, connection_t *pConn)
{
}

static void cleanup(void) 
{
	WSACleanup();
	_getch();
}

int wmain(int argc, char **argv)
{

	WSADATA wsa_data;
	WSAStartup(0x0202, &wsa_data);
	ChkExit(SetConsoleOutputCP(CP_UTF8));
	atexit(cleanup);
		
	event_init();

	{
		/*async_accept(&ovListen2, 2121);*/
		struct sockaddr_in name;
		int namelen = sizeof name;
		async_accept(&ovListen, PORT);
		ChkExit(!getsockname(ovListen.fd, (struct sockaddr*)&name, &namelen));
		p_ii(ovListen.fd, htons(name.sin_port));
	}

	event_dispatch();

	printf("done\n");
	return 0;
}