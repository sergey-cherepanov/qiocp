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
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stddef.h>

#include "networking.h"
#include "oelog.h"
#include "ftpd.h"
#include "security.h"


#define CMD(A) en##A,
#define CMD_LIST \
CMD(USER) /* USER <SP> <username> <CRLF> */ \
CMD(PASS) /* PASS <SP> <password> <CRLF> */ \
CMD(SYST) /* SYST <CRLF> */ \
CMD(TYPE) /* TYPE <SP> <type-code> <CRLF> */ \
CMD(MODE) /* MODE <SP> <mode-code> <CRLF> */ \
CMD(ABOR) /* ABOR <CRLF> */ \
CMD(QUIT) /* QUIT <CRLF> */ \
CMD(NOOP) /* NOOP <CRLF> */ \
CMD(PORT) /* PORT <SP> <host-port> <CRLF> */ \
CMD(EPRT) /* EPRT <SP> <d> <net-prt> <d> <net-addr> <d> <tcp-port> <d> <CRLF> */ \
CMD(PWD) /* PWD  <CRLF> */ \
CMD(CWD) /* CWD  <SP> <pathname> <CRLF> */ \
CMD(CDUP) /* CDUP <CRLF> */ \
CMD(XCUP) /* XCUP <CRLF> */ \
CMD(RMD) /* RMD  <SP> <pathname> <CRLF> */ \
CMD(XRMD) /* XRMD <SP> <pathname> <CRLF> */ \
CMD(MKD) /* MKD  <SP> <pathname> <CRLF> */ \
CMD(XMKD) /* XMKD <SP> <pathname> <CRLF> */ \
CMD(DELE) /* DELE <SP> <pathname> <CRLF> */ \
CMD(PASV) /* PASV <CRLF> */ \
CMD(EPSV) /* EPSV <SP> <net-prt> <CRLF> OR EPSV <SP> ALL <CRLF> */ \
CMD(LPSV) /* LPSV ??? */ \
CMD(LIST) /* LIST [<SP> <pathname>] <CRLF> */ \
CMD(NLST) /* NLST [<SP> <pathname>] <CRLF> */ \
CMD(ACCT) /* ACCT <SP> <account-information> <CRLF> */ \
CMD(SIZE) /* SIZE <SP> <pathname> <CRLF> */ \
CMD(STRU) /* STRU <SP> <structure-code> <CRLF> */ \
CMD(RNFR) /* RNFR <SP> <pathname> <CRLF> */ \
CMD(RNTO) /* RNTO <SP> <pathname> <CRLF> */ \
CMD(RETR) /* RETR <SP> <pathname> <CRLF> */ \
CMD(STOR) /* STOR <SP> <pathname> <CRLF> */ \
CMD(APPE) /* APPE <SP> <pathname> <CRLF> */ \
CMD(REST) /* REST <SP> <marker> <CRLF> */ \
CMD(MDTM) /* MDTM <SP> <pathname> <CRLF> */ \
CMD(OPTS) /* OPTS <SP> <option> <value> <CRLF> */ \
CMD(SITE) /* SITE <SP> <string> <CRLF> */ \
CMD(HELP) /* HELP [<SP> <string>] <CRLF> */ \
CMD(CLNT) /* CLNT <SP> <string> <CRLF> */ \
	
#if 0L /* TODO */ 

CMD(SMNT) /* SMNT <SP> <pathname> <CRLF> */ \
CMD(REIN) /* REIN <CRLF> */ \
CMD(STOU) /* STOU <CRLF> */ \
CMD(STAT) /* STAT [<SP> <pathname>] <CRLF> */ \
CMD(ALLO) /* ALLO <SP> <decimal-integer> [<SP> R <SP> <decimal-integer>] <CRLF> */ \

#endif

enum cmnd { enNotCmnd=-1, CMD_LIST };
typedef enum cmnd CmndT;

typedef enum client clientT;
const char sUndef[] = "Undef";
const char sTotalCommander[] = "Total Commander";

const struct clients{
	clientT clnt; const char * const sClient;
} clients[] = { 
	{ Undef, sUndef },
	{ TotalCommander, sTotalCommander } 
};

void getAccept(connection_t *ss, IN_ADDR peer, USHORT port)
{
	AcceptReq*req, *pReq;
	req = calloc(1, sizeof *req);
	req->ss = ss;
	req->peer = peer;
	req->port = port;
	pReq = sessionList;
	if (sessionList){
		for (; NULL != pReq->nextReq; pReq = pReq->nextReq){ ; }
		pReq->nextReq = req;
	}else{
		sessionList = req;
	}
}

void send_msg(connection_t *conn, const char *format, ...)
{
	DWORD Flags = 0;
	OVX* po;

	ChkExit(po = malloc(sizeof(OVX)+CMD_SEND_BUF_SIZE));
	po->wb.buf = (char*)(po + 1);
	po->ev_callback = send_msg_cplt_handler;
	po->fd = conn->ox.fd;
	po->ov.hEvent = conn->ox.ov.hEvent;
	{
		va_list ap;
		va_start(ap, format);
		ChkExit(0 < (po->wb.len = _vsnprintf_s(po->wb.buf, CMD_SEND_BUF_SIZE-1, _TRUNCATE, format, ap)));
		ChkExit(po->wb.len == strlen(po->wb.buf));
		ChkExit(po->wb.len <= CMD_SEND_BUF_SIZE - 1);
		va_end(ap);
	}
	/*realloc(po, sizeof(OVX) + po->wb.len + 1);*/
	/*ChkExit(SOCKET_ERROR != WSAEventSelect(ss->fd, ss->ov.hEvent, FD_READ | FD_WRITE | FD_CLOSE));*/
	if (SOCKET_ERROR == WSASend(conn->ox.fd, &po->wb, 1, &conn->BytesSEND,
		Flags, &po->ov, NULL))
	{
		ChkExit(ERROR_IO_PENDING == WSAGetLastError(), close_conn(conn); break);
	}
	else
	{
		/*ChkExit(SOCKET_ERROR != WSAEventSelect(ss->fd, ss->ov.hEvent, FD_READ | FD_CLOSE));*/
		print_debug("sent %d bytes %.*s", po->wb.len, po->wb.len, po->wb.buf);
	}
}

#undef CMD
#define CMD(A) void ftpdCmnd_##A(Session *ss)

void makePathW(Session *ss, wchar_t path[])
{
	size_t len = 0;
	if ('/' != ss->u8opts[0])
	{
		len = wcslen(ss->sCurrPath);
		wcscpy(path, ss->sCurrPath);
		{
			switch (path[len - 1]){
			case L'\\':break;
			case L'/': path[len - 1] = L'\\'; break;
			default:
				path[len] = L'\\';
				path[++len] = 0;
			}
		}
	}
	ChkExit(MultiByteToWideChar(CP_UTF8, 0, ss->u8opts, -1, path + len, MAX_PATH - (int)len));
}


void makePath(Session *ss, wchar_t path[], char utf8[])
{
	char *pw;
	makePathW(ss, path);
	ChkExit(WideCharToMultiByte(CP_UTF8, 0, path, -1, utf8 , 2 * MAX_PATH, 0, 0));
	for (pw = utf8; *pw && pw < utf8 + 2*MAX_PATH; ++pw){
		if ('\\' == *pw){
			*pw = '/';
		}
	}
}

CMD(STOR)	/* STOR <SP> <pathname> <CRLF> */
{
	DWORD cbWritten = 0;
#define STOR_BLOCK	0x80000
	crBegin;

	send_msg(ss->conn, "125 Data connection already open; transfer starting.\r\n");
	while (!ss->sdt){
		crReturn;
	}
	{
		char utf8[2 * MAX_PATH];
		wchar_t path[MAX_PATH];

		makePath(ss, path, utf8);
		print_debug("STOR file %s\n", utf8);
		ChkExit(ImpersonateLoggedOnUser(ss->phToken));
		if (INVALID_HANDLE_VALUE == (ss->handle = CreateFile(path, GENERIC_WRITE, 0, NULL,
			CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, 0))){
			send_msg(ss->conn, "451 Requested action aborted. Local error in processing.\r\n");
			RevertToSelf();
			goto Finally;
		}
		RevertToSelf();
	}
	ChkExit(CreateIoCompletionPort(ss->handle, ep_fd, (ULONG_PTR)ss, 0));

	ss->sdt->ovs.ov.Offset = 0; ss->sdt->ovs.ov.OffsetHigh = 0;
	ss->sdt->wb.buf = malloc(STOR_BLOCK);
	ss->sdt->wb.len = STOR_BLOCK;
	for (;;)
	{
		{
			DWORD Flags = 0;

			if (SOCKET_ERROR == WSARecv(ss->sdt->ox.fd, &ss->sdt->wb, 1, &ss->sdt->recvLen,
				&Flags, &ss->sdt->ox.ov, NULL))
			{
				ChkExit(ERROR_IO_PENDING == WSAGetLastError(), CloseHandle(ss->handle));
			}
			else
			{
				print_debug("net recv %ld bytes\n", ss->sdt->recvLen);
				/*if (!WriteFile(ss->handle, ss->sdt->wb.buf, ss->sdt->recvLen, &ss->sdt->recvLen,
					&ss->sdt->ox.ov))
					{
					ChkExit(ERROR_IO_PENDING == GetLastError(), close_conn(ss->sdt));
					}
					else
					{
					print_debug("file write %ld bytes\n", ss->sdt->recvLen);
					continue;
					}*/
			}
		}
		crReturn;
		if (0 == ss->sdt->recvLen)
		{
			break;
		}
		if (!WriteFile(ss->handle, ss->sdt->wb.buf, ss->sdt->recvLen, &cbWritten,
			&ss->sdt->ox.ov))
		{
			ChkExit(ERROR_IO_PENDING == GetLastError(), close_conn(ss->sdt));
		}
		else
		{
			print_debug("file write %ld bytes\n", cbWritten);
		}
		crReturn;
		{
			ULONGLONG *pOffset = (ULONGLONG*)&ss->sdt->ox.ov.Offset;
			*pOffset += ss->sdt->recvLen;
		}
	}
	{
		ULONGLONG *pOffset = (ULONGLONG*)&ss->sdt->ox.ov.Offset;
		*pOffset += ss->sdt->recvLen;
		p_ii(*pOffset, ss->sdt->recvLen);
	}
	free(ss->sdt->wb.buf); ss->sdt->wb.buf = 0;

	ChkExit(CloseHandle(ss->handle));
	ss->handle = INVALID_HANDLE_VALUE;
	send_msg(ss->conn, "226 Transfer complete\r\n");
Finally:
	ss->sdt->ox.ov.Offset = 0; ss->sdt->ox.ov.OffsetHigh = 0;
	close_conn(ss->sdt);  ss->sdt = 0;
	crFinish;
}

CMD(RETR)	/* RETR <SP> <pathname> <CRLF> */
{
#define BLOCK_SIZE	0x8000
	{
		crBegin;
		while (!ss->sdt){
			crReturn;
		}
		ss->sdt->ovs.ov.Offset = 0; ss->sdt->ovs.ov.OffsetHigh = 0;
		send_msg(ss->conn, "125 Data connection already open; transfer starting.\r\n");
		{
			char utf8[2 * MAX_PATH];
			wchar_t path[MAX_PATH];

			makePath(ss, path, utf8);
			print_debug("retr file %s\n", utf8);
			ChkExit(ImpersonateLoggedOnUser(ss->phToken));

			CHECK_ERR(INVALID_HANDLE_VALUE != (ss->handle = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
				OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0)),
				RevertToSelf();
				switch (ierr){ case 5:
				send_msg(ss->conn, "450 Requested file action not taken. Access denied.\r\n");
				goto Finally; },
				exit(ierr));
			RevertToSelf();
			ss->fileSize.LowPart = GetFileSize(ss->handle, &ss->fileSize.HighPart);
			ChkExit(CreateIoCompletionPort(ss->handle, ep_fd, (ULONG_PTR)ss, 0));
		}

#if 0
#define BUF_LEN		0x4000
		{
			ChkExit(ss->hMap = CreateFileMapping(ss->handle, 0, PAGE_READONLY
				, 0, 0, NULL));
			ss->pCh=MapViewOfFile(ss->hMap, FILE_MAP_READ, 0, 0, 0);
			ss->ir = ss->fileSize.QuadPart;

			send_msg(ss->conn, "125 Data connection already open; transfer starting.\r\n");
			for (; ss->ir>0; ss->ir -= BLOCK_SIZE, ss->pCh += BLOCK_SIZE)
			{
				ULONG nbRest = (ULONG)((ss->ir >= BLOCK_SIZE) ? BLOCK_SIZE : ss->ir);
				ULONG bufRest = (ULONG)(nbRest % BUF_LEN);
				ULONG nBuf = (ULONG)(nbRest / BUF_LEN)
					+ ((nbRest % BUF_LEN) ? 1 : 0);
				ss->wBufs = calloc(nBuf, sizeof(WSABUF));
				__int64 rest, n;

				for (n = 0, rest = nbRest; rest > BUF_LEN; rest -= BUF_LEN, ++n){
					ss->wBufs[n].buf = ss->pCh + n*BUF_LEN;
					ss->wBufs[n].len = BUF_LEN;
				}
				if (rest > 0)
				{
					ss->wBufs[n].buf = ss->pCh + n*BUF_LEN;
					ss->wBufs[n].len = (ULONG)rest;
				}
				{
					DWORD Flags = 0;
					if (SOCKET_ERROR == WSASend(ss->sdt->ox.fd, ss->wBufs, nBuf, &ss->sdt->BytesSEND,
						Flags, &ss->sdt->ovs.ov, NULL))
					{
						ChkExit(ERROR_IO_PENDING == WSAGetLastError(), close_conn(ss->sdt));
					}
					else
					{
						print_debug("sent %lld bytes\n", nbRest);
					}
					crReturn;
					free(ss->wBufs);
				}
			}
			ChkExit(CloseHandle(ss->hMap));
		}
#elif 0
		ss->sdt->wb.buf=malloc(BLOCK_SIZE);
		for (;;)
		{
			{
				ULONGLONG *pOffset = (ULONGLONG*)&ss->sdt->ovs.ov.Offset;
				ULONGLONG ullnbRest = ss->fileSize.QuadPart - *pOffset;
				ss->sdt->wb.len = (LONG)((ullnbRest >= BLOCK_SIZE) ? BLOCK_SIZE : ullnbRest);
				if (!ReadFile(ss->handle, ss->sdt->wb.buf, ss->sdt->wb.len, &ss->read_len1, &ss->sdt->ovs.ov))
				{
					ChkExit(ERROR_IO_PENDING == GetLastError(), CloseHandle(ss->handle));
				}
				else
				{
					print_debug("read %lld bytes\n", ss->sdt->wb.len);
				}
			}
			crReturn;
			{
				DWORD Flags = 0;
				if (SOCKET_ERROR == WSASend(ss->sdt->ox.fd, &ss->sdt->wb, 1, &ss->sdt->BytesSEND,
					Flags, &ss->sdt->ovs.ov, NULL))
				{
					ChkExit(ERROR_IO_PENDING == WSAGetLastError(), close_conn(ss->sdt));
				}
				else
				{
					print_debug("sent %lld bytes\n", ss->sdt->BytesSEND);
				}
			}
			crReturn;
			{
				ULONGLONG *pOffset = (ULONGLONG*)&ss->sdt->ovs.ov.Offset;
				*pOffset += BLOCK_SIZE;
				if (*pOffset >= ss->fileSize.QuadPart)
					break;
			}
		}
		free(ss->sdt->wb.buf); ss->sdt->wb.buf = 0;

#else
		for (;;)
		{
			{
				ULONGLONG *pOffset = (ULONGLONG*)&ss->sdt->ovs.ov.Offset;
				ULONGLONG ullnbRest = ss->fileSize.QuadPart - *pOffset;
				LONG nbRest = (LONG)((ullnbRest >= BLOCK_SIZE) ? BLOCK_SIZE : ullnbRest);
				if (SOCKET_ERROR == lpfnTransmitFile(ss->sdt->ox.fd, ss->handle, nbRest, 0, &ss->sdt->ovs.ov, NULL,
					TF_USE_DEFAULT_WORKER | TF_USE_KERNEL_APC | TF_WRITE_BEHIND))
				{
					ChkExit(ERROR_IO_PENDING == WSAGetLastError(), close_conn(ss->sdt));
				}
				else
				{
					print_debug("sent %lld bytes\n", nbRest);
				}
			}
			crReturn;
			{
				ULONGLONG *pOffset = (ULONGLONG*)&ss->sdt->ovs.ov.Offset;
				*pOffset += BLOCK_SIZE;
				if (*pOffset >= ss->fileSize.QuadPart)
					break;
			}
		}
#endif
		ChkExit(CloseHandle(ss->handle));
		ss->handle = INVALID_HANDLE_VALUE;
		send_msg(ss->conn, "226 Transfer complete\r\n");
	Finally:
		ss->sdt->ovs.ov.Offset = 0; ss->sdt->ovs.ov.OffsetHigh = 0;
		close_conn(ss->sdt);  ss->sdt = 0;
		crFinish;
	}
}

/* time */
enum {
 OPT_l = 1
, OPT_a = 2
, OPT_p=4
, OPT_F=8
, OPT_R=16
};

static struct tm systime;

void timeStr(Session *ss, WIN32_FIND_DATA *s_stat_ptr, char *sTime)
{
	struct tm tmFile = { 0 };
	char *mmm, *dd, *hhmm, *yyyy;
	char tokens[32];
	{
		int len;
		time_t ftime = 
			(0x100000000ULL * s_stat_ptr->ftLastWriteTime.dwHighDateTime + s_stat_ptr->ftLastWriteTime.dwLowDateTime) / 10000000
			- 11644473600ULL;

		ChkExit(0 == _gmtime64_s(&tmFile, &ftime),
			strcpy(sTime, "Jan 01 1980"); return);
		asctime_s(tokens, 32, &tmFile);
		len = (int)strlen(tokens);
		tokens[--len] = 0;
		/*Tue Jan 01 12:00:00 1970
			0123456789012345678901234 */
		strcpy(tokens, tokens + 4);
		strcpy(sTime, tokens);
		/*Jan 01 12:00:00 1970
	    012345678901234567890 */
		/*May 16 17:09:01 2017*/
		char *NextToken;
		mmm = strtok_s(tokens, " ", &NextToken);
		dd = strtok_s(0, " ", &NextToken);
		hhmm = strtok_s(0, " ", &NextToken);
		yyyy = strtok_s(0, " ", &NextToken);
		hhmm[5] = 0;
	}
	switch (ss->clnt){
	default:;
	case Undef:
	{
		/*if (OPT_l & ss->opts || 0 == ss->opts)*/
		{
				sprintf(sTime, "%s %s %s", mmm, dd, ((tmFile.tm_year == systime.tm_year) ? hhmm : yyyy));
		}
	}break;
	case TotalCommander:
	{
		/*Jan 01 12:00:00 1970
			012345678901234567890 */
		strncpy(sTime + 20, sTime + 6, 9); sTime[26] = 0;
		/*Jan 01 12:00:00 1970 12:00:00
			012345678901234567890123456789 */
		strcpy(sTime + 7, sTime + 16);
		/*Jan 01 1970 12:00
			012345678901234567890 */
	}	break;
	}
}

#if 0
void timeStr(unsigned opts, WIN32_FIND_DATA *s_stat_ptr, char *sTime)
{
	SYSTEMTIME SysTime = { 0 }; FILETIME ftLocal = { 0 };
	WCHAR fTimeStr[MAX_PATH];
	int len;
	/*ChkExit(FileTimeToLocalFileTime(&s_stat_ptr->ftLastWriteTime, &ftLocal));*/
	ChkExit(FileTimeToSystemTime(&s_stat_ptr->ftLastWriteTime, &SysTime), strcpy(sTime, "Jan 01 1980 00:00"); return);
	if (OPT_l & opts){
		if (SysTime.wYear == systime.wYear){
			ChkExit(len = GetDateFormatEx(LOCALE_NAME_SYSTEM_DEFAULT,
				0, &SysTime, L"MMM dd ",
				fTimeStr, sizeof fTimeStr / sizeof fTimeStr[0], NULL));
			ChkExit(GetTimeFormatEx(LOCALE_NAME_SYSTEM_DEFAULT,
				TIME_NOSECONDS | TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT,
				&SysTime,
				NULL, fTimeStr + len - 1, sizeof fTimeStr / sizeof fTimeStr[0] - len + 1));
		}
		else{
			ChkExit(len = GetDateFormatEx(LOCALE_NAME_SYSTEM_DEFAULT,
				0, &SysTime, L"MMM dd yyyy",
				fTimeStr, sizeof fTimeStr / sizeof fTimeStr[0], NULL));
		}
	}
	else{
		ChkExit(len = GetDateFormatEx(LOCALE_NAME_SYSTEM_DEFAULT,
		0, &SysTime, L"MMM dd yyyy ", 
		fTimeStr, sizeof fTimeStr / sizeof fTimeStr[0], NULL));
		ChkExit(GetTimeFormatEx(LOCALE_NAME_SYSTEM_DEFAULT,
		TIME_NOSECONDS|TIME_NOTIMEMARKER|TIME_FORCE24HOURFORMAT,
		&SysTime,
		NULL, fTimeStr + len-1, sizeof fTimeStr / sizeof fTimeStr[0] - len+1));
	}
	ChkExit(WideCharToMultiByte(CP_UTF8, 0, fTimeStr, -1, sTime, MAX_PATH, 0, 0));
}
#endif

void GetPrivilege(Session *ss, LPCWSTR priv, DWORD attr)
{
	TOKEN_PRIVILEGES tp;
	/*ChkExit(OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES, &hToken));*/
	CHECK(LookupPrivilegeValue(NULL, priv, &tp.Privileges[0].Luid));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = attr;
	CHECK(AdjustTokenPrivileges(ss->phToken, FALSE, &tp,
		sizeof(TOKEN_PRIVILEGES), NULL, NULL), ;);
	/*CloseHandle(hToken);*/
}

/* linkname */
static void FileNameStr(Session* ss, WIN32_FIND_DATA *findData, WCHAR *s_path
	, char *s_buffer) 
{
	int ret;
	ChkExit(ret = WideCharToMultiByte(CP_UTF8, 0, findData->cFileName, -1, s_buffer, 2*MAX_PATH, 0, 0));

	if ((FILE_ATTRIBUTE_REPARSE_POINT & findData->dwFileAttributes)
		&& (IO_REPARSE_TAG_SYMLINK & findData->dwReserved0))
	{
		/*if (IsReparseTagNameSurrogate(findData->dwFileAttributes))*/{
			WCHAR s_temp[MAX_PATH];
			HANDLE hF;
			size_t len = wcslen(s_path) - 1; /*remove last character '*' */
			wcsncpy(s_temp, s_path, len);
			wcscpy(s_temp + len, findData->cFileName);
			GetPrivilege(ss, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED);
			ChkExit(INVALID_HANDLE_VALUE != (hF = CreateFile(s_temp,
				FILE_READ_EA, 
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
				NULL, 
				OPEN_EXISTING, 
				FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, 
				NULL)),
				GetPrivilege(ss, SE_BACKUP_NAME, SE_PRIVILEGE_REMOVED);
				return);                 // no attr. template
			ChkExit(GetFinalPathNameByHandle(hF, s_temp, sizeof s_temp / sizeof s_temp[0], VOLUME_NAME_DOS));
			CloseHandle(hF);
			GetPrivilege(ss, SE_BACKUP_NAME, SE_PRIVILEGE_REMOVED);
			strcpy(s_buffer + ret -1, " -> ");
			ret += 3;
			ChkExit(WideCharToMultiByte(CP_UTF8, 0, s_temp+4, -1,
				s_buffer + ret, 2 * MAX_PATH - ret, 0, 0));
		}
	}
}

void getFilePermission(wchar_t fullPathName[], char *secur)
{
	struct _stat64i32 stat;
	CHECK_ERR(!_wstat(fullPathName, &stat), switch (ierr){ case 0:case 5:case 32:return; default:; }, assert(!"qq"); exit(1));
	if (_S_IFDIR & stat.st_mode) {
		secur[0] = 'd';
	}
	else if (_S_IFCHR & stat.st_mode) {
		secur[0] = 'c';
	}

	/* user */
	if (stat.st_mode & _S_IREAD)
		secur[1] = 'r';

	if (stat.st_mode & _S_IWRITE)
		secur[2] = 'w';

	if (stat.st_mode & _S_IEXEC) {
		secur[3] = 'x';
	}
}

CMD(LIST)	/* LIST [<SP> <pathname>] <CRLF> */
{
	__time64_t time64;
		WIN32_FIND_DATA findData;

		crBegin;
		send_msg(ss->conn, "150 Opening ASCII mode data connection for file list\r\n");
		while (!ss->sdt){
			crReturn;
		}
		p_xx(ss->sdt, ss->sdt->ox.fd);
		{
			unsigned opts = 0;
			char *p = ss->u8opts;
 
			ss->file_name[0] = 0;
			if ('-' == *p){
				for (++p;; ++p){
					switch (*p){
					default:
						goto SyntaxError;
					case ' ': goto Parse_Path;
					case '\0': goto OPT_OK;
					case 'l': opts |= OPT_l; break;
						case 'a': opts |= OPT_a; break;
						case 'p': opts |= OPT_p; break;
						case 'F': opts |= OPT_F; break;
						case 'R': opts |= OPT_R; break;
					}
				}
				goto Parse_Path;
				SyntaxError:
				send_msg(ss->conn, "501 Syntax error in parameters or arguments.\r\n");
				goto Finally;
				crBreak;
			}
		Parse_Path:
			ChkExit(MultiByteToWideChar(CP_UTF8, 0, ++p, -1, 
				ss->file_name, sizeof ss->file_name / sizeof ss->file_name[0]));
		OPT_OK:
			ss->opts = opts;
		}
		{
			wchar_t *pch;
			wchar_t *s_path = ss->sCurrPath;
			wcscpy_s(ss->file_name, MAX_PATH, s_path);
			for (pch = ss->file_name; *pch; ++pch)
			{
				if (L'/' == *pch)
					*pch = L'\\';
			}
			if (L'\\' != *(pch - 1))
				*pch++ = L'\\';
			*pch = L'*';
			*++pch = L'\0';
			ChkExit(ImpersonateLoggedOnUser(ss->phToken));
			CHECK(INVALID_HANDLE_VALUE != (ss->handle = FindFirstFileW(ss->file_name, &findData)),
				RevertToSelf();
				findData.cFileName[0] = L'\0';
				send_msg(ss->conn, "450 Requested file action not taken. File unavailable(e.g., file busy).\r\n");
				goto Finally;
			);
			RevertToSelf();
		}
		time(&time64);
		_gmtime64_s(&systime, &time64);
		do {
			if (OPT_a & ss->opts || !(FILE_ATTRIBUTE_HIDDEN & findData.dwFileAttributes)) 
			{
				char u8[2 * MAX_PATH];
				char secur[] = "----------+";
				char fileTime[64];
				//char ownerGroup[MAX_PATH] = "unknown unknown";
				char ownerGroup[MAX_PATH] = "ftp ftp";
				wchar_t chFileName[MAX_PATH];

				wcscpy(chFileName, ss->sCurrPath);
				wcscat(chFileName, findData.cFileName);

				/*getOwnerGroup(chFileName, ownerGroup);*/
				getFilePermission(chFileName, secur);
				if (FILE_ATTRIBUTE_REPARSE_POINT & findData.dwFileAttributes) {
					secur[0] = 'l';
				}
				timeStr(ss, &findData, fileTime);
				FileNameStr(ss, &findData, ss->file_name, &u8[0]);

				send_msg(ss->sdt, "%s 1 %s %10llu %s %s\r\n",
					secur, ownerGroup,
					0x100000000LL * findData.nFileSizeHigh + findData.nFileSizeLow, fileTime, u8);
				crReturn;
			}
		} while (FindNextFile(ss->handle, &findData));
		/*send_msg(ss->conn, "226 Transfer complete\r\n");*/
		send_msg(ss->conn, "250 Requested file action okay, completed.\r\n");
		FindClose(ss->handle);
		ss->handle = INVALID_HANDLE_VALUE;
	Finally:
		close_conn(ss->sdt); ss->sdt = 0;
		crFinish;
}

CMD(DELE)
{
	char utf8[2 * MAX_PATH];
	wchar_t path[MAX_PATH];

	ChkExit(ImpersonateLoggedOnUser(ss->phToken));
	makePath(ss, path, utf8);
	if(DeleteFile(path)){
		send_msg(ss->conn, "257 \"%s\" file deleted.\r\n", utf8);
	}else{
		send_msg(ss->conn, "550 \"%s\" file wasn't deleted.\r\n", utf8);
	}
	RevertToSelf();
}

CMD(RMD)
{
	char utf8[2 * MAX_PATH];
	wchar_t path[MAX_PATH];

	ChkExit(ImpersonateLoggedOnUser(ss->phToken));
	makePath(ss, path, utf8);
	if(0 == _wrmdir(path)){
		send_msg(ss->conn, "257 \"%s\" directory created.\r\n", utf8);
	}else{
		send_msg(ss->conn, "550 \"%s\" directory wasn't created.\r\n", utf8);
	}
	RevertToSelf();
}

CMD(MKD)
{
	char utf8[2 * MAX_PATH];
	wchar_t path[MAX_PATH];

	ChkExit(ImpersonateLoggedOnUser(ss->phToken));
	makePath(ss, path, utf8);
	if(-1 != _wmkdir(path)){
		send_msg(ss->conn, "250 \"%s\" directory created.\r\n", utf8);
	}else{
		send_msg(ss->conn, "550 \"%s\" directory wasn't created.\r\n", utf8);
	}
	RevertToSelf();
}

CMD(PWD)
{
	char utf8[MAX_PATH], *pu;
	/*GetCurrentDirectory(MAX_PATH, ss->file_name);*/
	ChkExit(WideCharToMultiByte(CP_UTF8, 0, ss->sCurrPath, -1, utf8, sizeof utf8, 0, 0));
	for (pu = utf8; *pu; ++pu){
		if ('\\' == *pu){
			*pu = '/';
		}
	}
	send_msg(ss->conn, "257 \"%s\" is current directory.\r\n", utf8);
}

CMD(CWD)
{
	char utf8[2 * MAX_PATH];
	wchar_t path[MAX_PATH];

	makePath(ss, path, utf8);
	if (FILE_ATTRIBUTE_DIRECTORY & GetFileAttributes(path)){
		wchar_t *p;
		for (p = path; *p; ++p){
			if (L'/' == *p){
				*p = L'\\';
			}
		}
		if (L'\\' != path[wcslen(path)-1])
			wcscat(path, L"\\");
		wcscpy(ss->sCurrPath, path);
		send_msg(ss->conn, "250 CWD successful. \"%s\" is current directory.\r\n", utf8);
	}
	else{
		send_msg(ss->conn, "550 CWD : It is not directory.\r\n");
	}
}
CMD(CDUP)
{
	char utf8[MAX_PATH]; /*WCHAR path[MAX_PATH];*/
	size_t len = wcslen(ss->sCurrPath);
	WCHAR *pwc=wcsrchr(ss->sCurrPath, L'\\');
	if (NULL == pwc)
	{
	}
	else {
		if(ss->sCurrPath + len-1 == pwc){
			*pwc = 0;
			pwc=wcsrchr(ss->sCurrPath, L'\\');
		}
		if (NULL == pwc)
		{
		}
		else if (ss->sCurrPath == pwc){
			*(pwc+1) = 0;
		}
		else {
			*pwc = 0;
		}
	}
	
	ChkExit(WideCharToMultiByte(CP_UTF8, 0, ss->sCurrPath, -1, utf8, sizeof utf8, 0, 0));
	{
		char *pu;
		for (pu = utf8; *pu; ++pu){
			if ('\\' == *pu){
				*pu = '/';
			}
		}
	}
	send_msg(ss->conn, "200 Command okay.\r\n");
}
CMD(PASV)	/* PASV <CRLF> */
{
	/*crBegin;*/
	{
		struct sockaddr_in name, peer, sess;
		int namelen = sizeof name;
		int sesslen = sizeof sess;
		int peerlen = sizeof peer;
		ChkExit(!getsockname(ss->conn->ox.fd, (SOCKADDR*)&sess, &sesslen));
		ChkExit(!getpeername(ss->conn->ox.fd, (SOCKADDR*)&peer, &peerlen));
		PrepareNextAcceptEx(&ss->ovAcc);
		ChkExit(!getsockname(ss->ovAcc.fd, (SOCKADDR*)&name, &namelen));
		getAccept(ss->conn, peer.sin_addr, name.sin_port);
		send_msg(ss->conn, "227 Entering passive mode (%u,%u,%u,%u,%u,%u).\r\n"
			, sess.sin_addr.s_net, sess.sin_addr.s_host, sess.sin_addr.s_lh, sess.sin_addr.s_impno
			, name.sin_port & 0xff, name.sin_port >> 8);
		/*, port & 0xff, port >> 8);*/
	}
	/*crReturn;
	crFinish;*/
}
CMD(SIZE)
{
	struct _stat64 stat = { 0 };
	char utf8[2 * MAX_PATH];
	wchar_t path[MAX_PATH];

	makePath(ss, path, utf8);
	if(!_wstati64(path, &stat))
		send_msg(ss->conn, "213 %llu\r\n", stat.st_size);
	else
		send_msg(ss->conn, "550 File not found\r\n");
}
CMD(SYST)
{
	send_msg(ss->conn, "215 WINDOWS-NT-5.1\r\n");
}
CMD(OPTS)
{
	if (!_strcmpi("UTF8 ON", ss->u8opts)){
		send_msg(ss->conn, "202 UTF8 mode is always enabled. No need to send this command.\r\n");
	}
	else{
		send_msg(ss->conn, "504 Command not implemented for that parameter.\r\n");
	}
}
CMD(TYPE)
{
	if (!_strcmpi("I", ss->u8opts)){
		send_msg(ss->conn, "200 Type set to I\r\n");
	}
	else if (!_strcmpi("A", ss->u8opts)){
		send_msg(ss->conn, "200 Type set to I\r\n");
	}
	else{
		send_msg(ss->conn, "504 Command not implemented for that parameter.\r\n");
	}
}

CMD(CLNT)
{
	int i = sizeof clients/sizeof clients[0];
	while (--i){
		if (strstr(ss->u8opts, clients[i].sClient)){
			ss->clnt = clients[i].clnt;
		}
	}
	send_msg(ss->conn, "200 Command okay.\r\n");
}

CMD(NOOP)
{
	send_msg(ss->conn, "200 Command okay.\r\n");
}

CMD(QUIT)
{
	close_conn(ss->sdt); ss->sdt = 0;
	/*close_conn(ss->conn);*/
	CloseHandle(ss->phToken);
}
CMD(USER)	/* USER <SP> <username> <CRLF> */
{
	if (0 == strcmp("anonymous", ss->u8opts)){
		PSID psid;
		wchar_t RefDomainName[64];
		SID_NAME_USE sidNameUse;
		DWORD cchName = sizeof ss->_user / sizeof ss->_user[0],
			cchRefDomainName = sizeof RefDomainName / sizeof RefDomainName[0];

		ChkExit(ConvertStringSidToSidW(L"S-1-5-7", &psid));
		ChkExit(LookupAccountSidW(NULL, psid, ss->_user, &cchName
			, RefDomainName, &cchRefDomainName, &sidNameUse));
		RefDomainName[63] = RefDomainName[63];
	}
	else{
		ChkExit(MultiByteToWideChar(CP_UTF8, 0, ss->u8opts, -1, ss->_user, sizeof ss->_user / sizeof ss->_user[0]));
	}
	if(LogonUser(ss->_user, 0, 0,
		LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &ss->phToken))
	{
		send_msg(ss->conn, "230 Login successful.\r\n");
	}
	else{
		ChkExit(ERROR_LOGON_FAILURE == GetLastError());
		send_msg(ss->conn, "331 Password required.\r\n");
	}
}
CMD(PASS)	/* PASS <SP> <password> <CRLF> */
{
	USE_CONVERSION_U2W;
	if (LogonUser(ss->_user, 0, u2w(ss->u8opts),
		LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &ss->phToken))
		/*
		SECURITY_ANONYMOUS_LOGON_RID
		S-1-5-7
*/
	{
		send_msg(ss->conn, "230 Login successful.\r\n");
	}
	else{
		ChkExit(ERROR_LOGON_FAILURE == GetLastError());
		send_msg(ss->conn, "331 Password required.\r\n");
	}
}

#undef CMD
#define CMD(A) #A
#define DOER(A) ftpdCmnd_##A

void handler(Session *ss)
{
	typedef void(*FtpdDoerT)(Session *);
	static const struct {
		CmndT _cmnd;
		const char *cmnd_;
		FtpdDoerT hndl_;
		unsigned int m_flags; /* bit0=NeedCheckLogin */
	} CmndTable[] = {
		{ enUSER, CMD(USER), DOER(USER),	0 },	/* USER <SP> <username> <CRLF> */
		{ enPASS, CMD(PASS), DOER(PASS),	0 },	/* PASS <SP> <password> <CRLF> */
		{ enSYST, CMD(SYST), DOER(SYST),	1 },	/* SYST <CRLF> */
		{ enTYPE, CMD(TYPE), DOER(TYPE),	1 },	/* TYPE <SP> <type-code> <CRLF> */
#if 0L /* TODO */
		{ enMODE, CMD(MODE), DOER(MODE),	1 },	/* MODE <SP> <mode-code> <CRLF> */
		{ enABOR, CMD(ABOR), DOER(ABOR),	1 },	/* ABOR <CRLF> */
#endif
		{ enQUIT, CMD(QUIT), DOER(QUIT),	0 },	/* QUIT <CRLF> */
		{ enNOOP, CMD(NOOP), DOER(NOOP),	1 },	/* NOOP <CRLF> */
#if 0L /* TODO */
		{ enPORT, CMD(PORT), DOER(PORT),	1 },	/* PORT <SP> <host-port> <CRLF> */
		{ enEPRT, CMD(EPRT), DOER(EPRT),	1 },	/* EPRT <SP> <d> <net-prt> <d> <net-addr> <d> <tcp-port> <d> <CRLF> */
#endif
		{ enPWD,  CMD(PWD),  DOER(PWD), 	1 },	/* PWD  <CRLF> */
		{ enCWD,  CMD(CWD),  DOER(CWD),		1 },	/* CWD  <SP> <pathname> <CRLF> */
		{ enCDUP, CMD(CDUP), DOER(CDUP),	1 },	/* CDUP <CRLF> */
		{ enXCUP, CMD(XCUP), DOER(CDUP),	1 },	/* XCUP <CRLF> */
		{ enRMD,  CMD(RMD),	 DOER(RMD), 	1 },	/* RMD  <SP> <pathname> <CRLF> */
		{ enXRMD, CMD(XRMD), DOER(RMD),		1 },	/* XRMD <SP> <pathname> <CRLF> */
		{ enMKD,  CMD(MKD),  DOER(MKD), 	1 },	/* MKD  <SP> <pathname> <CRLF> */
		{ enXMKD, CMD(XMKD), DOER(MKD),   1 },	/* XMKD <SP> <pathname> <CRLF> */
		{ enDELE, CMD(DELE), DOER(DELE),	1 },	/* DELE <SP> <pathname> <CRLF> */
		{ enPASV, CMD(PASV), DOER(PASV),	1 },	/* PASV <CRLF> */
#if 0
		{ enEPSV, CMD(EPSV), DOER(EPSV),	1 },	/* EPSV <SP> <net-prt> <CRLF> OR EPSV <SP> ALL <CRLF> */
		{ enLPSV, CMD(LPSV), DOER(LPSV),	1 },	/* LPSV ??? */
#endif
		{ enLIST, CMD(LIST), DOER(LIST),	1 },	/* LIST [<SP> <pathname>] <CRLF> */
#if 0
		{ enNLST, CMD(NLST), DOER(NLST),	1 },	/* NLST [<SP> <pathname>] <CRLF> */
		{ enACCT, CMD(ACCT), DOER(ACCT),	1 },	/* ACCT <SP> <account-information> <CRLF> */
#endif
		{ enSIZE, CMD(SIZE), DOER(SIZE),  1 },	/* SIZE <SP> <pathname> <CRLF> */
#if 0
		{ enSTRU, CMD(STRU), DOER(STRU),	1 },	/* STRU <SP> <structure-code> <CRLF> */
		{ enRNFR, CMD(RNFR), DOER(RNFR),	1 },	/* RNFR <SP> <pathname> <CRLF> */
		{ enRNTO, CMD(RNTO), DOER(RNTO),	1 },	/* RNTO <SP> <pathname> <CRLF> */
#endif
		{ enRETR, CMD(RETR), DOER(RETR),	1 },	/* RETR <SP> <pathname> <CRLF> */
		{ enSTOR, CMD(STOR), DOER(STOR),	1 },	/* STOR <SP> <pathname> <CRLF> */
#if 0
		{ enAPPE, CMD(APPE), DOER(APPE),	1 },	/* APPE <SP> <pathname> <CRLF> */
		{ enREST, CMD(REST), DOER(REST),	1 },	/* REST <SP> <marker> <CRLF> */
		{ enMDTM, CMD(MDTM), DOER(MDTM),	1 },	/* MDTM <SP> <pathname> <CRLF> */
#endif
		{ enOPTS, CMD(OPTS), DOER(OPTS),	1 },	/* OPTS <SP> <option> <value> <CRLF> */
#if 0
		{ enSITE, CMD(SITE), DOER(SITE),	1 },	/* SITE <SP> <string> <CRLF> */
		{ enHELP, CMD(HELP), DOER(HELP),	1 },	/* HELP [<SP> <string>] <CRLF> */
		{ enSMNT, CMD(SMNT), DOER(SMNT),	1 },	/* SMNT <SP> <pathname> <CRLF> */
		{ enREIN, CMD(REIN), DOER(REIN),	1 },	/* REIN <CRLF> */
		{ enSTOU, CMD(STOU), DOER(STOU),	1 },	/* STOU <CRLF> */
		{ enSTAT, CMD(STAT), DOER(STAT),	1 },	/* STAT [<SP> <pathname>] <CRLF> */
		{ enALLO, CMD(ALLO), DOER(ALLO),	1 },	/* ALLO <SP> <decimal-integer> [<SP> R <SP> <decimal-integer>] <CRLF> */
#endif
		{ enCLNT, CMD(CLNT), DOER(CLNT),  1 },	/* HELP [<SP> <string>] <CRLF> */
		{ enNotCmnd, (const char *)0, (FtpdDoerT)0, 0 }
	};

	if (!ss->state)
	{
		int iCmnd = 0;
		for (; CmndTable[iCmnd].cmnd_ != ((const char *)0); ++iCmnd) {
			if (strcmp(ss->cmnd_, CmndTable[iCmnd].cmnd_) == 0)
			{
				ss->iCmnd = iCmnd;
				goto DoCommand;
			}
		}
		send_msg(ss->conn, "500 %s not understood\r\n", ss->cmnd_);
		print_info("Command '%s' with parameters '%s' has not implemented.\n",
			ss->cmnd_, ss->u8opts);
		goto done;
	}
	DoCommand:
	CmndTable[ss->iCmnd].hndl_(ss);

	if (ss->state){
		print_debug("command '%s' line '%d'",
			ss->cmnd_, ss->state);
		return;
	}
	print_info("command '%s' with parameters '%s' done.\n",
		ss->cmnd_, ss->u8opts);
	done:
	ss->cmnd_[0] = '\0';
	ss->u8opts[0] = '\0';
}
