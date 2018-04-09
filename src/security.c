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

#include "networking.h"
#include "oelog.h"
#include "security.h"
#include "ftpd.h"

void getOwnerGroup(wchar_t *chFileName, char *ownerGrp)
{
	USE_CONVERSION_W2U;
	PSID pSidOwner = NULL;
	PSID pSidGroup = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	BOOL bOwnerDefaulted = FALSE;
	BOOL bGroupDefaulted = FALSE;


	DWORD dwLength = 0;

	CHECK_ERR(GetFileSecurity(
		chFileName,
		GROUP_SECURITY_INFORMATION |
		OWNER_SECURITY_INFORMATION,
		pSD,
		dwLength,
		&dwLength), if (dwLength)break; else if (32 == ierr)return, print_error(" %s\n", w2u(chFileName));  return);

	pSD = (PSECURITY_DESCRIPTOR)malloc(dwLength);

	ChkExit(GetFileSecurity(
		chFileName,      // имя файла
		GROUP_SECURITY_INFORMATION |
		OWNER_SECURITY_INFORMATION,    // информация, которую нужно получить
		pSD,             // адрес буфера для дескриптора безопасности
		dwLength,        // длина буфера
		&dwLength), free(pSD); return);      // необходимая длина

	ChkExit(GetSecurityDescriptorOwner(
		pSD,
		&pSidOwner,
		&bOwnerDefaulted));

	// получаем SD первичной группы владельца объекта
	ChkExit(GetSecurityDescriptorGroup(
		pSD,
		&pSidGroup,
		&bGroupDefaulted));
	{
		wchar_t lpStringSid[64];
		wchar_t RefDomainName[64];
		SID_NAME_USE sidNameUse;
		DWORD cchName = sizeof lpStringSid / sizeof lpStringSid[0],
			cchRefDomainName = sizeof RefDomainName / sizeof RefDomainName[0];

		ChkExit(LookupAccountSidW(NULL, pSidOwner, lpStringSid, &cchName
			, RefDomainName, &cchRefDomainName, &sidNameUse));

		//ChkExit(LookupAccountSid()
		ChkExit(WideCharToMultiByte(CP_UTF8, 0, lpStringSid, -1, ownerGrp, 2 * MAX_PATH, 0, 0));

		strcat(ownerGrp, " ");

		cchName = sizeof lpStringSid / sizeof lpStringSid[0];
		cchRefDomainName = sizeof RefDomainName / sizeof RefDomainName[0];
		CHECK_ERR(LookupAccountSidW(NULL, pSidGroup, lpStringSid, &cchName
			, RefDomainName, &cchRefDomainName, &sidNameUse),
		if (1332 == ierr)
		{ WCHAR* ptr = 0; ConvertSidToStringSid(pSidGroup, &ptr); wcscpy(lpStringSid, ptr); LocalFree(ptr); break; }
		);
		ChkExit(WideCharToMultiByte(CP_UTF8, 0, lpStringSid, -1, ownerGrp + strlen(ownerGrp),
			2 * MAX_PATH - (int)strlen(ownerGrp), 0, 0));
	}
	free(pSD);

}