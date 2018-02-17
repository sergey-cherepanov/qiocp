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

	/*SERVICE_TABLE_ENTRY это структура, котора€ описывает точку входа дл€ сервис менеджера, 
	в данном случаи вход будет происходить через ф-цию ServiceMain. 
	‘ункци€ StartServiceCtrlDispatcher собственно св€зывает наш сервис с SCM (Service Control Manager)

“очка входа сервиса

ѕрежде чем описывать ф-цию нам понадобитьс€ две глобальные переменные:
*/
SERVICE_STATUS serviceStatus; 
SERVICE_STATUS_HANDLE serviceStatusHandle;
/*
—труктура SERVICE_STATUS используетс€ дл€ оповещени€ SCM текущего статуса сервиса. 
ќ пол€х и их значени€х детальней можно прочитать на MSDN
*/
WCHAR serviceName[] = L"qiocpFtpd";
void ControlHandler(DWORD request);

void ServiceMain(int argc, char** argv) { 
  int error; 
  int i = 0;

  serviceStatus.dwServiceType    = SERVICE_WIN32_OWN_PROCESS; 
  serviceStatus.dwCurrentState    = SERVICE_START_PENDING; 
  serviceStatus.dwControlsAccepted  = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  serviceStatus.dwWin32ExitCode   = 0; 
  serviceStatus.dwServiceSpecificExitCode = 0; 
  serviceStatus.dwCheckPoint     = 0; 
  serviceStatus.dwWaitHint      = 0; 

	serviceStatusHandle = RegisterServiceCtrlHandler(serviceName, (LPHANDLER_FUNCTION)ControlHandler);
  if (serviceStatusHandle == (SERVICE_STATUS_HANDLE)0) { 
    return; 
  } 

  error = InitService(); 
  if (error) {
    serviceStatus.dwCurrentState    = SERVICE_STOPPED; 
    serviceStatus.dwWin32ExitCode   = -1; 
		(SetServiceStatus(serviceStatusHandle, &serviceStatus));
    return; 
  } 
  
  serviceStatus.dwCurrentState = SERVICE_RUNNING; 
	(SetServiceStatus(serviceStatusHandle, &serviceStatus));

	event_dispatch();

	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	serviceStatus.dwWin32ExitCode = -1;
	(SetServiceStatus(serviceStatusHandle, &serviceStatus));

  return; 
}

/*
Ћогика этой ф-ции проста. —начала регистрируем ф-цию котора€ будет 
обрабатывать управл€ющие запросы от SCM, например, запрос на остановку. 
–егистраци€ производитьс€ при помощи ф-ции RegisterServiceCtrlHandler. 
» при корректном запуске сервиса пишем в файлик значени€ переменой i.
ƒл€ изменени€ статуса сервиса используетс€ ф-ци€ SetServiceStatus.
“еперь опишем ф-цию по обработке запросов:
*/
void ControlHandler(DWORD request) { 
  switch(request) 
  { 
    case SERVICE_CONTROL_STOP: 
		print_info("Stopped.");

      serviceStatus.dwWin32ExitCode = 0; 
      serviceStatus.dwCurrentState = SERVICE_STOPPED; 
      SetServiceStatus (serviceStatusHandle, &serviceStatus);
      return; 

    case SERVICE_CONTROL_SHUTDOWN: 
      print_info("Shutdown.");

      serviceStatus.dwWin32ExitCode = 0; 
      serviceStatus.dwCurrentState = SERVICE_STOPPED; 
      SetServiceStatus (serviceStatusHandle, &serviceStatus);
      return; 
    
    default:
      break;
  } 

  SetServiceStatus (serviceStatusHandle, &serviceStatus);

  return; 
} 

	/*ControlHandler вызываетс€ каждый раз, как SCM шлет запросы на изменени€ состо€ни€ сервиса. ¬ основном ее используют дл€ описани€ корректной завершении работа сервиса.

”становка сервиса

≈сть несколько вариантов, один из них, при помощи утилита sc. ”становка производитьс€ следующей командой:
sc create SampleService binpath= c:\SampleService.exe

”даление сервиса:
sc delete SampleService
*/

/*int wmain(int argc, WCHAR* argv[])*/ 
int wmain(int argc, wchar_t **argv)
{
	if (argc > 1)
	{
		if (0 == wcscmp(L"/console", (wchar_t*)argv[1])){
			void __cdecl getch(void);
			atexit(getch);
			InitService();
			event_dispatch();
			return 0;
		}
		print_error("Usage:\n"
			"To run as console application:\n\t%s noservice\n"
			"To run as windows service:\n\t%s\n","");
		return 1;
	}
	SERVICE_TABLE_ENTRY ServiceTable[1];
	ServiceTable[0].lpServiceName = serviceName;
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	(StartServiceCtrlDispatcher(ServiceTable));
	return 0;
}
/*
ƒанный способ, как по мне, неочень программерский потому опишем установку сервиса в коде. »зменим не много логику ф-ции _tmain:*/
#if 0
int _tmain(int argc, _TCHAR* argv[]) {

  servicePath = LPTSTR(argv[0]);

  if(argc - 1 == 0) {
    SERVICE_TABLE_ENTRY ServiceTable[1];
    ServiceTable[0].lpServiceName = serviceName;
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    if(!StartServiceCtrlDispatcher(ServiceTable)) {
      addLogMessage("Error: StartServiceCtrlDispatcher");
    }
  } else if( wcscmp(argv[argc-1], _T("install")) == 0) {
    InstallService();
  } else if( wcscmp(argv[argc-1], _T("remove")) == 0) {
    RemoveService();
  } else if( wcscmp(argv[argc-1], _T("start")) == 0 ){
    StartService();
  }
}
	/*” нас по€витьс€ теперь еще три ф-ции:*/
int InstallService() { 
  SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if(!hSCManager) {
    addLogMessage("Error: Can't open Service Control Manager");
    return -1;
  }
  
  SC_HANDLE hService = CreateService(
     hSCManager,
     serviceName,
     serviceName,
     SERVICE_ALL_ACCESS,
     SERVICE_WIN32_OWN_PROCESS,
     SERVICE_DEMAND_START,
     SERVICE_ERROR_NORMAL,
     servicePath,
     NULL, NULL, NULL, NULL, NULL
  );

  if(!hService) {
    int err = GetLastError();
    switch(err) {
      case ERROR_ACCESS_DENIED: 
        addLogMessage("Error: ERROR_ACCESS_DENIED");
        break;
      case ERROR_CIRCULAR_DEPENDENCY:
        addLogMessage("Error: ERROR_CIRCULAR_DEPENDENCY");
        break;
      case ERROR_DUPLICATE_SERVICE_NAME:
        addLogMessage("Error: ERROR_DUPLICATE_SERVICE_NAME");
        break;
      case ERROR_INVALID_HANDLE:
        addLogMessage("Error: ERROR_INVALID_HANDLE");
        break;
      case ERROR_INVALID_NAME:
        addLogMessage("Error: ERROR_INVALID_NAME");
        break;
      case ERROR_INVALID_PARAMETER:
        addLogMessage("Error: ERROR_INVALID_PARAMETER");
        break;
      case ERROR_INVALID_SERVICE_ACCOUNT:
        addLogMessage("Error: ERROR_INVALID_SERVICE_ACCOUNT");
        break;
      case ERROR_SERVICE_EXISTS:
        addLogMessage("Error: ERROR_SERVICE_EXISTS");
        break;
      default:
        addLogMessage("Error: Undefined");
    }
    CloseServiceHandle(hSCManager);
    return -1;
  }
  CloseServiceHandle(hService);
  
  CloseServiceHandle(hSCManager);
  addLogMessage("Success install service!");
  return 0;
}

int RemoveService() {
  SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if(!hSCManager) {
     addLogMessage("Error: Can't open Service Control Manager");
     return -1;
  }
  SC_HANDLE hService = OpenService(hSCManager, serviceName, SERVICE_STOP | DELETE);
  if(!hService) {
     addLogMessage("Error: Can't remove service");
     CloseServiceHandle(hSCManager);
     return -1;
  }
  
  DeleteService(hService);
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
  addLogMessage("Success remove service!");
  return 0;
}

int StartService() { 
  SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  SC_HANDLE hService = OpenService(hSCManager, serviceName, SERVICE_START);
  if(!StartService(hService, 0, NULL)) {
    CloseServiceHandle(hSCManager);
    addLogMessage("Error: Can't start service");
    return -1;
  }
  
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
  return 0;
}
#endif