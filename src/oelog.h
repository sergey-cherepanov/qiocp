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

#ifndef LOG_H_
#define LOG_H_
#include <stdarg.h>
#include <errno.h>

extern SERVICE_STATUS_HANDLE serviceStatusHandle;
#define LOGFILE "C:\\memstatus.txt"

#define ChkRet(func,...) do{ \
if (!(func)){ \
	LPWSTR sErr = NULL; \
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
	NULL, errno, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPWSTR)&sErr, 0, NULL); \
	print_error("func "#func" returns fatal error %d '%S' in %s line %d func %s \n" \
	, errno, sErr, __FILE__, __LINE__, __FUNCTION__); \
	LocalFree(sErr); \
	 {__VA_ARGS__; } \
}} while (0)

#define p_xx(i1,i2) {print_info("%s "#i1"=%p "#i2"=%p\n",__FUNCTION__,(void*)(i1),(void*)(i2));}

int print_log(unsigned short color, const char *format, ...);

#define LOG_DEBUG 3
#define LOG_MSG   2
#define LOG_WARN  1
#define LOG_ERR   0

#if LOG_LEVEL < LOG_DEBUG
#define print_debug(format,...)
#else
#define print_debug(format,...) print_log(COLOR_DEBUG, format, __VA_ARGS__)
#endif

#if LOG_LEVEL < LOG_MSG
#define print_info(format,...)
#else
#define print_info(format,...) print_log(COLOR_INFO, format, __VA_ARGS__)
#endif

#if LOG_LEVEL < LOG_WARN
#define print_warning(format,...)
#else
#define print_warning(format,...) print_log(COLOR_WARNING, format, __VA_ARGS__)
#endif

#if LOG_LEVEL < LOG_ERR
#define print_error(format,...)
#else
#define print_error(format,...) print_log(COLOR_ERROR, format, __VA_ARGS__)
#endif

#define COLOR_NONE 7
#define COLOR_ERROR 12
#define COLOR_WARNING 14
#define COLOR_INFO 11
#define COLOR_DEBUG 10

void printLastErr(char* file, char* func, int line, char* expr);

#endif                          /* LOG_H_ */
