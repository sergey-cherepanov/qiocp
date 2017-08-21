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
#include <windows.h>
#include "oelog.h"

HANDLE hConsole = 0, hConErr = 0;
int print_log(WORD clr, const char *format, ...)
{
	int ret;
	va_list ap;
	va_start(ap, format);
	if (!hConsole) hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, clr);
	ret = vfprintf(stdout, format, ap);
	SetConsoleTextAttribute(hConsole, COLOR_NONE);
	fflush(stdout);
	va_end(ap);
	return ret;
}
