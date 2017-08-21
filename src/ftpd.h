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

#define USE_CONVERSION_W2U char u8_170702[512]
#define USE_CONVERSION_U2W WCHAR w_170702[260]
#define u2w(u) (MultiByteToWideChar(CP_UTF8, 0, u, -1, w_170702, (sizeof w_170702 / sizeof w_170702[0])),w_170702)
#define w2u(w) (WideCharToMultiByte(CP_UTF8, 0, w, -1, u8_170702, (sizeof u8_170702 / sizeof u8_170702[0]),0,0),u8_170702)
