qiocp
=====

# Description

qiocp is a windows ftp server sample to perform asynchronous operations in synchronous manner. It bases on coroutine macros. This significantly simplifies the writing of network applications or other nontrivial concurrent algorithms. This sample demonstrates how using the coroutines allows to achieve described simplifications. The code itself looks like synchronous invocations while internally it uses asynchronous scheduling.

## Features

1. Only one thread. You can use different pools for different purposes.
2. No mutexs. No synchronization.
3. Basic network support.
4. UTF-8 messages. Please, set Lucida Console font in console properties.
5. Passive mode only.

Some of the ideas was inspired by fashion on coroutine implemention in future c++.

# Requirements

* Supported compilers:
    * GCC (MinGW)
    * MSVC 

MinGW version runs faster.

#References
Stackless coroutine macro idea is described in http://www.chiark.greenend.org.uk/~sgtatham/coroutines.html