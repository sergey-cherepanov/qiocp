cmake_minimum_required(VERSION 2.8)	 

project(qiocp)

file(GLOB QIOCP_SRC src/*)
add_definitions(-D_UNICODE)
add_definitions(-DUNICODE)
add_definitions(-DLOG_LEVEL=3)
set(SOURCE_EXE ftpdmain.c ftpd.c networking.c oelog.c service.c security.c)
if(MINGW)
	set(CMAKE_EXE_LINKER_FLAGS "-municode")
endif()
add_executable(qiocp ${QIOCP_SRC})

target_link_libraries(qiocp ws2_32)