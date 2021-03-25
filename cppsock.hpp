/**
 * @file cppsock.hpp
 * @author PrugClem 
 * @brief Main header file for the header-based cppsock library
 * @version 0.1
 * @date 2021-03-04
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#pragma once

// std include files
#include <functional>
#include <iostream>
#include <string.h>
#include <sstream>
#include <atomic>
#include <memory>
#include <cerrno>
#include <string>
#include <vector>
#include <map>

// mingw-compatiblity
#ifdef CPPSOCK_MINGW_IMPLEMENTATION
    #include <mingw.stdthread.h>
    #include <mingw.condition_variable.h>
#else
    #include <thread>
    #include <condition_variable>
#endif

#if defined __linux__ || defined __CYGWIN__

// linux include files
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>

// library definitions for platform independence
using socket_t = int;
constexpr socket_t INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
inline int closesocket(socket_t s){return close(s);}
inline int ioctlsocket(socket_t s, long cmd, void *argp) {return ioctl(s, cmd, argp);}

// this is needed because windows does not set errno
// however in linux nothing has to be done
#define __set_errno_from_WSA(){}
#define __is_error(s) (s < 0)

#elif defined _WIN32

// Windows use newer versions
#undef WINVER
#define WINVER 0x0A00
#undef _WIN32_WINNT
#define _WIN32_WINNT 0xA00

// windows define constants with linux name
#define SHUT_RDWR SD_BOTH
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND

// Windows include files
#include <winsock2.h>
#include <ws2tcpip.h>

// windows define missing types
using sa_family_t = unsigned short;
using in_port_t = uint16_t;
using socket_t = SOCKET;
using error_t = int;

// this is needed because windows does not set errno
#define __set_errno_from_WSA() {errno = WSAGetLastError();}
#define __is_error(s) (s == SOCKET_ERROR)

class __wsa_loader_class
{
    WSADATA wsaData;
    int iResult;
public:
    inline __wsa_loader_class(){
        // Initialize Winsock
        iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
        if (iResult != 0) {
            printf("WSAStartup failed with error: %d\n", iResult);
            exit(1);
        }
    }
    inline ~__wsa_loader_class(){
         WSACleanup();
    }
};
inline __wsa_loader_class __wsa_loader_instance;

#pragma comment(lib, "ws2_32.lib")

#else // else if defined _WIN32
#error unsupported OS used
#endif

#include "cppsock_types.hpp"
#include "cppsock_socketaddr.hpp"
#include "cppsock_addressinfo.hpp"
#include "cppsock_socket.hpp"
#include "cppsock_utility.hpp"
#include "cppsock_tcp_socket.hpp"
#include "cppsock_tcp_listener.hpp"
#include "cppsock_tcp_client.hpp"
#include "cppsock_udp_socket.hpp"
#include "cppsock_tcp_socket_collection.hpp"
#include "cppsock_tcp_server.hpp"
