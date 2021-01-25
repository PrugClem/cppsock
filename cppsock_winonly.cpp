/**
 *  author: Clemens Pruggmayer (PrugClem)
 *  date:   2020-12-22
 *  desc:   implementation to load windows' WSA library which is required to use sockets in windows
 */
#if defined _WIN32 || defined __CYGWIN__
// This is needed becuase windows requires initialisation of a dll to run sockets.
// Linux uses systemcalls and does not need such a gross sh*t
#include <winsock2.h>
#include <cstdio>

class __wsa_loader_class
{
    WSADATA wsaData;
    int iResult;
public:
    __wsa_loader_class(){
        // Initialize Winsock
        iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
        if (iResult != 0) {
            printf("WSAStartup failed with error: %d\n", iResult);
            exit(1);
        }
    }
    ~__wsa_loader_class(){
         WSACleanup();
    }
};
static __wsa_loader_class __wsa_loader_instance;
#endif // defined _WIN32
