# cppsock
a low-level implementation for POSIX sockets in C++ for windows and linux

## building
1. clone this repository
2. * For Windows: run ``build_win.bat`` as it currently is the best way to build for windows
   * For Cygwin and Linux: run ``make full`` to build the library
3. The header file is ``cppsock.hpp`` and the library file is ``out/libcppsock.a``
   To verify functionality, run ```cppsock_test``` (linux) or ```cppsock_test.exe``` (windows) to run the test program. The test program should output something like this at the end to indicate successful execution:

       =================================================
       cppsock test completed successfully

   Please note that you need the WSA library in Windows. This can be done by linking the library ``-lws2_32`` (provided by windows) to the final program
