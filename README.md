# cppsock
a low-level implementation for POSIX sockets in C++ for windows and linux

## building
1. clone this repository
2. * For Windows: run ``build_win.bat`` as it currently is the best way to build for windows
   * For Cygwin and Linux: run ``make full`` to build the library
3. The header file is ``cppsock.hpp`` and the library file is ``out/libcppsock.a``
   To verify functionality, run ```cppsock_test``` or ```cppsock_test.exe``` to run the test program. The test program should output something like this at the end to indicate successful execution:
      
       =================================================
       cppsock test completed successfully

   Please note that you need the WSA dll in Windows. this can be done by linking the file ``cppsock_winonly.cpp`` and ``-lws3_32`` to the final program
