# cppsock
a (mostly) platform independent low-level implementation for sockets

## building
1. clone this repository
2. * For Windows: run ``build_win.bat`` as it currently is the best way to build for windows
   * For Cygwin and Linux: run ``make lib`` to build the library
3. The header file is ``cppsock.hpp`` and the library file is ``out/libcppsock.a``
   Please note that you need to load the WSA dll in Windows. this can be done by linking the file ``cppsock_winonly.cpp`` to the final program
