# cppsock
a simple, low-level, header-only implementation for POSIX sockets in C++ tested under windows and linux

## using the library

To use the library, include the ``cppsock.hpp``. In windows, it is required to link the winsock library. this can be done by adding ``-lws2_32`` to the linker arguments

    Please note that you need the WSA library in Windows. This can be done by linking the library ``-lws2_32`` (provided by windows) to the final program
