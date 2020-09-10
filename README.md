# sockpuppet

Header only C++ implementation of encrypted socket communication over TCP/IP using [RC6-GCM-SIV](https://gitlab.com/optimisticninja/rc6) using protobuf for messages.

## Features

* TCP/IP sockets encrypted with [RC6-GCM-SIV](https://gitlab.com/optimisticninja/rc6)
* Protobuf for messaging

## Usage

### Documentation

Doxygen generated files are in [`doc/latex`](doc/latex) and [`doc/html`](doc/html).

### Secure TCP/IP socket communications with custom handshake/port agreement.

#### Server (Blocking)

```cpp
#include <sockpuppet/server.h>

int main()
{
    sockpuppet::blocking server(31337);
    server.start(); // or s.start_detached() to run in background
}
```

#### Client

```cpp
#include <sockpuppet/client.h>

#include "proto/commands.pb.h"

int main()
{
    sockpuppet::client client(31337);
    
    Request request;
    request.set_type(EXIT);
    
    client.send_request(request);
}
```

## Building/Installation

### Requirements

* CMake >= 3.13
* Protobuf
* GTest
* GMock

### The Build

```bash
$ mkdir build && cd build # Create and move into build directory
$ cmake ..                # Configure
$ make                    # Build
$ sudo make install       # Install headers
```

The headers are now in `/usr/local/include/rc6`.

### Uninstall

```bash
$ sudo rm -rf /usr/local/include/rc6
```

## Running (from `build/` folder)

### Tests

Tests run a Google Test suite that test constraints of the paper as well as the test vectors.

```bash
$ ./tests/tests
[==========] Running X tests from Y test suites.
[----------] Global test environment set-up.
[----------] Z tests from SockPuppet
[ RUN      ] ...
[       OK ] ... (0 ms)
...
...
...
[----------] Global test environment tear-down
[==========] X tests from Y test suites ran. (4 ms total)
[  PASSED  ] X tests.

...
[  PASSED  ] X tests.
```

## License

None.
