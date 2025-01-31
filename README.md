# sockpuppet

Header only C++ implementation of encrypted non-blocking socket communication over TCP/IP using [RC6-GCM-SIV](https://gitlab.com/optimisticninja/rc6) for encryption/protobuf for messages. 

In progress:

* Node roles
	* Recon
		- SYN scan other targets
		- Read ARP cache from executing node
		- Sniff packets with libpcap
		- Identify host OS/versions of running services
	* Proxy
		- Passthrough Protobuf message with onion encryption
		- Become a SOCKS5 proxy
	* Command
		- Orchestrator of other node roles including command (need at least 1 to horizontally scale and be redundant)

## Features

* TCP/IP sockets encrypted with [RC6-GCM-SIV](https://gitlab.com/optimisticninja/rc6)
* Protobuf for messaging

## Packet Layout

```
Packet {
    Header {
        unsigned little endian 4-byte integer for message size
    }
    
    Encrypted Body {
        unsigned little endian 4-byte integer for protobuf size
        protobuf message
    }
}
```

## Usage

### Documentation

Doxygen generated files are in [`doc/latex`](doc/latex) and [`doc/html`](doc/html).

### TODO: Handshake via SIDH

Secure TCP/IP socket communications with post-quantum handshake negotiation.

#### Server (Non-Blocking)

```cpp
#include <sockpuppet/server.h>

int main()
{
    sockpuppet::server serv(31337);
    serv.start(); // or s.start_detached() to run in background
    
    // and execute code down here
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

#### TODO: Recon

Describe creating a recon node.

## Building/Installation

### Requirements

* CMake >= 3.13
* Protobuf
* GTest
* GMock
* libpcap
* GMP
* My [log](https://gitlab.com/optimisticninja/log) and [rc6-gcm-siv](https://gitlab.com/optimisticninja/rc6) implementation.

### The Build

First, install my [log](https://gitlab.com/optimisticninja/log) and [rc6-gcm-siv](https://gitlab.com/optimisticninja/rc6) headers.

Then:

```bash
$ mkdir build && cd build # Create and move into build directory
$ cmake ..                # Configure
$ make                    # Build
$ sudo make install       # Install headers
```

The headers are now in `/usr/local/include/sockpuppet`.

### Uninstall

```bash
$ sudo rm -rf /usr/local/include/sockpuppet
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
