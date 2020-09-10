#include "sockpuppet/client.h"

int main(int argc, char** argv)
{
    if (argc != 2) {
        cerr << "ERROR: Must provide port number.\n";
        exit(1);
    }

    Request request;
    request.set_type(EXIT);
    request.set_id("TEST");
    request.set_origin("127.0.0.1");
    
    int port = atoi(argv[1]);
    sockpuppet::client c = sockpuppet::client(port);
    c.send_request(request);
}
