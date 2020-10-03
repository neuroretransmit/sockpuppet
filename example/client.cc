#include "sockpuppet/client.h"
#include "sockpuppet/util/uuid.h"

int main(int argc, char** argv)
{
    if (argc != 2) {
        cerr << "ERROR: Must provide port number.\n";
        exit(1);
    }

    Request request;
    request.set_type(INFO);
    request.set_id(uuid::gen_v4());
    request.set_origin("zombabie");

    int port = atoi(argv[1]);
    sockpuppet::client c(port);
    c.send_request(request);
}
