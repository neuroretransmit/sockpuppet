#include "sockpuppet/blocking.h"

int main(int argc, char** argv)
{
    if (argc != 2) {
        cerr << "ERROR: Must provide port number.\n";
        exit(1);
    }

    int port = atoi(argv[1]);
    sockpuppet::blocking s(port);
    s.start();
}
