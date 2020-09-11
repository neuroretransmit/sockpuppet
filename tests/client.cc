#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "sockpuppet/client.h"
#include "sockpuppet/server.h"

using namespace ::testing;

TEST(SockPuppet, ClientToServerExit)
{
    u16 port = 31000 + (std::rand() % (31000 - 32000 + 1));

    // Send exit command to terminate server
    Request request;
    request.set_type(EXIT);
    request.set_id("TEST");
    request.set_origin("127.0.0.1");

    // Start in detached mode so below code can run
    sockpuppet::server serv(port);
    serv.start_detached();

    sockpuppet::client c(port);
    c.send_request(request);

    // Wait for shutdown
    serv.wait();

    ASSERT_TRUE(serv.is_stopped());
}
