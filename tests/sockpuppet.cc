#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "sockpuppet/client.h"
#include "sockpuppet/server.h"

using namespace ::testing;

TEST(SockPuppet, ClientToServerExit)
{
    // Send exit command to terminate server
    Request request;
    request.set_type(EXIT);
    request.set_id("TEST");
    request.set_origin("127.0.0.1");

    // Start in detached mode so below code can run
    server serv(31337);
    serv.start_detached();

    client c(31337);
    c.send_request(request);

    // Wait for shutdown
    serv.wait();

    ASSERT_TRUE(serv.is_stopped());
}

TEST(SockPuppet, StopDetached)
{
    // Start in detached mode so below code can run
    server serv(31338);
    serv.start_detached();
    serv.stop();

    ASSERT_TRUE(serv.is_stopped());
}
