#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "sockpuppet/blocking.h"
#include "sockpuppet/client.h"

using namespace ::testing;

TEST(SockPuppet, StopDetached)
{
    u16 port = 30000 + (std::rand() % (30000 - 31000 + 1));
    // Start in detached mode so below code can run
    sockpuppet::blocking serv(port);
    serv.start_detached();
    serv.stop();

    ASSERT_TRUE(serv.is_stopped());
}
