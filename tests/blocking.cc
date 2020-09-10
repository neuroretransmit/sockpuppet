#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "sockpuppet/blocking.h"
#include "sockpuppet/client.h"

using namespace ::testing;

TEST(SockPuppet, StopDetached)
{
    // Start in detached mode so below code can run
    sockpuppet::blocking serv(31338);
    serv.start_detached();
    serv.stop();

    ASSERT_TRUE(serv.is_stopped());
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
}
