#include <gtest/gtest.h>

#include "sockpuppet/util/privs.h"
#include <log/log.h>

TEST(Privs, IsRoot) { ASSERT_EQ(is_root(), true); }
