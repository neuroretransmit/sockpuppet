#pragma once

#include <cstdio>
#include <unistd.h>

/**
 * Check if UID is 0 for root
 * @return root or not
 */
static inline bool is_root() { return getuid() == 0 ? true : false; }

/**
 * Check if privileged user
 * @return privileged user or not
 */
static inline bool is_privileged_user()
{
    return is_root(); // Placeholder for other privileged types
}
