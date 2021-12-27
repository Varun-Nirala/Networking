#ifndef __HELPER_H__
#define __HELPER_H__

#include <cmath>
#include <chrono>
#include <iostream>
#include <string>
#include <type_traits>

#include "logger.h"

namespace nsNW
{
using Logger = nsUtil::Logger;

class Timer
{
public:
    inline void start() { m_start = std::chrono::high_resolution_clock::now(); }

    inline std::chrono::milliseconds getElapsedMS()
    { 
        const auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(end - m_start);
    }

    inline std::chrono::seconds getElapsedS()
    {
        const auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(end - m_start);
    }

    inline void print(std::string msg)
    {
        Logger::LOG_MSG(msg, std::to_string(getElapsedMS().count()), " ms.");
    }
private:
    std::chrono::high_resolution_clock::time_point     m_start;
};
}   // namespace nsNW
#endif // #ifndef __HELPER_H__