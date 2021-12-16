#ifndef __HELPER_H__
#define __HELPER_H__

#include <cmath>
#include <chrono>
#include <iostream>
#include <string>
#include <type_traits>

namespace nsNW
{
#ifdef DEBUG
    #define LOG_ERROR(msg)  std::cerr << "ERROR :: " << __FUNCTION__ << "::" << __LINE__ << ":: " << msg << '\n'
    #define LOG_INFO(msg)  std::cerr << "INFO :: " << __FUNCTION__ << "::" << __LINE__ << ":: " << msg << '\n'
#else
    #define LOG_ERROR(msg)  std::cerr << "ERROR :: " << __FUNCTION__ << "::" << __LINE__ << ":: " << msg << '\n'
    #define LOG_INFO(msg)  ;
#endif

#define PRINT_MSG(msg)  std::cout << msg << '\n'

class Timer
{
public:
    inline void start() { m_start = std::chrono::high_resolution_clock::now(); }

    inline std::chrono::milliseconds getElapsedMS() { 
        const auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(end - m_start);
    }

    inline void print(std::string msg)
    {
        PRINT_MSG(msg + std::to_string(getElapsedMS().count()) + " ms.");
    }
private:
    std::chrono::high_resolution_clock::time_point     m_start;
};
}   // namespace nsNW
#endif // #ifndef __HELPER_H__