#ifndef __HELPER_H__
#define __HELPER_H__

#include <cmath>
#include <chrono>
#include <iostream>
#include <string>
#include <type_traits>

namespace nsNW
{
class Logger
{
public:
#ifdef DEBUG
    template<typename T>
    static inline void LOG_INFO(T last) { std::cerr << last ; }

    template<typename T>
    static inline void LOG_ERROR(T last) { std::cerr << last ; }

    template<typename T, typename ... Args>
    static inline void LOG_INFO(T first, Args ... args)
    {
        std::cerr << first << " ";
        LOG_INFO(args ...);
    }

    template<typename T, typename ... Args>
    static inline void LOG_ERROR(T first, Args ... args)
    {
        std::cerr << first << " ";
        LOG_ERROR(args ...);
    }

    template<typename ... Args>
    static inline void LOG_INFO(Args ... args)
    {
        std::cerr << "INFO  : ";
        LOG_INFO(args ...);
    }

    template<typename ... Args>
    static inline void LOG_ERROR(Args ... args)
    {
        std::cerr << "ERROR : ";
        LOG_ERROR(args ...);
    }
#else
    template<typename T>
    static inline void LOG_INFO(T last) { ; }

    template<typename T>
    static inline void LOG_ERROR(T last) { ; }

    template<typename T, typename ... Args>
    static inline void LOG_INFO(T first, Args ... args) { ; }

    template<typename T, typename ... Args>
    static inline void LOG_ERROR(T first, Args ... args) { ; }
#endif

    template<typename T>
    static inline void LOG_MSG(T last) { std::cerr << last ; }

    template<typename T, typename ... Args>
    static inline void LOG_MSG(T first, Args ... args)
    {
        std::cerr << first << " ";
        LOG_MSG(args ...);
    }
};

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
        Logger::LOG_MSG(msg, std::to_string(getElapsedMS().count()), " ms.");
    }
private:
    std::chrono::high_resolution_clock::time_point     m_start;
};
}   // namespace nsNW
#endif // #ifndef __HELPER_H__