#ifndef __LOGGER007_H__
#define __LOGGER007_H__

#include <iostream>

namespace nsUtil
{
class Logger
{
public:
#ifndef DEBUG
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
}

#endif //#ifndef __LOGGER007_H__