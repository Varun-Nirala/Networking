#ifndef __BUFFER007_H__
#define __BUFFER007_H__

#include <memory>
#include <string>

#include "logger.h"

namespace nsCpp_DS { namespace ns_Buffer
{
template<typename T = char>
class Buffer
{
	using DataType = T;
public:
	Buffer() = default;
	~Buffer() = default;

	Buffer(const Buffer& other);
	Buffer& operator=(const Buffer& other);

	Buffer(Buffer&& other) noexcept;
	Buffer& operator=(Buffer&& other) noexcept;

	//template < typename = typename std::enable_if< std::is_same<DataType, char>::value >::type >

	template <typename Type = DataType, std::enable_if_t<std::is_same_v<Type, char>, bool> = true >
	inline operator std::string() { return std::string(m_pBuf.get()); }

	//template < typename = typename std::enable_if< std::is_same<DataType, wchar_t>::value >::type >
	template <typename Type = DataType, std::enable_if_t<std::is_same_v<Type, wchar_t>, bool> = true >
	inline operator std::wstring() { return std::wstring(m_pBuf.get()); }

	inline DataType& operator[](size_t id) { return m_pBuf[id]; }
	inline const DataType& operator[](size_t id) const { return m_pBuf[id]; }

	inline DataType* get() { return m_pBuf.get(); }
	inline const DataType* get() const { return m_pBuf.get(); }
	inline const size_t size() const { return m_size; }
	inline bool init(size_t s) { clear(); m_size = s; m_pBuf = std::make_unique<DataType[]>(m_size); return m_pBuf != nullptr; }
	inline void clear() { m_size = 0; m_pBuf.reset(nullptr); }
	inline bool empty() const { return m_size == 0; }
private:
	Buffer* copyHelper(const Buffer& other);

private:
	std::unique_ptr<DataType[]>			m_pBuf;
	size_t								m_size{};
};

template<typename T>
Buffer<T>::Buffer(const Buffer<T>& other)
{
	copyHelper(other);
}

template<typename T>
Buffer<T>& Buffer<T>::operator=(const Buffer<T>& other)
{
	if (this != &other)
	{
		clear();
		copyHelper(other);
	}
	return *this;
}

template<typename T>
Buffer<T>::Buffer(Buffer<T>&& other) noexcept
{
	m_pBuf = std::exchange(other.m_pBuf, nullptr);
	m_size = std::exchange(other.m_size, 0);
}

template<typename T>
Buffer<T>& Buffer<T>::operator=(Buffer<T>&& other) noexcept
{
	if (this != &other)
	{
		m_pBuf = std::exchange(other.m_pBuf, nullptr);
		m_size = std::exchange(other.m_size, 0);
	}
	return *this;
}

template<typename T>
Buffer<T>* Buffer<T>::copyHelper(const Buffer<T>& other)
{
	if (init(other.m_size))
	{
		std::memcpy(m_pBuf.get(), other.m_pBuf.get(), m_size);
	}
	return this;
}


static void test_1()
{
	const char* testName = "Char Buffer.";
	ns_Util::Logger::LOG_MSG("Executing Test 1 : ", testName, "\n\n");

	std::string str{ "Hello how are you???" };
	Buffer buff;
	buff.init(str.size() + 1);
	for (size_t i = 0, size = str.size(); i < size; ++i)
	{
		buff[i] = str[i];
	}
	buff[str.size()] = '\0';
	ns_Util::Logger::LOG_MSG("String[", str.size(), "] : ", str, '\n');
	ns_Util::Logger::LOG_MSG("Buffer[", buff.size(), "] : ", buff.get(), '\n');
	ns_Util::Logger::LOG_MSG("\n\n");
}

static void test_2()
{
	const char* testName = "WChar Buffer.";
	ns_Util::Logger::LOG_MSG("Executing Test 1 : ", testName, "\n\n");

	std::wstring str{ L"Hello how are you???" };
	Buffer<wchar_t> buff;
	buff.init(str.size() + 1);
	for (size_t i = 0, size = str.size(); i < size; ++i)
	{
		buff[i] = str[i];
	}
	buff[str.size()] = '\0';
	ns_Util::Logger::LOG_MSG("String[", str.size(), "] : ", str, '\n');
	ns_Util::Logger::LOG_MSG("Buffer[", buff.size(), "] : ", buff.get(), '\n');
	ns_Util::Logger::LOG_MSG("\n\n");
}

void test_Buffer()
{
	test_1();
	test_2();
	ns_Util::Logger::LOG_MSG("#####################################\n");
}
}}	 // namespace ns_Buffer // namespace nsCpp_DS
#endif //#ifndef __BUFFER007_H__