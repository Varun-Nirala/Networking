#ifndef __BUFFER007_H__
#define __BUFFER007_H__

#include <memory>

namespace nsUtil
{
class Buffer
{
public:
	Buffer() = default;
	~Buffer() = default;

	Buffer(const Buffer&) = delete;
	Buffer& operator=(const Buffer& other) = delete;

	Buffer(Buffer&& other) noexcept { m_pBuf = std::exchange(other.m_pBuf, nullptr); m_size = std::exchange(other.m_size, 0); }
	
	Buffer& operator=(Buffer&& other) noexcept
	{
		if (this != &other)
		{
			m_pBuf.reset(nullptr);
			m_pBuf = std::exchange(other.m_pBuf, nullptr);
			m_size = std::exchange(other.m_size, 0);
		}
		return *this;
	}

	char& operator[](size_t id) { return m_pBuf[id]; }
	const char& operator[](size_t id) const { return m_pBuf[id]; }

	char* get() { return m_pBuf.get(); }
	const size_t size() const { return m_size; }
	inline bool init(size_t s) { clear(); m_size = s; m_pBuf = std::make_unique<char[]>(m_size); return m_pBuf != nullptr; }
	inline void clear() { m_size = 0; m_pBuf.reset(nullptr); }
	inline bool empty() const { return m_size == 0; }

private:
	std::unique_ptr<char[]>				m_pBuf;
	size_t								m_size{};
};
}

#endif //#ifndef __BUFFER007_H__