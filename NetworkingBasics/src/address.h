#ifndef __ADDRESS_H__
#define __ADDRESS_H__

#include "common.h"

namespace nsNW
{
class Address
{
public:
	Address() = default;
	~Address() { clear(); }

	Address(const Address&) = delete;
	Address(Address&& other) noexcept;

	Address& operator=(const Address&) = delete;
	Address& operator=(Address&& other) noexcept;

	bool init(const std::string &pAddr, const std::string &pService, bool tcp, int family);
	bool init(const std::string &pAddr, const std::string &pService, bool tcp);
	
	inline bool empty() const { return m_pServinfo == nullptr && !m_pValidAddress; }

	inline std::string getService() const { return m_szService; }

	inline const struct addrinfo* getaddress() const { return m_pValidAddress; }

	inline struct addrinfo* getaddress() { return m_pValidAddress; }

	inline int getFamily() const { return m_pValidAddress->ai_family; }
	inline int getSocketType() const { return m_pValidAddress->ai_socktype; }
	inline int getProtocol() const { return m_pValidAddress->ai_protocol; }
	inline int getFlags() const { return m_pValidAddress->ai_flags; }
	inline sockaddr* getai_addr() const { return m_pValidAddress->ai_addr; }
	inline decltype(addrinfo::ai_addrlen) getai_addrlen() const { return m_pValidAddress->ai_addrlen; }

	inline bool isTCP() const { return m_pValidAddress->ai_socktype == SOCK_STREAM;}
	inline bool isIPv4() const { return getFamily() == AF_INET; }
	inline std::string getHostname() const { return std::string(m_pValidAddress->ai_canonname); }
	inline int port() const { return HelperMethods::getPort(m_pValidAddress); }
	inline std::string IP() const { return HelperMethods::getIP(m_pValidAddress); }

	inline const struct addrinfo* getNextAddress();

	inline void clear();
	inline void print() const;
	
private:
	inline bool init(int family, int type, int flags);
private:
	std::string							m_szIP;			// e.g "www.example.com" or IP
	std::string							m_szService;	// e.g. "http" or port number
	struct addrinfo						*m_pServinfo{};
	struct addrinfo						*m_pValidAddress{};
};

Address::Address(Address &&other) noexcept
{
	m_szIP = std::exchange(other.m_szIP, std::string());
	m_szService = std::exchange(other.m_szService, std::string());
	m_pServinfo = std::exchange(other.m_pServinfo, nullptr);
	m_pValidAddress = std::exchange(other.m_pValidAddress, nullptr);
}

Address& Address::operator=(Address &&other) noexcept
{
	if(this != &other)
	{
		clear();
		m_szIP = std::exchange(other.m_szIP, std::string());
		m_szService = std::exchange(other.m_szService, std::string());
		m_pServinfo = std::exchange(other.m_pServinfo, nullptr);
		m_pValidAddress = std::exchange(other.m_pValidAddress, nullptr);
	}
	return *this;
}

bool Address::init(const std::string &pAddr, const std::string &pService, bool tcp, int family)
{
	clear();
	m_szIP = pAddr;
	m_szService = pService;
	return init(family, tcp ? SOCK_STREAM : SOCK_DGRAM, m_szIP.empty() ? AI_PASSIVE : 0);
}

bool Address::init(const std::string &pAddr, const std::string &pService, bool tcp)
{
	clear();
	m_szIP = pAddr;
	m_szService = pService;
	return init(AF_UNSPEC, tcp ? SOCK_STREAM : SOCK_DGRAM, m_szIP.empty() ? AI_PASSIVE : 0);
}

inline const addrinfo* Address::getNextAddress()
{
	if (m_pServinfo)
	{
		if (!m_pValidAddress)
		{
			m_pValidAddress = m_pServinfo;
		}
		else if (m_pValidAddress)
		{
			m_pValidAddress = m_pValidAddress->ai_next;
		}
	}
	return m_pValidAddress;
}

void Address::clear()
{
	HelperMethods::freeAddress(m_pServinfo);
	m_pValidAddress = nullptr;
}

void Address::print() const
{
	Logger::LOG_MSG("IP/URL          :", m_szIP.empty() ? "nullptr" : m_szIP, '\n');
	Logger::LOG_MSG("Service         :", m_szService.empty() ? "nullptr" : m_szService, "\n\n");
	Logger::LOG_MSG("Addresses       :\n");
	Logger::LOG_MSG(HelperMethods::asString(*m_pServinfo));
}

bool Address::init(int family, int type, int flags)
{
	struct addrinfo hints{};
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = family;								//AF_UNSPEC;     /* Allow IPv4 or IPv6 */
	hints.ai_socktype = type;								//SOCK_DGRAM or SOCK_STREAM;
	hints.ai_flags = flags;									//AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;									//0				 /* for Any protocol */
	hints.ai_canonname = nullptr;
	hints.ai_addr = nullptr;
	hints.ai_next = nullptr;

	m_pServinfo = HelperMethods::getAddrInfo(hints, m_szIP, m_szService);
	return m_pServinfo != nullptr;
}
}

#endif //#ifndef __ADDRESS_H__