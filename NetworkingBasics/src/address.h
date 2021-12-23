#ifndef __ADDRESS_H__
#define __ADDRESS_H__

#if defined(_WIN32) || defined(_WIN64)
	#define PLATFORM_WIN
#else
	#define PLATFORM_UNIX
#endif

#if defined(PLATFORM_WIN)
	#include <winsock2.h>
	#include <ws2tcpip.h>
#elif defined(PLATFORM_UNIX)
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/ip.h>
	#include <netdb.h>
	#include <unistd.h>
#endif
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <memory>

#include "helper.h"

#if defined(PLATFORM_WIN)
	#pragma comment(lib,"ws2_32.lib") 
#endif

namespace nsNW
{
/*
struct addrinfo
{
	int              ai_flags;     // AI_PASSIVE, AI_CANONNAME, etc.
	int              ai_family;    // AF_INET, AF_INET6, AF_UNSPEC
	int              ai_socktype;  // SOCK_STREAM, SOCK_DGRAM
	int              ai_protocol;  // use 0 for "any"
	size_t           ai_addrlen;   // size of ai_addr in bytes
	struct sockaddr	*ai_addr;      // struct sockaddr_in or _in6
	char			*ai_canonname; // full canonical hostname

	struct addrinfo* ai_next;      // linked list, next node
};

struct sockaddr
{
	unsigned short    sa_family;    // address family, AF_xxx
	char              sa_data[14];  // 14 bytes of protocol address
};

// IPv4
struct sockaddr_in
{
	short int          sin_family;  // Address family, AF_INET
	unsigned short int sin_port;    // Port number
	struct in_addr     sin_addr;    // Internet address
	unsigned char      sin_zero[8]; // Same size as struct sockaddr
};

struct in_addr
{
	uint32_t			s_addr; // that's a 32-bit int (4 bytes)
};

struct sockaddr_in6
{
	u_int16_t			sin6_family;   // address family, AF_INET6
	u_int16_t			sin6_port;     // port number, Network Byte Order
	u_int32_t			sin6_flowinfo; // IPv6 flow information
	struct in6_addr		sin6_addr;     // IPv6 address
	u_int32_t			sin6_scope_id; // Scope ID
};

struct in6_addr
{
	unsigned char		s6_addr[16];   // IPv6 address
};

 struct sockaddr_storage
 {
	sa_family_t			ss_family;     // address family

	// all this is padding, implementation specific, ignore it:
	char				__ss_pad1[_SS_PAD1SIZE];
	int64_t				__ss_align;
	char				__ss_pad2[_SS_PAD2SIZE];
};

struct hostent {
	char  *h_name;            official name of host
	char** h_aliases;         alias list
	int    h_addrtype;        host address type
	int    h_length;          length of address
	char** h_addr_list;       list of addresses
}
*/
class Address
{
public:
	Address() = default;
	Address(const char* pAddr, const char* pService, bool tcp);
	Address(const char* pAddr, const char* pService, bool tcp, bool ipv4);
	
	~Address() { clear(); }

	bool init(const char* pAddr, const char* pService, bool tcp);
	bool init(const char* pAddr, const char* pService, bool tcp, bool ipv4);

	inline bool empty() const { return m_pServinfo == nullptr && !m_pValidAddress; }

	inline std::string getService() const { return m_szService; }

	inline const struct addrinfo* getAddrinfo() const { return m_pValidAddress; }
	inline struct addrinfo* getAddrinfo() { return m_pValidAddress; }
	inline int getFamily() const { return m_pValidAddress->ai_family; }
	inline bool isTCP() const { return m_pValidAddress->ai_socktype == SOCK_STREAM;}
	inline bool isIPv4() const { return getFamily() == AF_INET; }
	inline std::string getHostname() const { return std::string(m_pValidAddress->ai_canonname); }
	inline int getPort() const { return getPort(m_pValidAddress); }
	inline std::string getIP() const { return getIP(m_pValidAddress); }

	inline int getPort(struct addrinfo *addr) const;
	inline std::string getIP(struct addrinfo *addr) const;

	inline const struct addrinfo* getNextAddress();
	inline void clear();
	inline void print() const;



private:
	
	inline bool init(int family, int type, int flags);
	inline bool fillAddressInfo(const char* pAddr, const char* pService, struct addrinfo &hints);
private:
	std::string							m_szIP;			// e.g "www.example.com" or IP
	std::string							m_szService;	// e.g. "http" or port number
	struct addrinfo						*m_pServinfo{};
	struct addrinfo						*m_pValidAddress{};
};

Address::Address(const char* pAddr, const char* pService, bool tcp)
	: m_szIP(pAddr)
	, m_szService(pService)
{
	init(AF_UNSPEC, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
}

Address::Address(const char* pAddr, const char* pService, bool tcp, bool ipv4)
	: m_szIP(pAddr)
	, m_szService(pService)
{
	init(ipv4 ? AF_INET : AF_INET6, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
}

bool Address::init(const char* pAddr, const char* pService, bool tcp)
{
	clear();
	m_szIP = pAddr;
	m_szService = pService;
	return init(AF_UNSPEC, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
}

bool Address::init(const char* pAddr, const char* pService, bool tcp, bool ipv4)
{
	clear();
	m_szIP = pAddr;
	m_szService = pService;
	return init(ipv4 ? AF_INET : AF_INET6, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
}

int Address::getPort(struct addrinfo* addr) const
{
	if (addr->ai_family == AF_INET)
	{
		return ntohs(((struct sockaddr_in*)addr->ai_addr)->sin_port);
	}
	return ntohs(((struct sockaddr_in6*)addr->ai_addr)->sin6_port);
}

std::string Address::getIP(struct addrinfo* addr) const
{
	void* ptr{};
	char ipstr[INET6_ADDRSTRLEN];
	if (addr->ai_family == AF_INET)
	{
		ptr = &(((struct sockaddr_in*)addr->ai_addr)->sin_addr);
	}
	else
	{
		ptr = &(((struct sockaddr_in6*)addr->ai_addr)->sin6_addr);
	}
	inet_ntop(addr->ai_family, ptr, ipstr, sizeof(INET6_ADDRSTRLEN));

	return std::string(ipstr);
}

inline const addrinfo* Address::getNextAddress()
{
	if (m_pServinfo)
	{
		m_pValidAddress = m_pValidAddress->ai_next;
	}
	return m_pValidAddress;
}

void Address::clear()
{
	freeaddrinfo(m_pServinfo);
	m_pServinfo = m_pValidAddress = nullptr;
}

bool Address::init(int family, int type, int flags)
{
	struct addrinfo hints{};
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = family;
	hints.ai_socktype = type;
	hints.ai_flags = flags;
	hints.ai_protocol = 0;
	hints.ai_canonname = nullptr;
	hints.ai_addr = nullptr;
	hints.ai_next = nullptr;

	return fillAddressInfo(m_szIP.c_str(), m_szService.c_str(), hints);
}

bool Address::fillAddressInfo(const char* pAdd, const char* pService, struct addrinfo &hints)
{
	if (m_pServinfo)
	{
		freeaddrinfo(m_pServinfo);	// Free the Link List
		m_pServinfo = nullptr;
	}
	int ret = 0;
	if (ret = getaddrinfo(pAdd, pService, &hints, &m_pServinfo) != 0)
	{
		LOG_ERROR("getaddrinfo: " + std::string(gai_strerror(ret)));
		return false;
	}
	return true;
}

void Address::print() const
{
	PRINT_MSG("IP Addresses for " + m_szIP + " , Service : " + m_szService + " :");

	int i = 1;
	for (addrinfo *p = m_pServinfo; p != nullptr; p = p->ai_next)
	{
		void* addr{};
		std::string str{ "Address # " + std::to_string(i++)};

		str += (p->ai_family == AF_INET) ? "IPv4" : "IPv6";
		str += " " + getIP(p);
		PRINT_MSG(str);
	}
}
}

#endif //#ifndef __ADDRESS_H__