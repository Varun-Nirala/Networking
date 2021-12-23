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
#include <sstream>

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

#if defined(PLATFORM_WIN)
	inline bool onetimeSetup()
	{
		static bool bInitialized = false;
		if (!bInitialized)
		{
			WSADATA wsa;
			PRINT_MSG("One time initialisation of Winsock...");
			if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
			{
				PRINT_MSG("Failed in initialisation of Winsock. Error Code : " + std::to_string(WSAGetLastError()));
				return false;
			}
			bInitialized = true;
		}
		return true;
	}
	inline int getErrorCode() { return WSAGetLastError(); }
#endif
#if defined(PLATFORM_UNIX)
	inline bool onetimeSetup() { return true; }
	inline int getErrorCode() { return errno; }
#endif

inline std::string asString(const struct addrinfo& info);
inline std::string getIP(const struct addrinfo* addr);
inline int getPort(const struct addrinfo* addr);
inline std::string getPortIP(const struct addrinfo* addr);

class Address
{
public:
	Address() = default;
	~Address() { clear(); }
	
	explicit Address(const char* pAddr, const char* pService, bool tcp, int family = AF_UNSPEC);

	bool init(const char* pAddr, const char* pService, bool tcp, int family);
	bool init(const char* pAddr, const char* pService, bool tcp);

	inline bool empty() const { return m_pServinfo == nullptr && !m_pValidAddress; }

	inline std::string getService() const { return m_szService; }

	inline const struct addrinfo* getAddrinfo() const { return m_pValidAddress; }
	inline struct addrinfo* getAddrinfo() { return m_pValidAddress; }
	inline int getFamily() const { return m_pValidAddress->ai_family; }
	inline bool isTCP() const { return m_pValidAddress->ai_socktype == SOCK_STREAM;}
	inline bool isIPv4() const { return getFamily() == AF_INET; }
	inline std::string getHostname() const { return std::string(m_pValidAddress->ai_canonname); }
	inline int port() const { return getPort(m_pValidAddress); }
	inline std::string IP() const { return getIP(m_pValidAddress); }

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

Address::Address(const char* pAddr, const char* pService, bool tcp, int family)
	: m_szIP(pAddr)
	, m_szService(pService)
{
	init(family, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
}

bool Address::init(const char* pAddr, const char* pService, bool tcp, int family)
{
	clear();
	m_szIP = pAddr;
	m_szService = pService;
	return init(family, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
}

bool Address::init(const char* pAddr, const char* pService, bool tcp)
{
	clear();
	m_szIP = pAddr;
	m_szService = pService;
	return init(AF_UNSPEC, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
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
	onetimeSetup();
	struct addrinfo hints{};
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = family;
	hints.ai_socktype = type;
	hints.ai_flags = flags;
	hints.ai_protocol = 0;
	hints.ai_canonname = nullptr;
	hints.ai_addr = nullptr;
	hints.ai_next = nullptr;

	const char* paddr = m_szIP.empty() ? nullptr : m_szIP.c_str();
	const char* pservice = m_szService.empty() ? nullptr : m_szService.c_str();

	return fillAddressInfo(paddr, pservice, hints);
}

bool Address::fillAddressInfo(const char* pAdd, const char* pService, struct addrinfo &hints)
{
	if (m_pServinfo)
	{
		freeaddrinfo(m_pServinfo);	// Free the Link List
		m_pServinfo = nullptr;
	}
	int ret = getaddrinfo(pAdd, pService, &hints, &m_pServinfo);
	if (ret != 0)
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
		PRINT_MSG("Address # " + std::to_string(i++));
		PRINT_MSG(asString(*p));
	}
}

inline int getPort(const struct addrinfo* addr)
{
	if (addr->ai_family == AF_INET)
	{
		return ntohs(((struct sockaddr_in*)addr->ai_addr)->sin_port);
	}
	return ntohs(((struct sockaddr_in6*)addr->ai_addr)->sin6_port);
}

inline std::string getIP(const struct addrinfo* addr)
{
	void* ptr{};
	char ipstr[INET6_ADDRSTRLEN];
	memset(ipstr, 0, INET6_ADDRSTRLEN);
	if (addr->ai_family == AF_INET)
	{
		ptr = &(((struct sockaddr_in*)addr->ai_addr)->sin_addr);
	}
	else
	{
		ptr = &(((struct sockaddr_in6*)addr->ai_addr)->sin6_addr);
	}
	inet_ntop(addr->ai_family, ptr, ipstr, INET6_ADDRSTRLEN);

	return std::string(ipstr);
}

inline std::string getPortIP(const struct addrinfo* addr)
{
	return getIP(addr) + " : " + std::to_string(getPort(addr));
}

inline std::string asString(const struct addrinfo &info)
{
	std::ostringstream os;
	os << "\nFlags                : 0x" << std::hex << info.ai_flags;
	os << "\nFamily               : ";
	switch (info.ai_family)
	{
		case AF_UNSPEC:
			os << "Unspecified.";
			break;
		case AF_INET:
			os << "IPv4   : " << getIP(&info);
			break;
		case AF_INET6:
			os << "IPv6   : " << getIP(&info);
			break;
		default:
			os << "Other : " << info.ai_family;
			break;
	}
	
	os << "\nSocket               : ";
	switch (info.ai_socktype)
	{
		case 0:
			os << "Unspecified.";
			break;
		case SOCK_STREAM:
			os << "TCP.";
			break;
		case SOCK_DGRAM:
			os << "UDP.";
			break;
		case SOCK_RAW:
			os << "RAW.";
			break;
		case SOCK_RDM:
			os << "Reliable UDP.";
			break;
		case SOCK_SEQPACKET:
			os << " Pseudo TCP.";
			break;
		default:
			os << "Other : " << info.ai_socktype;
			break;
	}
	
	os << "\nProtocol             : ";
	switch (info.ai_protocol)
	{
		case 0:
			os << "Unspecified.";
			break;
		case IPPROTO_TCP:
			os << "IP TCP.";
			break;
		case IPPROTO_UDP:
			os << "IP UDP.";
			break;
		default:
			os << "Other : " << info.ai_protocol;
			break;
	}

	os << "\nCanonical name       : " << (info.ai_canonname == nullptr) ? "nullptr" : info.ai_canonname;
	
	os << "\nSockaddr length      : " << info.ai_addrlen;
	return os.str();
}
}

#endif //#ifndef __ADDRESS_H__