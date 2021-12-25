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
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		{
			Logger::LOG_ERROR("One tine initialisation of Winsock. : Failed. Error Code :", WSAGetLastError(), '\n');
			return false;
		}
		Logger::LOG_ERROR("One tine initialisation of Winsock. : Success.\n");
		return true;
	}
	inline int getErrorCode() { return WSAGetLastError(); }
	inline void callAtExit() { WSACleanup(); }
#endif
#if defined(PLATFORM_UNIX)
	inline bool onetimeSetup() { return true; }
	inline int getErrorCode() { return errno; }
	inline void callAtExit() { ; }
#endif

class GlobalInit
{
public:
	GlobalInit()
	{
		onetimeSetup();
	}
	~GlobalInit()
	{
		callAtExit();
	}
};

GlobalInit __globalInit;

class HelperMethods
{
public:
	static inline std::string whoami();
	static inline int getPort(const struct addrinfo* addr);
	static inline std::string getIP(const struct addrinfo* addr);
	static inline std::string getPortIP(const struct addrinfo* addr);
	static inline std::string asString(const struct addrinfo& info);
	static inline bool getNameInfo(const struct addrinfo& addr, std::string& hostname, std::string& service);
	static inline struct addrinfo* getAddrInfo(const addrinfo& hints, const std::string& address, const std::string& service);
	static inline void freeAddress(struct addrinfo* serverPtr);
};

class Address
{
public:
	Address() = default;
	~Address() { clear(); }

	bool init(const std::string &pAddr, const std::string &pService, bool tcp, int family);
	bool init(const std::string &pAddr, const std::string &pService, bool tcp);
	
	inline bool empty() const { return m_pServinfo == nullptr && !m_pValidAddress; }

	inline std::string getService() const { return m_szService; }

	inline const struct addrinfo* getaddress() const { return m_pValidAddress; }
	inline struct addrinfo* getaddress() { return m_pValidAddress; }
	inline int getFamily() const { return m_pValidAddress->ai_family; }
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
		else
		{
			m_pValidAddress = m_pValidAddress->ai_next;
		}
	}
	return m_pValidAddress;
}

void Address::clear()
{
	HelperMethods::freeAddress(m_pServinfo);
	m_pServinfo = m_pValidAddress = nullptr;
}

void Address::print() const
{
	Logger::LOG_MSG("IP Addresses :", m_szIP, "Service :", m_szService, '\n');

	int i = 1;
	for (addrinfo* p = m_pServinfo; p != nullptr; p = p->ai_next)
	{
		Logger::LOG_MSG("    Address ", i++);
		Logger::LOG_MSG(HelperMethods::asString(*p) + '\n');
	}
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

inline std::string HelperMethods::whoami()
{
	const int MAX = 128;
	char hostname[MAX];
	int ret = ::gethostname(hostname, MAX);
	if (ret == -1)
	{
		Logger::LOG_ERROR("gethostname API unsuccessful. Error Code", getErrorCode(), '\n');
		return {};
	}
	return std::string(hostname);
}

inline int HelperMethods::getPort(const struct addrinfo* addr)
{
	if (addr->ai_family == AF_INET)
	{
		return ntohs(((struct sockaddr_in*)addr->ai_addr)->sin_port);
	}
	return ntohs(((struct sockaddr_in6*)addr->ai_addr)->sin6_port);
}

inline std::string HelperMethods::getIP(const struct addrinfo* addr)
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

inline std::string HelperMethods::getPortIP(const struct addrinfo* addr)
{
	return getIP(addr) + " : " + std::to_string(getPort(addr));
}

inline bool HelperMethods::getNameInfo(const struct addrinfo& addr, std::string& hostname, std::string& service)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	int ret = ::getnameinfo((addr.ai_addr), sizeof(addr), hbuf, NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0)
	{
		Logger::LOG_ERROR("getnameinfo API unsuccessful.", gai_strerror(ret), '\n');
		return false;
	}
	hostname = std::string(hbuf);
	service = std::string(sbuf);
	Logger::LOG_ERROR("Hostname :", hostname, "Service :", service);
	return true;
}

inline struct addrinfo* HelperMethods::getAddrInfo(const addrinfo& hints, const std::string& address, const std::string& service)
{
	struct addrinfo* servers{};
	int ret = ::getaddrinfo(address.empty() ? nullptr : address.c_str(), service.empty() ? nullptr : service.c_str(), &hints, &servers);
	if (ret != 0)
	{
		Logger::LOG_ERROR("getaddrinfo API unsuccessful.", gai_strerror(ret), '\n');
		return nullptr;
	}
	return servers;
}

inline void HelperMethods::freeAddress(struct addrinfo* serverPtr)
{
	freeaddrinfo(serverPtr);
	serverPtr = nullptr;
}

inline std::string HelperMethods::asString(const struct addrinfo &info)
{
	std::ostringstream os;
	os << "\nFlags                : 0x" << std::hex << info.ai_flags << std::dec;
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
		case IPPROTO_SCTP:
			os << "SCTP.";
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