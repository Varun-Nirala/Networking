#ifndef __COMMON_H__
#define __COMMON_H__

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

#include "logger.h"

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

using Logger = nsUtil::Logger;

#if defined(PLATFORM_WIN)
	using SOCKET_TYPE = SOCKET;
#elif defined(PLATFORM_UNIX)
	using SOCKET_TYPE = int;
	#define INVALID_SOCKET -1
#endif

#if defined(PLATFORM_WIN)
	inline bool onetimeSetup()
	{
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		{
			Logger::LOG_ERROR("One tine initialisation of Winsock. : Failed. Error Code :", WSAGetLastError(), '\n');
			return false;
		}
		Logger::LOG_INFO("One tine initialisation of Winsock. : Success.\n");
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
	GlobalInit() { 	onetimeSetup(); }
	~GlobalInit() { callAtExit(); }
};

GlobalInit __globalInit;

class HelperMethods
{
public:
	static inline std::string whoami();

	static inline int getPort(const struct addrinfo* addr);
	static inline std::string getIP(const struct addrinfo* addr);
	static inline std::string getPortIP(const struct addrinfo* addr);

	static inline int getPort(const struct sockaddr_storage* addr);
	static inline std::string getIP(const struct sockaddr_storage* addr);
	static inline std::string getPortIP(const struct sockaddr_storage* addr);

	static inline bool getNameInfo(const struct addrinfo& addr, std::string& hostname, std::string& service);
	static inline struct addrinfo* getAddrInfo(const addrinfo& hints, const std::string& address, const std::string& service);
	static inline void freeAddress(struct addrinfo*& serverPtr);

	static inline std::string asString(const struct addrinfo* info);
	static inline std::string asString(const struct sockaddr_storage* addr);

	static inline std::string getProtocolAsString(const int protocol);
	static inline std::string getFamilyAsString(const int family);
	static inline std::string getSocketTypeAsString(const int sockType);
};

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
	if (!inet_ntop(addr->ai_family, ptr, ipstr, INET6_ADDRSTRLEN))
	{
		Logger::LOG_ERROR("inet_ntop API unsuccessful. Error Code", getErrorCode(), '\n');
		return {};
	}
	return std::string(ipstr);
}

inline std::string HelperMethods::getPortIP(const struct addrinfo* addr)
{
	return getIP(addr) + " : " + std::to_string(getPort(addr));
}

inline int HelperMethods::getPort(const struct sockaddr_storage* addr)
{
	if (addr->ss_family == AF_INET)
	{
		return ntohs(((struct sockaddr_in*)addr)->sin_port);
	}
	return ntohs(((struct sockaddr_in6*)addr)->sin6_port);
}

inline std::string HelperMethods::getIP(const struct sockaddr_storage* addr)
{
	void* ptr{};
	char ipstr[INET6_ADDRSTRLEN];
	memset(ipstr, 0, INET6_ADDRSTRLEN);
	if (addr->ss_family == AF_INET)
	{
		ptr = &(((struct sockaddr_in*)addr)->sin_addr);
	}
	else
	{
		ptr = &(((struct sockaddr_in6*)addr)->sin6_addr);
	}
	if (!inet_ntop(addr->ss_family, ptr, ipstr, INET6_ADDRSTRLEN))
	{
		Logger::LOG_ERROR("inet_ntop API unsuccessful. Error Code", getErrorCode(), '\n');
		return {};
	}
	return std::string(ipstr);
}

inline std::string HelperMethods::getPortIP(const struct sockaddr_storage* addr)
{
	return getIP(addr) + " : " + std::to_string(getPort(addr));
}

inline bool HelperMethods::getNameInfo(const struct addrinfo& addr, std::string& hostname, std::string& service)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	int ret = ::getnameinfo((addr.ai_addr), sizeof(addr), hbuf, NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0)
	{
		Logger::LOG_ERROR("getnameinfo API unsuccessful. Error : ", gai_strerror(ret), '\n');
		return false;
	}
	hostname = std::string(hbuf);
	service = std::string(sbuf);
	return true;
}

inline struct addrinfo* HelperMethods::getAddrInfo(const addrinfo& hints, const std::string& address, const std::string& service)
{
	struct addrinfo* servers{};
	int ret = ::getaddrinfo(address.empty() ? nullptr : address.c_str(), service.empty() ? nullptr : service.c_str(), &hints, &servers);
	if (ret != 0)
	{
		Logger::LOG_ERROR("getaddrinfo API unsuccessful. Error : ", gai_strerror(ret), '\n');
		return nullptr;
	}
	return servers;
}

inline void HelperMethods::freeAddress(struct addrinfo*& serverPtr)
{
	freeaddrinfo(serverPtr);
	serverPtr = nullptr;
}

inline std::string HelperMethods::asString(const struct addrinfo* info)
{
	std::ostringstream os;
	os << "Flags           : 0x" << std::hex << info->ai_flags << std::dec << '\n';
	os << "Family          : " << HelperMethods::getFamilyAsString(info->ai_family) << '\n';
	os << "Socket Type     : " << HelperMethods::getSocketTypeAsString(info->ai_socktype) << '\n';
	os << "Protocol        : " << HelperMethods::getProtocolAsString(info->ai_protocol) << '\n';

	if (info->ai_canonname)
	{
		os << "Canonical name  : " << info->ai_canonname << '\n';
	}
	else
	{
		os << "Canonical name  : nullptr\n";
	}
	os << "Sockaddr length : " << info->ai_addrlen << '\n';
	int i = 1;

	for (const addrinfo* p = info; p != nullptr; p = p->ai_next)
	{

		os << "**************** Address #" << i++ << "****************\n";
		os << "IP              : " << HelperMethods::getIP(p) << '\n';
		os << "Port            : " << HelperMethods::getPort(p) << '\n';
		os << "**********************************************\n";
	}
	return os.str();
}

inline std::string HelperMethods::asString(const struct sockaddr_storage* addr)
{
	std::ostringstream os;
	os << "Family          : " << HelperMethods::getFamilyAsString(addr->ss_family) << '\n';
	os << "IP              : " << HelperMethods::getIP(addr) << '\n';
	os << "Port            : " << HelperMethods::getPort(addr) << '\n';
	return os.str();
}

inline std::string HelperMethods::getProtocolAsString(const int protocol)
{
	switch (protocol)
	{
		case 0:
			return "Unspecified";
			break;
		case IPPROTO_TCP:
			return "IPPROTO_TCP";
			break;
		case IPPROTO_UDP:
			return "IPPROTO_UDP";
			break;
		case IPPROTO_SCTP:
			return "IPPROTO_SCTP";
			break;
		default:
			break;
	}
	return "Unkown ( " + std::to_string(protocol) + " )";
}

inline std::string HelperMethods::getFamilyAsString(const int family)
{
	switch (family)
	{
		case AF_UNSPEC:
			return "Unspecified";
			break;
		case AF_INET:
			return "AF_INET (IPv4)";
			break;
		case AF_INET6:
			return "AF_INET6 (IPv6)";
			break;
		case AF_UNIX:
			return "AF_UNIX (Local host to unix pipes, portals)";
			break;
		default:
			break;
	}
	return "Unkown ( " + std::to_string(family) + " )";
}

inline std::string HelperMethods::getSocketTypeAsString(const int sockType)
{
	switch (sockType)
	{
		case 0:
			return "Unspecified";
			break;
		case SOCK_STREAM:
			return "SOCK_STREAM (TCP)";
			break;
		case SOCK_DGRAM:
			return "SOCK_DGRAM (UDP)";
			break;
		case SOCK_RAW:
			return "SOCK_RAW";
			break;
		case SOCK_RDM:
			return "SOCK_RDM (Reliable UDP, Reliably delivered message)";
			break;
		case SOCK_SEQPACKET:
			return "SOCK_SEQPACKET (Pseudo TCP)";
			break;
		default:
			break;
		}
	return "Unkown ( " + std::to_string(sockType) + " )";
}


class CommData
{
public:
	sockaddr_storage		_addr;
	SOCKET_TYPE				_sId{ INVALID_SOCKET };
	int						_sockType{ -1 };
	int						_protocol{ -1 };

	CommData() { std::memset(&_addr, 0, sizeof(sockaddr_storage)); }
	~CommData() = default;

	CommData(const CommData&) = delete;
	CommData& operator=(const CommData&) = delete;

	CommData(CommData&& other) noexcept;
	CommData& operator=(CommData&& other) noexcept;

	inline std::string getIP() const { return HelperMethods::getIP(&_addr); }
	inline int getPort() const { return HelperMethods::getPort(&_addr); }
	inline int getFamily() const { return _addr.ss_family; }
	inline int getSocketType() const { return _sockType; }
	inline int getProtocol() const { return _protocol; }
	inline bool isTCP() const { return _sockType == SOCK_STREAM; }
	inline bool isIPv4() const { return _addr.ss_family == AF_INET; }
	inline void print() const;
};

CommData::CommData(CommData&& other) noexcept
{
	_addr = std::exchange(other._addr, sockaddr_storage());
	_sId = std::exchange(other._sId, INVALID_SOCKET);
	_sockType = std::exchange(other._sockType, -1);
	_protocol = std::exchange(other._protocol, -1);
}

CommData& CommData::operator=(CommData&& other) noexcept
{
	if (this != &other)
	{
		_addr = std::exchange(other._addr, sockaddr_storage());
		_sId = std::exchange(other._sId, INVALID_SOCKET);
		_sockType = std::exchange(other._sockType, -1);
		_protocol = std::exchange(other._protocol, -1);
	}
	return *this;
}

void CommData::print() const
{
	Logger::LOG_MSG("Socket          :", _sId, '\n');
	Logger::LOG_MSG("Family          :", HelperMethods::getSocketTypeAsString(getFamily()), '\n');
	Logger::LOG_MSG("Socket Type     :", HelperMethods::getSocketTypeAsString(getSocketType()), '\n');
	Logger::LOG_MSG("Protocol        :", HelperMethods::getProtocolAsString(getProtocol()), '\n');
	Logger::LOG_MSG(HelperMethods::asString(&_addr), '\n');
}
}   // namespace nsNW
#endif // #ifndef __COMMON_H__