#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <memory>


#include "helper.h"

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
*/

#define IF_NOTACTIVE_RETURN(x) ({\
			if (!isActive())\
			{\
				LOG_ERROR("No active socket.");\
				return x;\
			}})

class Address
{
public:
	Address(bool tcp, const char* pService, const char* pAddr);
	Address(bool ipv4, bool tcp, const char* pService, const char* pAddr);
	~Address();

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

	inline void print() const;
private:
	inline bool init(int family, int type, int flags);
	inline bool fillAddressInfo(const char* pService, const char* pAddr, struct addrinfo &hints);
private:
	std::string							m_szIP;			// e.g "www.example.com" or IP
	std::string							m_szService;	// e.g. "http" or port number
	struct addrinfo						*m_pServinfo{};
	struct addrinfo						*m_pValidAddress{};
};

class Socket
{
public:
	Socket(const Socket& sock) = delete;
	Socket& operator=(const Socket& sock) = delete;

	~Socket() { close(); };

	explicit Socket(bool tcp, const std::string &pService, const std::string &pAddr);
	explicit Socket(bool ipv4, bool tcp, const std::string& pService, const std::string& pAddr);
	Socket(Socket&& sock) = default;
	Socket& operator=(Socket&& sock) = default;

	inline void setBacklog(int val) { m_backlog = val; }

	inline int getSocketId() const { return m_desc; }
	inline bool isActive() const { return !(m_desc == -1); }

	inline int getFamily() const { return m_address.getFamily(); }
	inline std::string getHostname() const { return m_address.getHostname(); }
	inline bool isTCP() const { return m_address.isTCP(); }
	inline bool isIPv4() const { return m_address.isIPv4(); }
	int getPort() const { return m_address.getPort(); }
	const std::string getIPAddress() const { return m_address.getIP(); }

	bool bind();
	bool listen();
	int accept(struct sockaddr_storage &theirAddr);
	bool connect();

	bool close();

protected:
	bool getValidSocket();
	bool setSocketOptions(bool reuseAddr, bool reusePort);

private:
	int										m_desc{-1};
	Address									m_address;
	int										m_backlog{5};
};


Address::Address(bool tcp, const char* pService, const char* pAddr)
	: m_szIP(pAddr)
	, m_szService(pService)
{
	init(AF_UNSPEC, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
}

Address::Address(bool ipv4, bool tcp, const char* pService, const char* pAddr)
	: m_szIP(pAddr)
	, m_szService(pService)
{
	init(ipv4 ? AF_INET : AF_INET6, tcp ? SOCK_STREAM : SOCK_DGRAM, !pAddr ? AI_PASSIVE : 0);
}

Address::~Address()
{
	freeaddrinfo(m_pServinfo);
	m_pServinfo = m_pValidAddress = nullptr;
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

bool Address::init(int family, int type, int flags)
{
	struct addrinfo hints{};
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = family;
	hints.ai_socktype = type;
	hints.ai_flags = flags;

	fillAddressInfo(m_szIP.c_str(), m_szService.c_str(), hints);
}

bool Address::fillAddressInfo(const char* pService, const char* pAdd, struct addrinfo &hints)
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




Socket::Socket(bool tcp, const std::string& pService, const std::string& pAddr)
	: m_address(tcp, pService.c_str(), pAddr.c_str())
{
	if (!getValidSocket() || !setSocketOptions(true, true))
	{
		LOG_ERROR("Socket setup error.");
		return;
	}
	PRINT_MSG("Socket created : " + std::to_string(m_desc));
}

Socket::Socket(bool ipv4, bool tcp, const std::string& pService, const std::string& pAddr)
	:m_address(ipv4, tcp, pService.c_str(), pAddr.c_str())
{

}

bool Socket::bind()
{
	IF_NOTACTIVE_RETURN(false);
	if (::bind(m_desc, m_address.getAddrinfo()->ai_addr, m_address.getAddrinfo()->ai_addrlen) == -1)
	{
		LOG_ERROR("Socket bind error. Error code : " + std::to_string(errno));
		return false;
	}
	PRINT_MSG("Socket bind success.");
	return true;
}

bool Socket::listen()
{
	if (::listen(m_desc, m_backlog) == -1)
	{
		LOG_ERROR("Socket listen error. Error code : " + std::to_string(errno));
		return false;
	}
	PRINT_MSG("Socket listen success.");
	return true;
}

int Socket::accept(struct sockaddr_storage& theirAddr)
{
	IF_NOTACTIVE_RETURN(-1);

	socklen_t addr_size = sizeof(theirAddr);
	memset(&theirAddr, 0, addr_size);

	int new_fd = ::accept(m_desc, (struct sockaddr*)&theirAddr, &addr_size);
	if (new_fd == -1)
	{
		LOG_ERROR("Connection accept error. Error code : " + std::to_string(errno));
		return new_fd;
	}
	PRINT_MSG("Connection accepted. Their socket ID : " + std::to_string(new_fd));
	return new_fd;
}

bool Socket::connect()
{
	IF_NOTACTIVE_RETURN(false);

	if (::connect(m_desc, m_address.getAddrinfo()->ai_addr, m_address.getAddrinfo()->ai_addrlen) == -1)
	{
		LOG_ERROR("Socket connect error. Error code : " + std::to_string(errno));
		return false;
	}
	PRINT_MSG("Socket connect success.");
	return true;
}

bool Socket::close()
{
	IF_NOTACTIVE_RETURN(true);
	if (::close(m_desc) != 0)
	{
		LOG_ERROR("Socket close error. Error code : " + std::to_string(errno));
		return false;
	}
	PRINT_MSG("Socket close success.");
	return true;
}

bool Socket::getValidSocket()
{
	// Create Socket
	const struct addrinfo* p = m_address.getNextAddress();
	while (p)
	{
		m_desc = socket(p->ai_family, p->ai_family, p->ai_protocol);
		if (m_desc != -1)
		{
			break;
		}
		p = m_address.getNextAddress();
	}
	if (!p)
	{
		LOG_ERROR("Socket creation error. Error code : " + std::to_string(m_desc));
		return false;
	}
	PRINT_MSG("Socket creation success. Socket ID : " + std::to_string(m_desc));
	return true;
}

bool Socket::setSocketOptions(bool reuseAddr, bool reusePort)
{
	IF_NOTACTIVE_RETURN(false);

	int optVal = 1;
	int option = 0;
	if (reuseAddr)
	{
		option = SO_REUSEADDR;
	}
	if (reusePort)
	{
		option = option | SO_REUSEPORT;
	}
	int ret = setsockopt(m_desc, SOL_SOCKET, option, &optVal, sizeof(optVal));
	if (ret == -1)
	{
		LOG_ERROR("Socket option settting error. Error code : " + std::to_string(ret));
		return false;
	}
	LOG_ERROR("Socket option settting success.");
	return true;
}
}

#endif //#ifndef __SOCKET_H__