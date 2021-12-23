#ifndef __SOCKET_H__
#define __SOCKET_H__

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
int getErrorCode() { return WSAGetLastError(); }
#endif
#if defined(PLATFORM_UNIX)
inline bool onetimeSetup() { return true; }
inline int getErrorCode() { return errno; }
#endif



#define IF_NOTACTIVE_RETURN(x)              \
  do {                                      \
    if (!isActive()) {                      \
      LOG_ERROR("Socket not active.");      \
      return x;                             \
    }                                       \
  } while (0);

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
	Socket() = default;
	~Socket() { clear(); };

	Socket(const Socket& sock) = delete;
	Socket& operator=(const Socket& sock) = delete;

	explicit Socket(const std::string &pAddr, const std::string &pService, bool tcp)
		: m_address(pAddr.c_str(), pService.c_str(), tcp)
	{
		init();
	}

	explicit Socket(const std::string& pAddr, const std::string& pService, bool tcp, bool ipv4)
		: m_address(pAddr.c_str(), pService.c_str(), tcp, ipv4)
	{
		init();
	}

	Socket(Socket&& sock) = default;
	Socket& operator=(Socket && sock) = default;

	inline bool init(const std::string& pAddr, const std::string& pService, bool tcp);
	inline bool init(const std::string& pAddr, const std::string& pService, bool tcp, bool ipv4);

	inline void setBacklog(int val) { m_backlog = val; }

	inline int getSocketId() const { return m_socketFd; }
	inline bool isActive() const { return !(m_socketFd == -1); }

	inline int getFamily() const { return m_address.getFamily(); }
	inline std::string getHostname() const { return m_address.getHostname(); }
	inline bool isTCP() const { return m_address.isTCP(); }
	inline bool isIPv4() const { return m_address.isIPv4(); }
	int getPort() const { return m_address.getPort(); }
	const std::string getIPAddress() const { return m_address.getIP(); }

	inline int getPort(struct addrinfo* addr) const { return m_address.getPort(addr); }
	inline std::string getIP(struct addrinfo* addr) const { return m_address.getIP(addr); }

	bool bind();
	bool listen();
	bool accept(struct sockaddr_storage &theirAddr, int &sId);
	bool connect();

	void clear();

	bool sendTcp(int toSocketFd, const std::string& msg, int& sentBytes);
	bool recvTcp(int fromSocketFd, const std::string& msg, const int maxSize);

	bool sendDatagram(int toSocketFd, const std::string& msg, int& sentBytes);
	bool recvDatagram(int fromSocketFd, struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize);

	bool sendTcp(const std::string& msg, int& sentBytes);
	bool recvTcp(const std::string& msg, const int maxSize);

	bool sendDatagram(const std::string& msg, int& sentBytes);
	bool recvDatagram(struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize);
	bool recvDatagram(const std::string& msg, const int maxSize);

protected:
	bool close();
	bool init();
	bool getValidSocket();
	bool setSocketOptions(bool reuseAddr, bool reusePort);

	struct Buffer
	{
		std::unique_ptr<char[]>				m_pBuf;
		size_t								m_size{};

		char& operator[](size_t id) { return m_pBuf[id]; }
		const char& operator[](size_t id) const { return m_pBuf[id]; }

		char* get() { return m_pBuf.get(); }
		const size_t size() const { return m_size; }
		inline bool init(size_t s) { clear(); m_size = s; m_pBuf = std::make_unique<char[]>(m_size); return m_pBuf != nullptr; }
		inline void clear() { m_size = 0; m_pBuf.reset(nullptr); }
		inline bool empty() const { return m_size == 0; }
	};

private:
	int										m_socketFd{-1};	// Socket file descriptor
	Address									m_address;
	int										m_backlog{5};
	Buffer									m_buffer;
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

	return fillAddressInfo(m_szIP.c_str(), m_szService.c_str(), hints);
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

bool Socket::close()
{
	IF_NOTACTIVE_RETURN(true);
	int ret{};

#if defined(PLATFORM_WIN)
	ret = closesocket(m_socketFd);
	WSACleanup();
#else
	ret = ::close(m_socketFd);
#endif

	if (ret != 0)
	{
		m_socketFd = -1;
		LOG_ERROR("Socket close error. Error code : " + std::to_string(getErrorCode()));
		return false;
	}
	m_socketFd = -1;
	PRINT_MSG("Socket close success.");
	return true;
}

bool Socket::init(const std::string& pAddr, const std::string& pService, bool tcp)
{
	clear();
	m_address.init(pAddr.c_str(), pService.c_str(), tcp);
	return init();
}

bool Socket::init(const std::string& pAddr, const std::string& pService, bool tcp, bool ipv4)
{
	clear();
	m_address.init(pAddr.c_str(), pService.c_str(), tcp, ipv4);
	return init();
}

bool Socket::bind()
{
	IF_NOTACTIVE_RETURN(false);
	if (::bind(m_socketFd, m_address.getAddrinfo()->ai_addr, m_address.getAddrinfo()->ai_addrlen) == -1)
	{
		LOG_ERROR("Socket bind error. Error code : " + std::to_string(getErrorCode()));
		return false;
	}
	PRINT_MSG("Socket bind success.");
	return true;
}

bool Socket::listen()
{
	if (::listen(m_socketFd, m_backlog) == -1)
	{
		LOG_ERROR("Socket listen error. Error code : " + std::to_string(getErrorCode()));
		return false;
	}
	PRINT_MSG("Socket listen success.");
	return true;
}

bool Socket::accept(struct sockaddr_storage& theirAddr, int& sId)
{
	sId = -1;
	IF_NOTACTIVE_RETURN(false);
	
	socklen_t addr_size = sizeof(theirAddr);
	memset(&theirAddr, 0, addr_size);

	sId = ::accept(m_socketFd, (struct sockaddr*)&theirAddr, &addr_size);
	if (sId == -1)
	{
		LOG_ERROR("Connection accept error. Error code : " + std::to_string(getErrorCode()));
		return sId;
	}
	PRINT_MSG("Connection accepted. Their socket ID : " + std::to_string(sId));
	return sId;
}

bool Socket::connect()
{
	IF_NOTACTIVE_RETURN(false);

	if (::connect(m_socketFd, m_address.getAddrinfo()->ai_addr, m_address.getAddrinfo()->ai_addrlen) == -1)
	{
		LOG_ERROR("Socket connect error. Error code : " + std::to_string(getErrorCode()));
		return false;
	}
	PRINT_MSG("Socket connect success.");
	return true;
}

void Socket::clear()
{
	close();
	m_address.clear();
	m_buffer.clear();
}

bool Socket::sendTcp(int toSocketFd, const std::string& msg, int &sentBytes)
{
	if (msg.empty())
	{
		PRINT_MSG("Trying to send empty msg.");
		return false;
	}

	sentBytes = ::send(toSocketFd, msg.c_str(), msg.size(), 0);
	if (sentBytes == -1)
	{
		LOG_ERROR("Send error. Error code : " + std::to_string(getErrorCode()));
		return false;
	}
	else if (sentBytes == 0)
	{
		LOG_ERROR("Connectioned closed by server on socket : " + std::to_string(toSocketFd));
		return false;
	}
	PRINT_MSG("Sent byte count : " + std::to_string(sentBytes));
	return true;
}

bool Socket::recvTcp(int fromSocketFd, const std::string& msg, const int maxSize)
{
	if (m_buffer.empty() || m_buffer.size() < maxSize)
	{
		m_buffer.init(maxSize);
	}
	int recvBytes = ::recv(fromSocketFd, m_buffer.get(), maxSize - 1, 0);
	if (recvBytes == -1)
	{
		LOG_ERROR("Recieve error. Error code : " + std::to_string(getErrorCode()));
		return false;
	}
	else if (recvBytes == 0)
	{
		LOG_ERROR("Connectioned closed by server on socket : " + std::to_string(fromSocketFd));
		return false;
	}

	PRINT_MSG("Packet length   : " + std::to_string(recvBytes));
	PRINT_MSG("Packet          : " + std::string(m_buffer.get()));
	return true;
}

bool Socket::sendDatagram(int toSocketFd, const std::string & msg, int& sentBytes)
{
	sentBytes = ::sendto(toSocketFd, msg.c_str(), msg.size(), 0, m_address.getAddrinfo()->ai_addr, m_address.getAddrinfo()->ai_addrlen);
	if (sentBytes == -1)
	{
		LOG_ERROR("Send error. Error code : " + std::to_string(getErrorCode()));
		return false;
	}
	else if (sentBytes == 0)
	{
		LOG_ERROR("Connectioned closed by server on socket : " + std::to_string(toSocketFd));
		return false;
	}
	PRINT_MSG("Sent byte count : " + std::to_string(sentBytes));
	return true;
}

bool Socket::recvDatagram(int fromSocketFd, struct sockaddr_storage &theirAddr, const std::string& msg, const int maxSize)
{
	if (m_buffer.empty() || m_buffer.size() < maxSize)
	{
		m_buffer.init(maxSize);
	}
	socklen_t addr_size = sizeof(theirAddr);
	memset(&theirAddr, 0, addr_size);

	int recvBytes = ::recvfrom(fromSocketFd, m_buffer.get(), maxSize - 1, 0, (struct sockaddr*)&theirAddr, &addr_size);

	if (recvBytes == -1)
	{
		LOG_ERROR("Recieve error. Error code : " + std::to_string(getErrorCode()));
		return false;
	}
	m_buffer[recvBytes] = '\0';
	std::string ip = m_address.getIP((struct addrinfo*)&theirAddr);
	PRINT_MSG("Got packet from : " + ip);
	PRINT_MSG("Packet length   : " + std::to_string(recvBytes));
	PRINT_MSG("Packet          : " + std::string(m_buffer.get()));
	return true;
}

bool Socket::sendTcp(const std::string& msg, int& sentBytes)
{
	return sendTcp(m_socketFd, msg, sentBytes);
}

bool Socket::recvTcp(const std::string& msg, const int maxSize)
{
	return recvTcp(m_socketFd, msg, maxSize);
}

bool Socket::sendDatagram(const std::string& msg, int& sentBytes)
{
	return sendDatagram(m_socketFd, msg, sentBytes);
}

bool Socket::recvDatagram(struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize)
{
	return recvDatagram(m_socketFd, theirAddr, msg, maxSize);
}

bool Socket::recvDatagram(const std::string& msg, const int maxSize)
{
	sockaddr_storage theirAddr;
	return recvDatagram(m_socketFd, theirAddr, msg, maxSize);
}

bool Socket::init()
{
	if (!onetimeSetup() || !getValidSocket() || !setSocketOptions(true, true))
	{
		LOG_ERROR("Socket setup error.");
		return false;
	}
	PRINT_MSG("Socket created : " + std::to_string(m_socketFd));
	return true;
}

bool Socket::getValidSocket()
{
	// Create Socket
	const struct addrinfo* p = m_address.getNextAddress();
	while (p)
	{
		m_socketFd = socket(p->ai_family, p->ai_family, p->ai_protocol);
		if (m_socketFd != -1)
		{
			break;
		}
		p = m_address.getNextAddress();
	}
	if (!p)
	{
		LOG_ERROR("Socket creation error. Error code : " + std::to_string(m_socketFd));
		return false;
	}
	PRINT_MSG("Socket creation success. Socket ID : " + std::to_string(m_socketFd));
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
	#if defined(PLATFORM_UNIX)
		if (reusePort)
		{
			option = option | SO_REUSEPORT;
		}
	#endif
	int ret = ::setsockopt(m_socketFd, SOL_SOCKET, option, (char *)&optVal, sizeof(optVal));
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