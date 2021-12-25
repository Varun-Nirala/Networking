#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "helper.h"
#include "address.h"

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
#define IF_NOTACTIVE_RETURN(x)						\
  do {												\
    if (!isActive()) {								\
      Logger::LOG_ERROR("Socket not active.\n");      \
      return x;										\
    }												\
  } while (0);

#if defined(PLATFORM_WIN)
	using SOCKET_TYPE = SOCKET;
#elif defined(PLATFORM_UNIX)
	using SOCKET_TYPE = int;
	#define INVALID_SOCKET -1
#endif

struct CommData
{
	sockaddr_storage		_addr;
	SOCKET_TYPE				_sId{ INVALID_SOCKET };

	CommData()
	{
		std::memset(&_addr, 0, sizeof(sockaddr_storage));
	}

	inline std::string getIP() const { return HelperMethods::getIP((struct addrinfo*)&(_addr)); }
	inline int getPort() const { return HelperMethods::getPort((struct addrinfo*)&(_addr));}
	inline int getFamily() const { return ((struct addrinfo*)&(_addr))->ai_family; }
	inline std::string getHostname() const { return ((struct addrinfo*)&(_addr))->ai_canonname; }
	inline bool isTCP() const { return ((struct addrinfo*)&(_addr))->ai_socktype == SOCK_STREAM; }
	inline bool isIPv4() const { return ((struct addrinfo*)&(_addr))->ai_family == AF_INET; }
};

class Socket
{
public:
	Socket() = default;
	~Socket() { clear(); };

	Socket(const Socket& sock) = delete;
	Socket& operator=(const Socket& sock) = delete;

	Socket(Socket&& sock) = default;
	Socket& operator=(Socket && sock) = default;

	inline bool init(const std::string& pAddr, const std::string& pService, bool tcp, int family);

	inline void setBacklog(int val) { m_backlog = val; }

	inline const Address& getAddress() const { return m_address; }
	inline Address& getAddress() { return m_address; }

	inline SOCKET_TYPE getSocketId() const { return m_socketFd; }
	inline bool isActive() const { return !(m_socketFd == INVALID_SOCKET); }

	inline int getFamily() const { return m_address.getFamily(); }
	inline std::string getHostname() const { return m_address.getHostname(); }
	inline bool isTCP() const { return m_address.isTCP(); }
	inline bool isIPv4() const { return m_address.isIPv4(); }
	int getPort() const { return m_address.port(); }
	const std::string getIPAddress() const { return m_address.IP(); }

	bool bind();
	bool listen();
	bool accept(struct sockaddr_storage &theirAddr, SOCKET_TYPE &sId);
	bool connect();

	void clear();

	bool sendTcp(const SOCKET_TYPE useSocket, const std::string& msg, int& sentBytes);
	bool sendTcp(const std::string& msg, int& sentBytes);

	bool recvTcp(const SOCKET_TYPE useSocket, const std::string& msg, const int maxSize);
	bool recvTcp(const std::string& msg, const int maxSize);

	bool sendDatagram(const SOCKET_TYPE useSocket, const struct sockaddr_storage& theirAddr, const std::string& msg, int& sentBytes);
	bool sendDatagram(const struct sockaddr_storage& theirAddr, const std::string& msg, int& sentBytes);

	bool recvDatagram(SOCKET_TYPE useSocket, struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize);
	bool recvDatagram(struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize);

protected:
	bool close();
	bool init();
	bool getValidSocket();
	bool setSocketOptions(const bool reuseAddr, const bool reusePort);

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
	SOCKET_TYPE								m_socketFd{ INVALID_SOCKET };	// Socket file descriptor
	Address									m_address;
	int										m_backlog{5};
	Buffer									m_buffer;
};

bool Socket::close()
{
	IF_NOTACTIVE_RETURN(true);
	int ret{};

#if defined(PLATFORM_WIN)
	ret = closesocket(m_socketFd);
#else
	ret = ::close(m_socketFd);
#endif

	if (ret != 0)
	{
		m_socketFd = -1;
		Logger::LOG_ERROR("Socket close error. Error code :", getErrorCode(), '\n');
		return false;
	}
	m_socketFd = -1;
	Logger::LOG_MSG("Socket close success.\n");
	return true;
}

bool Socket::init(const std::string& pAddr, const std::string& pService, bool tcp, int family)
{
	clear();
	m_address.init(pAddr, pService, tcp, family);
	return init();
}

bool Socket::bind()
{
	IF_NOTACTIVE_RETURN(false);
	if (::bind(m_socketFd, m_address.getaddress()->ai_addr, m_address.getaddress()->ai_addrlen) == -1)
	{
		Logger::LOG_ERROR("Socket bind error. Error code :", getErrorCode(), '\n');
		return false;
	}
	Logger::LOG_MSG("Socket bind success.\n");
	return true;
}

bool Socket::listen()
{
	if (::listen(m_socketFd, m_backlog) == -1)
	{
		Logger::LOG_ERROR("Socket listen error. Error code :", getErrorCode(), '\n');
		return false;
	}
	Logger::LOG_MSG("Socket listen success.\n");
	return true;
}

bool Socket::accept(struct sockaddr_storage& theirAddr, SOCKET_TYPE& sId)
{
	sId = -1;
	IF_NOTACTIVE_RETURN(false);
	
	socklen_t addr_size = sizeof(theirAddr);
	memset(&theirAddr, 0, addr_size);

	sId = ::accept(m_socketFd, (struct sockaddr*)&theirAddr, &addr_size);
	if (sId == -1)
	{
		Logger::LOG_ERROR("Connection accept error. Error code :", getErrorCode(), '\n');
		return sId;
	}
	Logger::LOG_MSG("Connection accepted. Their socket ID :", sId, '\n');
	return true;
}

bool Socket::connect()
{
	IF_NOTACTIVE_RETURN(false);

	if (::connect(m_socketFd, m_address.getaddress()->ai_addr, m_address.getaddress()->ai_addrlen) == -1)
	{
		Logger::LOG_ERROR("Socket connect error. Error code :", getErrorCode(), '\n');
		return false;
	}
	Logger::LOG_MSG("Socket connect success.\n");
	return true;
}

void Socket::clear()
{
	close();
	m_address.clear();
	m_buffer.clear();
}

bool Socket::sendTcp(SOCKET_TYPE useSocket, const std::string& msg, int& sentBytes)
{
	if (msg.empty())
	{
		Logger::LOG_MSG("Trying to send empty msg.\n");
		return false;
	}

	sentBytes = ::send(useSocket, msg.c_str(), msg.size(), 0);
	if (sentBytes == -1)
	{
		Logger::LOG_ERROR("Send error. Error code :", getErrorCode(), '\n');
		return false;
	}
	else if (sentBytes == 0)
	{
		Logger::LOG_ERROR("Connecton closed by server on socket :", useSocket, '\n');
		return false;
	}
	Logger::LOG_MSG("Sent byte count :", sentBytes, '\n');
	return true;
}

bool Socket::sendTcp(const std::string& msg, int& sentBytes)
{
	return sendTcp(m_socketFd, msg, sentBytes);
}

bool Socket::recvTcp(const SOCKET_TYPE useSocket, const std::string& msg, const int maxSize)
{
	if (m_buffer.empty() || m_buffer.size() < maxSize)
	{
		m_buffer.init(maxSize);
	}
	int recvBytes = ::recv(useSocket, m_buffer.get(), maxSize - 1, 0);
	if (recvBytes == -1)
	{
		Logger::LOG_ERROR("Recieve error. Error code :", useSocket, '\n');
		return false;
	}
	else if (recvBytes == 0)
	{
		Logger::LOG_ERROR("Connecton closed by server on socket :", useSocket, '\n');
		return false;
	}
	Logger::LOG_MSG("Packet length :", recvBytes, "Packet :", m_buffer.get(), '\n');
	return true;
}

bool Socket::recvTcp(const std::string& msg, const int maxSize)
{
	return recvTcp(m_socketFd, msg, maxSize);
}

bool Socket::sendDatagram(const SOCKET_TYPE useSocket, const struct sockaddr_storage& theirAddr, const std::string& msg, int& sentBytes)
{
	sentBytes = ::sendto(useSocket, msg.c_str(), msg.size(), 0, (struct sockaddr*)&theirAddr, sizeof(theirAddr));
	if (sentBytes == -1)
	{
		Logger::LOG_ERROR("Send error. Error code :", getErrorCode(), '\n');
		return false;
	}
	else if (sentBytes == 0)
	{
		Logger::LOG_ERROR("Connecton closed by server on socket :", useSocket, '\n');
		return false;
	}
	Logger::LOG_MSG("Sent byte count :", sentBytes, '\n');
	return true;
}

bool Socket::sendDatagram(const struct sockaddr_storage& theirAddr, const std::string& msg, int& sentBytes)
{
	return sendDatagram(m_socketFd, theirAddr, msg, sentBytes);
}

bool Socket::recvDatagram(const SOCKET_TYPE useSocket, struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize)
{
	if (m_buffer.empty() || m_buffer.size() < maxSize)
	{
		m_buffer.init(maxSize);
	}
	socklen_t addr_size = sizeof(theirAddr);
	memset(&theirAddr, 0, addr_size);

	int recvBytes = ::recvfrom(useSocket, m_buffer.get(), maxSize - 1, 0, (struct sockaddr*)&theirAddr, &addr_size);

	if (recvBytes == -1)
	{
		Logger::LOG_ERROR("Recieve error. Error code :", useSocket, '\n');
		return false;
	}
	m_buffer[recvBytes] = '\0';
	std::string ip = HelperMethods::getIP((struct addrinfo*)&theirAddr);
	Logger::LOG_MSG("Got packet from :", ip, "Packet length :", recvBytes, "Packet :", m_buffer.get(), '\n');
	return true;
}

bool Socket::recvDatagram(struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize)
{
	return recvDatagram(m_socketFd, theirAddr, msg, maxSize);
}

bool Socket::init()
{
	if (!onetimeSetup() || !getValidSocket() || !setSocketOptions(true, true))
	{
		Logger::LOG_ERROR("Socket setup error.\n");
		return false;
	}
	Logger::LOG_MSG("Socket created : ", m_socketFd, '\n');
	return true;
}

bool Socket::getValidSocket()
{
	// Create Socket
	const struct addrinfo* p = m_address.getNextAddress();
	while (p)
	{
		m_socketFd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (m_socketFd != -1)
		{
			break;
		}
		p = m_address.getNextAddress();
	}
	if (!p)
	{
		Logger::LOG_ERROR("Socket creation error. Error code :", m_socketFd, '\n');
		return false;
	}
	Logger::LOG_MSG("Socket creation success. Socket ID :", m_socketFd, '\n');
	return true;
}

bool Socket::setSocketOptions(const bool reuseAddr, const bool reusePort)
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
		Logger::LOG_ERROR("Socket option settting error. Error code :", getErrorCode(), '\n');
		return false;
	}
	Logger::LOG_MSG("Socket option settting success.\n");
	return true;
}
}

#endif //#ifndef __SOCKET_H__