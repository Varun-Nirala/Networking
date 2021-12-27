#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "helper.h"
#include "address.h"
#include "buffer.h"

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
	int						_sockType{-1};
	int						_protocol{-1};

	CommData() { std::memset(&_addr, 0, sizeof(sockaddr_storage)); }

	CommData(const CommData&) = delete;
	CommData& operator=(const CommData&) = delete;

	CommData(CommData&& other) noexcept;
	CommData& operator=(CommData&& other) noexcept;

	inline std::string getIP() const { return HelperMethods::getIP(&_addr); }
	inline int getPort() const { return HelperMethods::getPort(&_addr);}
	inline int getFamily() const { return _addr.ss_family; }
	inline int getSocketType() const { return _sockType; }
	inline int getProtocol() const { return _protocol; }
	inline bool isTCP() const { return _sockType == SOCK_STREAM; }
	inline bool isIPv4() const { return _addr.ss_family == AF_INET; }
	inline void print() const;
};

class Socket
{
public:
	Socket() = default;
	~Socket() { clear(); };

	Socket(const Socket&) = delete;
	Socket& operator=(const Socket&) = delete;

	Socket(Socket &&other) noexcept;
	Socket& operator=(Socket &&other) noexcept;

	inline bool init(const std::string& pAddr, const std::string& pService, bool tcp, int family);

	inline void setBacklog(int val) { m_backlog = val; }
	inline int getBacklog() const { return m_backlog; }

	inline const Address& getAddress() const { return m_address; }
	inline Address& getAddress() { return m_address; }

	inline SOCKET_TYPE getSocketId() const { return m_socketFd; }
	inline bool isActive() const { return !(m_socketFd == INVALID_SOCKET); }

	inline int getFamily() const { return m_address.getFamily(); }

	inline int getSocketType() const { return m_address.getSocketType(); }
	inline int getProtocol() const { return m_address.getProtocol(); }
	inline int getFlags() const { return m_address.getFlags(); }
	inline sockaddr* getai_addr() const { return m_address.getai_addr(); }
	inline int getai_addrlen() const { return m_address.getai_addrlen();; }

	inline std::string getHostname() const { return m_address.getHostname(); }
	inline bool isTCP() const { return m_address.isTCP(); }
	inline bool isIPv4() const { return m_address.isIPv4(); }
	int getPort() const { return m_address.port(); }
	const std::string getIPAddress() const { return m_address.IP(); }

	bool bind() const;
	bool listen() const;
	bool accept(struct sockaddr_storage &theirAddr, SOCKET_TYPE &sId) const;
	bool connect() const;

	void clear();

	bool sendTcp(const SOCKET_TYPE useSocket, const std::string& msg, int& sentBytes);
	bool sendTcp(const std::string& msg, int& sentBytes);

	bool recvTcp(const SOCKET_TYPE useSocket, const std::string& msg, const int maxSize);
	bool recvTcp(const std::string& msg, const int maxSize);

	bool sendDatagram(const SOCKET_TYPE useSocket, const struct sockaddr_storage& theirAddr, const std::string& msg, int& sentBytes);
	bool sendDatagram(const struct sockaddr_storage& theirAddr, const std::string& msg, int& sentBytes);

	bool recvDatagram(SOCKET_TYPE useSocket, struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize);
	bool recvDatagram(struct sockaddr_storage& theirAddr, const std::string& msg, const int maxSize);

	void print() const;

protected:
	bool close();
	bool init();
	bool getValidSocket();
	bool setSocketOptions(const bool reuseAddr, const bool reusePort);

	

private:
	SOCKET_TYPE								m_socketFd{ INVALID_SOCKET };	// Socket file descriptor
	Address									m_address;
	int										m_backlog{5};
	nsUtil::Buffer							m_buffer;
};

Socket::Socket(Socket&& other) noexcept
{
	m_socketFd = std::exchange(other.m_socketFd, INVALID_SOCKET);
	m_address = std::exchange(other.m_address, Address());
	m_backlog = std::exchange(other.m_backlog, 0);
	m_buffer = std::exchange(other.m_buffer, nsUtil::Buffer());
}

Socket& Socket::operator=(Socket&& other) noexcept
{
	if (this != &other)
	{
		clear();
		m_socketFd = std::exchange(other.m_socketFd, INVALID_SOCKET);
		m_address = std::exchange(other.m_address, Address());
		m_backlog = std::exchange(other.m_backlog, 0);
		m_buffer = std::exchange(other.m_buffer, nsUtil::Buffer());
	}
	return *this;
}

bool Socket::close()
{
	if (m_socketFd == INVALID_SOCKET)
	{
		return true;
	}
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
	Logger::LOG_INFO("Socket close success.\n");
	return true;
}

bool Socket::init(const std::string& pAddr, const std::string& pService, bool tcp, int family)
{
	clear();
	if (!m_address.init(pAddr, pService, tcp, family))
	{
		Logger::LOG_ERROR("Socket init failed.\n");
	}
	return init();
}

bool Socket::bind() const
{
	IF_NOTACTIVE_RETURN(false);
	if (::bind(m_socketFd, m_address.getaddress()->ai_addr, static_cast<int>(m_address.getaddress()->ai_addrlen)) == -1)
	{
		Logger::LOG_ERROR("Socket bind error. Error code :", getErrorCode(), '\n');
		return false;
	}
	Logger::LOG_INFO("Socket bind success.\n");
	return true;
}

bool Socket::listen() const
{
	if (::listen(m_socketFd, m_backlog) == -1)
	{
		Logger::LOG_ERROR("Socket listen error. Error code :", getErrorCode(), '\n');
		return false;
	}
	Logger::LOG_INFO("Socket listen success.\n");
	return true;
}

bool Socket::accept(struct sockaddr_storage& theirAddr, SOCKET_TYPE& sId) const
{
	sId = INVALID_SOCKET;
	IF_NOTACTIVE_RETURN(false);
	
	socklen_t addr_size = sizeof(theirAddr);
	memset(&theirAddr, 0, addr_size);

	sId = ::accept(m_socketFd, (struct sockaddr*)&theirAddr, &addr_size);
	if (sId == -1)
	{
		Logger::LOG_ERROR("Connection accept error. Error code :", getErrorCode(), '\n');
		return sId;
	}
	Logger::LOG_INFO("Connection accepted. Their socket ID :", sId, '\n');
	return true;
}

bool Socket::connect() const
{
	IF_NOTACTIVE_RETURN(false);

	if (::connect(m_socketFd, m_address.getaddress()->ai_addr, static_cast<int>(m_address.getaddress()->ai_addrlen)) == -1)
	{
		Logger::LOG_ERROR("Socket connect error. Error code :", getErrorCode(), '\n');
		return false;
	}
	Logger::LOG_INFO("Socket connect success.\n");
	return true;
}

void Socket::clear()
{
	m_address.clear();
	m_buffer.clear();
	close();
}

bool Socket::sendTcp(SOCKET_TYPE useSocket, const std::string& msg, int& sentBytes)
{
	if (msg.empty())
	{
		Logger::LOG_MSG("Trying to send empty msg.\n");
		return false;
	}
	sentBytes = ::send(useSocket, msg.c_str(), static_cast<int>(msg.size()), 0);
	if (sentBytes == -1)
	{
		Logger::LOG_ERROR("Send error. Error code :", getErrorCode(), '\n');
		return false;
	}
	else if (sentBytes == 0)
	{
		Logger::LOG_INFO("Connecton closed by server on socket :", useSocket, '\n');
		return false;
	}
	if (msg.size() > sentBytes)
	{
		Logger::LOG_MSG("Tried sending   :", msg.size(), "Bytes, Sent :", sentBytes, ", Unsent :", msg.size() - sentBytes, "Bytes.\n");
	}
	else
	{
		Logger::LOG_MSG("Whole message sent successfully.\n");
	}
	
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
		Logger::LOG_INFO("Connecton closed by server on socket :", useSocket, '\n');
		return false;
	}
	Logger::LOG_MSG("Packet length   :", recvBytes, "Packet :", m_buffer.get(), '\n');
	return true;
}

bool Socket::recvTcp(const std::string& msg, const int maxSize)
{
	return recvTcp(m_socketFd, msg, maxSize);
}

bool Socket::sendDatagram(const SOCKET_TYPE useSocket, const struct sockaddr_storage& theirAddr, const std::string& msg, int& sentBytes)
{
	sentBytes = ::sendto(useSocket, msg.c_str(), static_cast<int>(msg.size()), 0, (struct sockaddr*)&theirAddr, static_cast<int>(sizeof(theirAddr)));
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
	if (msg.size() > sentBytes)
	{
		Logger::LOG_MSG("Tried sending   :", msg.size(), "Bytes, Sent :", sentBytes, ", Unsent :", msg.size() - sentBytes, "Bytes.\n");
	}
	else
	{
		Logger::LOG_MSG("Whole message sent successfully.\n");
	}
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
	if (!getValidSocket() || !setSocketOptions(true, true))
	{
		Logger::LOG_ERROR("Socket setup error.\n");
		return false;
	}
	Logger::LOG_MSG("Socket created  :", m_socketFd, '\n');
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
	Logger::LOG_INFO("setsockopt API success.\n");
	return true;
}

void Socket::print() const
{
	Logger::LOG_MSG("Socket          :", m_socketFd, '\n');
	Logger::LOG_MSG("Backlog         :", m_backlog, '\n');
	m_address.print();
	Logger::LOG_MSG("\n\n");
}



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
}

#endif //#ifndef __SOCKET_H__
