#include "socket.h"
#include "helper.h"
#include <cstring>
#include <string>

namespace nsNW
{
#define IF_NOTACTIVE_RETURN(x) ({\
			if (!isActive())\
			{\
				LOG_ERROR("No active socket.");\
				return x;\
			}})


Address::Address(bool tcp, const char* pService, const char* pAddr)
	: m_szIP(pAddr)
	, m_szService(pService)
{
	memset(&m_hints, 0, sizeof(m_hints));

	m_hints.ai_family = AF_UNSPEC;	// AF_INET or AF_INET6;
	m_hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;
	if (!pAddr)
	{
		m_hints.ai_flags = AI_PASSIVE;
	}

	getAddressInfo(pAddr, pService);
}

Address::~Address()
{
	m_vecAddrInfo.clear();
	freeaddrinfo(m_pServinfo);	// Free the Link List
}

void Address::print()
{
	PRINT_MSG("IP Addresses for " + m_szIP + " , Service : " + m_szService + " :");

	if (m_pServinfo)
	{
		addrinfo *p{};

		for (p = m_pServinfo; p != nullptr; p = p->ai_next)
		{
			void *addr{};
			std::string ipver;

			if (p->ai_family == AF_INET)
			{
				sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
				addr = &(ipv4->sin_addr);
				ipver = "IPv4";
			}
			else if (p->ai_family == AF_INET6)
			{
				sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
				addr = &(ipv6->sin6_addr);
				ipver = "IPv6";
			}
			char ipstr[INET6_ADDRSTRLEN];
			inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));

			PRINT_MSG("\t" + ipver + " : " + ipstr);
		}
	}
}

int Address::getPort(int id) const
{
	int port;
	if (isIPv4(id))
	{
		sockaddr_in* ipv4 = (struct sockaddr_in*)m_vecAddrInfo[id]->ai_addr;
		port = isIPv4->sin_port;
	}
	else
	{
		sockaddr_in6* ipv6 = (struct sockaddr_in6*)m_vecAddrInfo[id]->ai_addr;
		port = isIPv4->sin6_port;
	}
	
	return ntohs(port);
}

std::string Address::getService() const
{
	return m_szService;
}

int Address::getFamily(int id) const
{
	return m_vecAddrInfo[id]->ai_family;
}

bool Address::isTCP(int id) const
{
	return m_vecAddrInfo[id]->ai_socktype == SOCK_STREAM;
}

bool Address::isIPv4(int id) const
{
	return getFamily(id) == AF_INET;
}

std::string Address::getIP(int id) const
{
	void* addr{};
	char ipstr[INET6_ADDRSTRLEN];
	if (isIPv4(id))
	{
		sockaddr_in *ipv4 = (struct sockaddr_in*)m_vecAddrInfo[id]->ai_addr;
		addr = &(ipv4->sin_addr);
	}
	else
	{
		sockaddr_in6 *ipv6 = (struct sockaddr_in6*)m_vecAddrInfo[id]->ai_addr;
		addr = &(ipv6->sin6_addr);
	}
	inet_ntop(getFamily(id), addr, ipstr, sizeof(INET6_ADDRSTRLEN));
	
	return std::string(ipstr);
}

std::string Address::getHostname(int id) const
{
	return std::string(m_vecAddrInfo[id]->ai_canonname);
}

bool Address::fillAddressInfo(const char* pService, const char* pAdd)
{
	m_vecAddrInfo.clear();
	if (m_pServinfo)
	{
		freeaddrinfo(m_pServinfo);	// Free the Link List
		m_pServinfo = nullptr;
	}
	if (getaddrinfo(pAdd, pService, &m_hints, &m_pServinfo) == 0)
	{
		for (addrinfo* p = m_pServinfo; p != nullptr; p = p->ai_next)
		{
			m_vecAddrInfo.push_back(p);
		}
		return true;
	}
	return false;
}





Socket::Socket(bool tcp, const std::string& pService, const std::string& pAddr)
	: m_address(tcp, pService.c_str(), pAddr.c_str())
{
	if (!createConnection() || !setOptions(true, true))
	{
		LOG_ERROR("Socket setup error.");
		return;
	}
	PRINT_MSG("Socket created : " + std::to_string(m_desc));
}

int Socket::getPort() const
{
	IF_NOTACTIVE_RETURN(-1);
	if (m_pSa)
	{
		return ntohs(m_pSa->sin_port);
	}
	return ntohs(m_pSa6->sin6_port);
}

const std::string Socket::getAddress() const
{
	std::string str;
	IF_NOTACTIVE_RETURN(str);
	if (m_pSa)
	{
		
		inet_ntop(AF_INET, &(m_pSa->sin_addr), ip4, INET_ADDRSTRLEN);
		str = ip4;
	}
	else if (m_pSa6)
	{
		char ip6[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &(m_pSa6->sin6_addr), ip6, INET6_ADDRSTRLEN);
		str = ip6;
	}
	return str;
}

int Socket::accept()
{
	int connID{ -1 };
	IF_NOTACTIVE_RETURN(connID);
	
	if (m_pSa)
	{
		socklen_t addrLen = sizeof(sockaddr_in);
		connID = ::accept(m_desc, (struct sockaddr*)(m_pSa.get()), &addrLen);
	}
	else if (m_pSa6)
	{
		socklen_t addrLen = sizeof(sockaddr_in6);
		connID = ::accept(m_desc, (struct sockaddr*)(m_pSa6.get()), &addrLen);
	}
	if (connID < 0)
	{
		LOG_ERROR("Connection accept error. Error code : " + std::to_string(connID));
	}
	else
	{
		LOG_ERROR("Connection accepted. connID = " + std::to_string(connID));
	}
	
	return connID;
}

bool Socket::connect()
{
	IF_NOTACTIVE_RETURN(false);

	bool ret{ true };
	if (m_pSa)
	{
		ret = ::connect(m_desc, (struct sockaddr *)(m_pSa.get()), sizeof(sockaddr_in)) == 0;
	}
	else if (m_pSa6)
	{
		ret = ::connect(m_desc, (struct sockaddr *)(m_pSa6.get()), sizeof(sockaddr_in6)) == 0;
	}
	if (!ret)
	{
		LOG_ERROR("Connect error.");
		return false;
	}
	PRINT_MSG("Connection Successful.");
	return true;
}

bool Socket::bind()
{
	IF_NOTACTIVE_RETURN(false);

	bool ret{ true };

	if (m_pSa)
	{
		ret = ::bind(m_desc, (struct sockaddr*)(m_pSa.get()), sizeof(sockaddr_in)) == 0;
	}
	else if (m_pSa6)
	{
		ret = ::bind(m_desc, (struct sockaddr*)(m_pSa6.get()), sizeof(sockaddr_in6)) == 0;
	}
	if (!ret)
	{
		LOG_ERROR("Bind error.");
		return false;
	}
	PRINT_MSG("Connection Successful.");
	return true;
}

bool Socket::close()
{
	IF_NOTACTIVE_RETURN(true);
	int ret = ::close(m_desc);
	// TODO @ ret != 0 ERROR
	return (ret == 0);
}

bool Socket::createConnection()
{
	// Create Socket
	if (m_pSa)
	{
		m_desc = socket(m_pSa->sin_family, (m_connType == ConnType::TCP ? SOCK_STREAM : SOCK_DGRAM), 0);
	}
	else if (m_pSa6)
	{
		m_desc = socket(m_pSa6->sin6_family, (m_connType == ConnType::TCP ? SOCK_STREAM : SOCK_DGRAM), 0);
	}
	if (m_desc == 0)
	{
		LOG_ERROR("Socket creation error. Error code : " + std::to_string(m_desc));
		return false;
	}
	return true;
}

bool Socket::setOptions(bool reuseAddr, bool reusePort)
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
	return setsockopt(m_desc, SOL_SOCKET, option, &optVal, sizeof(optVal)) == 0;
}

bool Socket::parseAsIPv4(int port, const std::string& addr, sockaddr_in &sockAddr)
{
	std::memset(sockAddr, 0, sizeof(sockAddr));
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = parsePort(port);
	parseAddress(addr);
}

bool Socket::parseAsIPv6(int port, const std::string& addr)
{
	m_pSa6 = std::make_unique<sockaddr_in6>();
	std::memset(m_pSa6.get(), 0, sizeof(sockaddr_in6));
	m_pSa6->sin6_family = AF_INET6;
	m_pSa6->sin6_port = parsePort(port);
	parseAddress(addr);
}

bool Socket::parseAddress(const std::string& addr)
{
	bool ret{true};
	if (addr == "INADDR_ANY")
	{
		if (m_pSa)
		{
			m_pSa->sin_addr.s_addr = INADDR_ANY;
		}
		else if (m_pSa6)
		{
			m_pSa6->sin6_addr = in6addr_any;
		}
	}
	else
	{
		if (m_pSa)
		{
			ret = inet_pton(AF_INET, addr.c_str(), &(m_pSa->sin_addr)) == 1; // IPv4
		}
		else if (m_pSa6)
		{
			ret = inet_pton(AF_INET6, addr.c_str(), &(m_pSa6->sin6_addr)) == 1; // IPv6
		}
	}
	return ret;
}

uint16_t Socket::parsePort(int port) const
{
	return htons(port);
}
}