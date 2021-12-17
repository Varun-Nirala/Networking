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


Address::Address(bool tcp, bool ipv4, const std::string service, const std::string& ipaddr)
{
	memset(&m_hints, 0, sizeof(m_hints));
	m_hints.ai_family = ipv4 ? AF_INET : AF_INET6;
	m_hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;

	if (ipaddr.empty())
	{
		m_hints.ai_flags = AI_PASSIVE;
	}
	m_szIP = ipaddr;
	m_szService = service;
}

Address::~Address()
{
	freeaddrinfo(m_pServinfo);	// Free the Link List
}

void Address::print()
{
	PRINT_MSG("IP Addresses for " + m_szIP + " :");

	if (getAddressInfo())
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

bool Address::getAddressInfo()
{
	if (m_pServinfo)
	{
		freeaddrinfo(m_pServinfo);	// Free the Link List
		m_pServinfo = nullptr;
	}
	return getaddrinfo(m_szIP.empty() ? nullptr : m_szIP.c_str(), m_szService.c_str(), &m_hints, &m_pServinfo) == 0;
}





Socket::Socket(bool tcp, bool ipv4, int port, const std::string& addr)
{
	m_connType = tcp ? ConnType::TCP : ConnType::UDP;
	bool ret = ipv4 ? parseAsIPv4(port, addr) : parseAsIPv6(port, addr);
	if (!ret || !createConnection() || !setOptions(true, true))
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
		char ip4[INET_ADDRSTRLEN];
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

bool Socket::parseAsIPv4(int port, const std::string& addr)
{
	m_pSa = std::make_unique<sockaddr_in>();
	std::memset(m_pSa.get(), 0, sizeof(sockaddr_in));
	m_pSa->sin_family = AF_INET;
	m_pSa->sin_port = parsePort(port);
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