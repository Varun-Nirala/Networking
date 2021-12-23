#ifndef __SERVER_H__
#define __SERVER_H__

#include "socket.h"
#include <unordered_map>

namespace nsNW
{
class Server
{
public:
	Server() = default;
	~Server() = default;

	bool initConnection(const std::string& addr, const std::string& port, bool tcp, bool ipv4);
	bool initConnection(const std::string& addr, const std::string& port, bool tcp);

	bool listen();
	bool accept(std::string clientUniqueName = "");

	bool read(std::string& msg, const int maxSize = 1000);
	bool write(std::string to, std::string& msg);

	void print() const;
private:
	inline bool initTCP(Socket& socket, const std::string& addr, const std::string& port, int family);
	inline bool initUDP(Socket& socket, const std::string& addr, const std::string& port, int family);

private:
	int												m_backLog{ 5 };
	Socket											m_socket;
	std::unordered_map<std::string, CommData>		m_clients;
	
};

bool Server::initConnection(const std::string& addr, const std::string& port, bool tcp, bool ipv4)
{
	return tcp ? initTCP(m_socket, addr, port, ipv4 ? AF_INET : AF_INET6) : initUDP(m_socket, addr, port, ipv4 ? AF_INET : AF_INET6);
}

bool Server::initConnection(const std::string& addr, const std::string& port, bool tcp)
{
	return tcp ? initTCP(m_socket, addr, port, AF_UNSPEC) : initUDP(m_socket, addr, port, AF_UNSPEC);
}

bool Server::listen()
{
	PRINT_MSG("Server listening for connection...");
	if (m_socket.listen())
	{
		PRINT_MSG("Server got connect request...");
		return true;	
	}
	PRINT_MSG("Server listen failed");
	return false;
}

bool Server::accept(std::string clientUniqueName)
{
	CommData client;
	if (m_socket.accept(client._addr, client._sId))
	{
		PRINT_MSG("Server accepted connect request from ID : " + std::to_string(client._sId) + " : " + getIP((addrinfo *)(&client._addr)));
		if (clientUniqueName.empty())
		{
			m_clients[std::to_string(client._sId)] = client;
		}
		else
		{
			m_clients[clientUniqueName] = client;
		}
		
		return true;
	}
	PRINT_MSG("Server accept failed");
	return false;
}

bool Server::read(std::string& msg, const int maxSize)
{
	bool ret{};
	if (m_socket.isTCP())
	{
		ret = m_socket.recvTcp(msg, maxSize);
	}
	else
	{
		std::string clientId;
		CommData data;
		ret = m_socket.recvDatagram(data._addr, msg, maxSize);
		clientId = getPortIP((addrinfo*)&data._addr);
		m_clients[clientId] = data;
		PRINT_MSG("Server Id : " + clientId);

		CommData client;
		ret = m_socket.recvDatagram(client._addr, msg, maxSize);
	}
	PRINT_MSG("Got msg : " + msg);
	return ret;
}

bool Server::write(std::string to, std::string& msg)
{
	bool ret{};
	int sentBytes{};
	if (m_socket.isTCP())
	{
		ret = m_socket.sendTcp(msg, sentBytes);
	}
	else
	{
		ret = m_socket.sendDatagram(m_clients[to]._addr, msg, sentBytes);
	}
	PRINT_MSG("Tried sending msg[" + std::to_string(msg.size()) + "]   : " + msg);
	PRINT_MSG("Number of bytes sent : " + std::to_string(sentBytes));
	return ret;
}

void Server::print() const
{
	std::string msg{ "Server Data :\n" };
	msg += "\t ID      : " + std::to_string(m_socket.getSocketId()) + "\n";
	msg += "\t Is IPv4 : " + std::to_string(m_socket.isIPv4()) + "\n";
	msg += "\t Is TCP  : " + std::to_string(m_socket.isTCP()) + "\n";
	PRINT_MSG("Server ID : ");
}

bool Server::initTCP(Socket& socket, const std::string& addr, const std::string& port, int family)
{
	if (socket.isActive())
	{
		socket.clear();
	}
	m_socket.setBacklog(m_backLog);
	if (m_socket.init(addr, port, true, family))
	{
		PRINT_MSG("Got socket : " + std::to_string(m_socket.getSocketId()));
		if (m_socket.bind())
		{
			PRINT_MSG("Socket bind success.");
			return true;
		}
		PRINT_MSG("Socket bind failed.");
	}
	PRINT_MSG("Socket creation failed.");
	return false;
}

bool Server::initUDP(Socket& socket, const std::string& addr, const std::string& port, int family)
{
	if (socket.isActive())
	{
		socket.clear();
	}
	m_socket.setBacklog(m_backLog);
	if (m_socket.init(addr, port, true, family))
	{
		PRINT_MSG("Got socket : " + std::to_string(m_socket.getSocketId()));
		if (m_socket.bind())
		{
			PRINT_MSG("Socket bind success.");
			return true;
		}
		PRINT_MSG("Socket bind failed.");
	}
	PRINT_MSG("Socket creation failed.");
	return false;
}
}
#endif // #ifndef __SERVER_H__