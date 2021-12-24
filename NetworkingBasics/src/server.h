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

	bool startServer(const std::string& addr, const std::string& port, bool tcp, bool ipv4);
	bool startServer(const std::string& addr, const std::string& port, bool tcp);

	inline SOCKET_TYPE getSocketId() const { return m_socket.getSocketId(); }
	inline std::string getIPAddress() const { return m_socket.getIPAddress(); }
	inline int getPort() const { return m_socket.getPort(); }
	inline int getFamily() const { return m_socket.getFamily(); }
	inline std::string getHostname() const { return m_socket.getHostname(); }
	inline bool isTCP() const { return m_socket.isTCP(); }
	inline bool isIPv4() const { return m_socket.isIPv4(); }

	bool acceptConnection(std::string& clientName);

	SOCKET_TYPE getClientSocketId(const std::string& clientName) const;

	bool read(const std::string from, std::string& msg, const int maxSize = 1000);
	bool write(const std::string to, std::string& msg);

	void print() const;
private:
	bool addClient(CommData& commData, std::string& clientName, const std::string &msg);

	inline bool initTCP(Socket& socket, const std::string& addr, const std::string& port, int family);
	inline bool initUDP(Socket& socket, const std::string& addr, const std::string& port, int family);

private:
	int												m_backLog{ 5 };
	Socket											m_socket;
	std::unordered_map<std::string, CommData>		m_clients;
	
};

bool Server::startServer(const std::string& addr, const std::string& port, bool tcp, bool ipv4)
{
	return tcp ? initTCP(m_socket, addr, port, ipv4 ? AF_INET : AF_INET6) : initUDP(m_socket, addr, port, ipv4 ? AF_INET : AF_INET6);
}

bool Server::startServer(const std::string& addr, const std::string& port, bool tcp)
{
	return tcp ? initTCP(m_socket, addr, port, AF_UNSPEC) : initUDP(m_socket, addr, port, AF_UNSPEC);
}

bool Server::acceptConnection(std::string& clientName)
{
	PRINT_MSG("Server is listening for connection...");
	if (m_socket.listen())
	{
		PRINT_MSG("Server got connection request...");
		CommData client;
		if (m_socket.accept(client._addr, client._sId))
		{
			addClient(client, clientName, "Server accepted connect request from ");
			return true;
		}
		PRINT_MSG("Server failed to accept connection request.");
	}
	PRINT_MSG("Server listen failed.");
	return false;
}

SOCKET_TYPE Server::getClientSocketId(const std::string& clientName) const
{
	if (m_clients.count(clientName))
	{
		return m_clients.at(clientName)._sId;
	}
	return INVALID_SOCKET;
}


bool Server::read(const std::string from, std::string& msg, const int maxSize)
{
	bool ret{false};
	
	if (m_clients.count(from))
	{
		const CommData& data = m_clients.at(from);
		if (data.isTCP())
		{
			ret = m_socket.recvTcp(data._sId, msg, maxSize);
		}
		else
		{
			CommData c;
			ret = m_socket.recvDatagram(data._sId, c._addr, msg, maxSize);
		}
		PRINT_MSG("Recieved : " + msg);
	}
	else
	{
		LOG_ERROR("No such connection : " + from);
	}
	return ret;
}

bool Server::write(const std::string to, std::string& msg)
{
	bool ret{ false };
	int sentBytes{};
	if (m_clients.count(to))
	{
		const CommData& data = m_clients.at(to);
		if (data.isTCP())
		{
			ret = m_socket.sendTcp(data._sId, msg, sentBytes);
		}
		else
		{
			CommData c;
			ret = m_socket.sendDatagram(data._sId, c._addr, msg, sentBytes);
		}
		PRINT_MSG("Sent bytes : " + std::to_string(ret));
	}
	else
	{
		LOG_ERROR("No such connection : " + to);
	}
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

bool Server::addClient(CommData& commData, std::string& clientName, const std::string &msg)
{
	clientName = std::to_string(commData._sId);
	PRINT_MSG(msg + clientName + " : " + HelperMethods::getIP((addrinfo*)(&commData._addr)));
	m_clients[clientName] = commData;
	return true;
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
	if (m_socket.init(addr, port, false, family))
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