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

	inline void setBacklog(int val) { m_socket.setBacklog(val); }
	inline int getBacklog() const { return m_socket.getBacklog(); }

	inline SOCKET_TYPE getSocketId() const { return m_socket.getSocketId(); }
	inline std::string getIPAddress() const { return m_socket.getIPAddress(); }
	inline int getPort() const { return m_socket.getPort(); }
	inline int getFamily() const { return m_socket.getFamily(); }
	inline std::string getHostname() const { return m_socket.getHostname(); }
	inline bool isTCP() const { return m_socket.isTCP(); }
	inline bool isIPv4() const { return m_socket.isIPv4(); }

	bool startListening() const;
	bool acceptConnection(std::string& clientName);

	SOCKET_TYPE getClientSocketId(const std::string& clientName) const;

	bool read(const std::string from, std::string& msg, const int maxSize = 1000);
	bool write(const std::string to, std::string& msg);

	void print(const std::string& prefix = "") const;
private:
	bool addClient(CommData& commData, std::string& clientName, const std::string &msg);

	inline bool initTCP(Socket& socket, const std::string& addr, const std::string& port, int family);
	inline bool initUDP(Socket& socket, const std::string& addr, const std::string& port, int family);

private:
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

bool Server::startListening() const
{
	Logger::LOG_MSG("Server is listening for connection.\n");
	return m_socket.listen();
}

bool Server::acceptConnection(std::string& clientName)
{
	Logger::LOG_MSG("Server got connection request.\n");
	CommData client;
	if (m_socket.accept(client._addr, client._sId))
	{
		addClient(client, clientName, "Server accepted connect request from");
		return true;
	}
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
		Logger::LOG_INFO("Recieved :", msg, '\n');
	}
	else
	{
		Logger::LOG_ERROR("No such connection :", from, '\n');
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
	}
	else
	{
		Logger::LOG_ERROR("No such connection :", to, '\n');
	}
	return ret;
}

void Server::print(const std::string& prefix) const
{
	Logger::LOG_MSG(prefix, "nServer Data\n");
	m_socket.print();
	if (!m_clients.empty())
	{
		int i = 1;
		for (const auto& it : m_clients)
		{
			Logger::LOG_MSG(prefix, "************** Client #", i++, "**************\n");
			Logger::LOG_MSG(prefix, it.first, '\n');
			it.second.print();
			Logger::LOG_MSG(prefix, "*******************************************\n");
		}
	}
}

bool Server::addClient(CommData& commData, std::string& clientName, const std::string &msg)
{
	clientName = std::to_string(commData._sId);
	Logger::LOG_MSG(msg, clientName, " : ", HelperMethods::getIP((addrinfo*)(&commData._addr)));
	m_clients[clientName] = std::move(commData);
	return true;
}

bool Server::initTCP(Socket& socket, const std::string& addr, const std::string& port, int family)
{
	if (socket.isActive())
	{
		socket.clear();
	}
	return m_socket.init(addr, port, true, family) && m_socket.bind();
}

bool Server::initUDP(Socket& socket, const std::string& addr, const std::string& port, int family)
{
	if (socket.isActive())
	{
		socket.clear();
	}
	return m_socket.init(addr, port, false, family) && m_socket.bind();
}
}
#endif // #ifndef __SERVER_H__