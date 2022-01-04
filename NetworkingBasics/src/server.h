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

	bool read(std::string &from, std::string& msg, const int maxSize = 1000);
	bool write(std::string &to, std::string& msg);

	void print() const;
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
	Logger::LOG_INFO("Server is listening for connection.\n");
	return m_socket.listen();
}

bool Server::acceptConnection(std::string& clientName)
{
	Logger::LOG_INFO("Server got connection request.\n");
	CommData client;
	if (m_socket.accept(client._addr, client._sId))
	{
		client._sockType = m_socket.getSocketType();
		client._protocol = m_socket.getProtocol();
		addClient(client, clientName, "Accepted connect request from client :");
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


bool Server::read(std::string &from, std::string& msg, const int maxSize)
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
			struct sockaddr_storage client;
			ret = m_socket.recvDatagram(client, msg, maxSize);
		}
	}
	else
	{
		CommData client;
		ret = m_socket.recvDatagram(client._addr, msg, maxSize);
		client._sockType = m_socket.getSocketType();
		client._protocol = m_socket.getProtocol();
		client._sId = m_socket.getSocketId();
		addClient(client, from, "Got UDP Msg from client :");
	}
	if (!ret)
	{
		Logger::LOG_ERROR("Read unsuccessful. From :", from, '\n');
		return false;
	}
	return ret;
}

bool Server::write(std::string &to, std::string& msg)
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
			ret = m_socket.sendDatagram(data._sId, data._addr, msg, sentBytes);
		}
		if (!ret)
		{
			Logger::LOG_ERROR("Wrtie unsuccessful. To :", to, ", Msg : ", msg, '\n');
			return false;
		}
	}
	else
	{
		Logger::LOG_ERROR("No such connection :", to, '\n');
	}

	return ret;
}

void Server::print() const
{
	Logger::LOG_MSG("Server Data\n");
	m_socket.print();
	if (!m_clients.empty())
	{
		int i = 1;
		for (const auto& it : m_clients)
		{
			Logger::LOG_MSG("************** Client #", i++, "**************\n");
			Logger::LOG_MSG(it.first, '\n');
			it.second.print();
			Logger::LOG_MSG("*******************************************\n");
		}
	}
}

bool Server::addClient(CommData& commData, std::string& clientName, const std::string &msg)
{
	clientName = std::to_string(commData._sId);
	Logger::LOG_INFO(msg, clientName, " : ", HelperMethods::getIP(&(commData._addr)), '\n');
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