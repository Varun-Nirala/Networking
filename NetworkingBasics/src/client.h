#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "socket.h"
#include <unordered_map>

namespace nsNW
{
class Client
{
public:
	Client() = default;
	~Client() = default;

	inline bool connectTo(const std::string& addr, const std::string& port, bool tcp, bool ipv4, std::string &serverName);
	inline bool connectTo(const std::string& addr, const std::string& port, bool tcp, std::string& serverName);

	inline SOCKET_TYPE getSocketId(const std::string serverName) const;
	inline std::string getIPAddress(const std::string serverName) const;
	inline int getPort(const std::string serverName) const;
	inline int getFamily(const std::string serverName) const;
	inline std::string getHostname(const std::string serverName) const;
	inline bool isTCP(const std::string serverName) const;
	inline bool isIPv4(const std::string serverName) const;

	bool read(const std::string from, std::string& msg, const int maxSize = 1000);
	bool write(const std::string to, std::string& msg);

	void print() const;
protected:
	bool addServer(Socket& socket, std::string& serverName, const std::string& msg);

	inline bool initTCP(const std::string& addr, const std::string& port, int family, std::string& serverName);
	inline bool initUDP(const std::string& addr, const std::string& port, int family, std::string& serverName);

protected:
	std::unordered_map<std::string, Socket>			m_servers;
};

bool Client::connectTo(const std::string& addr, const std::string& port, bool tcp, bool ipv4, std::string& serverName)
{
	return tcp ? initTCP(addr, port, ipv4 ? AF_INET : AF_INET6, serverName) : initUDP(addr, port, ipv4 ? AF_INET : AF_INET6, serverName);
}

bool Client::connectTo(const std::string& addr, const std::string& port, bool tcp, std::string& serverName)
{
	return tcp ? initTCP(addr, port, AF_UNSPEC, serverName) : initUDP(addr, port, AF_UNSPEC, serverName);
}

SOCKET_TYPE Client::getSocketId(const std::string serverName) const
{
	if (m_servers.count(serverName))
	{
		return m_servers.at(serverName).getSocketId();
	}
	Logger::LOG_INFO("No such server. Server :", serverName, '\n');
	return INVALID_SOCKET;
}

std::string Client::getIPAddress(const std::string serverName) const
{
	if (m_servers.count(serverName))
	{
		return m_servers.at(serverName).getIPAddress();
	}
	Logger::LOG_INFO("No such server. Server :", serverName, '\n');
	return "";
}

int Client::getPort(const std::string serverName) const
{
	if (m_servers.count(serverName))
	{
		return m_servers.at(serverName).getPort();
	}
	Logger::LOG_INFO("No such server. Server :", serverName, '\n');
	return 0;
}

int Client::getFamily(const std::string serverName) const
{
	if (m_servers.count(serverName))
	{
		return m_servers.at(serverName).getFamily();
	}
	Logger::LOG_INFO("No such server. Server :", serverName, '\n');
	return -1;
}

std::string Client::getHostname(const std::string serverName) const
{
	if (m_servers.count(serverName))
	{
		return m_servers.at(serverName).getHostname();
	}
	Logger::LOG_INFO("No such server. Server :", serverName, '\n');
	return "";
}

bool Client::isTCP(const std::string serverName) const
{
	if (m_servers.count(serverName))
	{
		return m_servers.at(serverName).isTCP();
	}
	Logger::LOG_INFO("No such server. Server : ", serverName, '\n');
	return false;
}

bool Client::isIPv4(const std::string serverName) const
{
	if (m_servers.count(serverName))
	{
		return m_servers.at(serverName).isIPv4();
	}
	Logger::LOG_INFO("No such server. Server : ", serverName, '\n');
	return false;
}

bool Client::read(const std::string from, std::string& msg, const int maxSize)
{
	bool ret{ false };
	msg.clear();
	if (m_servers.count(from))
	{
		Socket& data = m_servers.at(from);
		if (data.isTCP())
		{
			ret = data.recvTcp(msg, maxSize);
		}
		else
		{
			struct sockaddr_storage client;
			ret = data.recvDatagram(client, msg, maxSize);
			Logger::LOG_INFO("Got UDP Msg from Server :", from, " : ", HelperMethods::getIP(&client), '\n');

		}
		if (!ret)
		{
			Logger::LOG_ERROR("Read unsuccessful. From :", from, '\n');
			return false;
		}
		//Logger::LOG_INFO("Recieved :", msg, '\n');
	}
	else
	{
		Logger::LOG_ERROR("No such connection :", from, '\n');
	}
	
	return ret;
}

bool Client::write(const std::string to, std::string& msg)
{
	bool ret{ false };
	int sentBytes{};
	if (m_servers.count(to))
	{
		Socket& data = m_servers.at(to);
		if (data.isTCP())
		{
			ret = data.sendTcp(msg, sentBytes);
		}
		else
		{
			ret = data.sendDatagram(*(data.getAddress().getaddress()), msg, sentBytes);
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

void Client::print() const
{
	if (!m_servers.empty())
	{
		Logger::LOG_MSG("Client Data\n");
		int i = 1;
		for (const auto& it : m_servers)
		{
			Logger::LOG_MSG("************** Server #", i++, "**************\n");
			Logger::LOG_MSG(it.first, '\n');
			it.second.print();
			Logger::LOG_MSG("*******************************************\n");
		}
	}
	else
	{
		Logger::LOG_MSG("No active connections.\n");
	}
}

bool Client::addServer(Socket& socket, std::string& serverName, const std::string& msg)
{
	serverName = std::to_string(socket.getSocketId());
	Logger::LOG_INFO(msg, serverName, ", IP : ", socket.getIPAddress(), '\n');
	m_servers[serverName] = std::move(socket);
	return true;
}

bool Client::initTCP(const std::string& addr, const std::string& port, int family, std::string &serverName)
{
	nsNW::Socket socket;
	if (socket.init(addr, port, true, family) && socket.connect())
	{
		addServer(socket, serverName, "Got TCP Socket connected to server   :");
		return true;
	}
	return false;
}

bool Client::initUDP(const std::string& addr, const std::string& port, int family, std::string& serverName)
{
	nsNW::Socket socket;
	if (socket.init(addr, port, false, family))
	{
		addServer(socket, serverName, "Got UDP Socket connected to server   :");
		return true;
	}
	return false;
}
}
#endif // #ifndef __CLIENT_H__