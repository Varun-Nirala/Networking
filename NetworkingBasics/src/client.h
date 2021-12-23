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

	inline bool initConnection(const std::string& addr, const std::string& port, bool tcp, bool ipv4);
	inline bool initConnection(const std::string& addr, const std::string& port, bool tcp);

	bool read(std::string& msg, const int maxSize = 1000);
	bool write(std::string to, std::string& msg);

	void print() const;
private:
	inline bool initTCP(Socket &socket, const std::string& addr, const std::string& port, int family);
	inline bool initUDP(Socket &socket, const std::string& addr, const std::string& port, int family);

private:
	Socket											m_socket;
	std::unordered_map<std::string, CommData>		m_servers;
};

bool Client::initConnection(const std::string& addr, const std::string& port, bool tcp, bool ipv4)
{
	return tcp ? initTCP(m_socket, addr, port, ipv4 ? AF_INET : AF_INET6) : initUDP(m_socket, addr, port, ipv4 ? AF_INET : AF_INET6);
}

bool Client::initConnection(const std::string& addr, const std::string& port, bool tcp)
{
	return tcp ? initTCP(m_socket, addr, port, AF_UNSPEC) : initUDP(m_socket, addr, port, AF_UNSPEC);
}

bool Client::read(std::string& msg, const int maxSize)
{
	bool ret{};
	if (m_socket.isTCP())
	{
		ret = m_socket.recvTcp(msg, maxSize);
	}
	else
	{
		std::string serverId;
		CommData data;
		ret = m_socket.recvDatagram(data._addr, msg, maxSize);
		serverId = getPortIP((addrinfo*)&data._addr);
		m_servers[serverId] = data;
		PRINT_MSG("Server Id : " + serverId);
	}

	PRINT_MSG("Msg       : " + msg);
	return ret;
}

bool Client::write(std::string to, std::string& msg)
{
	bool ret{};
	int sentBytes{};
	if (m_socket.isTCP())
	{
		ret = m_socket.sendTcp(msg, sentBytes);
	}
	else
	{
		ret = m_socket.sendDatagram(m_servers[to]._addr, msg, sentBytes);
	}
	PRINT_MSG("Tried sending msg[" + std::to_string(msg.size()) + "]   : " + msg + ", To : " + to);
	PRINT_MSG("Number of bytes sent : " + std::to_string(sentBytes));
	return ret;
}

void Client::print() const
{
	std::string msg{ "Client Data :\n" };
	msg += "\t ID      : " + std::to_string(m_socket.getSocketId()) + "\n";
	msg += "\t Is IPv4 : " + std::to_string(m_socket.isIPv4()) + "\n";
	msg += "\t Is TCP  : " + std::to_string(m_socket.isTCP()) + "\n";
	PRINT_MSG("Client ID : ");
}

bool Client::initTCP(Socket& socket, const std::string& addr, const std::string& port, int family)
{
	if (socket.isActive())
	{
		socket.clear();
	}
	if (socket.init(addr, port, true, family))
	{
		PRINT_MSG("Got socket : " + std::to_string(socket.getSocketId()));
		if (socket.connect())
		{
			PRINT_MSG("Socket connect success.");
			return true;
		}
		PRINT_MSG("Socket connect failed.");
	}
	PRINT_MSG("Socket creation failed.");
	return false;
}

bool Client::initUDP(Socket& socket, const std::string& addr, const std::string& port, int family)
{
	if (socket.isActive())
	{
		socket.clear();
	}
	if (socket.init(addr, port, false, family))
	{
		PRINT_MSG("Got socket : " + std::to_string(socket.getSocketId()));
		return true;
	}
	PRINT_MSG("Socket creation failed.");
	return false;
}
}
#endif // #ifndef __CLIENT_H__