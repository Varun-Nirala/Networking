#ifndef __SERVER_H__
#define __SERVER_H__

#include "socket.h"
#include <vector>

namespace nsNW
{
class Server
{
public:
	Server() = default;

	bool initConnection(const std::string& addr, const std::string& port, bool tcp, bool ipv4);
	bool initConnection(const std::string& addr, const std::string& port, bool tcp);

	bool listen();
	bool accept();

	bool read(std::string& msg, const int maxSize = 1000);
	bool write(std::string& msg);

	void print() const;
private:
	bool initTCP();
	bool initUDP();

private:
	struct ClientData
	{
		sockaddr_storage	_addr;
		int					_sId;
	};

	Socket						m_socket;
	int							m_backLog{5};
	std::vector<ClientData>		m_clients;
	
};

bool Server::initConnection(const std::string& addr, const std::string& port, bool tcp, bool ipv4)
{
	m_socket.clear();
	m_socket.setBacklog(m_backLog);
	if (m_socket.init(addr, port, tcp, ipv4))
	{
		PRINT_MSG("Got socket : " + std::to_string(m_socket.getSocketId()));
		if (tcp)
		{
			initTCP();
		}
		else
		{
			initUDP();
		}
	}
}

bool Server::initConnection(const std::string& addr, const std::string& port, bool tcp)
{
	m_socket.clear();
	m_socket.setBacklog(m_backLog);
	if (m_socket.init(addr, port, tcp))
	{
		PRINT_MSG("Got socket : " + std::to_string(m_socket.getSocketId()));
		if (tcp)
		{
			return initTCP();
		}
		else
		{
			return initUDP();
		}
	}
	return false;
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

bool Server::accept()
{
	ClientData client;
	if (m_socket.accept(client._addr, client._sId))
	{
		PRINT_MSG("Server accepted connect request from ID : " + std::to_string(client._sId) + " : " + m_socket.getIP(client._addr));
		m_clients.emplace_back(client);
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
		ret = m_socket.recvDatagram(msg, maxSize);
	}
	PRINT_MSG("Got msg : " + msg);
	return ret;
}

bool Server::write(std::string& msg)
{
	bool ret{};
	int sentBytes{};
	if (m_socket.isTCP())
	{
		ret = m_socket.sendTcp(msg, sentBytes);
	}
	else
	{
		ret = m_socket.sendDatagram(msg, sentBytes);
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

bool Server::initTCP()
{
	if (m_socket.bind())
	{
		PRINT_MSG("Socket bind success.");
		return true;
	}
	PRINT_MSG("Socket bind failed.");
	return false;
}

bool Server::initUDP()
{
	if (m_socket.bind())
	{
		PRINT_MSG("Socket bind success.");
		return true;
	}
	PRINT_MSG("Socket bind failed.");
	return false;
}
}
#endif // #ifndef __SERVER_H__