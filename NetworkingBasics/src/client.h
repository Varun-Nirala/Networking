#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "socket.h"

namespace nsNW
{
class Client
{
public:
	Client() = default;
	bool initConnection(const std::string& addr, const std::string& port, bool tcp, bool ipv4);
	bool initConnection(const std::string& addr, const std::string& port, bool tcp);

	bool read(std::string& msg, const int maxSize = 1000);
	bool write(std::string& msg);

	void print() const;
private:
	bool initTCP();
	bool initUDP();

private:
	Socket		m_socket;
};

bool Client::initConnection(const std::string& addr, const std::string& port, bool tcp, bool ipv4)
{
	m_socket.clear();
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

bool Client::initConnection(const std::string& addr, const std::string& port, bool tcp)
{
	m_socket.clear();
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

bool Client::read(std::string& msg, const int maxSize)
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

bool Client::write(std::string& msg)
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

void Client::print() const
{
	std::string msg{ "Client Data :\n" };
	msg += "\t ID      : " + std::to_string(m_socket.getSocketId()) + "\n";
	msg += "\t Is IPv4 : " + std::to_string(m_socket.isIPv4()) + "\n";
	msg += "\t Is TCP  : " + std::to_string(m_socket.isTCP()) + "\n";
	PRINT_MSG("Client ID : ");
}

bool Client::initTCP()
{
	if (m_socket.connect())
	{
		PRINT_MSG("Socket connect success.");
	}
}

bool Client::initUDP()
{
	//Noting required;
}
}
#endif // #ifndef __CLIENT_H__