#ifndef __SERVER_H__
#define __SERVER_H__

#include "socket.h"

namespace nsNW
{
class Server
{
public:
	Server() = default;
	bool initConnection(const std::string& addr = "INADDR_ANY", const std::string& port = "9090", bool tcp = true, bool ipv4 = true);

	void print() const;
private:
	Socket		m_socket;
};


void Server::print() const
{
	std::string msg{ "Server Data :\n" };
	msg += "\t ID      : " + std::to_string(m_socket.getSocketId()) + "\n";
	msg += "\t Is IPv4 : " + std::to_string(m_socket.isIPv4()) + "\n";
	msg += "\t Is TCP  : " + std::to_string(m_socket.isTCP()) + "\n";
	PRINT_MSG("Server ID : ");
}
}
#endif // #ifndef __SERVER_H__