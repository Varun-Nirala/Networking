#include "server.h"
#include "helper.h"

namespace nsNW
{
Server::Server(bool ipv4, bool tcp, int port, const std::string& addr)
	:m_socket(ipv4, tcp, port, addr)
{
}

void Server::print() const
{
	std::string msg{ "Server Data :\n" };
	msg += "\t ID      : " + std::to_string(m_socket.getDescriptior()) + "\n";
	msg += "\t Is IPv4 : " + std::to_string(m_socket.isIPv4()) + "\n";
	msg += "\t Is TCP  : " + std::to_string(m_socket.isTCP()) + "\n";
	PRINT_MSG("Server ID : ");
}
}