#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "socket.h"

namespace nsNW
{
class Client
{
public:
	Client(bool ipv4 = true, bool tcp = true, const std::string& port = "9090", const std::string& addr = "INADDR_ANY");

	void print() const;
private:
	Socket		m_socket;
};

Client::Client(bool ipv4, bool tcp, const std::string& port, const std::string& addr)
	:m_socket(ipv4, tcp, port, addr)
{
}
}
#endif // #ifndef __CLIENT_H__