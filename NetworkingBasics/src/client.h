#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "socket.h"

namespace nsNW
{
class Client
{
public:
	Client(bool ipv4 = true, bool tcp = true, int port = 9090, const std::string& addr = "INADDR_ANY");

	void print() const;
private:
	Socket		m_socket;
};
}
#endif // #ifndef __CLIENT_H__