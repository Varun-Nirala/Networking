#ifndef __SERVER_H__
#define __SERVER_H__

#include "socket.h"

namespace nsNW
{
class Server
{
public:
	Server(bool ipv4 = true, bool tcp = true, int port = 9090, const std::string& addr = "INADDR_ANY");

	void print() const;
private:
	Socket		m_socket;
};
}
#endif // #ifndef __SERVER_H__