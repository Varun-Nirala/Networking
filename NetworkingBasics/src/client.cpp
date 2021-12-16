#include "client.h"

namespace nsNW
{
Client::Client(bool ipv4, bool tcp, int port, const std::string& addr)
	:m_socket(ipv4, tcp, port, addr)
{
}
}