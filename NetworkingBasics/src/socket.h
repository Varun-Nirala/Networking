#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdlib>
#include <vector>
#include <string>
#include <memory>

namespace nsNW
{
enum class ConnType
{
	TCP,
	UDP,
};
class Address
{
public:
	Address(bool tcp, bool ipv4, const std::string service, const std::string& ipaddr);
	~Address();

	void print();

private:
	bool getAddressInfo();
private:
	std::string		m_szIP;			// e.g "www.example.com" or IP
	std::string		m_szService;	// e.g. "http" or port number
	addrinfo		m_hints{};
	addrinfo		*m_pServinfo{};
};

class Socket
{
public:
	Socket(const Socket& sock) = delete;
	Socket& operator=(const Socket& sock) = delete;

	~Socket() { close(); };

	explicit Socket(bool tcp, bool ipv4, int port, const std::string& addr);
	Socket(Socket&& sock) = default;
	Socket& operator=(Socket&& sock) = default;

	inline bool isActive() const { return !(m_desc == -1); }
	inline bool isTCP() const { return m_connType == ConnType::TCP; }
	inline bool isIPv4() const { return m_pSa != nullptr; }
	inline int getDescriptior() const { return m_desc; }

	int getPort() const;
	const std::string getAddress() const;

	int accept();
	bool connect();
	bool bind();

	bool close();

protected:
	bool createConnection();
	bool setOptions(bool reuseAddr, bool reusePort);
	bool parseAsIPv4(int port, const std::string& addr);
	bool parseAsIPv6(int port, const std::string& addr);

	bool parseAddress(const std::string& addr);
	uint16_t parsePort(int port) const;

private:
	int										m_desc{-1};
	ConnType								m_connType;
	std::unique_ptr<sockaddr_in>			m_pSa;
	std::unique_ptr<sockaddr_in6>			m_pSa6;
};
}

#endif //#ifndef __SOCKET_H__