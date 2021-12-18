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
/*
struct addrinfo
{
	int              ai_flags;     // AI_PASSIVE, AI_CANONNAME, etc.
	int              ai_family;    // AF_INET, AF_INET6, AF_UNSPEC
	int              ai_socktype;  // SOCK_STREAM, SOCK_DGRAM
	int              ai_protocol;  // use 0 for "any"
	size_t           ai_addrlen;   // size of ai_addr in bytes
	struct sockaddr	*ai_addr;      // struct sockaddr_in or _in6
	char			*ai_canonname; // full canonical hostname

	struct addrinfo* ai_next;      // linked list, next node
};

struct sockaddr
{
	unsigned short    sa_family;    // address family, AF_xxx
	char              sa_data[14];  // 14 bytes of protocol address
};

// IPv4
struct sockaddr_in
{
	short int          sin_family;  // Address family, AF_INET
	unsigned short int sin_port;    // Port number
	struct in_addr     sin_addr;    // Internet address
	unsigned char      sin_zero[8]; // Same size as struct sockaddr
};

struct in_addr
{
	uint32_t			s_addr; // that's a 32-bit int (4 bytes)
};

struct sockaddr_in6
{
	u_int16_t			sin6_family;   // address family, AF_INET6
	u_int16_t			sin6_port;     // port number, Network Byte Order
	u_int32_t			sin6_flowinfo; // IPv6 flow information
	struct in6_addr		sin6_addr;     // IPv6 address
	u_int32_t			sin6_scope_id; // Scope ID
};

struct in6_addr
{
	unsigned char		s6_addr[16];   // IPv6 address
};

 struct sockaddr_storage
 {
	sa_family_t			ss_family;     // address family

	// all this is padding, implementation specific, ignore it:
	char				__ss_pad1[_SS_PAD1SIZE];
	int64_t				__ss_align;
	char				__ss_pad2[_SS_PAD2SIZE];
};
*/

class Address
{
public:
	Address(bool tcp, const char* pService, const char* pAddr);
	~Address();

	inline size_t size() const { return m_vecAddrInfo.size(); }
	inline bool empty() const { return m_vecAddrInfo.empty(); }

	void print();

	std::string getService() const;

	int getPort(int id) const;
	int getFamily(int id) const;

	bool isTCP(int id) const;
	bool isIPv4(int id) const;

	std::string getIP(int id) const;

	std::string getHostname(int id) const;
private:
	bool fillAddressInfo(const char* pService, const char* pAddr);
private:
	std::string					m_szIP;			// e.g "www.example.com" or IP
	std::string					m_szService;	// e.g. "http" or port number
	addrinfo					m_hints{};
	addrinfo					*m_pServinfo{};
	std::vector<addrinfo*>		m_vecAddrInfo;
};

class Socket
{
public:
	Socket(const Socket& sock) = delete;
	Socket& operator=(const Socket& sock) = delete;

	~Socket() { close(); };

	explicit Socket(bool tcp, const std::string &pService, const std::string &pAddr);
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

private:
	int										m_desc{-1};
	Address									m_address;
};
}

#endif //#ifndef __SOCKET_H__