#ifndef __VERIFICATION_TESTS_H__
#define __VERIFICATION_TESTS_H__

#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>

#include "helper.h"
#include "socket.h"
#include "server.h"
#include "client.h"
#include "address.h"

namespace nsTestCase
{
using nsNW::Logger;
class Tester
{
public:
	Tester();

	void test_Address();
	void test_Socket();
	void test_CommData();

	void runTCP_Test();

	void runAll_Test();

private:
	void runTCP_Server(const std::string ip, const std::string port, bool tcp, std::vector<std::string>& msgList);
	void runTCP_Client(const std::string serverIP, const std::string serverPort, bool tcp, std::vector<std::string>& msgList);

	bool test_AddressHelper(int testNum, const std::string szIP, const std::string szService, int bTCP, bool bIPv4) const;
	bool test_SocketHelper(int testNum, const std::string szIP, const std::string szService, int bTCP, bool bIPv4) const;

private:
	std::vector<std::string>	m_serverMsgList;
	std::vector<std::string>	m_clientMsgList;
	std::mutex					m_mutex;
	std::condition_variable		m_serverReady;
};

Tester::Tester()
{
	m_serverMsgList.emplace_back("Tcp Server Msg 1.");
	m_serverMsgList.emplace_back("Tcp Server Msg 2.");
	m_serverMsgList.emplace_back("Tcp Server Msg 3.");
	m_serverMsgList.emplace_back("Tcp Server Msg 4.");
	m_serverMsgList.emplace_back("Tcp Server Msg 5.");

	m_clientMsgList.emplace_back("Tcp Client Msg 1.");
	m_clientMsgList.emplace_back("Tcp Client Msg 2.");
	m_clientMsgList.emplace_back("Tcp Client Msg 3.");
	m_clientMsgList.emplace_back("Tcp Client Msg 4.");
	m_clientMsgList.emplace_back("Tcp Client Msg 5.");
}

void Tester::runAll_Test()
{
}

void Tester::test_Address()
{
	Logger::LOG_MSG("START : Testing Address class.\n\n");

	Logger::LOG_MSG("Test # 0\n");
	Logger::LOG_MSG("whoami   :", nsNW::HelperMethods::whoami());
	Logger::LOG_MSG("\n\n");

	int testNum = 1;
	// Local host, TCP, IPv4
	test_AddressHelper(testNum++, "localhost", "http", true, true);
	Logger::LOG_MSG("\n\n");
	
	// Local host, TCP, IPv6
	test_AddressHelper(testNum++, "localhost", "http", true, false);
	Logger::LOG_MSG("\n\n");

	// Local host, UDP, IPv4
	test_AddressHelper(testNum++, "localhost", "https", false, true);
	Logger::LOG_MSG("\n\n");

	// Local host, UDP, IPv6
	test_AddressHelper(testNum++, "localhost", "https", false, false);
	Logger::LOG_MSG("\n\n");

	// Google, TCP, IPv4
	test_AddressHelper(testNum++, "www.google.com", "http", true, true);
	Logger::LOG_MSG("\n\n");

	// Google, TCP, IPv6
	test_AddressHelper(testNum++, "www.google.com", "http", true, false);
	Logger::LOG_MSG("\n\n");
	
	// Google, UDP, IPv4
	test_AddressHelper(testNum++, "www.google.com", "https", false, true);
	Logger::LOG_MSG("\n\n");

	// Google, UDP, IPv6
	test_AddressHelper(testNum++, "www.google.com", "https", false, false);
	Logger::LOG_MSG("\n\n");
	
	// Youtube, TCP, IPv4
	test_AddressHelper(testNum++, "www.youtube.com", "http", true, true);
	Logger::LOG_MSG("\n\n");

	Logger::LOG_MSG("END   : Testing Address class.\n\n");
}

void Tester::test_Socket()
{
	Logger::LOG_MSG("START : Testing Socket class.\n\n");

	int testNum = 1;
	// Local host, TCP, IPv4
	test_SocketHelper(testNum++, "localhost", "http", true, true);
	Logger::LOG_MSG("\n\n");

	// Local host, TCP, IPv6
	test_SocketHelper(testNum++, "localhost", "http", true, false);
	Logger::LOG_MSG("\n\n");

	// Local host, UDP, IPv4
	test_SocketHelper(testNum++, "localhost", "https", false, true);
	Logger::LOG_MSG("\n\n");

	// Local host, UDP, IPv6
	test_SocketHelper(testNum++, "localhost", "https", false, false);
	Logger::LOG_MSG("\n\n");

	// Google, TCP, IPv4
	test_SocketHelper(testNum++, "www.google.com", "http", true, true);
	Logger::LOG_MSG("\n\n");

	// Google, TCP, IPv6
	test_SocketHelper(testNum++, "www.google.com", "http", true, false);
	Logger::LOG_MSG("\n\n");

	// Google, UDP, IPv4
	test_SocketHelper(testNum++, "www.google.com", "https", false, true);
	Logger::LOG_MSG("\n\n");

	// Google, UDP, IPv6
	test_SocketHelper(testNum++, "www.google.com", "https", false, false);
	Logger::LOG_MSG("\n\n");

	// Youtube, TCP, IPv4
	test_SocketHelper(testNum++, "www.youtube.com", "http", true, true);
	Logger::LOG_MSG("\n\n");

	Logger::LOG_MSG("END   : Testing Socket class.\n\n");
}

void Tester::runTCP_Test()
{
	Logger::LOG_INFO("Running Tcp test(runTCP_Test).\n\n\n");
	bool tcpConnection = true;
	std::string serverIP{ "localhost" };
	std::string serverPort{ "8888" };
	
	std::vector<std::thread> threads;

	threads.emplace_back(std::thread(&Tester::runTCP_Server, this, serverIP, serverPort, tcpConnection, std::ref(m_serverMsgList)));
	threads.emplace_back(std::thread(&Tester::runTCP_Client, this, serverIP, serverPort, tcpConnection, std::ref(m_clientMsgList)));

	std::for_each(threads.begin(), threads.end(), std::mem_fn(&std::thread::join));

	Logger::LOG_INFO("Ended Tcp test(runTCP_Test).\n\n\n");
}

void Tester::runTCP_Server(const std::string ip, const std::string port, bool tcp, std::vector<std::string> &msgList)
{
	nsNW::Server server;
	Logger::LOG_MSG("Running TCP server on thread :", std::this_thread::get_id(), ", IP:", ip, ", PORT:", port, '\n');

	std::unordered_map<std::string, std::vector<std::string>> recievedMsgs;

	int nextMsgToSend = 0;
	if (server.startServer(ip, port, tcp))
	{
		server.print();
		if (server.startListening())
		{
			m_serverReady.notify_one();
		}
		std::string clientName;
		if (server.acceptConnection(clientName))
		{
			bool keepGoing = true;
			while (keepGoing)
			{
				std::string msg;
				if (server.read(clientName, msg))
				{
					Logger::LOG_MSG(clientName, " : ", msg);
					recievedMsgs[clientName].push_back(msg);

					if (!server.write(clientName, msgList[nextMsgToSend++]))
					{
						Logger::LOG_MSG("Server : Failed to write.\n");
					}
				}
				else
				{
					Logger::LOG_MSG("Server : Failed to read.\n");
				}
				keepGoing = (nextMsgToSend < msgList.size());
			}
		}
	}
}

void Tester::runTCP_Client(const std::string serverIP, const std::string serverPort, bool tcp, std::vector<std::string>& msgList)
{
	nsNW::Client client;
	Logger::LOG_MSG("Running TCP client on thread :", std::this_thread::get_id(), ", Server IP:", serverIP, ", Server PORT:", serverPort, '\n');

	std::unordered_map<std::string, std::vector<std::string>> recievedMsgs;

	int nextMsgToSend = 0;
	std::string serverName;
	{
		std::unique_lock<std::mutex> lk(m_mutex);
		m_serverReady.wait(lk);
	}
	if (client.connectTo(serverIP, serverPort, tcp, serverName))
	{
		client.print();
		bool keepGoing = true;
		while (keepGoing)
		{
			std::string msg;
			if (client.write(serverName, msgList[nextMsgToSend++]))
			{
				if (!client.read(serverName, msg))
				{
					Logger::LOG_MSG("Client : Failed to read.\n");
				}
				Logger::LOG_MSG(serverName, " : ", msg);
				recievedMsgs[serverName].push_back(msg);
			}
			else
			{
				Logger::LOG_MSG("Client : Failed to write.\n");
			}
			keepGoing = (nextMsgToSend < msgList.size());
		}
	}
}

bool Tester::test_AddressHelper(int testNum, const std::string szIP, const std::string szService, int bTCP, bool bIPv4) const
{
	Logger::LOG_MSG("----------------------------------------------------------------------------------------------------\n");
	Logger::LOG_MSG("Test #", testNum, '\n');
	Logger::LOG_MSG("           service://IP  :", szService);
	Logger::LOG_MSG("://");
	Logger::LOG_MSG(szIP, '\n');

	Logger::LOG_MSG("           Protocol      :", bTCP ? "TCP" : "UDP", '\n');
	Logger::LOG_MSG("           Family        :", bIPv4 ? "AF_INET" : "AF_INET6");
	Logger::LOG_MSG("\n\n");
	nsNW::Address addr;
	bool ret = addr.init(szIP, szService, bTCP, bIPv4 ? AF_INET : AF_INET6);
	addr.print();
	Logger::LOG_MSG("----------------------------------------------------------------------------------------------------\n");
	return ret;
}

bool Tester::test_SocketHelper(int testNum, const std::string szIP, const std::string szService, int bTCP, bool bIPv4) const
{
	Logger::LOG_MSG("----------------------------------------------------------------------------------------------------\n");
	Logger::LOG_MSG("Test #", testNum, '\n');
	Logger::LOG_MSG("           service://IP  :", szService);
	Logger::LOG_MSG("://");
	Logger::LOG_MSG(szIP, '\n');

	Logger::LOG_MSG("           Protocol      :", bTCP ? "TCP" : "UDP", '\n');
	Logger::LOG_MSG("           Family        :", bIPv4 ? "AF_INET" : "AF_INET6");
	Logger::LOG_MSG("\n\n");
	nsNW::Socket socket;
	bool ret = socket.init(szIP, szService, bTCP, bIPv4 ? AF_INET : AF_INET6);
	socket.print();
	Logger::LOG_MSG("----------------------------------------------------------------------------------------------------\n");
	return ret;
}
}

#endif //#ifndef __VERIFICATION_TESTS_H__