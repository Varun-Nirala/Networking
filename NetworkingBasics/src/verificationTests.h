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
class TestSocket
{
public:
	TestSocket();

	void runAll_Test();

	void runBasic_Test();

	void runTCP_Test();

private:
	void runTCP_Server(const std::string ip, const std::string port, bool tcp, std::vector<std::string>& msgList);
	void runTCP_Client(const std::string serverIP, const std::string serverPort, bool tcp, std::vector<std::string>& msgList);

private:
	std::vector<std::string>	m_serverMsgList;
	std::vector<std::string>	m_clientMsgList;
	std::mutex					m_mutex;
	std::condition_variable		m_serverReady;
};

TestSocket::TestSocket()
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

void TestSocket::runAll_Test()
{
	runBasic_Test();
}

void TestSocket::runBasic_Test()
{
	Logger::LOG_INFO("Running basic test :");
	bool ipv4 = true;

	nsNW::Address addr;
	addr.init("localhost", "", ipv4, AF_INET);
	addr.print();

	addr.init("www.google.com", "", ipv4, AF_INET);
	addr.print();

	addr.init("www.youtube.com", "", !ipv4, AF_INET6);
	addr.print();

	std::cout << nsNW::HelperMethods::whoami() << "\n\n\n";
}

void TestSocket::runTCP_Test()
{
	Logger::LOG_INFO("Running Tcp test(runTCP_Test).\n\n\n");
	bool tcpConnection = true;
	std::string serverIP{ "localhost" };
	std::string serverPort{ "8888" };
	
	std::vector<std::thread> threads;

	threads.emplace_back(std::thread(&TestSocket::runTCP_Server, this, serverIP, serverPort, tcpConnection, std::ref(m_serverMsgList)));
	threads.emplace_back(std::thread(&TestSocket::runTCP_Client, this, serverIP, serverPort, tcpConnection, std::ref(m_clientMsgList)));

	std::for_each(threads.begin(), threads.end(), std::mem_fn(&std::thread::join));

	Logger::LOG_INFO("Ended Tcp test(runTCP_Test).\n\n\n");
}

void TestSocket::runTCP_Server(const std::string ip, const std::string port, bool tcp, std::vector<std::string> &msgList)
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

void TestSocket::runTCP_Client(const std::string serverIP, const std::string serverPort, bool tcp, std::vector<std::string>& msgList)
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
}

#endif //#ifndef __VERIFICATION_TESTS_H__