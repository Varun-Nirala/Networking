#ifndef __VERIFICATION_TESTS_H__
#define __VERIFICATION_TESTS_H__

#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <unordered_map>
#include <thread>

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
	void runAll_Test();

	void runBasic_Test();
	void runTCP_Test();
	void runUDP_Test();

private:
	void runTCP_Server(std::vector<std::string>& msgList);
	void runTCP_Client(std::vector<std::string>& msgList);

	void runUDP_Server(std::vector<std::string>& msgList);
	void runUDP_Client(std::vector<std::string>& msgList);
};

void TestSocket::runAll_Test()
{
	runBasic_Test();
	runTCP_Test();
	runUDP_Test();
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

	std::vector<std::string> serverMsgList;
	serverMsgList.emplace_back("Tcp Server Msg 1.");
	serverMsgList.emplace_back("Tcp Server Msg 2.");
	serverMsgList.emplace_back("Tcp Server Msg 3.");
	serverMsgList.emplace_back("Tcp Server Msg 4.");
	serverMsgList.emplace_back("Tcp Server Msg 5.");

	std::vector<std::string> clientMsgList;
	clientMsgList.emplace_back("Tcp Client Msg 1.");
	clientMsgList.emplace_back("Tcp Client Msg 2.");
	clientMsgList.emplace_back("Tcp Client Msg 3.");
	clientMsgList.emplace_back("Tcp Client Msg 4.");
	clientMsgList.emplace_back("Tcp Client Msg 5.");

	std::vector<std::thread> threads;

	threads.emplace_back(std::thread(&TestSocket::runTCP_Server, this, serverMsgList));
	threads.emplace_back(std::thread(&TestSocket::runTCP_Client, this, clientMsgList));

	std::for_each(threads.begin(), threads.end(), std::mem_fn(&std::thread::join));

	Logger::LOG_INFO("Tcp test(runTCP_Test). Ended\n\n\n");
}

void TestSocket::runUDP_Test()
{
	Logger::LOG_INFO("Running Udp test :");
	Logger::LOG_MSG("\n\n\n");
}

void TestSocket::runTCP_Server(std::vector<std::string> &msgList)
{
	bool tcpConnection = true;
	std::string serverPort{ "8080" };
	nsNW::Server server;
	Logger::LOG_MSG("Running TCP server on thread :", std::this_thread::get_id(), ", On Port :", serverPort, '\n');

	std::unordered_map<std::string, std::vector<std::string>> clientData;

	int i = 0;
	if (server.startServer("", serverPort, true))
	{
		server.print();
		std::string clientName;
		if (server.acceptConnection(clientName))
		{
			bool keepGoing = true;
			while (keepGoing)
			{
				std::string clientMsg;
				server.read(clientName, clientMsg);

				Logger::LOG_MSG(clientName, " : ", clientMsg);

				clientData[clientName].push_back(clientMsg);
				server.write(clientName, msgList[i++]);
				keepGoing = (i <= msgList.size());
			}
		}
	}
}

void TestSocket::runTCP_Client(std::vector<std::string>& msgList)
{
	using namespace std::chrono_literals;
	std::this_thread::sleep_for(20ms);
	bool tcpConnection = true;
	std::string serverPort{ "8080" };
	nsNW::Client client;

	Logger::LOG_MSG("Running TCP client on thread :", std::this_thread::get_id(), ", Connecting to server on Port :", serverPort, '\n');

	std::unordered_map<std::string, std::vector<std::string>> serverData;

	std::string serverName = "Server_1";
	int i = 0;
	if (client.connectTo("", serverPort, true, serverName))
	{
		client.print();
		bool keepGoing = true;
		while (keepGoing)
		{
			std::string serverMsg;
			client.write(serverName, msgList[i++]);
			client.read(serverName, serverMsg);

			Logger::LOG_MSG(serverName, " : ", serverMsg);

			keepGoing = (i <= msgList.size());
		}
	}
}

void TestSocket::runUDP_Server(std::vector<std::string>& msgList)
{

}

void TestSocket::runUDP_Client(std::vector<std::string>& msgList)
{

}
}

#endif //#ifndef __VERIFICATION_TESTS_H__