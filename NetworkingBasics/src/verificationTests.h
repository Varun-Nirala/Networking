#ifndef __VERIFICATION_TESTS_H__
#define __VERIFICATION_TESTS_H__

#include <iostream>
#include <vector>
#include <unordered_map>
#include <thread>

#include "socket.h"
#include "server.h"
#include "client.h"
#include "address.h"

namespace nsTestCase
{
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
	std::cout << "Running basic test :\n";
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
	std::cout << "Running Tcp test :\n";

	std::vector<std::string> serverMsgList;
	serverMsgList.emplace_back("Tcp Server Msg 1.");
	serverMsgList.emplace_back("Tcp Server Msg 2.");
	serverMsgList.emplace_back("Tcp Server Msg 3.");
	serverMsgList.emplace_back("Tcp Server Msg 4.");
	serverMsgList.emplace_back("Tcp Server Msg 5.");

	runTCP_Server(serverMsgList);

	std::vector<std::string> clientMsgList;
	clientMsgList.emplace_back("Tcp Client Msg 1.");
	clientMsgList.emplace_back("Tcp Client Msg 2.");
	clientMsgList.emplace_back("Tcp Client Msg 3.");
	clientMsgList.emplace_back("Tcp Client Msg 4.");
	clientMsgList.emplace_back("Tcp Client Msg 5.");
	runTCP_Client(clientMsgList);

	std::cout << "\n\n\n";
}

void TestSocket::runUDP_Test()
{
	std::cout << "Running Udp test :\n";
	std::cout << "\n\n\n";
}

void TestSocket::runTCP_Server(std::vector<std::string> &msgList)
{
	bool tcpConnection = true;
	std::string serverPort{ "8080" };
	nsNW::Server server;

	std::unordered_map<std::string, std::vector<std::string>> clientData;

	int i = 0;
	if (server.startServer("", serverPort, true))
	{
		std::string clientName;
		if (server.acceptConnection(clientName))
		{
			bool keepGoing = true;
			while (keepGoing)
			{
				std::string clientMsg;
				server.read(clientName, clientMsg);
				PRINT_MSG(clientName + " : " + clientMsg);
				clientData[clientName].push_back(clientMsg);
				server.write(clientName, msgList[i++]);
				keepGoing = (i <= msgList.size());
			}
		}
	}
}

void TestSocket::runTCP_Client(std::vector<std::string>& msgList)
{
	bool tcpConnection = true;
	std::string serverPort{ "8080" };
	nsNW::Client client;

	std::unordered_map<std::string, std::vector<std::string>> serverData;

	std::string serverName = "Server_1";
	int i = 0;
	if (client.connectTo("", serverPort, true, serverName))
	{
		bool keepGoing = true;
		while (keepGoing)
		{
			std::string serverMsg;
			client.write(serverName, msgList[i++]);
			client.read(serverName, serverMsg);
			PRINT_MSG(serverName + " : " + serverMsg);
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