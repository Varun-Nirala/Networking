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
#include <cassert>

#include "common.h"
#include "socket.h"
#include "server.h"
#include "client.h"
#include "address.h"
#include "http.h"

namespace nsTestCase
{
using nsNW::Logger;
class Tester
{
public:
	Tester();
	void runAll_Test();

	void test_Address();
	void test_Socket();

	void runTCP_Test();
	void runUDP_Test();

	void httpGetRequest_Test(bool useHttp, const std::string url);
	
private:
	void runTCP_Server(const std::string ip, const std::string port, bool tcp, bool bIPv4, std::vector<std::string>& msgList);
	void runTCP_Client(const std::string serverIP, const std::string serverPort, bool tcp, bool bIPv4, std::vector<std::string>& msgList);

	void runUDP_Server(const std::string ip, const std::string port, bool tcp, bool bIPv4, std::vector<std::string>& msgList);
	void runUDP_Client(const std::string serverIP, const std::string serverPort, bool tcp, bool bIPv4, std::vector<std::string>& msgList);

	bool test_AddressHelper(int testNum, const std::string szIP, const std::string szService, int bTCP, bool bIPv4) const;
	bool test_SocketHelper(int testNum, const std::string szIP, const std::string szService, int bTCP, bool bIPv4) const;

	void waitForCondition(const bool& value);
	void notifyOther(bool &value);

private:
	std::vector<std::string>	m_serverMsgList;
	std::vector<std::string>	m_clientMsgList;
	std::mutex					m_mutex;
	std::condition_variable		m_conditionVariable;
	bool						m_bServerIsUp{false};
	bool						m_bServerCanRead{false};
	bool						m_bClientCanRead{false};
	
};

Tester::Tester()
{
	m_serverMsgList.emplace_back("Server Msg 1.");
	m_serverMsgList.emplace_back("Server Msg 2.");
	m_serverMsgList.emplace_back("Server Msg 3.");
	m_serverMsgList.emplace_back("Server Msg 4.");
	m_serverMsgList.emplace_back("Server Msg 5.");

	m_clientMsgList.emplace_back("Client Msg 1.");
	m_clientMsgList.emplace_back("Client Msg 2.");
	m_clientMsgList.emplace_back("Client Msg 3.");
	m_clientMsgList.emplace_back("Client Msg 4.");
	m_clientMsgList.emplace_back("Client Msg 5.");
}

void Tester::runAll_Test()
{
	test_Address();
	test_Socket();
	runTCP_Test();
	runUDP_Test();
	httpGetRequest_Test(true, "www.google.com");
	httpGetRequest_Test(false, "www.google.com");
}

void Tester::httpGetRequest_Test(bool useHttp, const std::string url)
{
	if (useHttp)
	{
		Logger::LOG_MSG("START : Testing HTTP GET Request using Http class.\n\n");
		//HTTP GET
		nsNW::Http http;
		
		if (!http.init("HTTP/1.1", "http", url))
		{
			Logger::LOG_ERROR("Http connect error : URL::PORT => ", url, "::", 80);
			assert(false);
			return;
		}

		nsNW::Http::bodyType bodyData;
		bodyData.push_back(std::make_pair("Connection", "close"));

		std::string request = http.formRequest(nsNW::Method::HTTP_GET, "/", bodyData);

		const char* port = "80";
		std::string serverName;
		nsNW::Client httpClient;
		if (!httpClient.connectTo(url, port, true, serverName))
		{
			Logger::LOG_ERROR("Connect Error : URL::PORT => ", url, "::", port);
			assert(false);
			return;
		}

		// send GET / HTTP
		if (!httpClient.write(serverName, request))
		{
			Logger::LOG_ERROR("Write Error : Server => ", serverName, ", Message => ", request);
			assert(false);
			return;
		}

		// recieve html
		std::string websiteHtml;
		std::string receivedMsg;
		while (httpClient.read(serverName, receivedMsg, 100000) && !receivedMsg.empty())
		{
			websiteHtml += receivedMsg;
			receivedMsg.clear();
		}

		Logger::LOG_MSG("\n**************************** [BEG] Recieved Web HTML CODE ****************************\n\n");
		// Display HTML source 
		Logger::LOG_MSG(websiteHtml);
		Logger::LOG_MSG("\n**************************** [END] Recieved Web HTML CODE ****************************\n\n");

		Logger::LOG_MSG("END   : Testing HTTP GET Request using Http class.\n\n");
	}
	else
	{
		Logger::LOG_MSG("START : Testing HTTP GET Request.\n\n");
		//HTTP GET
		std::string get_http = "GET / HTTP/1.1\r\nHost: " + url + "\r\nConnection: close\r\n\r\n";

		const char* port = "80";
		std::string serverName;
		nsNW::Client httpClient;
		if (!httpClient.connectTo(url, port, true, serverName))
		{
			Logger::LOG_ERROR("Connect Error : URL::PORT => ", url, "::", port);
			assert(false);
			return;
		}

		// send GET / HTTP
		if (!httpClient.write(serverName, get_http))
		{
			Logger::LOG_ERROR("Write Error : Server => ", serverName, ", Message => ", get_http);
			assert(false);
			return;
		}

		// recieve html
		std::string websiteHtml;
		std::string receivedMsg;
		while (httpClient.read(serverName, receivedMsg, 100000) && !receivedMsg.empty())
		{
			websiteHtml += receivedMsg;
			receivedMsg.clear();
		}

		Logger::LOG_MSG("\n**************************** [BEG] Recieved Web HTML CODE ****************************\n\n");
		// Display HTML source 
		Logger::LOG_MSG(websiteHtml);
		Logger::LOG_MSG("\n**************************** [END] Recieved Web HTML CODE ****************************\n\n");

		Logger::LOG_MSG("END   : Testing HTTP GET Request.\n\n");
	}
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
	Logger::LOG_INFO("Running TCP test(runTCP_Test).\n\n");
	bool tcpConnection = true;
	bool ipv4 = true;
	std::string serverIP{ "127.0.0.1" };
	std::string serverPort{ "8888" };
	
	std::vector<std::thread> threads;

	m_bServerIsUp = m_bServerCanRead = m_bClientCanRead = false;

	threads.emplace_back(std::thread(&Tester::runTCP_Server, this, serverIP, serverPort, tcpConnection, ipv4, std::ref(m_serverMsgList)));
	threads.emplace_back(std::thread(&Tester::runTCP_Client, this, serverIP, serverPort, tcpConnection, ipv4, std::ref(m_clientMsgList)));

	std::for_each(threads.begin(), threads.end(), std::mem_fn(&std::thread::join));

	Logger::LOG_INFO("Ended TCP test(runTCP_Test).\n\n");
}

void Tester::runUDP_Test()
{
	Logger::LOG_INFO("Running UDP test(runUDP_Test).\n\n");
	bool tcpConnection = false;
	bool ipv4 = true;
	std::string serverIP{ "127.0.0.1" };
	std::string serverPort{ "8888" };

	std::vector<std::thread> threads;

	m_bServerIsUp = m_bServerCanRead = m_bClientCanRead = false;

	threads.emplace_back(std::thread(&Tester::runUDP_Server, this, serverIP, serverPort, tcpConnection, ipv4, std::ref(m_serverMsgList)));
	threads.emplace_back(std::thread(&Tester::runUDP_Client, this, serverIP, serverPort, tcpConnection, ipv4, std::ref(m_clientMsgList)));

	std::for_each(threads.begin(), threads.end(), std::mem_fn(&std::thread::join));

	Logger::LOG_INFO("Ended UDP test(runUDP_Test).\n\n");
}

void Tester::runTCP_Server(const std::string ip, const std::string port, bool tcp, bool bIPv4, std::vector<std::string> &msgList)
{
	nsNW::Server server;
	Logger::LOG_MSG("Running TCP server on thread :", std::this_thread::get_id());
	Logger::LOG_MSG(", IP :", ip);
	Logger::LOG_MSG(", Port :", port, '\n');

	std::unordered_map<std::string, std::vector<std::string>> recievedMsgs;

	int nextMsgToSend = 0;
	if (server.startServer(ip, port, tcp, bIPv4))
	{
		server.print();
		if (server.startListening())
		{
			notifyOther(m_bServerIsUp);
		}
		std::string clientName;
		if (server.acceptConnection(clientName))
		{
			bool keepGoing = true;
			while (keepGoing)
			{
				waitForCondition(m_bServerCanRead);
				std::string msg;
				if (server.read(clientName, msg))
				{
					m_bServerCanRead = false;
					Logger::LOG_MSG(clientName, " : ", msg, '\n');
					recievedMsgs[clientName].push_back(msg);
					if (!server.write(clientName, msgList[nextMsgToSend++]))
					{
						Logger::LOG_MSG("Server : Failed to write.\n");
						assert(false);
					}
					notifyOther(m_bClientCanRead);
				}
				else
				{
					Logger::LOG_MSG("Server : Failed to read.\n");
					assert(false);
				}
				keepGoing = (nextMsgToSend < msgList.size());
			}
		}
	}
}

void Tester::runTCP_Client(const std::string serverIP, const std::string serverPort, bool tcp, bool bIPv4, std::vector<std::string>& msgList)
{
	waitForCondition(m_bServerIsUp);

	nsNW::Client client;
	Logger::LOG_MSG("Running TCP client on thread :", std::this_thread::get_id());
	Logger::LOG_MSG(", Connecting server on IP :", serverIP);
	Logger::LOG_MSG(", Port :", serverPort, '\n');

	std::unordered_map<std::string, std::vector<std::string>> recievedMsgs;

	int nextMsgToSend = 0;
	std::string serverName;
	
	if (client.connectTo(serverIP, serverPort, tcp, bIPv4, serverName))
	{
		client.print();
		bool keepGoing = true;
		while (keepGoing)
		{
			std::string msg;
			if (client.write(serverName, msgList[nextMsgToSend++]))
			{
				notifyOther(m_bServerCanRead);
				waitForCondition(m_bClientCanRead);
				if (!client.read(serverName, msg))
				{
					Logger::LOG_MSG("Client : Failed to read.\n");
					assert(false);
				}
				Logger::LOG_MSG(serverName, " : ", msg, '\n');
				recievedMsgs[serverName].push_back(msg);
				m_bClientCanRead = false;
			}
			else
			{
				Logger::LOG_MSG("Client : Failed to write.\n");
				assert(false);
			}
			keepGoing = (nextMsgToSend < msgList.size());
		}
	}
}

void Tester::runUDP_Server(const std::string ip, const std::string port, bool tcp, bool bIPv4, std::vector<std::string>& msgList)
{
	nsNW::Server server;
	Logger::LOG_MSG("Running UDP server on thread :", std::this_thread::get_id());
	Logger::LOG_MSG(", IP :", ip);
	Logger::LOG_MSG(", Port :", port, '\n');

	std::unordered_map<std::string, std::vector<std::string>> recievedMsgs;

	int nextMsgToSend = 0;
	if (server.startServer(ip, port, tcp, bIPv4))
	{
		server.print();
		notifyOther(m_bServerIsUp);
		std::string clientName;
		bool keepGoing = true;
		while (keepGoing)
		{
			waitForCondition(m_bServerCanRead);
			std::string msg;
			if (server.read(clientName, msg))
			{
				m_bServerCanRead = false;
				Logger::LOG_MSG(clientName, " : ", msg, '\n');
				recievedMsgs[clientName].push_back(msg);
				if (!server.write(clientName, msgList[nextMsgToSend++]))
				{
					Logger::LOG_MSG("Server : Failed to write.\n");
					assert(false);
				}
				notifyOther(m_bClientCanRead);
			}
			else
			{
				Logger::LOG_MSG("Server : Failed to read.\n");
				assert(false);
			}
			keepGoing = (nextMsgToSend < msgList.size());
		}
	}
}

void Tester::runUDP_Client(const std::string serverIP, const std::string serverPort, bool tcp, bool bIPv4, std::vector<std::string>& msgList)
{
	waitForCondition(m_bServerIsUp);

	nsNW::Client client;
	Logger::LOG_MSG("Running UDP client on thread :", std::this_thread::get_id());
	Logger::LOG_MSG(", Connecting server on IP :", serverIP);
	Logger::LOG_MSG(", Port :", serverPort, '\n');

	std::unordered_map<std::string, std::vector<std::string>> recievedMsgs;

	int nextMsgToSend = 0;
	std::string serverName;

	if (client.connectTo(serverIP, serverPort, tcp, bIPv4, serverName))
	{
		client.print();
		bool keepGoing = true;
		while (keepGoing)
		{
			std::string msg;
			if (client.write(serverName, msgList[nextMsgToSend++]))
			{
				notifyOther(m_bServerCanRead);
				waitForCondition(m_bClientCanRead);
				if (!client.read(serverName, msg))
				{
					Logger::LOG_MSG("Client : Failed to read.\n");
					assert(false);
				}
				Logger::LOG_MSG(serverName, " : ", msg, '\n');
				recievedMsgs[serverName].push_back(msg);
				m_bClientCanRead = false;
			}
			else
			{
				Logger::LOG_MSG("Client : Failed to write.\n");
				assert(false);
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

void Tester::waitForCondition(const bool &value)
{
	std::unique_lock<std::mutex> lk(m_mutex);
	m_conditionVariable.wait(lk, [&]() { return value; });
}

void Tester::notifyOther(bool &value)
{
	std::unique_lock<std::mutex> lk(m_mutex);
	value = true;
	m_conditionVariable.notify_one();
}
}

#endif //#ifndef __VERIFICATION_TESTS_H__