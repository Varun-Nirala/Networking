#include <iostream>

#include "verificationTests.h"

using namespace std;

int main(int argc, char *argv[])
{
	//nsTestCase::TestSocket testSocket;

	//testSocket.runTCP_Test();
	//StestSocket.runAll_Test();
	nsNW::Address address;
	//address.init("www.google.com", "https", true, AF_INET);
	//address.print();

	nsNW::Socket socket;
	socket.init("www.google.com", "https", true, AF_INET);
	socket.print();

	return 0;
}
