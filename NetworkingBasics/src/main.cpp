#include <iostream>
#include "socket.h"
#include "server.h"
#include "client.h"

using namespace std;

int main(int argc, char *argv[])
{
	//nsNW::Client client;
	//client.initConnection("INADDR_ANY", "9090", true, true);
	//INADDR_ANY INADDR_LOOPBACK INADDR_BROADCAST INADDR_NONE
	bool ipv4 = true;

	nsNW::Address addr;
	addr.init("localhost", "", true, AF_INET);
	addr.print();

	addr.init("www.google.com", "", true, AF_INET);
	addr.print();

	cout << nsNW::whoami() << endl;
	return 0;
}