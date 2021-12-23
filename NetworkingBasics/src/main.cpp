#include <iostream>
#include "socket.h"
#include "server.h"
#include "client.h"

using namespace std;

int main(int argc, char *argv[])
{
	//nsNW::Client client;
	//client.initConnection("INADDR_ANY", "9090", true, true);
	bool ipv4 = true;
	int family = AF_UNSPEC;
	nsNW::Address addr("www.google.com", "", true);
	addr.print();
	return 0;
}