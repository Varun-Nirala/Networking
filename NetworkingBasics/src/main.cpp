#include <iostream>
#include "socket.h"
#include "server.h"
#include "client.h"

using namespace std;

int main(int argc, char *argv[])
{
	nsNW::Client client;
	nsNW::Server server;
	
	server.initConnection("INADDR_ANY", "9090", true, true);
	client.initConnection("INADDR_ANY", "9090", true, true);
	nsNW::Address addr("www.google.com", "https", true, true);
	addr.print();
	return 0;
}