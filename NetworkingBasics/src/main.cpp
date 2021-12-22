#include <iostream>
#include "socket.h"
#include "server.h"
#include "client.h"

using namespace std;

int main(int argc, char *argv[])
{
	nsNW::Client client;
	nsNW::Server server("INADDR_ANY", "9090", true, true);
	nsNW::Address addr(true, false, "3490", "www.google.com");
	addr.print();
	return 0;
}