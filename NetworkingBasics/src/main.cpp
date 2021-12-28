#include <iostream>

#include "verificationTests.h"

using namespace std;

int main(int argc, char *argv[])
{
	nsTestCase::Tester tester;
	tester.runUDP_Test();


	return 0;
}
