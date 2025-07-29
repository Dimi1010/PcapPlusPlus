#include "pch.h"

#include <iostream>

#include "PcapPlusPlusVersion.h"

#include "TestEnvironment.hpp"

int main(int argc, char* argv[])
{
	std::cout << "PcapPlusPlus Packet++Test"
	             "\nPcapPlusPlus version: "
	          << pcpp::getPcapPlusPlusVersionFull()       //
	          << "\nBuilt: " << pcpp::getBuildDateTime()  //
	          << "\nBuilt from: " << pcpp::getGitInfo() << std::endl;

	::testing::InitGoogleMock(&argc, argv);

	::testing::AddGlobalTestEnvironment(new pcpp::testing::PacketTestEnvironment());

	return RUN_ALL_TESTS();
}
