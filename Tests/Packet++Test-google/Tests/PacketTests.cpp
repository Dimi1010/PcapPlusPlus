#include "pch.h"

#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PPPoELayer.h"
#include "VlanLayer.h"
#include "IcmpLayer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IgmpLayer.h"
#include "DnsLayer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "RadiusLayer.h"
#include "PacketTrailerLayer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"

#include "Utils\PacketFactory.hpp"

namespace pcpp
{
	TEST(PacketTest, InsertDataIntoPacket)
	{
		// Creating a packet
		// ~~~~~~~~~~~~~~~~~

		MacAddress srcMac("aa:aa:aa:aa:aa:aa");
		MacAddress dstMac("bb:bb:bb:bb:bb:bb");
		EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

		IPv4Address ipSrc("1.1.1.1");
		IPv4Address ipDst("20.20.20.20");
		IPv4Layer ip4Layer(ipSrc, ipDst);
		ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;

		uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
		PayloadLayer payloadLayer(payload, 10);

		// create the packet
		Packet ip4Packet(1);
		ASSERT_TRUE(ip4Packet.addLayer(&ethLayer));
		ASSERT_TRUE(ip4Packet.addLayer(&ip4Layer));
		ASSERT_TRUE(ip4Packet.addLayer(&payloadLayer));

		ip4Packet.computeCalculateFields();

		// Adding a VLAN layer between Eth and IP
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto vlanLayer = new VlanLayer(100, 0, 0, PCPP_ETHERTYPE_IP);

		ASSERT_TRUE(ip4Packet.insertLayer(&ethLayer, vlanLayer, true));
		ASSERT_EQ(ethLayer.getDestMac(), dstMac);
		ASSERT_EQ(ip4Layer.getIPv4Header()->internetHeaderLength, 5);
		ASSERT_EQ(ip4Layer.getDstIPAddress(), ipDst);
		ASSERT_EQ(ip4Layer.getSrcIPAddress(), ipSrc);
		ASSERT_EQ(payloadLayer.getPayload()[3], 0x04);

		// Adding another Eth layer at the beginning of the packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		MacAddress srcMac2("cc:cc:cc:cc:cc:cc");
		MacAddress dstMac2("dd:dd:dd:dd:dd:dd");
		auto ethLayer2 = new EthLayer(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(ip4Packet.insertLayer(nullptr, ethLayer2, true));

		ASSERT_EQ(ip4Packet.getFirstLayer(), ethLayer2, ptr);
		ASSERT_EQ(ip4Packet.getFirstLayer()->getNextLayer(), &ethLayer, ptr);
		ASSERT_EQ(ip4Packet.getFirstLayer()->getNextLayer()->getNextLayer(), vlanLayer, ptr);
		ASSERT_EQ(ethLayer.getDestMac(), dstMac);
		ASSERT_EQ(ip4Layer.getIPv4Header()->internetHeaderLength, 5);
		ASSERT_EQ(ip4Layer.getDstIPAddress(), ipDst);
		ASSERT_EQ(ip4Layer.getSrcIPAddress(), ipSrc);
		ASSERT_EQ(payloadLayer.getPayload()[3], 0x04);

		// Adding a TCP layer at the end of the packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto tcpLayer = new TcpLayer((uint16_t)12345, (uint16_t)80);
		ASSERT_TRUE(ip4Packet.insertLayer(&payloadLayer, tcpLayer, true));

		// Create a new packet and use insertLayer for the first layer in packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		EthLayer ethLayer3(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
		Packet testPacket(1);
		ASSERT_TRUE(testPacket.insertLayer(nullptr, &ethLayer3));
		ASSERT_EQ(testPacket.getFirstLayer(), &ethLayer3);
		ASSERT_EQ(testPacket.getFirstLayer()->getNextLayer(), nullptr);
		ASSERT_EQ(ethLayer3.getDestMac(), dstMac2);
	}

	TEST(PacketTest, CreatePacketFromBuffer)
	{
		size_t bufferSize = 46;
		auto buffer = std::make_unique<uint8_t[]>(bufferSize);
		memset(buffer.get(), 0, bufferSize);

		auto newPacket = std::make_unique<Packet>(buffer.get(), bufferSize);

		// Create the packet layers

		MacAddress srcMac("aa:aa:aa:aa:aa:aa");
		MacAddress dstMac("bb:bb:bb:bb:bb:bb");
		EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(newPacket->addLayer(&ethLayer));

		IPv4Address ipSrc("1.1.1.1");
		IPv4Address ipDst("20.20.20.20");
		IPv4Layer ip4Layer(ipSrc, ipDst);
		ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;
		ASSERT_TRUE(newPacket->addLayer(&ip4Layer));

		uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
		PayloadLayer payloadLayer(payload, 10);
		ASSERT_TRUE(newPacket->addLayer(&payloadLayer));

		Logger::getInstance().suppressLogs();

		// Inserting a new layer should fail because the size of the new layer exceeds the buffer size
		TcpLayer tcpLayer(12345, 80);
		ASSERT_FALSE(newPacket->insertLayer(&ip4Layer, &tcpLayer));

		// Extending the IPv4 layer should fail because the size of the new option exceeds the buffer size
		IPv4Option newOption = ip4Layer.addOption(IPv4OptionBuilder(IPV4OPT_RouterAlert, (uint16_t)100));
		EXPECT_TRUE(newOption.isNull());

		Logger::getInstance().enableLogs();

		newPacket->computeCalculateFields();

		// Delete the packet - the buffer should not be freed
		// delete newPacket;

		std::string expectedHexString =
		    "bbbbbbbbbbbbaaaaaaaaaaaa08004500001e00000000000690b101010101141414140102030405060708090a0000";
		EXPECT_EQ(byteArrayToHexString(buffer.get(), bufferSize), expectedHexString);
	}

	TEST(PacketTest, InsertVlanToPacket)
	{
		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/TcpPacketWithOptions3.dat");

		VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);

		Packet tcpPacket(rawPacket1.get());

		ASSERT_TRUE(tcpPacket.insertLayer(tcpPacket.getFirstLayer(), &vlanLayer));

		EXPECT_EQ(tcpPacket.getRawPacket()->getRawDataLen(), 78);
		EXPECT_EQ(tcpPacket.getFirstLayer()->getNextLayer(), &vlanLayer);
		EXPECT_NE(vlanLayer.getNextLayer(), nullptr);
		EXPECT_EQ(vlanLayer.getNextLayer()->getProtocol(), IPv4);
	}

	TEST(PacketTest, RemoveLayer)
	{
		// parse packet and remove layers
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/TcpPacketNoOptions.dat");
		Packet tcpPacket(rawPacket1.get());

		// a. Remove layer from the middle
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(tcpPacket.removeLayer(IPv4));
		ASSERT_FALSE(tcpPacket.isPacketOfType(IPv4));
		ASSERT_TRUE(tcpPacket.isPacketOfType(Ethernet));
		ASSERT_EQ(tcpPacket.getLayerOfType<IPv4Layer>(), nullptr);
		ASSERT_EQ(tcpPacket.getFirstLayer()->getNextLayer()->getProtocol(), TCP);
		ASSERT_EQ(tcpPacket.getRawPacket()->getRawDataLen(), 271);

		// b. Remove first layer
		// ~~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(tcpPacket.removeFirstLayer());
		ASSERT_FALSE(tcpPacket.isPacketOfType(IPv4));
		ASSERT_FALSE(tcpPacket.isPacketOfType(Ethernet));
		ASSERT_EQ(tcpPacket.getFirstLayer()->getProtocol(), TCP);
		ASSERT_EQ(tcpPacket.getFirstLayer()->getNextLayer()->getNextLayer(), nullptr);
		ASSERT_EQ(tcpPacket.getRawPacket()->getRawDataLen(), 257);

		// c. Remove last layer
		// ~~~~~~~~~~~~~~~~~~~~
		ASSERT_TRUE(tcpPacket.removeLastLayer());
		ASSERT_FALSE(tcpPacket.isPacketOfType(IPv4));
		ASSERT_FALSE(tcpPacket.isPacketOfType(Ethernet));
		ASSERT_EQ(tcpPacket.getFirstLayer(), tcpPacket.getLastLayer());
		ASSERT_EQ(tcpPacket.getFirstLayer()->getProtocol(), TCP);
		ASSERT_EQ(tcpPacket.getRawPacket()->getRawDataLen(), 20);

		// d. Remove a second layer of the same type
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto rawPacket2 = test::createPacketFromHexResource("PacketExamples/Vxlan1.dat");

		Packet vxlanPacket(rawPacket2.get());
		ASSERT_TRUE(vxlanPacket.isPacketOfType(Ethernet));
		ASSERT_TRUE(vxlanPacket.isPacketOfType(IPv4));
		ASSERT_TRUE(vxlanPacket.removeLayer(Ethernet, 1));
		ASSERT_TRUE(vxlanPacket.removeLayer(IPv4, 1));
		ASSERT_TRUE(vxlanPacket.removeLayer(ICMP));
		vxlanPacket.computeCalculateFields();
		ASSERT_TRUE(vxlanPacket.isPacketOfType(Ethernet));
		ASSERT_TRUE(vxlanPacket.isPacketOfType(IPv4));
		ASSERT_TRUE(vxlanPacket.isPacketOfType(VXLAN));
		ASSERT_EQ(vxlanPacket.getRawPacket()->getRawDataLen(), 50);

		// e. Remove a layer that doesn't exist
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		Logger::getInstance().suppressLogs();
		ASSERT_FALSE(vxlanPacket.removeLayer(HTTPRequest));
		ASSERT_FALSE(vxlanPacket.removeLayer(Ethernet, 1));
		Logger::getInstance().enableLogs();

		// create packet and remove layers
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		Packet testPacket(10);

		MacAddress srcMac("aa:aa:aa:aa:aa:aa");
		MacAddress dstMac("bb:bb:bb:bb:bb:bb");
		EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(testPacket.addLayer(&ethLayer));

		IPv4Address ipSrc("1.1.1.1");
		IPv4Address ipDst("20.20.20.20");
		IPv4Layer ip4Layer(ipSrc, ipDst);
		ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;
		ASSERT_TRUE(testPacket.addLayer(&ip4Layer));

		uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
		PayloadLayer payloadLayer(payload, 10);
		ASSERT_TRUE(testPacket.addLayer(&payloadLayer));

		// a. remove first layer
		// ~~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(testPacket.removeLayer(Ethernet));
		ASSERT_EQ(testPacket.getFirstLayer(), &ip4Layer);
		ASSERT_EQ(testPacket.getFirstLayer()->getNextLayer()->getNextLayer(), nullptr);
		ASSERT_FALSE(testPacket.isPacketOfType(Ethernet));
		ASSERT_TRUE(testPacket.isPacketOfType(IPv4));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 30);

		// b. remove last layer
		// ~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(testPacket.removeLayer(GenericPayload));
		ASSERT_EQ(testPacket.getFirstLayer(), &ip4Layer);
		ASSERT_EQ(testPacket.getFirstLayer()->getNextLayer(), nullptr);
		ASSERT_TRUE(testPacket.isPacketOfType(IPv4));
		ASSERT_FALSE(testPacket.isPacketOfType(Ethernet));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 20);

		// c. insert a layer
		// ~~~~~~~~~~~~~~~~~

		VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(testPacket.insertLayer(nullptr, &vlanLayer));
		ASSERT_EQ(testPacket.getFirstLayer(), &vlanLayer);
		ASSERT_EQ(testPacket.getFirstLayer()->getNextLayer(), &ip4Layer, ptr);
		ASSERT_TRUE(testPacket.isPacketOfType(VLAN));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 24);

		// d. remove the remaining layers (packet remains empty!)
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(testPacket.removeLayer(IPv4));
		ASSERT_EQ(testPacket.getFirstLayer(), &vlanLayer);
		ASSERT_FALSE(testPacket.isPacketOfType(IPv4));
		ASSERT_TRUE(testPacket.isPacketOfType(VLAN));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 4);
		ASSERT_TRUE(testPacket.removeLayer(VLAN));
		ASSERT_FALSE(testPacket.isPacketOfType(VLAN));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 0);

		// Detach layer and add it to another packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		// a. create a layer nad a packet and move it to another packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		EthLayer eth(MacAddress("0a:00:27:00:00:15"), MacAddress("0a:00:27:00:00:16"));
		Packet packet1, packet2;
		ASSERT_TRUE(packet1.addLayer(&eth));
		ASSERT_EQ(packet1.getRawPacket()->getRawDataLen(), 14);
		ASSERT_TRUE(packet1.detachLayer(&eth));
		ASSERT_EQ(packet1.getRawPacket()->getRawDataLen(), 0);
		ASSERT_EQ(packet2.getRawPacket()->getRawDataLen(), 0);
		ASSERT_TRUE(packet2.addLayer(&eth));
		ASSERT_EQ(packet2.getRawPacket()->getRawDataLen(), 14);

		// b. parse a packet, detach a layer and move it to another packet
		// c. detach a second instance of the the same protocol
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto rawPacket3 = test::createPacketFromHexResource("PacketExamples/Vxlan1.dat");

		Packet vxlanPacketOrig(rawPacket3.get());
		EthLayer* vxlanEthLayer = dynamic_cast<EthLayer*>(vxlanPacketOrig.detachLayer(Ethernet, 1));
		IcmpLayer* vxlanIcmpLayer = dynamic_cast<IcmpLayer*>(vxlanPacketOrig.detachLayer(ICMP));
		IPv4Layer* vxlanIP4Layer = dynamic_cast<IPv4Layer*>(vxlanPacketOrig.detachLayer(IPv4, 1));
		ASSERT_NE(vxlanEthLayer, nullptr) << "Failed detaching Ethernet layer from vxlan packet";
		ASSERT_NE(vxlanIcmpLayer, nullptr) << "Failed detaching ICPM layer from vxlan packet";
		ASSERT_NE(vxlanIP4Layer, nullptr) << "Failed detaching IPv4 layer from vxlan packet";

		vxlanPacketOrig.computeCalculateFields();
		ASSERT_FALSE(vxlanEthLayer->isAllocatedToPacket());
		ASSERT_FALSE(vxlanIcmpLayer->isAllocatedToPacket());
		ASSERT_FALSE(vxlanIP4Layer->isAllocatedToPacket());
		ASSERT_NE(vxlanPacketOrig.getLayerOfType(Ethernet), nullptr);
		ASSERT_EQ(vxlanPacketOrig.getLayerOfType(Ethernet, 1), nullptr);
		ASSERT_NE(vxlanPacketOrig.getLayerOfType(IPv4), nullptr);
		ASSERT_EQ(vxlanPacketOrig.getLayerOfType(IPv4, 1), nullptr);
		ASSERT_EQ(vxlanPacketOrig.getLayerOfType(ICMP), nullptr);

		Packet packetWithoutTunnel;
		ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanEthLayer));
		ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanIP4Layer));
		ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanIcmpLayer));
		packetWithoutTunnel.computeCalculateFields();

		auto buffer4 = test::PacketTestEnvironment::getCurrent().getDataLoader().loadResource(
		    "PacketExamples/IcmpWithoutTunnel.dat", test::ResourceType::HexData);

		ASSERT_EQ(packetWithoutTunnel.getRawPacket()->getRawDataLen(), buffer4.size());

		// TODO: Improve this comparison
		EXPECT_TRUE(std::memcmp(packetWithoutTunnel.getRawPacket()->getRawData(), buffer4.data(), buffer4.size()) == 0);
		// ASSERT_BUF_COMPARE(packetWithoutTunnel.getRawPacket()->getRawData(), buffer4, bufferLength4);
	}

	TEST(PacketTest, CopyLayerAndPacket)
	{
		FAIL() << "This test is not implemented yet";
	}

	TEST(PacketTest, PacketLayerLookup)
	{
		FAIL() << "This test is not implemented yet";
	}

	// TODO: Move test above PacketTest fixture
	TEST(RawPacketTest, RawPacketTimeStampSetter)
	{
		FAIL() << "This test is not implemented yet";
	}

	TEST(PacketTest, ParsePartialPacket)
	{
		FAIL() << "This test is not implemented yet";
	}

	TEST(PacketTest, PacketTrailer)
	{
		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/packet_trailer_arp.dat");
		auto rawPacket2 = test::createPacketFromHexResource("PacketExamples/packet_trailer_ipv4.dat");
		auto rawPacket3 = test::createPacketFromHexResource("PacketExamples/packet_trailer_ipv6.dat");
		auto rawPacket4 = test::createPacketFromHexResource("PacketExamples/packet_trailer_pppoed.dat");
		auto rawPacket5 = test::createPacketFromHexResource("PacketExamples/packet_trailer_ipv6.dat");

		Packet trailerArpPacket(rawPacket1.get());
		Packet trailerIPv4Packet(rawPacket2.get());
		Packet trailerIPv6Packet(rawPacket3.get());
		Packet trailerPPPoEDPacket(rawPacket4.get());
		Packet trailerIPv6Packet2(rawPacket5.get());

		EXPECT_TRUE(trailerArpPacket.isPacketOfType(PacketTrailer));
		EXPECT_TRUE(trailerIPv4Packet.isPacketOfType(PacketTrailer));
		EXPECT_TRUE(trailerIPv6Packet.isPacketOfType(PacketTrailer));
		EXPECT_TRUE(trailerPPPoEDPacket.isPacketOfType(PacketTrailer));

		EXPECT_EQ(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerLen(), 18);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerLen(), 6);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerLen(), 4);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerLen(), 28);

		EXPECT_EQ(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString(),
		          "742066726f6d2062726964676500203d3d20");
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString(), "0101080a0000");
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString(), "cdfcf105");
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString(),
		          "00000000000000000000000000000000000000000000000000000000");

		EXPECT_EQ(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[3], 0x72);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[2], 0x8);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[1], 0xfc);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[12], 0);

		EthLayer* ethLayer = trailerIPv4Packet.getLayerOfType<EthLayer>();
		IPv4Layer* ip4Layer = trailerIPv4Packet.getLayerOfType<IPv4Layer>();
		ASSERT_NE(ethLayer, nullptr);
		ASSERT_NE(ip4Layer, nullptr);
		EXPECT_GE(ethLayer->getDataLen() - ethLayer->getHeaderLen(), ip4Layer->getDataLen());
		EXPECT_EQ(ip4Layer->getDataLen(), be16toh(ip4Layer->getIPv4Header()->totalLength));

		ethLayer = trailerIPv6Packet.getLayerOfType<EthLayer>();
		IPv6Layer* ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
		ASSERT_NE(ethLayer, nullptr);
		ASSERT_NE(ip6Layer, nullptr);
		EXPECT_GE(ethLayer->getDataLen() - ethLayer->getHeaderLen(), ip6Layer->getDataLen());
		EXPECT_EQ(ip6Layer->getDataLen(), be16toh(ip6Layer->getIPv6Header()->payloadLength) + ip6Layer->getHeaderLen());

		// add layer before trailer
		auto newVlanLayer = new VlanLayer(123, true, 1, PCPP_ETHERTYPE_IPV6);
		ASSERT_TRUE(trailerIPv6Packet.insertLayer(ethLayer, newVlanLayer, true));
		trailerIPv6Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen(), 468);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen(), 454);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen(), 446);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen(), 406);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen(), 398);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 4);

		// add layer just before trailer
		auto httpReq = new HttpRequestLayer(HttpRequestLayer::HttpGET, "/main.html", OneDotOne);
		httpReq->addEndOfHeader();
		TcpLayer* tcpLayer = trailerIPv4Packet.getLayerOfType<TcpLayer>();
		ASSERT_NE(tcpLayer, nullptr);
		trailerIPv4Packet.insertLayer(tcpLayer, httpReq, true);
		trailerIPv4Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen(), 87);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen(), 67);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<TcpLayer>()->getDataLen(), 47);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<HttpRequestLayer>()->getDataLen(), 27);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// add layer after trailer (result with an error)
		uint8_t payload[4] = { 0x1, 0x2, 0x3, 0x4 };
		std::unique_ptr<PayloadLayer> newPayloadLayer = std::make_unique<PayloadLayer>(payload, 4);
		Logger::getInstance().suppressLogs();
		ASSERT_FALSE(trailerIPv4Packet.addLayer(newPayloadLayer.get(), true));
		Logger::getInstance().enableLogs();

		// remove layer before trailer
		EXPECT_TRUE(trailerIPv4Packet.removeLayer(TCP));
		trailerIPv4Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen(), 67);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen(), 47);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<HttpRequestLayer>()->getDataLen(), 27);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// remove layer just before trailer
		EXPECT_TRUE(trailerIPv4Packet.removeLayer(HTTPRequest));
		trailerIPv4Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen(), 40);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen(), 20);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// remove trailer
		ethLayer = trailerIPv6Packet2.getLayerOfType<EthLayer>();
		auto newVlanLayer2 = new VlanLayer(456, true, 1, PCPP_ETHERTYPE_IPV6);
		ASSERT_TRUE(trailerIPv6Packet2.insertLayer(ethLayer, newVlanLayer2, true));
		PacketTrailerLayer* packetTrailer = trailerIPv6Packet2.getLayerOfType<PacketTrailerLayer>();
		ASSERT_NE(packetTrailer, nullptr);
		ASSERT_TRUE(trailerIPv6Packet2.removeLayer(PacketTrailer));
		trailerIPv6Packet2.computeCalculateFields();
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<EthLayer>()->getDataLen(), 464);
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<VlanLayer>()->getDataLen(), 450);
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<IPv6Layer>()->getDataLen(), 446);
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<UdpLayer>()->getDataLen(), 406);
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<DnsLayer>()->getDataLen(), 398);

		// remove all layers but the trailer
		ASSERT_TRUE(trailerIPv4Packet.removeLayer(Ethernet));
		trailerIPv4Packet.computeCalculateFields();
		ASSERT_TRUE(trailerIPv4Packet.removeLayer(IPv4));
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// rebuild packet starting from trailer
		auto newEthLayer =
		    new EthLayer(MacAddress("30:46:9a:23:fb:fa"), MacAddress("6c:f0:49:b2:de:6e"), PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(trailerIPv4Packet.insertLayer(nullptr, newEthLayer, true));
		auto newIp4Layer = new IPv4Layer(IPv4Address("173.194.78.104"), IPv4Address("10.0.0.1"));
		newIp4Layer->getIPv4Header()->ipId = htobe16(40382);
		newIp4Layer->getIPv4Header()->timeToLive = 46;
		trailerIPv4Packet.insertLayer(newEthLayer, newIp4Layer, true);
		auto newTcpLayer = new TcpLayer(443, 55194);
		newTcpLayer->getTcpHeader()->ackNumber = htobe32(0x807df56c);
		newTcpLayer->getTcpHeader()->sequenceNumber = htobe32(0x46529f28);
		newTcpLayer->getTcpHeader()->ackFlag = 1;
		newTcpLayer->getTcpHeader()->windowSize = htobe16(344);
		trailerIPv4Packet.insertLayer(newIp4Layer, newTcpLayer, true);
		trailerIPv4Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen(), 60);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen(), 40);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<TcpLayer>()->getDataLen(), 20);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// extend layer before trailer
		ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
		IPv6RoutingHeader routingExt(4, 3, nullptr, 0);
		ip6Layer->addExtension<IPv6RoutingHeader>(routingExt);
		trailerIPv6Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen(), 476);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen(), 462);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen(), 454);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen(), 406);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen(), 398);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 4);

		// extend layer just before trailer
		PPPoEDiscoveryLayer* pppoeDiscovery = trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>();
		ASSERT_NE(pppoeDiscovery, nullptr);
		// clang-format off
		ASSERT_FALSE(pppoeDiscovery->addTag(PPPoEDiscoveryLayer::PPPoETagBuilder(PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, 0x42524153)).isNull());
		// clang-format on
		trailerPPPoEDPacket.computeCalculateFields();
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<EthLayer>()->getDataLen(), 68);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>()->getDataLen(), 26);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 28);

		// shorten layer before trailer
		ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
		ip6Layer->removeAllExtensions();
		trailerIPv6Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen(), 468);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen(), 454);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen(), 446);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen(), 406);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen(), 398);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 4);

		// shorten layer just before trailer
		pppoeDiscovery = trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>();
		ASSERT_TRUE(pppoeDiscovery->removeAllTags());
		trailerPPPoEDPacket.computeCalculateFields();
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<EthLayer>()->getDataLen(), 48);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>()->getDataLen(), 6);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 28);
	}

	// TODO: Should this be in PacketTest fixture?
	TEST(PacketTest, ResizeLayer)
	{
		FAIL() << "This test is not implemented yet";
	}

	TEST(PacketTest, PrintPacketAndLayers)
	{
		FAIL() << "This test is not implemented yet";
	}

	// TODO: Should this be in PacketTest fixture?
	TEST(PacketTest, ProtocolFamilyMembership)
	{
		auto rawPacket = test::createPacketFromHexResource("PacketExamples/TwoHttpRequests1.dat");
		Packet packet(rawPacket.get());

		auto ipV4Layer = packet.getLayerOfType<IPv4Layer>();
		EXPECT_TRUE(ipV4Layer->isMemberOfProtocolFamily(IP));
		EXPECT_TRUE(ipV4Layer->isMemberOfProtocolFamily(IPv4));
		EXPECT_FALSE(ipV4Layer->isMemberOfProtocolFamily(IPv6));
		EXPECT_FALSE(ipV4Layer->isMemberOfProtocolFamily(HTTP));

		auto httpLayer = packet.getLayerOfType<HttpRequestLayer>();
		EXPECT_TRUE(httpLayer->isMemberOfProtocolFamily(HTTP));
		EXPECT_TRUE(httpLayer->isMemberOfProtocolFamily(HTTPRequest));
		EXPECT_FALSE(httpLayer->isMemberOfProtocolFamily(HTTPResponse));
		EXPECT_FALSE(httpLayer->isMemberOfProtocolFamily(IP));
	}

	TEST(PacketTest, ParseUntilLayer)
	{
		auto rawPacket0 = test::createPacketFromHexResource("PacketExamples/TcpPacketWithOptions3.dat");
		Packet packet0(rawPacket0.get(), OsiModelPhysicalLayer);
		EXPECT_EQ(packet0.getLastLayer(), packet0.getFirstLayer());

		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/TcpPacketWithOptions3.dat");
		Packet packet1(rawPacket1.get(), OsiModelTransportLayer);
		EXPECT_EQ(packet1.getLastLayer()->getOsiModelLayer(), OsiModelTransportLayer);
	}
}  // namespace pcpp