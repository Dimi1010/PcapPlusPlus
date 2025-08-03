#include "pch.h"

#include "TestEnvironment.hpp"

#include "EndianPortable.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "PacketUtils.h"

namespace pcpp
{
	TEST(PacketUtilsTest, Hash5TupleUdp)
	{
		IPv4Address dstIP("10.0.0.6");
		IPv4Address srcIP("212.199.202.9");

		IPv4Layer ipLayer(srcIP, dstIP);
		ipLayer.getIPv4Header()->ipId = htobe16(20300);
		ipLayer.getIPv4Header()->fragmentOffset = htobe16(0x4000);
		ipLayer.getIPv4Header()->timeToLive = 59;
		UdpLayer udpLayer(63628, 1900);

		Packet srcDstPacket(1);
		srcDstPacket.addLayer(&ipLayer);
		srcDstPacket.addLayer(&udpLayer);
		srcDstPacket.computeCalculateFields();

		IPv4Layer ipLayer2(dstIP, srcIP);
		ipLayer2.getIPv4Header()->ipId = htobe16(20300);
		ipLayer2.getIPv4Header()->fragmentOffset = htobe16(0x4000);
		ipLayer2.getIPv4Header()->timeToLive = 59;
		UdpLayer udpLayer2(1900, 63628);

		Packet dstSrcPacket(1);
		dstSrcPacket.addLayer(&ipLayer2);
		dstSrcPacket.addLayer(&udpLayer2);
		dstSrcPacket.computeCalculateFields();

		// Test default behaviour where hash of SRC->DST == DST->SRC
		EXPECT_EQ(hash5Tuple(&srcDstPacket), hash5Tuple(&dstSrcPacket))
		    << "Undirected hashing of SRC->DST and DST->SRC packets is not equal.";

		// Test of direction-unique-hash where SRC->DST != DST->SRC
		EXPECT_NE(hash5Tuple(&srcDstPacket, true), hash5Tuple(&dstSrcPacket, true))
		    << "Direction-unique hashing is equal for symmetric packets.";

		EXPECT_EQ(hash5Tuple(&srcDstPacket, false), 683027169)
		    << "Hash of SRC->DST packet with direction-unique-hash set to false is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&srcDstPacket, true), 926590153)
		    << "Hash of SRC->DST packet with direction-unique-hash set to true is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&dstSrcPacket, false), 683027169)
		    << "Hash of DST->SRC packet with direction-unique-hash set to false is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&dstSrcPacket, true), 683027169)
		    << "Hash of DST->SRC packet with direction-unique-hash set to true is not equal to expected value.";
	}

	TEST(PacketUtilsTest, Hash5TupleTcp)
	{
		IPv4Address dstIP("10.0.0.6");
		IPv4Address srcIP("212.199.202.9");

		IPv4Layer ipLayer(srcIP, dstIP);
		ipLayer.getIPv4Header()->ipId = htobe16(20300);
		ipLayer.getIPv4Header()->fragmentOffset = htobe16(0x4000);
		ipLayer.getIPv4Header()->timeToLive = 59;

		TcpLayer tcpLayer((uint16_t)60388, (uint16_t)80);
		tcpLayer.getTcpHeader()->sequenceNumber = htobe32(0xb829cb98);
		tcpLayer.getTcpHeader()->ackNumber = htobe32(0xe9771586);
		tcpLayer.getTcpHeader()->ackFlag = 1;
		tcpLayer.getTcpHeader()->pshFlag = 1;
		tcpLayer.getTcpHeader()->windowSize = htobe16(20178);

		Packet srcDstPacket(1);
		srcDstPacket.addLayer(&ipLayer);
		srcDstPacket.addLayer(&tcpLayer);
		srcDstPacket.computeCalculateFields();

		IPv4Layer ipLayer2(dstIP, srcIP);
		ipLayer2.getIPv4Header()->ipId = htobe16(20300);
		ipLayer2.getIPv4Header()->fragmentOffset = htobe16(0x4000);
		ipLayer2.getIPv4Header()->timeToLive = 59;

		TcpLayer tcpLayer2((uint16_t)80, (uint16_t)60388);
		tcpLayer2.getTcpHeader()->sequenceNumber = htobe32(0xb829cb98);
		tcpLayer2.getTcpHeader()->ackNumber = htobe32(0xe9771586);
		tcpLayer2.getTcpHeader()->ackFlag = 1;
		tcpLayer2.getTcpHeader()->pshFlag = 1;
		tcpLayer2.getTcpHeader()->windowSize = htobe16(20178);

		Packet dstSrcPacket(1);
		dstSrcPacket.addLayer(&ipLayer2);
		dstSrcPacket.addLayer(&tcpLayer2);
		dstSrcPacket.computeCalculateFields();

		// Test default behaviour where hash of SRC->DST == DST->SRC
		EXPECT_EQ(hash5Tuple(&srcDstPacket), hash5Tuple(&dstSrcPacket))
		    << "Undirected hashing of SRC->DST and DST->SRC packets is not equal.";

		// Test of direction-unique-hash where SRC->DST != DST->SRC
		EXPECT_NE(hash5Tuple(&srcDstPacket, true), hash5Tuple(&dstSrcPacket, true))
		    << "Direction-unique hashing is equal for symmetric packets.";

		EXPECT_EQ(hash5Tuple(&srcDstPacket, false), 1576639238)
		    << "Hash of SRC->DST packet with direction-unique-hash set to false is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&srcDstPacket, true), 2243556734)
		    << "Hash of SRC->DST packet with direction-unique-hash set to true is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&dstSrcPacket, false), 1576639238)
		    << "Hash of DST->SRC packet with direction-unique-hash set to false is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&dstSrcPacket, true), 1576639238)
		    << "Hash of DST->SRC packet with direction-unique-hash set to true is not equal to expected value.";

		tcpLayer.getTcpHeader()->portDst = 80;
		tcpLayer.getTcpHeader()->portSrc = 80;

		tcpLayer2.getTcpHeader()->portDst = 80;
		tcpLayer2.getTcpHeader()->portSrc = 80;

		EXPECT_EQ(hash5Tuple(&srcDstPacket), hash5Tuple(&dstSrcPacket))
		    << "Hash of SRC->DST packet with same ports is not equal to hash of DST->SRC packet with same ports.";
		EXPECT_NE(hash5Tuple(&srcDstPacket, true), hash5Tuple(&dstSrcPacket, true))
		    << "Direction-unique hash of SRC->DST packet with same ports is equal to hash of DST->SRC packet with same ports.";
	}

	TEST(PacketUtilsTest, Hash5TupleIPv6)
	{
		IPv6Address dstIP("fe80::4dc7:f593:1f7b:dc11");
		IPv6Address srcIP("ff02::c");

		IPv6Layer ipLayer(srcIP, dstIP);
		UdpLayer udpLayer(63628, 1900);

		Packet srcDstPacket(1);
		srcDstPacket.addLayer(&ipLayer);
		srcDstPacket.addLayer(&udpLayer);
		srcDstPacket.computeCalculateFields();

		IPv6Layer ipLayer2(dstIP, srcIP);
		UdpLayer udpLayer2(1900, 63628);

		Packet dstSrcPacket(1);
		dstSrcPacket.addLayer(&ipLayer2);
		dstSrcPacket.addLayer(&udpLayer2);
		dstSrcPacket.computeCalculateFields();

		// Test default behaviour where hash of SRC->DST == DST->SRC
		EXPECT_EQ(hash5Tuple(&srcDstPacket), hash5Tuple(&dstSrcPacket))
		    << "Undirected hashing of SRC->DST and DST->SRC packets is not equal.";

		// Test of direction-unique-hash where SRC->DST != DST->SRC
		EXPECT_NE(hash5Tuple(&srcDstPacket, true), hash5Tuple(&dstSrcPacket, true))
		    << "Direction-unique hashing is equal for symmetric packets.";

		EXPECT_EQ(hash5Tuple(&srcDstPacket, false), 4288746927)
		    << "Hash of SRC->DST packet with direction-unique-hash set to false is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&srcDstPacket, true), 2229527039)
		    << "Hash of SRC->DST packet with direction-unique-hash set to true is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&dstSrcPacket, false), 4288746927)
		    << "Hash of DST->SRC packet with direction-unique-hash set to false is not equal to expected value.";
		EXPECT_EQ(hash5Tuple(&dstSrcPacket, true), 4288746927)
		    << "Hash of DST->SRC packet with direction-unique-hash set to true is not equal to expected value.";

		udpLayer.getUdpHeader()->portDst = 80;
		udpLayer.getUdpHeader()->portSrc = 80;

		udpLayer2.getUdpHeader()->portDst = 80;
		udpLayer2.getUdpHeader()->portSrc = 80;

		EXPECT_EQ(hash5Tuple(&srcDstPacket), hash5Tuple(&dstSrcPacket))
		    << "Hash of SRC->DST packet with same ports is not equal to hash of DST->SRC packet with same ports.";
		EXPECT_NE(hash5Tuple(&srcDstPacket, true), hash5Tuple(&dstSrcPacket, true))
		    << "Direction-unique hash of SRC->DST packet with same ports is equal to hash of DST->SRC packet with same ports.";
	}
}  // namespace pcpp
