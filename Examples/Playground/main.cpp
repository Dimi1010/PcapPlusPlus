#include <iostream>

#include "TcpReassemblyNext.h"

#define PTF_EQ(a, b, msg)                                                                                              \
	do                                                                                                                 \
	{                                                                                                                  \
		if ((a) != (b))                                                                                                \
		{                                                                                                              \
			std::cerr << "PTF_EQ failed: " << (a) << " != " << (b) << ". " << msg << std::endl;                        \
		}                                                                                                              \
	} while (0)

int main()
{
	using namespace pcpp;

	internal::TcpByteStream stream;

	std::array<uint8_t, 256> data;
	uint8_t c = 0;
	for (auto& e : data)
	{
		e = c++;
	}

	auto onDataReady = [](internal::TcpByteStreamDataReadyEvent const& event) {
		PCPP_LOG_DEBUG("Data ready callback batch parts ready. Missing Bytes="<<event.getLeadingMissingBytes());
		if(event.hasMainPart)
		{
			PCPP_LOG_DEBUG("Data ready callback: main part with SEQ " << event.mainPart.seqNum << " and length "
			                                                          << event.mainPart.dataLen);
		}

		for (auto& part : event.extraParts)
		{
			PCPP_LOG_DEBUG("Data ready callback: extra part with SEQ " << part.seqNum << " and length " << part.dataLen);
		}

		PCPP_LOG_DEBUG("Data ready callback done. Next SEQ=" << event.nextSeqPart());
	};

	// stream.reserveReorderBuffer(15);

	// SYN packet with 40 bytes of data, but the logical end sequence number is 41 (40 + 1 for SYN)
	stream.insertSeq(onDataReady, 0, &data[0], 40, { 1, 0 });
	PTF_EQ(stream.expectedSeq(), 41, "");

	stream.insertSeq(onDataReady, 41, &data[0], 20);  // SEQ=41 -> SEQ=61
	PTF_EQ(stream.expectedSeq(), 61, "");

	// Past OOS

	stream.insertSeq(onDataReady, 45, &data[0], 10);  // SEQ=30 -> SEQ=40, out of order, retransmission
	PTF_EQ(stream.expectedSeq(), 61, "");

	stream.insertSeq(onDataReady, 55, &data[0], 10);  // SEQ=35 -> SEQ=45, out of order, retransmission, new data
	PTF_EQ(stream.expectedSeq(), 65, "");

	// Future OOS

	stream.insertSeq(onDataReady, 100, &data[0], 20);  // SEQ=100 -> SEQ=120, future out of order, new data.

	stream.insertSeq(onDataReady, 120, &data[0], 20);  // SEQ=120 -> SEQ=140, future out of order, new data.

	stream.insertSeq(onDataReady, 155, &data[0], 10);  // SEQ=155 -> SEQ=165, future out of order, new data.

	// Filled regions: [100 - 140), [155, 165)
	// As parts:       [100, 120), [120, 140), ----------, [155, 165)
	// Should fill:                            [140, 145)
	stream.insertSeq(onDataReady, 135, &data[0],
	                 10);  // SEQ=135 -> SEQ=145, future out of order, new data, right overlap.

	// Filled regions: [100, 145), [155, 165)
	// As parts:       [100, 120), [120, 140), [140, 145), ----------, [155, 165)
	// Should fill                       [130, ----  145)  [145, 155)
	stream.insertSeq(onDataReady, 130, &data[0],
	                 25);  // SEQ=130 -> SEQ=155, future out of order, new data, right + left overlap.

	stream.insertSeq(onDataReady, 200, &data[0], 20);
	stream.insertSeq(onDataReady, 240, &data[0], 20);
	stream.insertSeq(onDataReady, 280, &data[0], 10);

	// Filled regions: [200, 220) , ---------- , [240, 260), ---------- , [280, 290)
	// Should fill:                 [220, 240)               [260, 280)              , [290, 300)
	stream.insertSeq(onDataReady, 220, &data[0], 80);  // SEQ=220 -> SEQ=300

    // Should unblock [60, 155).
    stream.insertSeq(onDataReady, 65, &data[0], 40);
    
    stream.setSeqHeadAndFlush(200, onDataReady);

	return 0;
}