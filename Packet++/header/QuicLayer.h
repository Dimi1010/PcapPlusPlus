#pragma once

#include "Layer.h"

// https://datatracker.ietf.org/doc/rfc9000/

namespace pcpp
{
	namespace internal
	{
#pragma pack(push, 1)
		/// @brief A long form QUIC packet header.
		struct quic_header_long
		{
			/// @brief Should always be 1 for long headers
			uint8_t headerForm : 1;
			/// @brief Should always be 1 for valid packets.
			/// Only version negotiation packets can have this bit set to 0.
			uint8_t fixedBit : 1;
			/// @brief The QUIC packet type
			uint8_t longPacketType : 2;
			/// @brief Reserved for use by the specific packet type
			uint8_t packetSpecificBits : 4;
			uint32_t version;
		};

		/// @brief A short form QUIC packet header.
		struct quic_header_short
		{
		};
#pragma pack(pop)
	}  // namespace internal

	class QuicLayer : public Layer
	{
	};
}  // namespace pcpp
