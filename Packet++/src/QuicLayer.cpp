#include "QuicLayer.h"

#include "EndianPortable.h"
#include "TLVData.h"

namespace pcpp
{
	namespace
	{
#pragma pack(push, 1)
		/// @brief Represents a version invariant first byte of a QUIC packet header as per [RFC 8999].
		struct quic_v0_first_byte
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t versionSpecificBits : 7;
			/// @brief Should always be 1 for long headers, and 0 for short headers.
			uint8_t headerForm : 1;
#else
			/// @brief Should always be 1 for long headers, and 0 for short headers.
			uint8_t headerForm : 1;
			uint8_t versionSpecificBits : 7;
#endif
		};

		/// @brief Represents a version invariant long header QUIC packet as per [RFC 8999].
		struct quic_v0_fixed_header_long
		{
			quic_v0_first_byte firstByte;
			uint32_t version;

			// Followed by:
			// - Destination Connection ID Length (1 byte)
			// - Destination Connection ID (variable length, max 255 bytes)
			// - Source Connection ID Length (1 byte)
			// - Source Connection ID (variable length, max 255 bytes)
			// - Version Specific Data (...)
		};
#pragma pack(pop)
	}  // namespace

	QuicLayer* QuicLayer::parseFromBuffer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		// V1 Limits
		// QUIC Short form header is at least 3 bytes:
		// - 1 byte for fixed initial header.
		// - 0 to 20 bytes for Destination connection id
		// - 1 to 4 bytes for Packet number
		// - 1+ bytes of protected payload. Always included due to encryption, but may be empty after decryption.
		// TODO: Research minimum length of AEAD tag that is mandatory as part of the payload (16 bytes)?
		constexpr size_t minViableShortFormSize = 3;

		// QUIC Long form header is at least 8 bytes:
		// - 1 for fixed initial header.
		// - 4 byte for version
		// - 1 byte for DCID length
		// - 0 to 20 bytes for DCID
		// - 1 byte for SCID length
		// - 0 to 20 bytes for SCID
		// - 1+ byte of type specific payload.
		// TODO: Does it have AEAD tag?
		constexpr size_t minViableLongFormSize = 8;

		// At least 1 byte is required.
		if (data == nullptr || dataLen < 1)
		{
			return nullptr;
		}

		auto* const dataEnd = data + dataLen;

		quic_v0_first_byte firstByte = *reinterpret_cast<quic_v0_first_byte*>(&data[0]);

		// internal::quic_common_first_byte firstByte = *reinterpret_cast<internal::quic_common_first_byte*>(&data[0]);

		// Check the fixed bit. Must be 1 for valid QUIC packets. See [RFC 9000, Section 17.1 / 17.3]
		// Version negotiation packet is the only exception.
		// const bool fixedBitSet = firstByte.fixedBit;

		// Check the form bit.
		const bool isLongForm = firstByte.headerForm;
		if (isLongForm)  // Long form
		{
			// Check the version signature of the packet:
			constexpr uint32_t VerNegotiation = 0;
			constexpr uint32_t Version1 = 1;
			constexpr uint32_t Version2 = 0x6b3343cf;

			uint32_t version = 0;
			{
				quic_v0_fixed_header_long longHeader = *reinterpret_cast<quic_v0_fixed_header_long*>(&data[0]);
				version = be32toh(longHeader.version);
			}

			switch (version)
			{
			case VerNegotiation:
			case Version1:
			case Version2:
				break;
			default:
				return nullptr;  // Failed version signature check, not a valid QUIC packet.
			}

			// Parse common data
			// Get the location of the type specific data.
			// Pass that to the layer for lazy eval.

			if (dataLen < minViableLongFormSize)
			{
				return nullptr;
			}

			uint8_t* basePtr = data;

			internal::quic_fixed_header_long const* longFixedHeader =
			    reinterpret_cast<internal::quic_fixed_header_long const*>(basePtr);

			uint32_t version = be32toh(longFixedHeader->version);

			if (version == 0)
			{
				// Version negotiation packet. TODO: Support parsing this type of packet.
				return nullptr;
			}

			if (version != 1)
			{
				// Only V1 is supported for now. TODO: Support parsing other versions.
				return nullptr;
			}

			basePtr += sizeof(internal::quic_fixed_header_long);

			uint8_t dcidLen = *basePtr;  // Included in minViableLongFormSize
			basePtr += 1;

			//
			if (dcidLen > 20)
			{
				return nullptr;
			}

			// Out of bounds check for DCID length byte and DCID value
			if (basePtr + dcidLen > dataEnd)
			{
				return nullptr;
			}

			// TODO: Length, Value
			// LV - DCID
			// LV - SCID

			// Type Payload.
		}
		else  // Short form
		{
			// Short header does not have a version field.

			// Fixed bit must be set to 1 for valid short header packets. See [RFC 9000, Section 17.2]
			// if (!fixedBitSet)
			// {
			//	  return nullptr;
			// }

			if (dataLen < minViableShortFormSize)
			{
				return nullptr;
			}

			// TODO
		}

		return nullptr;
	}
}  // namespace pcpp