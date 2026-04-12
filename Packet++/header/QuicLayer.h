#pragma once

#include "Layer.h"

// https://datatracker.ietf.org/doc/rfc9000/

namespace pcpp
{
	namespace internal
	{
#pragma pack(push, 1)
		/// @brief A structure that represents the fixed part of a long header QUIC packet.
		///
		/// This structure excludes the variable-length fields that may follow the fixed header, such as the Destination
		/// Connection ID, Source Connection ID, and any additional fields specific to the packet type.
		struct quic_fixed_header_long
		{
			/// @brief Should always be 1 for long headers
			uint8_t headerForm : 1;
			/// @brief Should always be 1 for valid packets.
			/// Only version negotiation packets can have this bit set to 0.
			uint8_t fixedBit : 1;
			/// @brief The QUIC packet type
			uint8_t longPacketType : 2;
			/// @brief Reserved for use by the specific packet type
			/// @remarks These bits are protected using header protection [QUIC-TLS Section 5.4].
			uint8_t typeSpecificBits : 4;

			uint32_t version;

			// Followed by variable-length fields:
			// - Destination Connection ID Length (8 bits)
			// - Destination Connection ID (variable length, max 20)
			// - Source Connection ID Length (8 bits)
			// - Source Connection ID (variable length, max 20)
			// - Type specific payload (variable length)
		};

		struct QuicLongHeader
		{
			quic_fixed_header_long* fixedHeader;

			uint8_t destConnLen;
			uint8_t const* destId;
			uint8_t sourceConnLen;
			uint8_t const* sourceId;
			uint8_t const* typePayload;
		};

		/// @brief A structure that represents the fixed part of a short header QUIC packet.
		///
		/// This structure excludes the variable-length header fields that may follow the fixed header, such as
		/// the Destination Connection ID and Packet Number.
		struct quic_fixed_header_short
		{
			/// @brief Should always be 0 for short headers
			uint8_t headerForm : 1;
			/// @brief Should always be 1 for valid packets.
			/// All short headers with 0 value in this bit are considered invalid and MUST be discarded.
			uint8_t fixedBit : 1;
			/// @brief Latency spin bit.
			uint8_t spinBit : 1;

			/// @brief Reserved bits. Must be 0 when header protection is removed.
			/// @remarks This bit is protected using header protection [QUIC-TLS Section 5.4].
			uint8_t reservedBits : 2;

			/// @brief The key phase bit indicates which keys are used for packet protection.
			/// @remarks This bit is protected using header protection [QUIC-TLS Section 5.4].
			uint8_t keyPhaseBit : 1;

			/// @brief The length of the Packet Number field in bytes, encoded as a 2-bit unsigned integer.
			/// @remarks This bit is protected using header protection [QUIC-TLS Section 5.4].
			uint8_t packetNumberLength : 2;

			// Followed by variable-length fields:
			// - Destination Connection ID (variable length, determined by the connection, max 20)
			// - Packet Number (variable length, determined by the packetNumberLength field)
			// - Protected Payload (variable length)
		};
#pragma pack(pop)
	}  // namespace internal

	// TODO: assign a proper value
	// const ProtocolType QuicProtocol = 0x00;

	class QuicLayer : public Layer
	{
	public:
		QuicLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) 
			: Layer(data, dataLen, prevLayer, packet, UnknownProtocol)
		{}

		void parseNextLayer() override
		{
			// Dump unparsed encrypted payload as PayloadLayer, as parsing QUIC packets is non-trivial and requires decryption.
		}

		void parseSelf()
		{
			// Parse as much of the QUIC header as possible.
			// TODO: Cache fields?
		}

		/// @return The header length in bytes
		size_t getHeaderLen() const override
		{
			// TODO: Placeholder
			return 0;
		}

		/// Each layer can compute field values automatically using this method. This is an abstract method
		void computeCalculateFields() override
		{}

		/// @return A string representation of the layer most important data (should look like the layer description in
		/// Wireshark)
		std::string toString() const override
		{
			return "QuicLayer - parsing not implemented";
		}

		/// @return The OSI Model layer this protocol belongs to
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelLayer::OsiModelLayerUnknown;
		}

	private:

	};
}  // namespace pcpp
