#pragma once

#include "Layer.h"
#include "EndianPortable.h"

// https://datatracker.ietf.org/doc/rfc9000/

namespace pcpp
{
	namespace internal
	{
#pragma pack(push, 1)
		struct quic_common_first_byte
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t formSpecificBits : 6;
			uint8_t fixedBit : 1;
			uint8_t headerForm : 1;
#else
			uint8_t headerForm : 1;
			uint8_t fixedBit : 1;
			uint8_t formSpecificBits : 6;
#endif
		};
		static_assert(sizeof(quic_common_first_byte) == 1, "Size of quic_common_first_byte must be 1 byte");

		/// @brief A structure that represents the fixed part of a long header QUIC packet.
		///
		/// This structure excludes the variable-length fields that may follow the fixed header, such as the Destination
		/// Connection ID, Source Connection ID, and any additional fields specific to the packet type.
		struct quic_fixed_header_long
		{
			struct
			{
#if (BYTE_ORDER == LITTLE_ENDIAN)
				/// @brief Reserved for use by the specific packet type
				/// @remarks These bits are protected using header protection [QUIC-TLS Section 5.4].
				uint8_t typeSpecificBits : 4;
				/// @brief The QUIC packet type
				uint8_t longPacketType : 2;
				/// @brief Should always be 1 for valid packets.
				/// Only version negotiation packets can have this bit set to 0.
				uint8_t fixedBit : 1;
				/// @brief Should always be 1 for long headers
				uint8_t headerForm : 1;
#else
				/// @brief Should always be 1 for long headers
				uint8_t headerForm : 1;
				/// @brief Should always be 1 for valid packets, except
				/// version negotiation packets can have this bit set to 0.
				uint8_t fixedBit : 1;
				/// @brief The QUIC packet type
				uint8_t longPacketType : 2;
				/// @brief Reserved for use by the specific packet type
				/// @remarks These bits are protected using header protection [QUIC-TLS Section 5.4].
				uint8_t typeSpecificBits : 4;
#endif
			} firstByte;

			uint32_t version;

			// Followed by variable-length fields:
			// - Destination Connection ID Length (1 byte)
			// - Destination Connection ID (variable length, max 20 bytes)
			// - Source Connection ID Length (1 byte)
			// - Source Connection ID (variable length, max 20 bytes)
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
			struct
			{
#if (BYTE_ORDER == LITTLE_ENDIAN)
				/// @brief The length of the Packet Number field in bytes, encoded as a 2-bit unsigned integer.
				/// @remarks This bit is protected using header protection [QUIC-TLS Section 5.4].
				uint8_t packetNumberLength : 2;

				/// @brief The key phase bit indicates which keys are used for packet protection.
				/// @remarks This bit is protected using header protection [QUIC-TLS Section 5.4].
				uint8_t keyPhaseBit : 1;

				/// @brief Reserved bits. Must be 0 when header protection is removed.
				/// @remarks This bit is protected using header protection [QUIC-TLS Section 5.4].
				uint8_t reservedBits : 2;

				/// @brief Latency spin bit.
				uint8_t spinBit : 1;

				/// @brief Should always be 1 for valid packets.
				/// All short headers with 0 value in this bit are considered invalid and MUST be discarded.
				uint8_t fixedBit : 1;

				/// @brief Should always be 0 for short headers
				uint8_t headerForm : 1;
#else
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
#endif
			} firstByte;

			// Followed by variable-length fields:
			// - Destination Connection ID (variable length, determined by the connection, max 20)
			// - Packet Number (variable length, determined by the packetNumberLength field)
			// - Protected Payload (variable length)
		};
#pragma pack(pop)
	}  // namespace internal

	// TODO: assign a proper value
	// const ProtocolType QuicV0Protocol = 0x00;
	// const ProtocolType QuicV1Protocol = 0x00;
	// const ProtocolType QuicV2Protocol = 0x00;

	class QuicLayer : public Layer
	{
	public:
		QuicLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, UnknownProtocol)
		{}

		/// @brief Attempts to parse a QUIC layer from the provided buffer.
		///
		/// This method may return nullptr if the data does not appear to be a valid QUIC packet or if parsing fails for
		/// any reason.
		///
		/// @param[in] data The raw data buffer containing the potential QUIC packet. This should point to the start of
		/// the QUIC header.
		/// @param[in] dataLen The length of the data buffer in bytes.
		/// @param[in] prevLayer The previous layer in the packet.
		/// @param[in] packet The packet to which this layer belongs.
		/// @return A pointer to the parsed QuicLayer, or nullptr if parsing fails.
		static QuicLayer* parseFromBuffer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		void parseNextLayer() override
		{
			// Dump unparsed encrypted payload as PayloadLayer, as parsing QUIC packets is non-trivial and requires
			// decryption.
		}

		void parseSelf()
		{
			// Parse as much of the QUIC header as possible.
			// TODO: Cache fields?

			// Determine long or short form.
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
			return OsiModelLayer::OsiModelTransportLayer;
		}
	};

	/// @brief Represents a QUIC version negotiation layer in a network packet.
	///
	/// See RFC 8999 and RFP 9000.
	class QuicVerNegLayer : public QuicLayer
	{
		// static QuicVerNegLayer parseVerNegFromBuffer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	};

	/// @brief Represents a QUIC version 1 layer in a network packet.
	///
	/// See RFC 9000.
	class QuicV1Layer : public QuicLayer
	{
		// static QuicV1Layer* parseV1FromBuffer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	};

	/// @brief Represents a QUIC version 2 layer in a network packet.
	///
	/// See RFC 9369.
	class QuicV2Layer : public QuicLayer
	{
		// static QuicV2Layer* parseV2FromBuffer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	};
}  // namespace pcpp
