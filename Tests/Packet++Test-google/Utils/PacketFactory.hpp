#pragma once

#include "pch.h"

#include "RawPacket.h"

namespace pcpp
{
	namespace test
	{
		class PacketFactory
		{
		public:
			/// @brief The time used for creating packets in the factory.
			timespec factoryTime;
			/// @brief The default link layer type for packets created by this factory.
			LinkLayerType defaultLinkType = LinkLayerType::LINKTYPE_ETHERNET;

			/// @brief Creates a new PacketFactory instance with the current time as factoryTime.
			PacketFactory();

			PacketFactory& withTime(timespec time);
			PacketFactory& withTime(timeval time);
			PacketFactory& withLinkType(LinkLayerType linkType);

			// TODO: RawPacket requires a move constructor to return by value efficiently.
			/// @brief Creates a RawPacket from a vector of bytes.
			/// @param buffer A unique pointer to a buffer containing the raw packet data.
			/// @param bufferLen The length of the buffer in bytes.
			/// @return A RawPacket object created from the buffer.
			std::unique_ptr<RawPacket> createFromBuffer(std::unique_ptr<uint8_t[]> buffer, size_t bufferLen) const;

			/// @brief Creates a RawPacket from a vector of bytes without taking ownership of the data.
			/// @param buffer A vector containing the raw packet data.
			/// @return A RawPacket object created from the buffer.
			std::unique_ptr<RawPacket> createFromBufferNonOwning(std::vector<uint8_t> const& buffer) const;

			/// @brief Creates a RawPacket from a buffer without taking ownership of the data.
			/// @param buffer A pointer to the raw packet data.
			/// @param bufferLen The length of the buffer in bytes.
			/// @return A RawPacket object created from the buffer.
			std::unique_ptr<RawPacket> createFromBufferNonOwning(const uint8_t* buffer, size_t bufferLen) const;
		};

		/// @brief Creates a RawPacket from a resource file.
		/// @param resourceName The name of the resource file to read the packet data from.
		/// @param factory The PacketFactory to use for creating the RawPacket.
		/// @param dataLoader An optional TestDataLoader to use for loading the resource file.
		///   Uses the test environment loader if not provided.
		/// @return A RawPacket object created from the resource file.
		std::unique_ptr<RawPacket> createPacketFromHexResource(const std::string& resourceName,
		                                                       const PacketFactory& factory = PacketFactory(),
		                                                       TestDataLoader const* dataLoader = nullptr);

	}  // namespace test
}  // namespace pcpp
