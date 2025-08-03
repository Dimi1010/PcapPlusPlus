#include "PacketFactory.hpp"

#include "SystemUtils.h"
#include "TimespecTimeval.h"

namespace pcpp
{
	namespace test
	{
		PacketFactory::PacketFactory()
		{
			timeval factoryTimeTV;
			// Initialize factoryTime to the current time
			gettimeofday(&factoryTimeTV, nullptr);
			factoryTime = internal::toTimespec(factoryTimeTV);
		}

		PacketFactory& PacketFactory::withTime(timespec time)
		{
			// TODO: insert return statement here
			factoryTime = time;
			return *this;
		}

		PacketFactory& PacketFactory::withTime(timeval time)
		{
			return withTime(internal::toTimespec(time));
		}

		PacketFactory& PacketFactory::withLinkType(LinkLayerType linkType)
		{
			defaultLinkType = linkType;
			return *this;
		}

		std::unique_ptr<RawPacket> PacketFactory::createFromBuffer(std::unique_ptr<uint8_t[]> buffer,
		                                                           size_t bufferLen) const
		{
			if (buffer == nullptr || bufferLen == 0)
			{
				throw std::invalid_argument("Buffer cannot be null and length must be greater than zero");
			}

			return std::make_unique<RawPacket>(buffer.release(), static_cast<int>(bufferLen), factoryTime, true,
			                                   defaultLinkType);
		}

		std::unique_ptr<RawPacket> PacketFactory::createFromBufferNonOwning(std::vector<uint8_t> const& buffer) const
		{
			return createFromBufferNonOwning(buffer.data(), buffer.size());
		}

		std::unique_ptr<RawPacket> PacketFactory::createFromBufferNonOwning(const uint8_t* buffer,
		                                                                    size_t bufferLen) const
		{
			if (buffer == nullptr || bufferLen == 0)
			{
				throw std::invalid_argument("Buffer cannot be null and length must be greater than zero");
			}

			return std::make_unique<RawPacket>(buffer, static_cast<int>(bufferLen), factoryTime, false,
			                                   defaultLinkType);
		}

		std::unique_ptr<RawPacket> createPacketFromHexResource(const std::string& resourceName,
		                                                       const PacketFactory& factory,
		                                                       TestDataLoader const* dataLoader)
		{
			if (dataLoader == nullptr)
			{
				// If no data loader is provided, use the current test environment's data loader
				dataLoader = &PacketTestEnvironment::getCurrent().getDataLoader();
			}

			auto resource = dataLoader->loadResource(resourceName, ResourceType::HexData);
			return factory.createFromBuffer(std::move(resource.data), resource.length);
		}
	}  // namespace test
}  // namespace pcpp