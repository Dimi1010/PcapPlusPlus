#include "experimental/ArenaPacket.h"

namespace pcpp
{
	namespace experimental
	{

		ArenaPacket::ArenaPacket(RawPacket* rawPacket, bool ownRawPacket, ParseOptions options)
		    : ArenaPacket(NoParse, rawPacket, ownRawPacket)
		{
			parseLayers(options);
		}

		ArenaPacket::ArenaPacket(NoParseTag, RawPacket* rawPacket, bool ownRawPacket)
		{
			setRawPacket(NoParse, rawPacket, ownRawPacket);
		}

		ArenaPacket::ArenaPacket(NoParseTag, MemoryArena arena, RawPacket* rawPacket, bool ownRawPacket)
		    : ArenaPacket(std::move(arena))
		{
			setRawPacket(NoParse, rawPacket, ownRawPacket);
		}

		ArenaPacket::ArenaPacket(MemoryArena arena, RawPacket* rawPacket, bool ownRawPacket, ParseOptions options)
		    : ArenaPacket(NoParse, std::move(arena), rawPacket, ownRawPacket)
		{
			parseLayers(options);
		}

		void ArenaPacket::setRawPacket(RawPacket* rawPacket, bool ownPacket, ParseOptions options)
		{
			// Delegate to the no parse overload.
			setRawPacket(NoParse, rawPacket, ownPacket);
			// Parse the layers based on the provided options
			parseLayers(options);
		}

		void ArenaPacket::setRawPacket(NoParseTag, RawPacket* rawPacket, bool ownRawPacket)
		{
			// Destroy the existing packet data, if any

			// Assign the new raw packet
		}

		void ArenaPacket::parseLayers(ParseOptions options)
		{}

		void ArenaPacket::clearParseData()
		{
			MemoryArenaAllocator<Layer> allocator(m_Arena);
			std::allocator_traits<MemoryArenaAllocator<Layer>> allocTraits;

			Layer* curLayer = m_FirstLayer;
			while (curLayer != nullptr)
			{
				Layer* nextLayer = curLayer->getNextLayer();

				if (curLayer->m_AllocationInfo.ownedByPacket)
				{
					// This calls the layer destructor, but does not free the memory.
					const size_t objSize = curLayer->getSizeOf();
					PCPP_LOG_DEBUG("Destroying layer of type " << typeid(*curLayer).name() << " of size " << objSize);

					allocTraits.destroy(allocator, curLayer);

					// Uses the arena directly to deallocate the memory, because we pass the size directly.
					// The allocator would have used sizeof(Layer), which is not correct for derived classes.
					m_Arena.deallocate(curLayer, objSize);
				}
				else
				{
					// TODO: This might be valid use case or not?
					throw std::logic_error("Handle layers that aren't in the packet?");
				}

				curLayer = nextLayer;
			}

			// Reset the layers linked list
			m_FirstLayer = nullptr;
			m_LastLayer = nullptr;

			// Clears the arena as everything on it should be deallocated.
			m_Arena.clear();
		}

		void ArenaPacket::setArena(MemoryArena arena)
		{
			clearParseData();
			// Move-assign the new arena.
			m_Arena = std::move(arena);
		}

		MemoryArena ArenaPacket::detachArena()
		{
			// Clears the data allocated on the arena. The function also marks the arena for reuse.
			clearParseData();

			// The move constructor keeps the arena configuration and just transfers the memory.
			// The moved from arena is still valid, but will need to request memory from the free store again.
			return std::move(m_Arena);
		}

		void ArenaPacket::clearPacketData()
		{
			clearParseData();

			// Deallocates the raw packet if owned by the current instance.
			if (m_RawPacket != nullptr && m_OwnRawPacket)
			{
				delete m_RawPacket;
			}

			// Resets the raw packet metadata.
			m_RawPacket = nullptr;
			m_OwnRawPacket = false;
			m_CanReallocateData = false;
			m_RawPacketCapacity = 0;
		}
	}  // namespace experimental
}