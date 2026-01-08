#pragma once
#include "Packet.h"
#include "experimental/MemoryArena.h"

namespace pcpp
{
	namespace experimental
	{
		/// Arena allocation concept
		///
		/// Each packet already handles its own memory management for Layers. When a packet is created from a raw
		/// packet, it allocates all the layers it needs using "new" and when the packet is destroyed it deletes all the
		/// layers it has.
		///
		/// The problem with this approach is that each layer is allocated separately which means a lot of calls to
		/// "new" and "delete" which are expensive. Also, each layer is a small object (usually less than 200 bytes).
		///
		/// The idea is that each packet will allocate an Arena and then each layer will be allocated from this arena.
		/// The arena will hold a list of slabs or a pool. Each slab will be sized for a common layer size (for example
		/// 64, 86, 128, 256 bytes). Choose just some sizes that are common and don't go overboard with the number of
		/// slabs. Perhaps 4x64, 4x128, 2x256, 2x512 slabs are enough?
		///
		/// When a layer is created, it will request memory from the lowest slab that can hold it. If the slab has free
		/// space, it will return a pointer to the layer. If not, fallback strategies can be next slab or allocating a
		/// new slab.
		///
		/// When the packet is destroyed:
		/// - The destructors of all layers are called manually.
		/// - Slabs will attempt to deallocate their memory when they are destroyed, but the arena deallocation is a
		/// no-op.
		/// - The arena is destroyed.

		struct ParseOptions
		{
			ProtocolTypeFamily parseUntil = UnknownProtocol;
			OsiModelLayer parseUntilLayer = OsiModelLayerUnknown;
		};

		/// @brief An tag to defer parsing of a packet.
		struct NoParseTag
		{
		};

		static constexpr NoParseTag NoParse = {};

		class ArenaPacket : public ILayerOwner
		{
		public:
			ArenaPacket() = default;

			/// @brief Creates an empty packet with an associated memory arena for layer allocations.
			/// @param arena The memory arena to use for layer allocations.
			explicit ArenaPacket(MemoryArena arena) : m_Arena(std::move(arena))
			{}

			/// @brief Creates a packet from a raw packet with an associated memory arena for layer allocation, with
			/// deferred parsing.
			/// @param rawPacket A pointer to the raw packet.
			/// @param ownRawPacket If true, the packet takes ownership of the raw packet and will handle its deletion.
			/// @remarks This constructor does not automatically parse the packet.
			explicit ArenaPacket(NoParseTag, RawPacket* rawPacket, bool ownRawPacket = false);

			/// @brief Creates a packet from a raw packet with an associated memory arena for layer allocation, with
			/// deferred parsing.
			/// @param arena The memory arena to use for layer allocations.
			/// @param rawPacket A pointer to the raw packet.
			/// @param ownRawPacket If true, the packet takes ownership of the raw packet and will handle its deletion.
			/// @remarks This constructor does not automatically parse the packet.
			explicit ArenaPacket(NoParseTag, MemoryArena arena, RawPacket* rawPacket, bool ownRawPacket = false);

			/// @brief Creates a packet from a raw packet with an associated memory arena for layer allocations.
			/// @param rawPacket A pointer to the raw packet.
			/// @param ownRawPacket If true, the packet takes ownership of the raw packet and will handle its deletion.
			/// @param options Parsing options for the packet.
			explicit ArenaPacket(RawPacket* rawPacket, bool ownRawPacket = false,
			                     ParseOptions options = ParseOptions{});

			/// @brief Creates a packet from a raw packet with an associated memory arena for layer allocations.
			/// @param arena The memory arena to use for layer allocations.
			/// @param rawPacket A pointer to the raw packet.
			/// @param ownRawPacket If true, the packet takes ownership of the raw packet and will handle its deletion.
			/// @param options Parsing options for the packet.
			ArenaPacket(MemoryArena arena, RawPacket* rawPacket, bool ownRawPacket = false,
			            ParseOptions options = ParseOptions{});

			virtual ~ArenaPacket()
			{
				clearPacketData();
			}

			void setRawPacket(RawPacket* rawPacket, bool ownRawPacket = false, ParseOptions options = ParseOptions{});

			void setRawPacket(NoParseTag, RawPacket* rawPacket, bool ownRawPacket = false);

			/// @brief Parses the packet.
			/// @param options Options to use when parsing.
			void parseLayers(ParseOptions options = ParseOptions{});

			/// @brief Clears all parse data from the packet.
			void clearParseData();

			/// @brief Sets the memory arena used for layer allocations.
			/// @param arena The memory arena to use.
			/// @remarks Any parse layer data that has been allocated will be cleared by this operation and will require
			/// a reparse. Use with care.
			void setArena(MemoryArena arena);

			/// @brief Detaches and returns the current memory arena.
			///
			/// This method detaches the current memory arena used for layer allocations and returns it.
			/// This can be useful if the user wants to reuse the arena for another packet or for other purposes.
			///
			/// The packet will lose all its layer information and will require re-parsing if they are needed again.
			/// The raw packet and its data will remain intact and attached to the packet.
			///
			/// After the detach operation, an arena with the same configuration will be created and set to the packet.
			/// Said arena won't contain any allocated memory to it, but can be used for future allocations.
			///
			/// @return A MemoryArena object representing the detached memory arena.
			MemoryArena detachArena();

		private:
			/// @brief Clears all data from the packet.
			/// This will remove all parse data, detach / deallocate the raw packet and clear the arena.
			void clearPacketData();

			MemoryArena m_Arena;
			RawPacket* m_RawPacket = nullptr;

			// Linked list of layers
			Layer* m_FirstLayer = nullptr;
			Layer* m_LastLayer = nullptr;

			// RawPacket metadata
			size_t m_RawPacketCapacity = 0;
			bool m_OwnRawPacket = false;
			bool m_CanReallocateData = false;
		};
	}  // namespace experimental
}  // namespace pcpp