#pragma once

#include "RawPacket.h"
#include "Layer.h"
#include <vector>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	

	/// @class Packet
	/// This class represents a parsed packet. It contains the raw data (RawPacket instance), and a linked list of
	/// layers, each layer is a parsed protocol that this packet contains. The layers linked list is ordered where the
	/// first layer is the lowest in the packet (currently it's always Ethernet protocol as PcapPlusPlus supports only
	/// Ethernet packets), the next layer will be L2.5 or L3 (e.g VLAN, IPv4, IPv6, etc.), and so on. etc.), etc. The
	/// last layer in the linked list will be the highest in the packet. For example: for a standard HTTP request packet
	/// the layer will look like this: EthLayer -> IPv4Layer -> TcpLayer -> HttpRequestLayer <BR> Packet instance isn't
	/// read only. The user can add or remove layers, update current layer, etc.
	class Packet : public ILayerOwner
	{
		friend class Layer;

	private:
		RawPacket* m_RawPacket;
		Layer* m_FirstLayer;
		Layer* m_LastLayer;
		size_t m_MaxPacketLen;
		bool m_FreeRawPacket;
		bool m_CanReallocateData;

	public:
		/// A constructor for creating a new packet (with no layers).
		/// When using this constructor an empty raw buffer is allocated (with the size of maxPacketLen) and a new
		/// RawPacket is created
		/// @param[in] maxPacketLen The expected packet length in bytes
		/// @param[in] linkType The link type to use for this packet (the default is Ethernet)
		explicit Packet(size_t maxPacketLen = 1, LinkLayerType linkType = LINKTYPE_ETHERNET);

		/// A constructor for creating a new packet with a buffer that is pre-allocated by the user.
		/// The packet is created empty (with no layers), which means the constructor doesn't parse the data in the
		/// buffer. Instead, all of the raw data of this packet it written to this buffer: whenever a layer is added,
		/// it's data is written to this buffer. The buffer isn't freed and it's content isn't erased when the packet
		/// object is deleted. This constructor is useful when you already have a memory buffer and you want to create
		/// packet data in it.
		/// @param[in] buffer A pointer to a pre-allocated memory buffer
		/// @param[in] bufferSize The size of the buffer
		/// @param[in] linkType The link type to use for this packet (the default is Ethernet)
		Packet(uint8_t* buffer, size_t bufferSize, LinkLayerType linkType = LINKTYPE_ETHERNET);

		/// A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets
		/// that came from the network. When using this constructor a pointer to the RawPacket is saved (data isn't
		/// copied) and the RawPacket is parsed, meaning all layers are created and linked to each other in the right
		/// order. In this overload of the constructor the user can specify whether to free the instance of raw packet
		/// when the Packet is free or not
		/// @param[in] rawPacket A pointer to the raw packet
		/// @param[in] freeRawPacket Optional parameter. A flag indicating if the destructor should also call the raw
		/// packet destructor or not. Default value is false
		/// @param[in] parseUntil Optional parameter. Parse the packet until you reach a certain protocol (inclusive).
		/// Can be useful for cases when you need to parse only up to a certain layer and want to avoid the performance
		/// impact and memory consumption of parsing the whole packet. Default value is ::UnknownProtocol which means
		/// don't take this parameter into account
		/// @param[in] parseUntilLayer Optional parameter. Parse the packet until you reach a certain layer in the OSI
		/// model (inclusive). Can be useful for cases when you need to parse only up to a certain OSI layer (for
		/// example transport layer) and want to avoid the performance impact and memory consumption of parsing the
		/// whole packet. Default value is ::OsiModelLayerUnknown which means don't take this parameter into account
		explicit Packet(RawPacket* rawPacket, bool freeRawPacket = false, ProtocolType parseUntil = UnknownProtocol,
		                OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

		/// A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets
		/// that came from the network. When using this constructor a pointer to the RawPacket is saved (data isn't
		/// copied) and the RawPacket is parsed, meaning all layers are created and linked to each other in the right
		/// order. In this overload of the constructor the user can specify whether to free the instance of raw packet
		/// when the Packet is free or not. This constructor should be used to parse the packet up to a certain layer
		/// @param[in] rawPacket A pointer to the raw packet
		/// @param[in] parseUntil Parse the packet until you reach a certain protocol (inclusive). Can be useful for
		/// cases when you need to parse only up to a certain layer and want to avoid the performance impact and memory
		/// consumption of parsing the whole packet
		explicit Packet(RawPacket* rawPacket, ProtocolType parseUntil);

		/// A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets
		/// that came from the network. When using this constructor a pointer to the RawPacket is saved (data isn't
		/// copied) and the RawPacket is parsed, meaning all layers are created and linked to each other in the right
		/// order. In this overload of the constructor the user can specify whether to free the instance of raw packet
		/// when the Packet is free or not. This constructor should be used to parse the packet up to a certain layer
		/// @param[in] rawPacket A pointer to the raw packet
		/// @param[in] parseUntilFamily Parse the packet until you reach a certain protocol family (inclusive). Can be
		/// useful for cases when you need to parse only up to a certain layer and want to avoid the performance impact
		/// and memory consumption of parsing the whole packet
		explicit Packet(RawPacket* rawPacket, ProtocolTypeFamily parseUntilFamily);

		/// A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets
		/// that came from the network. When using this constructor a pointer to the RawPacket is saved (data isn't
		/// copied) and the RawPacket is parsed, meaning all layers are created and linked to each other in the right
		/// order. In this overload of the constructor the user can specify whether to free the instance of raw packet
		/// when the Packet is free or not. This constructor should be used to parse the packet up to a certain layer in
		/// the OSI model
		/// @param[in] rawPacket A pointer to the raw packet
		/// @param[in] parseUntilLayer Optional parameter. Parse the packet until you reach a certain layer in the OSI
		/// model (inclusive). Can be useful for cases when you need to parse only up to a certain OSI layer (for
		/// example transport layer) and want to avoid the performance impact and memory consumption of parsing the
		/// whole packet
		explicit Packet(RawPacket* rawPacket, OsiModelLayer parseUntilLayer);

		/// A destructor for this class. Frees all layers allocated by this instance (Notice: it doesn't free layers
		/// that weren't allocated by this class, for example layers that were added by addLayer() or insertLayer() ).
		/// In addition it frees the raw packet if it was allocated by this instance (meaning if it was allocated by
		/// this instance constructor)
		virtual ~Packet()
		{
			destructPacketData();
		}

		/// A copy constructor for this class. This copy constructor copies all the raw data and re-create all layers.
		/// So when the original Packet is being freed, no data will be lost in the copied instance
		/// @param[in] other The instance to copy from
		Packet(const Packet& other)
		{
			copyDataFrom(other);
		}

		/// Assignment operator overloading. It first frees all layers allocated by this instance (Notice: it doesn't
		/// free layers that weren't allocated by this class, for example layers that were added by addLayer() or
		/// insertLayer() ). In addition it frees the raw packet if it was allocated by this instance (meaning if it was
		/// allocated by this instance constructor). Afterwards it copies the data from the other packet in the same way
		/// used in the copy constructor.
		/// @param[in] other The instance to copy from
		Packet& operator=(const Packet& other);

		/// Get a pointer to the Packet's RawPacket
		/// @return A pointer to the Packet's RawPacket
		RawPacket* getRawPacket() const
		{
			return m_RawPacket;
		}

		/// Set a RawPacket and re-construct all packet layers
		/// @param[in] rawPacket Raw packet to set
		/// @param[in] freeRawPacket A flag indicating if the destructor should also call the raw packet destructor or
		/// not
		/// @param[in] parseUntil Parse the packet until it reaches this protocol. Can be useful for cases when you need
		/// to parse only up to a certain layer and want to avoid the performance impact and memory consumption of
		/// parsing the whole packet. Default value is ::UnknownProtocol which means don't take this parameter into
		/// account
		/// @param[in] parseUntilLayer Parse the packet until certain layer in OSI model. Can be useful for cases when
		/// you need to parse only up to a certain layer and want to avoid the performance impact and memory consumption
		/// of parsing the whole packet. Default value is ::OsiModelLayerUnknown which means don't take this parameter
		/// into account
		void setRawPacket(RawPacket* rawPacket, bool freeRawPacket, ProtocolTypeFamily parseUntil = UnknownProtocol,
		                  OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

		/// Get a pointer to the Packet's RawPacket in a read-only manner
		/// @return A pointer to the Packet's RawPacket
		const RawPacket* getRawPacketReadOnly() const
		{
			return m_RawPacket;
		}

		/// Get a pointer to the first (lowest) layer in the packet
		/// @return A pointer to the first (lowest) layer in the packet
		Layer* getFirstLayer() const
		{
			return m_FirstLayer;
		}

		/// Get a pointer to the last (highest) layer in the packet
		/// @return A pointer to the last (highest) layer in the packet
		Layer* getLastLayer() const
		{
			return m_LastLayer;
		}

		/// Add a new layer as the last layer in the packet. This method gets a pointer to the new layer as a parameter
		/// and attaches it to the packet. Notice after calling this method the input layer is attached to the packet so
		/// every change you make in it affect the packet; Also it cannot be attached to other packets
		/// @param[in] newLayer A pointer to the new layer to be added to the packet
		/// @param[in] ownInPacket If true, Packet fully owns newLayer, including memory deletion upon destruct. Default
		/// is false.
		/// @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		/// such cases)
		bool addLayer(Layer* newLayer, bool ownInPacket = false)
		{
			return insertLayer(m_LastLayer, newLayer, ownInPacket);
		}

		/// Insert a new layer after an existing layer in the packet. This method gets a pointer to the new layer as a
		/// parameter and attaches it to the packet. Notice after calling this method the input layer is attached to the
		/// packet so every change you make in it affect the packet; Also it cannot be attached to other packets
		/// @param[in] prevLayer A pointer to an existing layer in the packet which the new layer should followed by. If
		/// this layer isn't attached to a packet and error will be printed to log and false will be returned
		/// @param[in] newLayer A pointer to the new layer to be added to the packet
		/// @param[in] ownInPacket If true, Packet fully owns newLayer, including memory deletion upon destruct. Default
		/// is false.
		/// @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		/// such cases)
		bool insertLayer(Layer* prevLayer, Layer* newLayer, bool ownInPacket = false);

		/// Remove an existing layer from the packet. The layer to removed is identified by its type (protocol). If the
		/// packet has multiple layers of the same type in the packet the user may specify the index of the layer to
		/// remove (the default index is 0 - remove the first layer of this type). If the layer was allocated during
		/// packet creation it will be deleted and any pointer to it will get invalid. However if the layer was
		/// allocated by the user and manually added to the packet it will simply get detached from the packet, meaning
		/// the pointer to it will stay valid and its data (that was removed from the packet) will be copied back to the
		/// layer. In that case it's the user's responsibility to delete the layer instance
		/// @param[in] layerType The layer type (protocol) to remove
		/// @param[in] index If there are multiple layers of the same type, indicate which instance to remove. The
		/// default value is 0, meaning remove the first layer of this type
		/// @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		/// such cases)
		bool removeLayer(ProtocolType layerType, int index = 0);

		/// Remove the first layer in the packet. The layer will be deleted if it was allocated during packet creation,
		/// or detached if was allocated outside of the packet. Please refer to removeLayer() to get more info
		/// @return True if layer removed successfully, or false if removing the layer failed or if there are no layers
		/// in the packet. In any case of failure an appropriate error log message will be printed
		bool removeFirstLayer();

		/// Remove the last layer in the packet. The layer will be deleted if it was allocated during packet creation,
		/// or detached if was allocated outside of the packet. Please refer to removeLayer() to get more info
		/// @return True if layer removed successfully, or false if removing the layer failed or if there are no layers
		/// in the packet. In any case of failure an appropriate error log message will be printed
		bool removeLastLayer();

		/// Remove all layers that come after a certain layer. All layers removed will be deleted if they were allocated
		/// during packet creation or detached if were allocated outside of the packet, please refer to removeLayer() to
		/// get more info
		/// @param[in] layer A pointer to the layer to begin removing from. Please note this layer will not be removed,
		/// only the layers that come after it will be removed. Also, if removal of one layer failed, the method will
		/// return immediately and the following layers won't be deleted
		/// @return True if all layers were removed successfully, or false if failed to remove at least one layer. In
		/// any case of failure an appropriate error log message will be printed
		bool removeAllLayersAfter(Layer* layer);

		/// Detach a layer from the packet. Detaching means the layer instance will not be deleted, but rather separated
		/// from the packet - e.g it will be removed from the layer chain of the packet and its data will be copied from
		/// the packet buffer into an internal layer buffer. After a layer is detached, it can be added into another
		/// packet (but it's impossible to attach a layer to multiple packets in the same time). After layer is
		/// detached, it's the user's responsibility to delete it when it's not needed anymore
		/// @param[in] layerType The layer type (protocol) to detach from the packet
		/// @param[in] index If there are multiple layers of the same type, indicate which instance to detach. The
		/// default value is 0, meaning detach the first layer of this type
		/// @return A pointer to the detached layer or nullptr if detaching process failed. In any case of failure an
		/// appropriate error log message will be printed
		Layer* detachLayer(ProtocolType layerType, int index = 0);

		/// Detach a layer from the packet. Detaching means the layer instance will not be deleted, but rather separated
		/// from the packet - e.g it will be removed from the layer chain of the packet and its data will be copied from
		/// the packet buffer into an internal layer buffer. After a layer is detached, it can be added into another
		/// packet (but it's impossible to attach a layer to multiple packets at the same time). After layer is
		/// detached, it's the user's responsibility to delete it when it's not needed anymore
		/// @param[in] layer A pointer to the layer to detach
		/// @return True if the layer was detached successfully, or false if something went wrong. In any case of
		/// failure an appropriate error log message will be printed
		bool detachLayer(Layer* layer)
		{
			return removeLayer(layer, false);
		}

		/// Get a pointer to the layer of a certain type (protocol). This method goes through the layers and returns a
		/// layer that matches the give protocol type
		/// @param[in] layerType The layer type (protocol) to fetch
		/// @param[in] index If there are multiple layers of the same type, indicate which instance to fetch. The
		/// default value is 0, meaning fetch the first layer of this type
		/// @return A pointer to the layer or nullptr if no such layer was found
		Layer* getLayerOfType(ProtocolType layerType, int index = 0) const;

		/// A templated method to get a layer of a certain type (protocol). If no layer of such type is found, nullptr
		/// is returned
		/// @param[in] reverseOrder The optional parameter that indicates that the lookup should run in reverse order,
		/// the default value is false
		/// @return A pointer to the layer of the requested type, nullptr if not found
		template <class TLayer> TLayer* getLayerOfType(bool reverseOrder = false) const;

		/// A templated method to get the first layer of a certain type (protocol), start searching from a certain
		/// layer. For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) ->
		/// IPv4Layer and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(3)
		/// will be returned If no layer of such type is found, nullptr is returned
		/// @param[in] startLayer A pointer to the layer to start search from
		/// @return A pointer to the layer of the requested type, nullptr if not found
		template <class TLayer> TLayer* getNextLayerOfType(Layer* startLayer) const;

		/// A templated method to get the first layer of a certain type (protocol), start searching from a certain
		/// layer. For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) ->
		/// IPv4Layer and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(1)
		/// will be returned If no layer of such type is found, nullptr is returned
		/// @param[in] startLayer A pointer to the layer to start search from
		/// @return A pointer to the layer of the requested type, nullptr if not found
		template <class TLayer> TLayer* getPrevLayerOfType(Layer* startLayer) const;

		/// Check whether the packet contains a layer of a certain protocol
		/// @param[in] protocolType The protocol type to search
		/// @return True if the packet contains a layer of a certain protocol, false otherwise
		bool isPacketOfType(ProtocolType protocolType) const;

		/// Check whether the packet contains a layer of a certain protocol family
		/// @param[in] protocolTypeFamily The protocol type family to search
		/// @return True if the packet contains a layer of a certain protocol family, false otherwise
		bool isPacketOfType(ProtocolTypeFamily protocolTypeFamily) const;

		/// Each layer can have fields that can be calculate automatically from other fields using
		/// Layer#computeCalculateFields(). This method forces all layers to calculate these fields values
		void computeCalculateFields();

		/// Each layer can print a string representation of the layer most important data using Layer#toString(). This
		/// method aggregates this string from all layers and print it to a complete string containing all packet's
		/// relevant data
		/// @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
		/// to false
		/// @return A string containing most relevant data from all layers (looks like the packet description in
		/// Wireshark)
		std::string toString(bool timeAsLocalTime = true) const;

		/// Similar to toString(), but instead of one string it outputs a list of strings, one string for every layer
		/// @param[out] result A string vector that will contain all strings
		/// @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
		/// to false
		void toStringList(std::vector<std::string>& result, bool timeAsLocalTime = true) const;

	private:
		void copyDataFrom(const Packet& other);

		void destructPacketData();

		bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
		bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

		void reallocateRawData(size_t newSize);

		bool removeLayer(Layer* layer, bool tryToDelete);

		std::string printPacketInfo(bool timeAsLocalTime) const;

		template <typename TLayer, typename NextLayerFn>
		static TLayer* searchLayerStackForType(Layer* startLayer, NextLayerFn nextLayerFn, bool skipFirst);
	};  // class Packet

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

		/// @brief A memory arena that allocates memory in blocks and doesn't free memory until the arena is destroyed
		class MemoryArena
		{
		private:
			/// @brief A header for each block in the arena, placed at the start of each block
			struct BlockHeader
			{
				/// @brief Pointer to the next block in the linked list
				BlockHeader* next = nullptr;
				/// @brief Number of bytes used in the block
				size_t usedBytes = 0;

				/// @brief Gets a pointer to the start of the block data
				void* getBlockData()
				{
					return reinterpret_cast<void*>(this + 1);
				}
				void const* getBlockData() const
				{
					return reinterpret_cast<void const*>(this + 1);
				}

				/// @brief Gets a pointer to the first unused byte in the block
				void* getUnusedData()
				{
					return reinterpret_cast<uint8_t*>(getBlockData()) + usedBytes;
				}
				void const* getUnusedData() const
				{
					return reinterpret_cast<uint8_t const*>(getBlockData()) + usedBytes;
				}

				/// @brief Gets the number of unused bytes in the block
				/// @param blockSize The total size of the block in bytes, including the header size
				/// @return The number of unused bytes in the block
				size_t getUnusedBytes(size_t blockSize) const
				{
					// blockSize includes the header size
					return blockSize - usedBytes - sizeof(BlockHeader);
				}
			};

		public:
			/// @brief The size of the block header in bytes
			static constexpr size_t BlockHeaderSize = sizeof(BlockHeader);

			/// @brief Creates a memory arena with a specified block size
			///
			/// The arena allocation can be configured to include the block header size in the block size.
			/// This is useful when the user wants to have a precise control over the memory usage of the arena.
			///
			/// In the default configuration (includeHeaderInBlockSize = false), the total memory allocated for each
			/// block may be larger than the block size, as the block header is allocated in addition to the block size.
			/// If the header is included in the block size, the usable memory in each block is reduced by the size of
			/// the header, but the total memory allocated for each block is equal to the block size.
			///
			/// @param blockSize The size of each block in bytes. By default, it's set to 4096 - sizeof(BlockHeader) to
			/// align the arena with typical memory page size.
			/// @param includeHeaderInBlockSize If true, the block header size is included in the block size.
			/// @throws std::invalid_argument if blockSize is less than or equal to the header size and
			/// includeHeaderInBlockSize is true.
			explicit MemoryArena(size_t blockSize = 4096 - sizeof(BlockHeader), bool includeHeaderInBlockSize = false)
			    : m_BlockSize(blockSize + !includeHeaderInBlockSize * sizeof(BlockHeader))
			{
				if (m_BlockSize < blockSize)
				{
					throw std::overflow_error("Block size overflow");
				}

				if (m_BlockSize <= BlockHeaderSize)
				{
					throw std::invalid_argument("Block size must be greater than the header size.");
				}
			}

			MemoryArena(MemoryArena const&) = delete;
			MemoryArena(MemoryArena&& other) noexcept;
			MemoryArena& operator=(MemoryArena const&) = delete;
			MemoryArena& operator=(MemoryArena&& other) noexcept;

			~MemoryArena()
			{
				reset(0);
			}

			/// @brief Checks if the arena has any blocks allocated
			/// @return True if the arena has at least one block allocated, false otherwise
			bool isAllocated() const;

			/// @brief Checks if the arena is empty (has no blocks or all blocks are empty)
			/// @return True if the arena is empty, false otherwise
			bool isEmpty() const;

			void* allocate(size_t bytes, size_t alignment = alignof(std::max_align_t));

			/// @brief Deallocation is a no-op in the arena. Memory is only freed when the arena is destroyed or reset.
			void deallocate(void* p, size_t bytes, size_t alignment = alignof(std::max_align_t))
			{}

			/// @brief Reserve a number of blocks in the arena.
			///
			/// This method can be used to reserve blocks in the arena before actual allocations are made.
			/// If the requested number of blocks is less than or equal to the current number of blocks, this method
			/// does nothing.
			///
			/// @param numBlocks The number of blocks to reserve
			void reserve(size_t numBlocks);

			/// @brief Clear all blocks in the arena but keep the blocks for future allocations.
			void clear();

			/// @brief Reset the arena, freeing all blocks except for a specified number of them.
			/// @param keepBlocks The number of blocks to keep. Default is 1.
			void reset(size_t keepBlocks = 1);

			/// @brief Gets the size of the blocks which the arena allocates.
			/// @return The block size in bytes
			/// @remarks The block size includes the header size. To get the usable block size, use
			/// getUsableBlockSize().
			size_t getBlockSize() const
			{
				return m_BlockSize;
			}

			/// @brief Gets the usable block size of the arena.
			/// @return The usable block size in bytes
			size_t getUsableBlockSize() const
			{
				return m_BlockSize - sizeof(BlockHeader);
			}

			/// @brief Gets the number of blocks currently allocated in the arena
			/// @return The number of blocks
			/// @remarks This method is slow (O(n)) and should be used for debugging or testing purposes only
			size_t getNumBlocks() const;

		private:
			/// @brief Creates a new block and links it to the previous block
			/// @param prevBlock The previous block in the linked list, or nullptr if this is the first block
			/// @return A pointer to the newly created block
			BlockHeader* createBlock(BlockHeader* prevBlock) const;

			/// @brief Frees a block and all its memory.
			/// @param block The block to free
			/// @remarks This method doesn't unlink the block from the linked list, it only frees its memory.
			void freeBlock(BlockHeader* block) const;

			BlockHeader* m_FirstBlock = nullptr;  ///< The first block in the linked list
			BlockHeader* m_AllocBlock = nullptr;  ///< The block currently used for allocations
			size_t m_BlockSize;                   ///< The size of each block in bytes, including the header size
		};

		/// @brief An STL-compatible allocator (C++11) that allocates memory from a MemoryArena
		/// @tparam T The type of object to allocate
		template <typename T> class MemoryArenaAllocator
		{
		public:
			using value_type = T;

			explicit MemoryArenaAllocator(MemoryArena& arena) noexcept : m_Arena(&arena)
			{}

			template <typename U>
			MemoryArenaAllocator(MemoryArenaAllocator<U> const& other) noexcept : m_Arena(other.m_Arena)
			{}

			template <typename U>
			MemoryArenaAllocator(MemoryArenaAllocator<U>&& other) noexcept : m_Arena(other.m_Arena)
			{}

			T* allocate(size_t n)
			{
				if (m_Arena == nullptr)
					return nullptr;

				void* p = m_Arena->allocate(n * sizeof(T), alignof(T));
				return static_cast<T*>(p);
			}

			void deallocate(T* p, size_t n) noexcept
			{
				if (m_Arena == nullptr)
					return;

				// Technically this is a no-op, as the arena deallocation is a no-op,
				// but its good practice to call it anyway unless profiling shows otherwise.
				m_Arena->deallocate(p, n * sizeof(T), alignof(T));
			}

			/// @brief Gets the maximum number of elements that can be allocated
			/// @return The maximum number of elements
			/// @remarks The arena allocations are limited by the block size, as an object cannot span multiple blocks.
			size_t max_size() const noexcept
			{
				return m_Arena->getUsableBlockSize() / sizeof(T);
			}

			bool operator==(MemoryArenaAllocator const& other) const noexcept
			{
				return m_Arena == other.m_Arena;
			}
			bool operator!=(MemoryArenaAllocator const& other) const noexcept
			{
				return !(*this == other);
			}

		private:
			MemoryArena* m_Arena;
		};

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

	// implementation of inline methods

	template <class TLayer> TLayer* Packet::getLayerOfType(bool reverse) const
	{
		if (!reverse)
		{
			return searchLayerStackForType<TLayer>(
			    m_FirstLayer, [](Layer* layer) { return layer->getNextLayer(); }, false);
		}

		// lookup in reverse order
		return searchLayerStackForType<TLayer>(m_LastLayer, [](Layer* layer) { return layer->getPrevLayer(); }, false);
	}

	template <class TLayer> TLayer* Packet::getNextLayerOfType(Layer* curLayer) const
	{
		return searchLayerStackForType<TLayer>(curLayer, [](Layer* layer) { return layer->getNextLayer(); }, true);
	}

	template <class TLayer> TLayer* Packet::getPrevLayerOfType(Layer* curLayer) const
	{
		return searchLayerStackForType<TLayer>(curLayer, [](Layer* layer) { return layer->getPrevLayer(); }, true);
	}

	template <typename TLayer, typename NextLayerFn>
	TLayer* Packet::searchLayerStackForType(Layer* curLayer, NextLayerFn nextLayerFn, bool skipFirst)
	{
		if (curLayer == nullptr)
			return nullptr;

		if (skipFirst)
		{
			curLayer = nextLayerFn(curLayer);
		}

		while (curLayer != nullptr)
		{
			auto* curLayerCasted = dynamic_cast<TLayer*>(curLayer);
			if (curLayerCasted != nullptr)
				return curLayerCasted;

			curLayer = nextLayerFn(curLayer);
		}

		return nullptr;
	}

	inline std::ostream& operator<<(std::ostream& os, const pcpp::Packet& packet)
	{
		os << packet.toString();
		return os;
	}
}  // namespace pcpp
