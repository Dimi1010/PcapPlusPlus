#pragma once
#include <cstdint>
#include <stdexcept>

namespace pcpp
{
	namespace experimental
	{
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
				// Deallocation from a memory arena is a no-op.
				// Memory is only freed at once when the arena is destroyed or reset.
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
	}
}  // namespace pcpp