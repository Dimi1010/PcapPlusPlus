#include "experimental/MemoryArena.h"

namespace pcpp
{
	namespace experimental
	{
		MemoryArena::MemoryArena(MemoryArena&& other) noexcept
		    : m_BlockSize(other.m_BlockSize), m_FirstBlock(other.m_FirstBlock), m_AllocBlock(other.m_AllocBlock)
		{
			// Block size is not changed in the moved-from object
			// This is to allow the moved from object to be reused
			other.m_FirstBlock = nullptr;
			other.m_AllocBlock = nullptr;
		}

		MemoryArena& MemoryArena::operator=(MemoryArena&& other) noexcept
		{
			if (this == &other)
				return *this;

			reset(0);
			m_BlockSize = other.m_BlockSize;
			m_FirstBlock = other.m_FirstBlock;
			m_AllocBlock = other.m_AllocBlock;

			// Block size is not changed in the moved-from object
			// This is to allow the moved from object to be reused
			other.m_FirstBlock = nullptr;
			other.m_AllocBlock = nullptr;
			return *this;
		}

		bool MemoryArena::isAllocated() const
		{
			return m_FirstBlock != nullptr;
		}

		bool MemoryArena::isEmpty() const
		{
			return m_FirstBlock == nullptr || (m_FirstBlock == m_AllocBlock && m_FirstBlock->usedBytes == 0);
		}

		void* MemoryArena::allocate(size_t bytes, size_t alignment)
		{
			if (bytes == 0)
			{
				// 0 bytes allocation requirements are implementation defined. We choose to return nullptr.
				return nullptr;
			}

			if (m_AllocBlock == nullptr)
			{
				// No blocks exist yet, create the first one
				reserve(1);
			}

			// Base ptr is the start of the block, used to update usedBytes if allocation succeeds
			// Alligned ptr is the pointer we will try to align, it starts as the first unused byte in the block
			void* basePtr = m_AllocBlock->getBlockData();
			void* alignedPtr = m_AllocBlock->getUnusedData();
			size_t space = m_AllocBlock->getUnusedBytes(m_BlockSize);

			// align modifies alignedPtr and space to reflect the alignment, if possible
			// space is the number of bytes available after alignment
			if (std::align(alignment, bytes, alignedPtr, space))
			{
				// We have enough space in this block, update usedBytes and return the aligned pointer
				size_t usedBytes = static_cast<uint8_t*>(alignedPtr) - static_cast<uint8_t*>(basePtr) + bytes;
				m_AllocBlock->usedBytes = usedBytes;
				return alignedPtr;
			}
			else if (m_AllocBlock->usedBytes == 0)
			{
				// There is no point in creating a new block if the alignment failed on an empty one.
				throw std::bad_alloc();
			}
			else
			{
				// The alignment failed on a non-empty block. Allocate a new one and attempt again.
				// This essentially wastes all the space left in the previous block, but it is done to keep the
				// allocation mechanism fast. (no list traversal to find a block)

				// Can't align in this block, try the next one
				if (m_AllocBlock->next == nullptr)
				{
					// No next block, create one
					m_AllocBlock = createBlock(m_AllocBlock);
				}
				else
				{
					// Move to the next block
					m_AllocBlock = m_AllocBlock->next;
				}

				// Try to allocate in the next block
				basePtr = m_AllocBlock->getBlockData();
				alignedPtr = m_AllocBlock->getUnusedData();
				space = m_AllocBlock->getUnusedBytes(m_BlockSize);

				if (std::align(alignment, bytes, alignedPtr, space))
				{
					// We have enough space in this block, update usedBytes and return the aligned pointer
					size_t usedBytes = static_cast<uint8_t*>(alignedPtr) - static_cast<uint8_t*>(basePtr) + bytes;
					m_AllocBlock->usedBytes = usedBytes;
					return alignedPtr;
				}
				else
				{
					// Can't align in this block either, allocation fails
					throw std::bad_alloc();
				}
			}
		}

		void MemoryArena::reserve(size_t numBlocks)
		{
			size_t reservedBlocks = 0;
			BlockHeader* block = m_FirstBlock;

			while (reservedBlocks < numBlocks && block != nullptr)
			{
				reservedBlocks++;
				block = block->next;
			}

			// Optimization: Allocate all the blocks in a single memory chunk?
			// But then we can't free individual blocks in reset()...
			// Possibly by adding a flag to the block header?
			while (reservedBlocks < numBlocks)
			{
				// Allocate additional blocks
				BlockHeader* newBlock = createBlock(block);
				reservedBlocks++;

				if (m_FirstBlock == nullptr)
				{
					// This is the first block, set both pointers
					m_FirstBlock = newBlock;
					m_AllocBlock = newBlock;
				}

				// Advances to the next block.
				block = newBlock;
			}
		}

		void MemoryArena::clear()
		{
			// Don't free the blocks, just reset their used bytes counter
			for (BlockHeader* block = m_FirstBlock; block != nullptr; block = block->next)
			{
				block->usedBytes = 0;
			}
		}

		void MemoryArena::reset(size_t keepBlocks)
		{
			if (m_FirstBlock == nullptr)
			{
				return;
			}

			// For the first 'keepBlocks' blocks, reset their used bytes counter
			// For the rest of the blocks, free them
			BlockHeader* prevBlock = nullptr;
			BlockHeader* block = m_FirstBlock;
			for (size_t i = 0; i < keepBlocks && block != nullptr; i++)
			{
				block->usedBytes = 0;
				prevBlock = block;
				block = block->next;
			}

			if (prevBlock != nullptr)
			{
				prevBlock->next = nullptr;    // Detach the blocks to free from the rest of the list
				m_AllocBlock = m_FirstBlock;  // Reset allocation pointer to the first block
			}
			else
			{
				// We are supposed to free all blocks
				m_AllocBlock = nullptr;
				m_FirstBlock = nullptr;
			}

			// Block now points to the first block to free
			while (block != nullptr)
			{
				BlockHeader* nextBlock = block->next;
				freeBlock(block);
				block = nextBlock;
			}
		}

		size_t MemoryArena::getNumBlocks() const
		{
			size_t count = 0;
			for (BlockHeader const* block = m_FirstBlock; block != nullptr; block = block->next)
			{
				count++;
			}
			return count;
		}

		MemoryArena::BlockHeader* MemoryArena::createBlock(BlockHeader* prevBlock) const
		{
			// Operator ::new is expected by the standard to align the memory up to std::max_align_t
			// This is sufficient for our BlockHeader structure, as it is a POD aggregate.
			static_assert(alignof(BlockHeader) <= alignof(std::max_align_t),
			              "BlockHeader alignment is greater than max_align_t");
			BlockHeader* newBlock = static_cast<BlockHeader*>(::operator new(m_BlockSize));
			newBlock->next = nullptr;
			newBlock->usedBytes = 0;

			// Add the new block to the list
			if (prevBlock != nullptr)
			{
				prevBlock->next = newBlock;
			}

			return newBlock;
		}

		void MemoryArena::freeBlock(BlockHeader* block) const
		{
			::operator delete(block);
		}
	}  // namespace experimental
}  // namespace pcpp