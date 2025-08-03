#pragma once

#include <memory>
#include <vector>
#include <string>

#include <gtest/gtest.h>

namespace pcpp
{
	/// @brief The namespace for PcapPlusPlus testing utilities
	namespace test
	{
		enum class ResourceType
		{
			BinaryData,  ///< Resource is a file containing binary data
			HexData,     ///< Resource is a file containing hex data
		};

		/// @brief Represents a resource loaded by the TestDataLoader.
		struct DataResource
		{
			size_t length = 0;                          ///< Length of the resource data in bytes
			std::unique_ptr<uint8_t[]> data = nullptr;  ///< Pointer to the resource data
		};

		/// @brief Manages the loading of test resources such as files, saved packets, and buffers.
		class TestDataLoader
		{
		public:
			TestDataLoader(std::string dataRoot);

			DataResource loadResource(std::string const& filename, ResourceType resourceType) const
			{
				return loadResource(filename.c_str(), resourceType);
			}

			DataResource loadResource(const char* filename, ResourceType resourceType) const;

			std::vector<uint8_t> loadResourceToVector(std::string const& filename, ResourceType resourceType) const
			{
				return loadResourceToVector(filename.c_str(), resourceType);
			}

			std::vector<uint8_t> loadResourceToVector(const char* filename, ResourceType resourceType) const;

		private:
			std::string m_DataRoot;  ///< The root directory for test data files
		};

		/// @brief The test environment for Packet++ tests, which sets up and tears down the test environment.
		class PacketTestEnvironment : public ::testing::Environment
		{
		public:
			static PacketTestEnvironment const& getCurrent();

			PacketTestEnvironment(TestDataLoader dataLoader);

			void SetUp() override;

			void TearDown() override;

			TestDataLoader const& getDataLoader() const
			{
				return m_DataLoader;
			}

		private:
			// Pointer to the current test environment instance
			// As only one instance of this class should be active at a time, we can use a static pointer.
			static PacketTestEnvironment* currentEnvironment;

			TestDataLoader m_DataLoader;
		};
	}  // namespace test
}  // namespace pcpp
