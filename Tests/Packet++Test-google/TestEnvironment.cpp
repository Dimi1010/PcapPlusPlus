#include "TestEnvironment.hpp"

#include <fstream>

namespace pcpp
{
	namespace testing
	{
		namespace
		{
			size_t getFileLength(std::ifstream& stream)
			{
				auto originalPos = stream.tellg();
				stream.seekg(0, std::ios::end);
				size_t length = static_cast<size_t>(stream.tellg());
				stream.seekg(originalPos, std::ios::beg);
				return length;
			}

			std::uint8_t hexCharToDigit(char c)
			{
				if (c >= '0' && c <= '9')
					return c - '0';
				if (c >= 'a' && c <= 'f')
					return c - 'a' + 10;
				if (c >= 'A' && c <= 'F')
					return c - 'A' + 10;
				throw std::invalid_argument("Invalid hex character");
			}

			std::uint8_t hexPairToByte(const char* pair)
			{
				return (hexCharToDigit(pair[0]) << 4) | hexCharToDigit(pair[1]);
			}

			std::vector<uint8_t> readHexResource(std::ifstream& stream)
			{
				std::vector<std::uint8_t> buffer;

				char hexPair[2];  // 0 - high, 1 - low
				while (stream.read(hexPair, 2))
				{
					buffer.push_back(hexPairToByte(hexPair));
				}
				return buffer;
			}
		}  // namespace

		TestDataLoader::TestDataLoader(std::string dataRoot) : m_DataRoot(std::move(dataRoot))
		{}

		std::vector<uint8_t> TestDataLoader::loadResource(const char* filename, ResourceType resourceType) const
		{
			std::string fullPath;
			if (!m_DataRoot.empty())
			{
				fullPath = m_DataRoot + '/' + filename;
			}
			else
			{
				fullPath = filename;
			}

			auto const requireOpen = [filename](std::ifstream& fileStream) {
				if (!fileStream)
				{
					throw std::runtime_error(std::string("Failed to open file: ") + filename);
				}
			};

			switch (resourceType)
			{
			case ResourceType::BinaryData:
			{
				std::ifstream fileStream(fullPath, std::ios::binary);
				requireOpen(fileStream);

				size_t fileLength = getFileLength(fileStream);
				std::vector<uint8_t> buffer(fileLength);
				fileStream.read(reinterpret_cast<char*>(buffer.data()), fileLength);
				return buffer;
			}
			case ResourceType::HexData:
			{
				// The file is expected to contain text data in hexadecimal format
				std::ifstream fileStream(fullPath);
				requireOpen(fileStream);

				return readHexResource(fileStream);
			}
			default:
				throw std::invalid_argument("Unsupported resource type");
			}
		}

		std::unique_ptr<uint8_t[]> TestDataLoader::loadResourceToNewBuffer(const char* filename, size_t& outBufferLen,
		                                                                   ResourceType resourceType) const
		{
			// Somewhat inefficient as it copies the data into a vector first, but it should work for testing,
			// as it saves on code duplication.
			auto vecBuffer = loadResource(filename, resourceType);

			auto buffer = std::make_unique<uint8_t[]>(vecBuffer.size());
			std::copy(vecBuffer.begin(), vecBuffer.end(), buffer.get());
			outBufferLen = vecBuffer.size();
			return buffer;
		}

		PacketTestEnvironment* PacketTestEnvironment::currentEnvironment = nullptr;

		PacketTestEnvironment const& PacketTestEnvironment::getCurrent()
		{
			if (currentEnvironment == nullptr)
			{
				throw std::runtime_error("No PacketTestEnvironment is currently set up");
			}
			return *currentEnvironment;
		}

		PacketTestEnvironment::PacketTestEnvironment(TestDataLoader dataLoader) : m_DataLoader(std::move(dataLoader))
		{}

		void PacketTestEnvironment::SetUp()
		{
			// Setup the test environment, such as initializing resources or configurations needed for tests.

			// Register the environment as the current active test environment
			ASSERT_EQ(currentEnvironment, nullptr) << "PacketTestEnvironment is already set up";
			currentEnvironment = this;  // Set the current environment pointer to this instance
		}

		void PacketTestEnvironment::TearDown()
		{
			// Unregister the environment as the current active test environment
			ASSERT_TRUE(currentEnvironment == nullptr || currentEnvironment == this)
			    << "PacketTestEnvironment points to a different environment object";
			currentEnvironment = nullptr;  // Reset the current environment pointer
		}

	}  // namespace testing
}  // namespace pcpp