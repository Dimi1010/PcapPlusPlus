#pragma once

#include <stdint.h>
#include <stdio.h>
#include "ProtocolType.h"
#include <string>
#include <stdexcept>
#include <utility>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	/// @class IDataContainer
	/// An interface (virtual abstract class) that indicates an object that holds a pointer to a buffer data. The Layer
	/// class is an example of such object, hence it inherits this interface
	class IDataContainer
	{
	public:
		/// Get a pointer to the data
		/// @param[in] offset Get a pointer in a certain offset. Default is 0 - get a pointer to start of data
		/// @return A pointer to the data
		virtual uint8_t* getDataPtr(size_t offset = 0) const = 0;

		virtual ~IDataContainer() = default;
	};

	/// @brief An interface (virtual abstract class) for classes that can provide their size in bytes at runtime
	/// This is to be used in polymorphic classes where sizeof() operator can't be used, for example when using
	/// a custom allocator.
	class IDynamicSizeOf
	{
	public:
		virtual ~IDynamicSizeOf() = default;

		/// @brief Get the size of the object in bytes at runtime
		/// @return The size of the object in bytes
		virtual size_t getSizeOf() const = 0;
	};

	template <typename Derived, typename Base = IDynamicSizeOf> class WithSizeOf : public Base
	{
	public:
		using Base::Base;

		~WithSizeOf() override = default;

		size_t getSizeOf() const override
		{
			return sizeof(Derived);
		}
	};

	class Layer;
	class RawPacket;

	// Consider this as the base class for Packet?
	class ILayerOwner
	{
	public:
		friend class Layer;

		~ILayerOwner() = default;

		virtual RawPacket* getRawPacket() const = 0;

		virtual Layer* getFirstLayer() const = 0;
		virtual Layer* getLastLayer() const = 0;

		virtual bool addLayer(Layer* newLayer, bool ownInPacket = false) = 0;
		virtual bool removeAllLayersAfter(Layer* layer) = 0;

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

		// Should not really be public?
	protected:
		virtual bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend) = 0;
		virtual bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten) = 0;
	};

	class Packet;
	namespace experimental
	{
		class ArenaPacket;
	}

	class ILayerOwner;

	/// @class Layer
	/// Layer is the base class for all protocol layers. Each protocol supported in PcapPlusPlus has a class that
	/// inherits Layer.
	/// The protocol layer class expose all properties and methods relevant for viewing and editing protocol fields.
	/// For example: a pointer to a structured header (e.g tcphdr, iphdr, etc.), protocol header size, payload size,
	/// compute fields that can be automatically computed, print protocol data to string, etc.
	/// Each protocol instance is obviously part of a protocol stack (which construct a packet). This protocol stack is
	/// represented in PcapPlusPlus in a linked list, and each layer is an element in this list. That's why each layer
	/// has properties to the next and previous layer in the protocol stack. The Layer class, as a base class, is
	/// abstract and the user can't create an instance of it (it has a private constructor). Each layer holds a pointer
	/// to the relevant place in the packet. The layer sees all the data from this pointer forward until the end of the
	/// packet. Here is an example packet showing this concept:
	///
	/// @code{.unparsed}
	/// ====================================================
	/// |Eth       |IPv4       |TCP       |Packet          |
	/// |Header    |Header     |Header    |Payload         |
	/// ====================================================
	///
	/// |--------------------------------------------------|
	/// EthLayer data
	///            |---------------------------------------|
	///            IPv4Layer data
	///                        |---------------------------|
	///                        TcpLayer data
	///                                   |----------------|
	///                                   PayloadLayer data
	/// @endcode
	class Layer : public IDataContainer, public WithSizeOf<Layer>
	{
		friend class Packet;
		friend class experimental::ArenaPacket;

	public:
		/// A destructor for this class. Frees the data if it was allocated by the layer constructor (see
		/// isAllocatedToPacket() for more info)
		~Layer() override;

		/// @return A pointer to the next layer in the protocol stack or nullptr if the layer is the last one
		Layer* getNextLayer() const
		{
			return m_NextLayer;
		}

		/// @return A pointer to the previous layer in the protocol stack or nullptr if the layer is the first one
		Layer* getPrevLayer() const
		{
			return m_PrevLayer;
		}

		/// @return The protocol enum
		ProtocolType getProtocol() const
		{
			return m_Protocol;
		}

		/// Check if the layer's protocol matches a protocol family
		/// @param protocolTypeFamily The protocol family to check
		/// @return True if the layer's protocol matches the protocol family, false otherwise
		bool isMemberOfProtocolFamily(ProtocolTypeFamily protocolTypeFamily) const;

		/// @return A pointer to the layer raw data. In most cases it'll be a pointer to the first byte of the header
		uint8_t* getData() const
		{
			return m_Data;
		}

		/// @return The length in bytes of the data from the first byte of the header until the end of the packet
		size_t getDataLen() const
		{
			return m_DataLen;
		}

		/// @return A pointer for the layer payload, meaning the first byte after the header
		uint8_t* getLayerPayload() const
		{
			return m_Data + getHeaderLen();
		}

		/// @return The size in bytes of the payload
		size_t getLayerPayloadSize() const
		{
			return m_DataLen - getHeaderLen();
		}

		/// Raw data in layers can come from one of sources:
		/// 1. from an existing packet - this is the case when parsing packets received from files or the network. In
		/// this case the data was already allocated by someone else, and layer only holds the pointer to the relevant
		/// place inside this data
		/// 2. when creating packets, data is allocated when layer is created. In this case the layer is responsible for
		/// freeing it as well
		///
		/// @return Returns true if the data was allocated by an external source (a packet) or false if it was allocated
		/// by the layer itself
		bool isAllocatedToPacket() const
		{
			return m_Packet != nullptr;
		}

		/// Copy the raw data of this layer to another array
		/// @param[out] toArr The destination byte array
		void copyData(uint8_t* toArr) const;

		// implement abstract methods

		uint8_t* getDataPtr(size_t offset = 0) const override
		{
			return static_cast<uint8_t*>(m_Data + offset);
		}

		// abstract methods

		/// Each layer is responsible for parsing the next layer
		virtual void parseNextLayer() = 0;

		/// @return The header length in bytes
		virtual size_t getHeaderLen() const = 0;

		/// Each layer can compute field values automatically using this method. This is an abstract method
		virtual void computeCalculateFields() = 0;

		/// @return A string representation of the layer most important data (should look like the layer description in
		/// Wireshark)
		virtual std::string toString() const = 0;

		/// @return The OSI Model layer this protocol belongs to
		virtual OsiModelLayer getOsiModelLayer() const = 0;

	protected:
		uint8_t* m_Data;
		size_t m_DataLen;
		ILayerOwner* m_Packet;
		ProtocolType m_Protocol;
		Layer* m_NextLayer;
		Layer* m_PrevLayer;
		bool m_IsAllocatedInPacket;

		Layer()
		    : m_Data(nullptr), m_DataLen(0), m_Packet(nullptr), m_Protocol(UnknownProtocol), m_NextLayer(nullptr),
		      m_PrevLayer(nullptr), m_IsAllocatedInPacket(false)
		{}

		Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, ILayerOwner* packet,
		      ProtocolType protocol = UnknownProtocol)
		    : m_Data(data), m_DataLen(dataLen), m_Packet(packet), m_Protocol(protocol), m_NextLayer(nullptr),
		      m_PrevLayer(prevLayer), m_IsAllocatedInPacket(false)
		{}

		// Copy c'tor
		Layer(const Layer& other);
		Layer& operator=(const Layer& other);

		void setNextLayer(Layer* nextLayer)
		{
			m_NextLayer = nextLayer;
		}
		void setPrevLayer(Layer* prevLayer)
		{
			m_PrevLayer = prevLayer;
		}

		virtual bool extendLayer(int offsetInLayer, size_t numOfBytesToExtend);
		virtual bool shortenLayer(int offsetInLayer, size_t numOfBytesToShorten);

		bool hasNextLayer() const
		{
			return m_NextLayer != nullptr;
		}

		/// Construct the next layer in the protocol stack. No validation is performed on the data.
		/// @tparam T The type of the layer to construct
		/// @tparam Args The types of the arguments to pass to the layer constructor
		/// @param[in] data The data to construct the layer from
		/// @param[in] dataLen The length of the data
		/// @param[in] packet The packet the layer belongs to
		/// @param[in] extraArgs Extra arguments to be forwarded to the layer constructor
		/// @return The constructed layer
		template <typename T, typename... Args>
		Layer* constructNextLayer(uint8_t* data, size_t dataLen, ILayerOwner* packet, Args&&... extraArgs)
		{
			if (hasNextLayer())
			{
				throw std::runtime_error("Next layer already exists");
			}

			Layer* newLayer = new T(data, dataLen, this, packet, std::forward<Args>(extraArgs)...);
			setNextLayer(newLayer);
			return newLayer;
		}

		/// Try to construct the next layer in the protocol stack with a fallback option.
		///
		/// The method checks if the data is valid for the layer type T before constructing it by calling
		/// T::isDataValid(data, dataLen). If the data is invalid, it constructs the layer of type TFallback.
		///
		/// @tparam T The type of the layer to construct
		/// @tparam TFallback The fallback layer type to construct if T fails
		/// @tparam Args The types of the extra arguments to pass to the layer constructor of T
		/// @param[in] data The data to construct the layer from
		/// @param[in] dataLen The length of the data
		/// @param[in] packet The packet the layer belongs to
		///	@param[in] extraArgs Extra arguments to be forwarded to the layer constructor of T
		/// @return The constructed layer of type T or TFallback
		template <typename T, typename TFallback, typename... Args>
		Layer* tryConstructNextLayerWithFallback(uint8_t* data, size_t dataLen, ILayerOwner* packet,
		                                         Args&&... extraArgs)
		{
			if (tryConstructNextLayer<T>(data, dataLen, packet, std::forward<Args>(extraArgs)...))
			{
				return m_NextLayer;
			}

			return constructNextLayer<TFallback>(data, dataLen, packet);
		}

		/// @brief Check if the data is large enough to reinterpret as a type
		///
		/// The data must be non-null and at least as large as the type
		///
		/// @tparam T The type to reinterpret as
		/// @param data The data to check
		/// @param dataLen The length of the data
		/// @return True if the data is large enough to reinterpret as T, false otherwise
		template <typename T> static bool canReinterpretAs(const uint8_t* data, size_t dataLen)
		{
			return data != nullptr && dataLen >= sizeof(T);
		}

	private:
		/// Try to construct the next layer in the protocol stack.
		///
		/// The method checks if the data is valid for the layer type T before constructing it by calling
		/// T::isDataValid(data, dataLen). If the data is invalid, a nullptr is returned.
		///
		/// @tparam T The type of the layer to construct
		/// @tparam Args The types of the extra arguments to pass to the layer constructor
		/// @param[in] data The data to construct the layer from
		/// @param[in] dataLen The length of the data
		/// @param[in] packet The packet the layer belongs to
		/// @param[in] extraArgs Extra arguments to be forwarded to the layer constructor
		/// @return The constructed layer or nullptr if the data is invalid
		template <typename T, typename... Args>
		Layer* tryConstructNextLayer(uint8_t* data, size_t dataLen, ILayerOwner* packet, Args&&... extraArgs)
		{
			if (T::isDataValid(data, dataLen))
			{
				return constructNextLayer<T>(data, dataLen, packet, std::forward<Args>(extraArgs)...);
			}
			return nullptr;
		}
	};

	inline std::ostream& operator<<(std::ostream& os, const pcpp::Layer& layer)
	{
		os << layer.toString();
		return os;
	}

	namespace internal
	{
		/// @brief Searches the layer stack for a layer of type TLayer starting from curLayer and using nextLayerFn to
		/// get the next layer in the stack
		/// @tparam TLayer The type of layer to search for.
		/// @tparam NextLayerFn A callable type that takes a Layer* and returns the next Layer* in the stack
		/// @param curLayer The layer to start the search from
		/// @param nextLayerFn A callable that takes a Layer* and returns the next Layer* in the stack
		/// @param skipFirst If true, the search will start from the layer after curLayer
		/// @return A pointer to the first layer of type TLayer found, or nullptr if no such layer exists in the stack
		template <typename TLayer, typename NextLayerFn>
		TLayer* searchLayerStackForType(Layer* curLayer, NextLayerFn nextLayerFn, bool skipFirst)
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

		/// @brief Finds the next layer of the specified type after the given layer.
		/// @tparam TLayer The type of layer to search for.
		/// @param curLayer A pointer to the current layer from which to start the search.
		/// @return A pointer to the next layer of the specified type, or nullptr if no such layer is found.
		template <class TLayer> TLayer* getNextLayerOfType(Layer* curLayer)
		{
			return searchLayerStackForType<TLayer>(curLayer, [](Layer* layer) { return layer->getNextLayer(); }, true);
		}

		/// @brief Finds the previous layer of a specified type in the layer stack, starting from the given layer.
		/// @tparam TLayer The type of layer to search for.
		/// @param curLayer A pointer to the current layer from which to begin the search.
		/// @return A pointer to the previous layer of the specified type, or nullptr if no such layer is found.
		template <class TLayer> TLayer* getPrevLayerOfType(Layer* curLayer)
		{
			return searchLayerStackForType<TLayer>(curLayer, [](Layer* layer) { return layer->getPrevLayer(); }, true);
		}

		/// @brief Finds the first layer of a specified type within a range of layers, searching either forwards or
		/// backwards.
		/// @tparam TLayer The type of layer to search for.
		/// @param first Pointer to the first layer in the range.
		/// @param last Pointer to the last layer in the range.
		/// @param reverse If true, searches from 'last' backwards; otherwise, searches from 'first' forwards.
		/// @return A pointer to the first layer of type TLayer found in the specified direction, or nullptr if not
		/// found.
		template <class TLayer> TLayer* getLayerOfType(Layer* first, Layer* last, bool reverse)
		{
			if (!reverse)
			{
				return searchLayerStackForType<TLayer>(
				    first, [](Layer* layer) { return layer->getNextLayer(); }, false);
			}

			// lookup in reverse order
			return searchLayerStackForType<TLayer>(last, [](Layer* layer) { return layer->getPrevLayer(); }, false);
		}
	}  // namespace internal

	template <typename TLayer> TLayer* ILayerOwner::getLayerOfType(bool reverseOrder) const
	{
		return internal::getLayerOfType<TLayer>(getFirstLayer(), getLastLayer(), reverseOrder);
	}

	template <typename TLayer> TLayer* ILayerOwner::getNextLayerOfType(Layer* startLayer) const
	{
		return internal::getNextLayerOfType<TLayer>(startLayer);
	}

	template <typename TLayer> TLayer* ILayerOwner::getPrevLayerOfType(Layer* startLayer) const
	{
		return internal::getPrevLayerOfType<TLayer>(startLayer);
	}
}  // namespace pcpp
