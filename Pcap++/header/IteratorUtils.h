#pragma once

#include <memory>
#include <iterator>

namespace pcpp
{
	namespace internal
	{
		template <class T>
		class DereferenceWrapperConstIterator
		{
		  public:
			using iterator_category = std::forward_iterator_tag;
			using value_type = T;
			using difference_type = std::ptrdiff_t;
			using pointer = value_type const*;
			using reference = value_type const&;

		  protected:
			// Hold a reference to the base iterator that returns a ref-smart pointer.
			// Forward calls to the base iterator.
			// Dereference cast to non-owning pointer.

			/**
			 * @class IteratorConcept
			 * A concept base class for a holder model for a base iterator to implement type-erasure.
			 */
			struct IteratorConcept
			{
				virtual IteratorConcept& operator++() = 0;
				// This has the issue of introducing object slicing as it returns by value.
				// virtual IteratorConcept operator++(int) = 0;
				virtual bool operator==(IteratorConcept const& other) const noexcept = 0;
				bool operator!=(IteratorConcept const& other) const noexcept { return !(*this == other); };
				virtual reference operator*() const = 0;

				virtual std::unique_ptr<IteratorConcept> clone() const = 0;
			};

			/*
			 * @class IteratorModel
			 *
			 */
			template <class IteratorType>
			struct IteratorModel : IteratorConcept
			{
				// Type of the iterator that the model holds.
				using iterator_type = IteratorType;

				explicit IteratorModel(IteratorType const &it) : m_BaseIterator(it) {}

				// TODO
				IteratorConcept& operator++() override;
				// TODO - This has the issue of introducing object slicing as it returns by value.
				// IteratorConcept operator++(int) override;

				bool operator==(IteratorConcept const& other) const noexcept override
				try
				{
					auto const& modelCast = dynamic_cast<IteratorModel<IteratorType> const &>(other);
					return m_BaseIterator == modelCast.m_BaseIterator;
				}
				catch (std::bad_cast const&)
				{
					return false;
				}

				std::unique_ptr<IteratorConcept> clone() const override
				{
					return std::unique_ptr<IteratorModel<IteratorType>>(new IteratorModel<IteratorType>(*this));
				}

			  private:
				IteratorType m_BaseIterator;
			};

		  public:
			DereferenceWrapperConstIterator(DereferenceWrapperConstIterator const& other)
			{
				if (other.m_BaseIteratorModel != nullptr)
				{
					m_BaseIteratorModel = other.m_BaseIteratorModel->clone();
				}
			}

			DereferenceWrapperConstIterator& operator++()
			{
				m_BaseIteratorModel->operator++();
				return *this;
			};
			DereferenceWrapperConstIterator operator++(int)
			{
				auto oldIt = DereferenceWrapperConstIterator(*this);
				m_BaseIteratorModel->operator++();
				return oldIt;
			}
			bool operator==(DereferenceWrapperConstIterator const& other) const noexcept
			{
				// There is the situation where the base iterator model might be nullptr,
				// but the main class should ensure that does not happen.
				return *m_BaseIteratorModel == *other.m_BaseIteratorModel;
			};
			bool operator!=(DereferenceWrapperConstIterator const& other) const noexcept { return !(*this == other); };

			reference operator*() const { return m_BaseIteratorModel->operator*(); }

		  private:
			std::unique_ptr<IteratorConcept> m_BaseIteratorModel;
		};
	} // namespace internal
}
