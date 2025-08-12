# frozen_string_literal: true

require 'elftools/sections/section'

module ELFTools
  module Sections
    # Class of version symbol table section.
    # Usually for section .gnu.version and .SUNW_version (VERSYM).
    class VersionSymbolSection < Section
      # Instantiate a {VersionSymbolSection} object.
      # There's a +section_at+ lambda for {VersionSymbolSection}
      # to easily fetch other sections.
      # @param [ELFTools::Structs::ELF_Shdr] header
      #   See {Section#initialize} for more information.
      # @param [#pos=, #read] stream
      #   See {Section#initialize} for more information.
      # @param [Proc] section_at
      #   The method for fetching other sections by index.
      #   This lambda should be {ELFTools::ELFFile#section_at}.
      def initialize(header, stream, section_at: nil, **_kwargs)
        @section_at = section_at
        super
      end

      # Number of version symbol entries.
      # @return [Integer] The number.
      # @example
      #   symtab.num_symbols
      #   #=> 75
      def num_symbols
        header.sh_size / header.sh_entsize
      end

      # Acquire the +n+-th version symbol entry, 0-based.
      #
      # Symbols are lazy loaded.
      # @param [Integer] idx The index.
      # @return [Integer, nil]
      #   The target value.
      #   If +idx+ is out of bound, +nil+ is returned.
      def value_at(idx)
        @version_symbols ||= LazyArray.new(num_symbols, &method(:create_symbol))
        @version_symbols[idx]
      end

      # Is the symbol locally scoped?
      # @param [Integer] idx The index.
      # @return [Boolean] Locally scoped
      def symbol_local?(idx)
        value_at(idx).zero?
      end

      # Is a symbol version defined?
      # @param [Integer] idx The index.
      # @return [Boolean] Symbol version defined
      def symbol_version_defined?(idx)
        (value_at(idx) & 0x7fff) > 1
      end

      # Is the symbol hidden?
      # @param [Integer] idx The index.
      # @return [Boolean] Symbol hidden
      def symbol_hidden?(idx)
        (value_at(idx) & 0x8000) != 0
      end

      private

      def symtab
        @symtab ||= @section_at.call(header.sh_link)
      end

      def create_symbol(n)
        stream.pos = header.sh_offset + n * header.sh_entsize

        {
          big: BinData::Uint16be,
          little: BinData::Uint16le
        }[header.class.self_endian].read(stream).to_i
      end
    end
  end
end
