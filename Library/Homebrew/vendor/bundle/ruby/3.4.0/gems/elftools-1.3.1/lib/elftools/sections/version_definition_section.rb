# frozen_string_literal: true

require 'elftools/sections/section'

module ELFTools
  module Sections
    # Class of version definition section.
    # Usually for section .gnu.version_d and .SUNW_version (VERDEF).
    class VersionDefinitionSection < Section
      include NonlinearObjectParser

      # Instantiate a {VersionDefinitionSection} object.
      # There's a +section_at+ lambda for {VersionDefinitionSection}
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

      # Iterate all version definitions.
      #
      # @yieldparam [ELFTools::Sections::VersionDefinition] definition A version definition object.
      # @yieldreturn [void]
      # @return [Enumerator<ELFTools::Sections::VersionDefinition>, Array<ELFTools::Sections::VersionDefinition>]
      #   If block is not given, an enumerator will be returned.
      #   Otherwise, return the array of version definitions.
      def each_definitions
        return enum_for(:each_definitions) unless block_given?

        stream.pos = header.sh_offset
        parse_nonlinear_objects(header.sh_size) do |definition|
          yield definition
          definition.header.vd_next
        end
      end

      # Simply use {#definitions} to get all version definitions.
      # @return [Array<ELFTools::Sections::VersionDefinition>]
      #   All version definitions.
      def definitions
        each_definitions.to_a
      end

      private

      def verdefstr
        @verdefstr ||= @section_at.call(header.sh_link)
      end

      def parse_object
        offset = stream.pos
        verdef = Structs::ELF_Verdef.new(endian: header.class.self_endian, offset:)
        verdef.read(stream)

        raise ELFSymbolVersionStructureError, "Invalid version #{verdef.vd_version}" if verdef.vd_version != 1

        section_end = header.sh_offset + header.sh_size
        VersionDefinition.new(verdef, stream, offset, section_end, strtab: method(:verdefstr))
      end
    end

    # Class of a version definition.
    class VersionDefinition
      include NonlinearObjectParser

      attr_reader :header # @return [ELFTools::Structs::ELF_Verdef] Section header.
      attr_reader :stream # @return [#pos=, #read] Streaming object.

      # Instantiate a {ELFTools::Sections::VersionDefinition} object.
      # @param [ELFTools::Structs::ELF_Verdef] header
      #   The verdef header.
      # @param [#pos=, #read] stream The streaming object.
      # @param [Integer] offset
      #   Start address of this version definition, includes the header.
      # @param [Integer] section_end
      #   End address of the containing section
      # @param [Proc] strtab
      #   The linked string table. It will be called at the first time
      #   each {VersionDefinitionAux#name} is accessed.
      def initialize(header, stream, offset, section_end, strtab:)
        @header = header
        @stream = stream
        @offset = offset
        @section_end = section_end
        @strtab = strtab
      end

      # Number of auxiliary entries.
      # @return [Integer] The number.
      def num_aux_entries
        header.vd_cnt
      end

      # Iterate all auxilary entries.
      #
      # @yieldparam [ELFTools::Sections::VersionDefinitionAux] aux A auxiliary entry object.
      # @yieldreturn [void]
      # @return [Enumerator<ELFTools::Sections::VersionDefinitionAux>, Array<ELFTools::Sections::VersionDefinitionAux>]
      #   If block is not given, an enumerator will be returned.
      #   Otherwise return array of auxiliary entries.
      def each_aux_entries
        return enum_for(:each_aux_entries) unless block_given?

        stream.pos = @offset + header.vd_aux
        entries = parse_nonlinear_objects(@section_end - stream.pos) do |aux|
          yield(aux)
          aux.header.vda_next
        end

        raise ELFSymbolVersionStructureError, 'Failed to parse all aux entries' if entries.count != num_aux_entries

        entries
      end

      # Simply use {#definitions} to get all auxiliary entries.
      # @return [Array<ELFTools::Sections::VersionDefinitionAux>]
      #   All version definition auxiliary entries.
      def aux_entries
        each_aux_entries.to_a
      end

      private

      def parse_object
        verdaux = Structs::ELF_Verdaux.new(endian: header.class.self_endian, offset: stream.pos)
        verdaux.read(stream)
        VersionDefinitionAux.new(verdaux, stream, strtab: @strtab)
      end
    end

    # Class of a version definition auxiliary information.
    class VersionDefinitionAux
      attr_reader :header # @return [ELFTools::Structs::ELF_Verdaux] Section header.
      attr_reader :stream # @return [#pos=, #read] Streaming object.

      # Instantiate a {ELFTools::Sections::VersionDefinitionAux} object.
      # @param [ELFTools::Structs::ELF_Verdaux] header
      #   The verdaux header.
      # @param [#pos=, #read] stream The streaming object.
      # @param [Proc] strtab
      #   The linked string table. It will be called at the first time
      #   {#name} is accessed.
      def initialize(header, stream, strtab: nil)
        @header = header
        @stream = stream
        @strtab = strtab
      end

      # Return the name.
      # @return [String] The name.
      def name
        @name ||= @strtab.call.name_at(header.vda_name)
      end
    end
  end
end
