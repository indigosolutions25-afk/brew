# frozen_string_literal: true

require 'elftools/sections/section'

module ELFTools
  module Sections
    # Class of version requirement section.
    # Usually for section .gnu.version_r and .SUNW_version (VERNEED).
    class VersionRequirementSection < Section
      include NonlinearObjectParser

      # Instantiate a {VersionRequirementSection} object.
      # There's a +section_at+ lambda for {VersionRequirementSection}
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

      # Iterate all version requirements.
      #
      # @yieldparam [ELFTools::Sections::VersionRequirement] requirement A version requirement object.
      # @yieldreturn [void]
      # @return [Enumerator<ELFTools::Sections::VersionRequirement>, Array<ELFTools::Sections::VersionRequirement>]
      #   If block is not given, an enumerator will be returned.
      #   Otherwise, return the array of version requirements.
      def each_requirements
        return enum_for(:each_requirements) unless block_given?

        stream.pos = header.sh_offset
        parse_nonlinear_objects(header.sh_size) do |requirement|
          yield requirement
          requirement.header.vn_next
        end
      end

      # Simply use {#requirements} to get all version requirements.
      # @return [Array<ELFTools::Sections::VersionRequirement>]
      #   All version requirements.
      def requirements
        each_requirements.to_a
      end

      private

      def verneedstr
        @verneedstr ||= @section_at.call(header.sh_link)
      end

      def parse_object
        offset = stream.pos
        verneed = Structs::ELF_Verneed.new(endian: header.class.self_endian, offset:)
        verneed.read(stream)

        raise ELFSymbolVersionStructureError, "Invalid version #{verneed.vn_version}" if verneed.vn_version != 1

        section_end = header.sh_offset + header.sh_size
        VersionRequirement.new(verneed, stream, offset, section_end, strtab: method(:verneedstr))
      end
    end

    # Class of a version requirement.
    class VersionRequirement
      include NonlinearObjectParser

      attr_reader :header # @return [ELFTools::Structs::ELF_Verneed] Section header.
      attr_reader :stream # @return [#pos=, #read] Streaming object.

      # Instantiate a {ELFTools::Sections::VersionRequirement} object.
      # @param [ELFTools::Structs::ELF_Verneed] header
      #   The verneed header.
      # @param [#pos=, #read] stream The streaming object.
      # @param [Integer] offset
      #   Start address of this version requirement, includes the header.
      # @param [Integer] section_end
      #   End address of the containing section
      # @param [Proc] strtab
      #   The linked string table. It will be called at the first time
      #   each {VersionRequirementAux#name} is accessed.
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
        header.vn_cnt
      end

      # Iterate all auxilary entries.
      #
      # @yieldparam [ELFTools::Sections::VersionRequirementAux] aux A auxiliary entry object.
      # @yieldreturn [void]
      # @return [Enumerator<ELFTools::Sections::VersionRequirementAux>,Array<ELFTools::Sections::VersionRequirementAux>]
      #   If block is not given, an enumerator will be returned.
      #   Otherwise return array of auxiliary entries.
      def each_aux_entries
        return enum_for(:each_aux_entries) unless block_given?

        stream.pos = @offset + header.vn_aux
        entries = parse_nonlinear_objects(@section_end - stream.pos) do |aux|
          yield(aux)
          aux.header.vna_next
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

      # Return the linked file name.
      # @return [String] The file name.
      def file
        @file ||= @strtab.call.name_at(header.vn_file)
      end

      private

      def parse_object
        vernaux = Structs::ELF_Vernaux.new(endian: header.class.self_endian, offset: stream.pos)
        vernaux.read(stream)
        VersionRequirementAux.new(vernaux, stream, strtab: @strtab)
      end
    end

    # Class of a version definition auxiliary information.
    class VersionRequirementAux
      attr_reader :header # @return [ELFTools::Structs::ELF_Vernaux] Section header.
      attr_reader :stream # @return [#pos=, #read] Streaming object.

      # Instantiate a {ELFTools::Sections::VersionRequirementAux} object.
      # @param [ELFTools::Structs::ELF_Vernaux] header
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
        @name ||= @strtab.call.name_at(header.vna_name)
      end
    end
  end
end
