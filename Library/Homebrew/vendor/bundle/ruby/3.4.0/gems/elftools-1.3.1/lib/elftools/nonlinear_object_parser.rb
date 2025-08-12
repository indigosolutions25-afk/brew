# frozen_string_literal: true

module ELFTools
  # @private
  module NonlinearObjectParser
    private

    def parse_nonlinear_objects(size)
      @parsed_offset_map ||= {}
      start = stream.pos
      cur = start
      next_offset = -1
      parsed_objects = []
      while cur < start + size && next_offset != 0
        stream.pos = cur
        @parsed_offset_map[cur] ||= parse_object
        parsed_object = @parsed_offset_map[cur]
        next_offset = yield(parsed_object)
        cur += next_offset
        parsed_objects << parsed_object
      end
      parsed_objects
    end
  end
end
