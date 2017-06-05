##
# Copyright (C) 2015 Tirasa (info@tirasa.net)
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use @file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

module Adsddl
  ##
  # ACE object flag.
  ##
  class Flag
    ##
    # Int value.
    ##
    attr_reader :value

    ##
    # Private constructor.
    #
    # @param value int value.
    ##
    def initialize(value)
      @value = value
    end

    ##
    # 0x00000001 - ObjectType is valid.
    ##
    ACE_OBJECT_TYPE_PRESENT = new(0x00000001)
    ##
    # 0x00000002 - InheritedObjectType is valid. If @value is not specified, all types of child objects can
    # inherit the ACE.
    ##
    ACE_INHERITED_OBJECT_TYPE_PRESENT = new(0x00000002)

    VALUES = constants.reject { |x| x == :VALUES }.map(&method(:const_get)).map { |flag| [flag.value, flag] }.to_h
  end

  ##
  # A 32-bit unsigned integer that specifies a set of bit flags that indicate whether the ObjectType and
  # InheritedObjectType fields contain valid data. This parameter can be one or more of the following values.
  #
  # @see https:#msdn.microsoft.com/en-us/library/cc230289.aspx
  ##
  class AceObjectFlags
    ##
    # Standard flags.
    ##
    attr_reader :flags

    ##
    # Custom/Other flags.
    ##
    attr_accessor :others

    ##
    # Constructor.
    #
    # @param fls ACE object flags.
    ##
    def initialize(*fls)
      @others = 0
      @flags = Set.new fls
    end

    ##
    # Parse flags given as int value.
    #
    # @param value flags given as int value.
    # @return ACE object flags.
    ##
    def self.parse_value(value)
      res = new

      res.others = value

      Flag::VALUES.keys.each do |type|
        if (value & type) == type
          res.flags.add(Flag::VALUES[type])
          res.others ^= type
        end
      end

      res
    end

    ##
    # Gets custom/other ACE object flags as long value.
    #
    # @return custom/other ACE object flags as long value.
    ##
    def as_uint
      res = others

      flags.each { |flag| res += flag.value }

      res
    end
  end
end
