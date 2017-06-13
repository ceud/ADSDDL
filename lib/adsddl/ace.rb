##
# Copyright (C) 2015 Tirasa (info@tirasa.net)
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

module Adsddl
  ##
  # An access control entry (ACE) is used to encode the user rights afforded to a principal, either a user or group. This
  # is generally done by combining an ACCESS_MASK and the SID of the principal.
  ##
  class ACE
    ##
    # @see AceType.
    ##
    attr_accessor :type

    ##
    # @see AceFlag.
    ##
    attr_accessor :flags

    ##
    # @see AceRights.
    ##
    attr_accessor :rights

    ##
    # @see AceObjectFlags.
    ##
    attr_accessor :object_flags

    ##
    # A GUID (16 bytes) that identifies a property set, property, extended right, or type of child object.
    ##
    attr_accessor :object_type

    ##
    # A GUID (16 bytes) that identifies the type of child object that can inherit the ACE.
    ##
    attr_accessor :inherited_object_type

    ##
    # Optional application data.
    ##
    attr_accessor :application_data

    ##
    # The SID of a trustee.
    ##
    attr_accessor :sid

    ##
    # Creates a new ACE instance.
    #
    # @param type ACE type.
    # @return ACE.
    ##
    def initialize(type: nil, sid: nil, rights: nil, flags: [], object_flags: nil)
      @type = type
      @flags = flags
      @rights = rights
      @object_flags = object_flags
      @sid = sid
    end

    ##
    # Load the ACE from the buffer returning the last ACE segment position into the buffer.
    #
    # @param buff source buffer.
    # @param start start loading position.
    # @return last loading position.
    ##
    def parse(buff, start)
      pos = start

      raw_type, raw_flag, len, raw_rights = buff[pos..(pos + 8)].unpack('CCvV')
      @type = AceType.parse_value(raw_type)
      @flags = AceFlag.parse_value(raw_flag)
      @rights = AceRights.parse_value(raw_rights)

      pos += 8

      if type == AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE || type == AceType::ACCESS_DENIED_OBJECT_ACE_TYPE
        @object_flags = AceObjectFlags.parse_value(buff[pos...(pos + 4)].unpack('V')[0])
        pos += 4

        if object_flags.flags.include?(Flag::ACE_OBJECT_TYPE_PRESENT)
          @object_type = buff[pos...(pos + 16)]
          pos += 16
        end

        if object_flags.flags.include?(Flag::ACE_INHERITED_OBJECT_TYPE_PRESENT)
          @inherited_object_type = buff[pos...(pos + 16)]
          pos += 16
        end
      end

      @sid = SID.new
      pos = sid.parse(buff, pos)

      last_pos = start + len
      @application_data = buff[pos...last_pos]

      last_pos
    end

    ##
    # An unsigned 16-bit integer that specifies the size, in bytes, of the ACE. The AceSize field can be greater than
    # the sum of the individual fields, but MUST be a multiple of 4 to ensure alignment on a DWORD boundary. In cases
    # where the AceSize field encompasses additional data for the callback ACEs types, that data is
    # implementation-specific. Otherwise, this additional data is not interpreted and MUST be ignored.
    #
    # @return ACE size.
    ##
    def size
      8 + (object_flags.nil? ? 0 : 4) + (object_type.nil? ? 0 : 16) + (inherited_object_type.nil? ? 0 : 16) +
        (sid.nil? ? 0 : sid.size) + (application_data.nil? ? 0 : application_data.length)
    end

    ##
    # Serializes to byte array.
    #
    # @return serialized ACE.
    ##
    def bytes
      flag_src = flags.inject(0x00) { |acc, flag| acc | flag.value }

      buff = [
        # Add type byte
        type.value,
        # add flags byte
        flag_src,
        # add size bytes (2 reversed)
        size,
        # add right mask
        rights.as_uint
      ].pack('CCvV')
      # add object flags (from int to byte[] + reversed)

      buff += [object_flags.as_uint].pack('V') unless object_flags.nil?

      # add object type
      buff += object_type unless object_type.nil?

      # add inherited object type
      buff += inherited_object_type unless inherited_object_type.nil?

      # add sid
      buff += sid.bytes

      # add application data
      buff += application_data unless application_data.nil?

      buff
    end

    ##
    # Serializes to string.
    #
    # @return serialized ACE.
    ##
    def to_s
      bld = '('
      bld += type.to_s
      bld += ';'

      flags.each { |flag| bld += flag.to_s }

      bld += ';'

      rights.rights.each { |right| bld += right.name }

      if rights.others != 0
        bld += '['
        bld += rights.others.to_s
        bld += ']'
      end

      bld += ';'

      bld += guid_string(object_type) unless object_type.nil?

      bld += ';'

      bld += guid_string(inherited_object_type) unless inherited_object_type.nil?

      bld += ';'

      bld += sid.to_s

      bld += ')'

      bld
    end

    private

    def guid_string(bytes)
      format('%08x-%04x-%04x-%04x-%04x%08x', *bytes.unpack('VvvnnN'))
    end
  end
end
