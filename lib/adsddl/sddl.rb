##
# Copyright (C) 2015 Tirasa (info@tirasa.net)
#
# Licensed under the Apache License, Version 2.0 (the "License");
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
  # The SECURITY_DESCRIPTOR structure defines the security attributes of an object. These attributes specify who owns the
  # object; who can access the object and what they can do with it; what level of audit logging should be applied to the
  # object; and what kind of restrictions apply to the use of the security descriptor.
  #
  # Security descriptors appear in one of two forms, absolute or self-relative.
  #
  # A security descriptor is said to be in absolute format if it stores all of its security information via pointer
  # fields, as specified in the RPC representation in section 2.4.6.1.
  #
  # A security descriptor is said to be in self-relative format if it stores all of its security information in a
  # contiguous block of memory and expresses all of its pointer fields as offsets from its beginning. The order of
  # appearance of pointer target fields is not required to be in any particular order; locating the OwnerSid, GroupSid,
  # Sacl, and/or Dacl should only be based on OffsetOwner, OffsetGroup, OffsetSacl, and/or OffsetDacl pointers found in
  # the fixed portion of the relative security descriptor.<58>
  #
  # The self-relative form of the security descriptor is required if one wants to transmit the SECURITY_DESCRIPTOR
  # structure as an opaque data structure for transmission in communication protocols over a wire, or for storage on
  # secondary media; the absolute form cannot be transmitted because it contains pointers to objects that are generally
  # not accessible to the recipient.
  #
  # When a self-relative security descriptor is transmitted over a wire, it is sent in little-endian format and requires
  # no padding.
  #
  # @see https:#msdn.microsoft.com/en-us/library/cc230366.aspx
  ##
  class SDDL
    ##
    # An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR structure.
    # This field MUST be set to one.
    ##
    attr_reader :revision

    ##
    # An unsigned 16-bit field that specifies control access bit flags. The Self Relative (SR) bit MUST be set when the
    # security descriptor is in self-relative format.
    ##
    attr_reader :control_flags

    ##
    # The SID of the owner of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if
    # the OffsetOwner field is not zero.
    ##
    attr_reader :owner

    ##
    # The SID of the group of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if
    # the GroupOwner field is not zero.
    ##
    attr_reader :group

    ##
    # The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the SP flag
    # is set.
    ##
    attr_reader :dacl

    ##
    # The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the DP flag
    # is set.
    ##
    attr_reader :sacl

    ##
    # Constructor.
    #
    # @param src source as byte array.
    ##
    def initialize(src)
      parse(src, 0)
    end

    ##
    # Load the SDDL from the buffer returning the last SDDL segment position into the buffer.
    #
    # @param buff source buffer.
    # @param start start loading position.
    # @return last loading position.
    ##
    def parse(buff, start)
      pos = start

      ##
      # Revision (1 byte): An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR
      # structure. This field MUST be set to one.
      ##
      @revision = buff[pos].unpack('C')[0]
      pos += 2
      ##
      # Control (2 bytes): An unsigned 16-bit field that specifies control access bit flags. The Self Relative
      # (SR) bit MUST be set when the security descriptor is in self-relative format.
      ##
      @control_flags = buff[pos...(pos + 2)].unpack('b*')[0]

      pos += 2
      ##
      # OffsetOwner (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
      # specifies the owner of the object to which the security descriptor is associated. This must be a valid
      # offset if the OD flag is not set. If this field is set to zero, the OwnerSid field MUST not be present.
      ##
      offset_owner = control_flags[0] == '0' ? buff[pos...(pos + 4)].unpack('V')[0] : 0
      pos += 4

      ##
      # OffsetGroup (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
      # specifies the group of the object to which the security descriptor is associated. This must be a valid
      # offset if the GD flag is not set. If this field is set to zero, the GroupSid field MUST not be present.
      ##
      offset_group = control_flags[1] == '0' ? buff[pos...(pos + 4)].unpack('V')[0] : 0
      pos += 4

      ##
      # OffsetSacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains
      # system ACEs. Typically, the system ACL contains auditing ACEs (such as SYSTEM_AUDIT_ACE,
      # SYSTEM_AUDIT_CALLBACK_ACE, or SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), and at most one Label ACE (as specified
      # in section 2.4.4.13). This must be a valid offset if the SP flag is set; if the SP flag is not set, this
      # field MUST be set to zero. If this field is set to zero, the Sacl field MUST not be present.
      ##
      offset_sacl = control_flags[4] == '1' ? buff[pos...(pos + 4)].unpack('V')[0] : 0
      pos += 4

      ##
      # OffsetDacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains ACEs
      # that control access. Typically, the DACL contains ACEs that grant or deny access to principals or groups.
      # This must be a valid offset if the DP flag is set; if the DP flag is not set, this field MUST be set to
      # zero. If this field is set to zero, the Dacl field MUST not be present.
      ##
      offset_dacl = control_flags[2] == '1' ? buff[pos...(pos + 4)].unpack('V')[0] : 0

      pos += 4

      ##
      # OwnerSid (variable): The SID of the owner of the object. The length of the SID MUST be a multiple of 4.
      # This field MUST be present if the OffsetOwner field is not zero.
      ##
      if offset_owner > 0
        pos = offset_owner
        # read for OwnerSid
        @owner = SID.new
        pos = owner.parse(buff, pos)
      end

      ##
      # GroupSid (variable): The SID of the group of the object. The length of the SID MUST be a multiple of 4.
      # This field MUST be present if the GroupOwner field is not zero.
      ##
      if offset_group > 0
        pos = offset_group
        @group = SID.new
        pos = group.parse(buff, pos)
      end

      ##
      # Sacl (variable): The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
      # be present if the SP flag is set.
      ##
      if offset_sacl > 0
        # read for Sacl
        pos = offset_sacl
        @sacl = ACL.new
        pos = sacl.parse(buff, pos)
      end

      ##
      # Dacl (variable): The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
      # be present if the DP flag is set.
      ##
      if offset_dacl > 0
        pos = offset_dacl
        @dacl = ACL.new
        pos = dacl.parse(buff, pos)
      end

      pos
    end

    ##
    # Gets size in terms of number of bytes.
    #
    # @return size.
    ##
    def size
      20 + (sacl.nil? ? 0 : sacl.size) + (dacl.nil? ? 0 : dacl.size) +
        (owner.nil? ? 0 : owner.size) + (group.nil? ? 0 : group.size)
    end

    ##
    # Serializes SDDL as byte array.
    #
    # @return SDL as byte array.
    ##
    def bytes
      body = ''
      append = lambda do |obj|
        if obj
          offset = 20 + body.size
          body += obj.bytes
          offset
        else
          0
        end
      end

      # add SACL
      offset_sacl = append[sacl]

      # add DACL
      offset_dacl = append[dacl]

      # add owner SID
      offset_owner = append[owner]

      # add group SID
      offset_group = append[group]

      header = [
        # add revision
        revision,

        # add reserved
        0x00,
        # add control flags
        control_flags,
        # add offset owner
        offset_owner,
        # add offset group
        offset_group,
        # add offset sacl
        offset_sacl,
        # add offset dacl
        offset_dacl
      ].pack('CCb16VVVV')

      header + body
    end

    ##
    # Serializes SDDL as string.
    # @return SDDL string representation.
    #
    # @see https:#msdn.microsoft.com/en-us/library/hh877835.aspx
    ##
    def to_s
      bld = ''
      bld += 'O:' + owner.to_s if owner
      bld += 'G:' + group.to_s if group
      bld += 'D:' + dacl.to_s if dacl
      bld += 'S:' + sacl.to_s if sacl
      bld
    end
  end
end
