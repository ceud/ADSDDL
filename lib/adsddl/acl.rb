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
  # The access control list (ACL) packet is used to specify a list of individual access control entries (ACEs). An ACL
  # packet and an array of ACEs comprise a complete access control list.
  #
  # The individual ACEs in an ACL are numbered from 0 to n, where n+1 is the number of ACEs in the ACL. When editing an
  # ACL, an application refers to an ACE within the ACL by the ACE index.
  #
  # In the absence of implementation-specific functions to access the individual ACEs, access to each ACE MUST be
  # computed by using the AclSize and AceCount fields to parse the wire packets following the ACL to identify each
  # ACE_HEADER, which in turn contains the information needed to obtain the specific ACEs.
  #
  # There are two types of ACL:
  #
  # - A discretionary access control list (DACL) is controlled by the owner of an object or anyone granted WRITE_DAC
  # access
  # to the object. It specifies the access particular users and groups can have to an object. For example, the owner of a
  # file can use a DACL to control which users and groups can and cannot have access to the file.
  #
  # - A system access control list (SACL) is similar to the DACL, except that the SACL is used to audit rather than
  # control
  # access to an object. When an audited action occurs, the operating system records the event in the security log. Each
  # ACE in a SACL has a header that indicates whether auditing is triggered by success, failure, or both; a SID that
  # specifies a particular user or security group to monitor; and an access mask that lists the operations to audit.
  #
  # @see https:#msdn.microsoft.com/en-us/library/cc230297.aspx
  ##
  class ACL
    ##
    # An unsigned 8-bit value that specifies the revision of the ACL. The only two legitimate forms of ACLs supported
    # for on-the-wire management or manipulation are type 2 and type 4. No other form is valid for manipulation on the
    # wire. Therefore this field MUST be set to one of the following values.
    #
    # ACL_REVISION (0x02) - When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, and 0x11 can be present in the ACL.
    # An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types.
    #
    # ACL_REVISION_DS (0x04) - When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of
    # revision 0x04 are applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for
    # DACLs.
    ##
    attr_reader :revision

    attr_reader :aces

    def initialize
      @aces = []
    end

    ##
    # Load the ACL from the buffer returning the last ACL segment position into the buffer.
    #
    # @param buff source buffer.
    # @param start start loading position.
    # @return last loading position.
    ##
    def parse(buff, start)
      pos = start

      # read for Dacl
      raw_revision, _reserved, _sz, ace_count, _reserved = buff[pos...(pos + 8)].unpack('CCvvv')

      @revision = AclRevision.parse_value(raw_revision)

      pos += 8

      (0...ace_count).each do |_i|
        ace = ACE.new
        aces << ace

        pos = ace.parse(buff, pos)
      end

      pos
    end

    ##
    # Gets ACL size in bytes.
    #
    # @return ACL size in bytes.
    ##
    def size
      aces.inject(8) { |sum, ace| sum + ace.size }
    end

    ##
    # Serializes to byte array.
    #
    # @return serialized ACL.
    ##
    def bytes
      header = [
        # add revision
        revision.value,

        # add reserved
        0x00,

        # add size (2 bytes reversed)
        size,

        # add ace count (2 bytes reversed)
        aces.count,

        # add reserved (2 bytes)
        0x00,
        0x00
      ].pack('CCvvCC')

      # add aces
      header + aces.map(&:bytes).join
    end

    ##
    # Serializes to string.
    #
    # @return serialized ACL.
    ##
    def to_s
      'P' + aces.map(&:to_s).join
    end
  end
end
