##
# Copyright (C) 2015 Tirasa (info@tirasa.net)
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

module Adsddl
  ##
  # An unsigned 8-bit integer that specifies the ACE types.
  #
  # @see https://msdn.microsoft.com/en-us/library/cc230296.aspx.
  ##
  class AceType
    attr_reader :str, :value

    ##
    # Private constructor.
    #
    # @param value byte value.
    # @param str string representation.
    ##
    def initialize(value, str)
      @value = value
      @str = str
    end

    ##
    # Return string representation.
    # @return string value.
    ##
    def to_s
      str
    end

    ##
    # Parses byte value.
    #
    # @param value byte value.
    # @return ACE type.
    ##
    def self.parse_value(value)
      VALUES[value]
    end

    ##
    # Unexpected value.
    ##
    UNEXPECTED = new(0xFF, 'UNEXPECTED')
    ##
    # 0x00 - Access-allowed ACE that uses the ACCESS_ALLOWED_ACE structure.
    ##
    ACCESS_ALLOWED_ACE_TYPE = new(0x00, 'A')
    ##
    # 0x01 - Access-denied ACE that uses the ACCESS_DENIED_ACE structure.
    ##
    ACCESS_DENIED_ACE_TYPE = new(0x01, 'D')
    ##
    # 0x02 - System-audit ACE that uses the SYSTEM_AUDIT_ACE structure.
    ##
    SYSTEM_AUDIT_ACE_TYPE = new(0x02, 'AU')
    ##
    # 0x03 - Reserved for future use.
    ##
    SYSTEM_ALARM_ACE_TYPE = new(0x03, 'AL')
    ##
    # 0x04 - Reserved for future use.
    ##
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = new(0x04, 'ACCESS_ALLOWED_COMPOUND_ACE_TYPE')
    ##
    # 0x05 - Object-specific access-allowed ACE that uses the ACCESS_ALLOWED_OBJECT_ACE structure.
    ##
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = new(0x05, 'OA')
    ##
    # 0x06 - Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE structure.
    ##
    ACCESS_DENIED_OBJECT_ACE_TYPE = new(0x06, 'OD')
    ##
    # 0x07 - Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE structure.
    ##
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = new(0x07, 'OU')
    ##
    # 0x09 - Reserved for future use.
    ##
    SYSTEM_ALARM_OBJECT_ACE_TYPE = new(0x08, 'OL')
    ##
    # 0x09 - Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE structure.
    ##
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = new(0x09, 'XA')
    ##
    # 0x0A - Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE structure.
    ##
    ACCESS_DENIED_CALLBACK_ACE_TYPE = new(0x0A, 'XD')
    ##
    # 0x0B - Object-specific access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_OBJECT_ACE structure.
    ##
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = new(0x0B, 'ZA')
    ##
    # 0x0C - Object-specific access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_OBJECT_ACE structure.
    ##
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = new(0x0C, 'ZD')
    ##
    # 0x0D - System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE structure.
    ##
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = new(0x0D, 'XU')
    ##
    # 0x0E - Reserved for future use.
    ##
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = new(0x0E, 'XL')
    ##
    # 0x0F - Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE structure.
    ##
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = new(0x0F, 'ZU')
    ##
    # 0x10 - Reserved for future use.
    ##
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = new(0x10, 'ZL')
    ##
    # 0x11 - Mandatory label ACE that uses the SYSTEM_MANDATORY_LABEL_ACE structure.
    ##
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = new(0x11, 'ML')
    ##
    # 0x12 - Resource attribute ACE that uses the SYSTEM_RESOURCE_ATTRIBUTE_ACE.
    ##
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = new(0x12, 'RA')
    ##
    # 0x13 - A central policy ID ACE that uses the SYSTEM_SCOPED_POLICY_ID_ACE.
    ##
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = new(0x13, 'SP')

    VALUES = constants.reject { |x| x == :VALUES }.map(&method(:const_get)).map { |type| [type.value, type] }.to_h
  end
end
