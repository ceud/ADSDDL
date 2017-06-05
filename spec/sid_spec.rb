require_relative 'spec_helper'

describe Adsddl::SID do
  describe 'a simple sid' do
    let(:value) { [0x03, 0x00, 0x00, 0x00, 0xBE, 0x3B, 0x0E, 0xF3, 0xF0, 0x9F].pack('C*') }

    let(:sid) { Adsddl::SID.parse(value) }
    it 'parses correctly' do
      expect(sid.to_s).to eq('S-1-3191541491-0')
    end

    it 'round trips' do
      expect(sid.bytes).to eq(value[0...8])
    end

    it 'can parse from offset and return new position' do
      sid = Adsddl::SID.new
      expect(sid.parse('x' + value + 'x', 1)).to eq(9)
    end

    it 'has the correct size' do
      expect(sid.size).to eq(8)
    end
  end

  describe 'a more complex sid' do
    let(:value) { ['010500000000000515000000856d85dfd38a02fed41c1bb800020000'].pack('H*') }

    let(:sid) { Adsddl::SID.parse(value) }
    it 'parses correctly' do
      expect(sid.to_s).to eq('S-1-5-21-3750063493-4261579475-3088784596-512')
    end

    it 'round trips' do
      expect(sid.bytes.unpack('H*')).to eq(value.unpack('H*'))
    end

    it 'can parse from offset and return new position' do
      sid = Adsddl::SID.new
      expect(sid.parse('x' + value + 'x', 1)).to eq(29)
    end

    it 'has the correct size' do
      expect(sid.size).to eq(28)
    end
  end
end
