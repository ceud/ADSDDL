require_relative 'spec_helper'

shared_examples_for 'ACE parsing' do |value, text|
  let(:ace) do
    a = Adsddl::ACE.new
    a.parse(value, 0)
    a
  end

  it 'parses correctly' do
    expect(ace.to_s).to eq(text)
  end

  it 'round trips' do
    expect(ace.bytes.unpack('H*')).to eq(value.unpack('H*'))
  end

  it 'can parse from offset and return new position' do
    ace = Adsddl::ACE.new
    expect(ace.parse('x' + value + 'x', 1)).to eq(value.size + 1)
  end

  it 'has the correct size' do
    expect(ace.size).to eq(value.size)
  end
end

describe Adsddl::ACE do
  describe 'OU' do
    include_examples 'ACE parsing',
                     [0x07, 0x5A, 0x38, 0x00, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00,
                      0x00, 0x00, 0xBE, 0x3B, 0x0E, 0xF3, 0xF0, 0x9F, 0xD1, 0x11,
                      0xB6, 0x03, 0x00, 0x00, 0xF8, 0x03, 0x67, 0xC1, 0xA5, 0x7A,
                      0x96, 0xBF, 0xE6, 0x0D, 0xD0, 0x11, 0xA2, 0x85, 0x00, 0xAA,
                      0x00, 0x30, 0x49, 0xE2, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x01, 0x00, 0x00, 0x00, 0x00].pack('C*'),
                     '(OU;CIIOIDSA;[32];;;S-1-3191541491-0)'
  end

  describe 'OA' do
    include_examples 'ACE parsing',
                     ['051248000001000003000000531A72AB2F1ED011981900AA0040529BBA7A96BFE60DD011A28500AA003049E2010500000000000515000000856D85DFD38A02FED41C1BB846050000'].pack('H*'),
                     '(OA;CIID;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3750063493-4261579475-3088784596-1350)'
  end
end
