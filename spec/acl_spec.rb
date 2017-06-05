require_relative 'spec_helper'

describe Adsddl::ACL do
  let(:value) { ['0400780002000000075A38002000000003000000BE3B0EF3F09FD111B6030000F80367C1A57A96BFE60DD011A28500AA003049E2010100000000000100000000075A38002000000003000000BF3B0EF3F09FD111B6030000F80367C1A57A96BFE60DD011A28500AA003049E2010100000000000100000000'].pack('H*') }

  let(:acl) do
    a = Adsddl::ACL.new
    a.parse(value, 0)
    a
  end

  it 'parses correctly' do
    expect(acl.to_s).to eq('P(OU;CIIOIDSA;[32];;;S-1-3191541491-0)(OU;CIIOIDSA;[32];;;S-1-3208318707-0)')
  end

  it 'round trips' do
    expect(acl.bytes.unpack('H*')).to eq(value.unpack('H*'))
  end

  it 'can parse from offset and return new position' do
    acl = Adsddl::ACL.new
    expect(acl.parse('x' + value + 'x', 1)).to eq(value.size + 1)
  end

  it 'has the correct size' do
    expect(acl.size).to eq(value.size)
  end
end
