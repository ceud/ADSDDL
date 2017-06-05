# coding: utf-8

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'adsddl/version'

Gem::Specification.new do |spec|
  spec.name          = 'adsddl'
  spec.version       = Adsddl::VERSION
  spec.authors       = ['Finlo Boyde']
  spec.email         = ['finlo.boyde@aridhia.com']

  spec.summary       = 'Active Directory ntSecurityDescriptor simple parser'
  spec.description   = <<EOS
  Active Directory ntSecurityDescriptor simple parser.
  Ported from the java library of the same name developed by Tirasa
EOS

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.executables   = []
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.12'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'simplecov'
end
