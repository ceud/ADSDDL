$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'simplecov'

SimpleCov.start do
  add_group 'Spec', 'spec'
  add_group 'Lib', 'lib'
end

require 'adsddl'
