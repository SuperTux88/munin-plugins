#!/usr/bin/env ruby

require 'sidekiq/api'

puts "#{Sidekiq::Stats.new.processed}:#{Sidekiq::Stats.new.failed}"
