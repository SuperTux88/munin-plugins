#!/usr/bin/env ruby

require 'sidekiq/api'

def count_errors(set)
  set.map {|job| job.item["error_class"] }
     .each_with_object(Hash.new(0)) {|error, counts| counts[error] += 1 }
     .sort
end

def dump_munin(error_count)
  error_count.each {|error, count| puts "#{error}|#{count}" }
end

if ARGV[0] == "retry"
  dump_munin(count_errors(Sidekiq::RetrySet.new))
elsif ARGV[0] == "dead"
  dump_munin(count_errors(Sidekiq::DeadSet.new))
end
