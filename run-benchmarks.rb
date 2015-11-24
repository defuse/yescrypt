#!/usr/bin/env ruby

# the end result is one of these for each implementation
class ImplementationResult
  # TODO: an assoc array for parameters...
  # TODO: variables for pwxform and shit
  # TODO:...this should actually contain the code for benchmarking this
  # implementation
end

# the result of an individual run
class ImplementationRunResult
  attr_accessor :success, :calls_per_sec
end

class Implementation
  attr_accessor :command, :performance_log_scale

  def initialize(command, performance_log_scale)
    @command = command
    @performance_log_scale = performance_log_scale
  end

  # TODO: these all return an ImpelemntationRunResult, note the success member
  def runYescryptBenchmark(yescrypt_parameters)
    # TODO: commands here, return c/s amount
  end

  def runPwxformBenchmark

  end

  def runSalsa20_8Benchmark

  end

  def get_scaled_iteration_count(iteration_count)
    performance_log_scale << @performance_log_scale
  end
end

class YescryptParameters
  attr_accessor :n, :r, :p, :t, :g, :flags, :dkLen, :benchmark_iterations

  def initialize(n, r, p, t, g, flags, dkLen, benchmark_iterations)
    @n = n
    @r = r
    @p = p
    @t = t
    @g = g
    @flags = flags
    @dkLen = dkLen
    @benchmark_iterations = benchmark_iterations
  end
end

IMPLEMENTATIONS = [
  # Javascript
  Implementation.new(
    "node javascript/yescrypt-cli.js",
    0
  ),
  # PHP
  Implementation.new(
    "node javascript/yescrypt-cli.js",
    -4
  ),
]

YESCRYPT_PARAMETERS = [
  # TODO: fill in more.
  YescryptParameters.new(4, 8, 1, 0, 0, 2048),
  YescryptParameters.new(4, 8, 1, 0, 1, 2048)
]

class BenchmarkResult
  attr_accessor samples, mean

  def initialize(samples)
    # TODO: compute the mean etc. from samples
    # TODO: 'nil' in samples array means error
    @samples = samples
    @mean = nil
  end

end

def benchmark
  samples = []
  SAMPLE_COUNT.times do |s|
    samples << yield
  end
  return BenchmarkResult.new(samples)
end

SAMPLE_COUNT = 5

IMPLEMENTATIONS.each do |implementation|

  YESCRYPT_PARAMETERS.each do |parameters|
    xxx = benchmark do
      implementation.runYescryptBenchmark(parameters)
    end
  end

  xxx = benchmark do
    implementation.runPwxformBenchmark()
  end

  xxx = benchmark do
    implementation.runSalsa20_8Benchmark()
  end

end

# TODO: output a report
