require_relative 'Yescrypt.rb'

if ARGV.length < 1
  puts "Not enough arguments."
  exit(false)
end

case ARGV[0]
when "yescrypt"
  puts "Not implemented."
  exit(false)
when "pwxform"
  if ARGV.length != 3
    puts "Wrong number of arguments for pwxform"
    exit(false)
  end

  input = [ARGV[1]].pack("H*")
  input = input.unpack("V*")
  sbox = [ARGV[2]].pack("H*")
  sbox = sbox.unpack("V*")
  Yescrypt.pwxform(input, sbox)
  binary = input.pack("V*")
  print binary
when "salsa20_8"
  if ARGV.length != 2
    puts "Wrong number of arguments for salsa20_8"
    exit(false)
  end

  binary = [ARGV[1]].pack("H*")
  ints = binary.unpack("VVVVVVVVVVVVVVVV")
  Yescrypt.salsa20_core_ints(ints)
  binary = ints.pack("VVVVVVVVVVVVVVVV")
  print binary
else
  puts "Bad function."
  exit(false)
end

exit(true)
