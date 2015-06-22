require_relative 'Yescrypt.rb'

if ARGV.length < 1
  puts "Not enough arguments."
  exit(false)
end

case ARGV[0]
when "yescrypt"
  if ARGV.length != 10
    puts "Wrong number of arguments for yescrypt"
    exit(false)
  end
  result = Yescrypt.calculate(
    [ARGV[1]].pack("H*"), # password
    [ARGV[2]].pack("H*"), # salt
    ARGV[3].to_i,       # N
    ARGV[4].to_i,       # r
    ARGV[5].to_i,       # p
    ARGV[6].to_i,       # t
    ARGV[7].to_i,       # g
    ARGV[8].to_i,       # flags
    ARGV[9].to_i        # dkLen
  )
  print result
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
  Yescrypt.salsa20_8_core_ints(ints)
  binary = ints.pack("VVVVVVVVVVVVVVVV")
  print binary
else
  puts "Bad function."
  exit(false)
end

exit(true)
