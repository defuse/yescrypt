# Yescrypt.rb
#
# This software is Copyright (c) 2015 Taylor Hornby <havoc@defuse.ca>,
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
# 
# There's ABSOLUTELY NO WARRANTY, express or implied.

#
# Compatibility: TODO
#
# Limitations: On systems where Fixnums can not hold 48-bit unsigned integers,
# the automatic switching between Fixnums and Bignums may create a side channel
# that would allow an attacker to extract a fast verifier, using attacks such as
# FLUSH+RELOAD.
#

require 'openssl'

module Yescrypt

  PWXSIMPLE = 2
  PWXGATHER = 4
  PWXROUNDS = 6
  SWIDTH = 8

  PWXBYTES = PWXGATHER * PWXSIMPLE * 8
  PWXWORDS = PWXBYTES / 4
  SBYTES = 2 * (1 << SWIDTH) * PWXSIMPLE * 8
  SWORDS = SBYTES / 4
  SMASK = ((1 << SWIDTH) - 1) * PWXSIMPLE * 8
  RMIN = (PWXBYTES + 127) / 128

  YESCRYPT_RW = 1
  YESCRYPT_WORM = 2
  YESCRYPT_PREHASH = 0x100000

  LO = 0
  HI = 1

  def self.calculate(password, salt, n, r, p, t, g, flags, dkLen)

    if !flags.is_a?(Integer) || (flags & ~(YESCRYPT_RW | YESCRYPT_WORM | YESCRYPT_PREHASH)) != 0
      raise ArgumentError.new("Unknown flags.")
    end

    if !n.is_a?(Integer)
      raise ArgumentError.new("N is not an integer.")
    end

    if !r.is_a?(Integer)
      raise ArgumentError.new("r is not an integer.")
    end

    if !p.is_a?(Integer)
      raise ArgumentError.new("p is not an integer.")
    end

    if !t.is_a?(Integer)
      raise ArgumentError.new("t is not an integer.")
    end

    if !g.is_a?(Integer)
      raise ArgumentError.new("g is not an integer.")
    end

    if !dkLen.is_a?(Integer)
      raise ArgumentError.new("dkLen is not an integer.")
    end

    if (n & (n - 1)) != 0
      raise ArgumentError.new("N is not a power of two.")
    end

    if n <= 1
      raise ArgumentError.new("N is too small.")
    end

    if r < 1
      raise ArgumentError.new("r is too small.")
    end

    if p < 1
      raise ArgumentError.new("p is too small.")
    end

    if g != 0
      raise NotImplementedError.new("g > 0 is not supported yet.")
    end

    if flags == 0 && t != 0
      raise ArgumentError.new("Can't use t > 0 without flags.")
    end

    # We don't bounds check 128 * r * p here, as we would normally do, since
    # Ruby's integers automatically get converted to Bignums upon overflow.

    if (flags & YESCRYPT_RW) != 0 && n/p <= 1
      raise ArgumentError.new("YESCRYPT_RW requires N/p >= 2")
    end

    if (flags & YESCRYPT_RW) != 0 && p >= 1 && n/p >= 0x100 && n/p * r >= 0x20000
      password = self.calculate(password, salt, n >> 6, r, p, 0, 0, flags | YESCRYPT_PREHASH, 32)
    end

    if flags != 0
      key = "yescrypt"
      if (flags & YESCRYPT_PREHASH) != 0
        key << "-prehash"
      end
      password = self.hmac_sha256(password, key)
    end

    bytes = self.pbkdf2_sha256(password, salt, 1, p * 128 * r)
    b = bytes.unpack("V*")

    if flags != 0
      password = bytes[0, 32]
    end

    if (flags & YESCRYPT_RW) != 0
      # New, YESCRYPT_RW parallelism.
      self.sMix(n, r, t, p, b, flags)
    else
      # Classic scrypt parallelism.
      0.upto(p - 1) do |i|
        b0 = b[i * 2 * r * 16, 2 * r * 16]
        self.sMix(n, r, t, 1, b0, flags)
        0.upto(2 * r * 16 - 1) do |j|
          b[i * 2 * r * 16 + j] = b0[j]
        end
      end
    end

    new_salt = b.pack("V*")

    # Make sure we get at least 32 bytes.
    result = self.pbkdf2_sha256(password, new_salt, 1, [dkLen, 32].max)

    if flags != 0 && (flags & YESCRYPT_PREHASH) == 0
      # Here's why we needed at least 32 bytes.
      client_value = result[0, 32]

      clientkey = self.hmac_sha256("Client Key", client_value)
      storedkey = self.sha256(clientkey)

      # Update the first 32 bytes of the result.
      0.upto([dkLen, 32].min - 1) do |i|
        result[i] = storedkey[i]
      end
    end

    # We might have gotten more than we needed, above, so truncate.
    return result[0, dkLen]
  end

  def self.sha256(message)
    sha256 = OpenSSL::Digest::SHA256.new
    return sha256.digest(message)
  end

  def self.hmac_sha256(message, key)
    sha256 = OpenSSL::Digest::SHA256.new
    return OpenSSL::HMAC.digest(sha256, key, message)
  end

  def self.pbkdf2_sha256(password, salt, iters, dkLen)
    sha256 = OpenSSL::Digest::SHA256.new
    return OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iters, dkLen, sha256)
  end

  def self.fNloop(n, t, flags)
    # +------+-----------------+-----------------+
    # |      | Nloop           |                 |
    # | t    | YESCRYPT_RW     | YESCRYPT_WORM   |
    # +------+-----------------+-----------------+
    # | 0    | (N+2)/3         | N               |
    # | 1    | (2N + 2) / 3    | N + (N + 1) / 2 |
    # | > 1  | (t - 1)*N       | t*N             |
    # +------+-----------------+-----------------+

    if (flags & YESCRYPT_RW) != 0
      case t
      when 0
        return (n+2) / 3
      when 1
        return (2 * n + 2) / 3
      else
        return (t - 1) * n
      end
    elsif (flags & YESCRYPT_WORM) != 0
      case t
      when 0
        return n
      when 1
        return n + (n+1) / 2
      else
        return t * n
      end
    else
      return n
    end
  end

  def self.p2floor(x)
    while (y = x & (x - 1)) != 0
      x = y
    end
    return x
  end

  def self.wrap(x, i)
    n = self.p2floor(i)
    return (x & (n - 1)) + (i - n)
  end

  def self.sMix(n, r, t, p, pbkdf2_blocks, flags)

    if !n.is_a?(Integer) || n <= 1 ||
       !r.is_a?(Integer) || r <= 0 ||
       !t.is_a?(Integer) || t <  0 ||
       !p.is_a?(Integer) || p <= 0 ||
       !pbkdf2_blocks.is_a?(Array) || pbkdf2_blocks.count != p * 2 * r * 16
      raise ArgumentError.new("Bad arguments to sMix.")
    end

    # There's one sbox for each thread.
    sboxes = Array.new(p) { nil }

    little_n = n/p

    nloop_all = self.fNloop(little_n, t, flags)

    if (flags & YESCRYPT_RW) != 0
      nloop_rw = nloop_all / p
    else
      nloop_rw = 0
    end

    little_n = little_n - (little_n & 1)

    nloop_all = nloop_all + (nloop_all & 1)
    nloop_rw = nloop_rw - (nloop_rw & 1)

    # Ordinarily, we'd have to check nloop_all for overflow, but Ruby does
    # automatic Bignums.

    v = Array.new(n * 2 * r * 16)

    0.upto(p - 1) do |i|
      little_v = i * little_n
      if i == p - 1
        little_n = n - little_v
      end
      w = little_v + little_n - 1

      if (flags & YESCRYPT_RW) != 0
        # Slice out the first two 64-byte blocks.
        x = pbkdf2_blocks[i * 2 * r * 16, 2 * 16]
        # Fill the sbox
        sboxes[i] = Array.new( SWORDS ) { 0 }
        self.sMix1(1, x, SBYTES/128, sboxes[i], flags & ~YESCRYPT_RW, nil)
        # Copy back over the first two 64-byte blocks.
        0.upto(2 * 16 - 1) do |j|
          pbkdf2_blocks[i * 2 * r * 16 + j] = x[j]
        end
      end

      block_i = pbkdf2_blocks[2 * r * 16 * i, 2 * r * 16]
      # XXX: try to only allocate this once (or twice)
      output = Array.new(little_n * 2 * r * 16) { 0 }
      self.sMix1(r, block_i, little_n, output, flags, sboxes[i])
      little_v.upto(w) do |j|
        0.upto(2 * r * 16 - 1) do |k|
          v[2 * r * 16 * j + k] = output[2 * r * 16 * (j-little_v) + k]
        end
      end

      self.sMix2(r, block_i, self.p2floor(little_n), nloop_rw, output, flags, sboxes[i])
      little_v.upto(w) do |j|
        0.upto(2 * r * 16 - 1) do |k|
          v[2 * r * 16 * j + k] = output[2 * r * 16 * (j-little_v) + k]
        end
      end

      # Write block_i back.
      0.upto(2 * r * 16 - 1) do |j|
        pbkdf2_blocks[2 * r * 16 * i + j] = block_i[j]
      end
    end

    0.upto(p - 1) do |i|
      block_i = pbkdf2_blocks[2 * r * 16 * i, 2 * r * 16]
      self.sMix2(r, block_i, n, nloop_all - nloop_rw, v, flags & ~YESCRYPT_RW, sboxes[i])
      # Write block_i back.
      0.upto(2 * r * 16 - 1) do |j|
        pbkdf2_blocks[2 * r * 16 * i + j] = block_i[j]
      end
    end

  end

  def self.sMix1(r, input_block, n, out_seq_write_memory, flags, sbox)
    if !r.is_a?(Integer) || r <= 0 ||
       !input_block.is_a?(Array) || input_block.count != 2 * r * 16 ||
       !n.is_a?(Integer) || n <= 0 ||
       !out_seq_write_memory.is_a?(Array) || out_seq_write_memory.count != 2 * r * 16 * n
      STDERR.puts "HEYYYY #{r} #{n} #{out_seq_write_memory.count}"
      raise ArgumentError.new("Bad arguments to sMix1.")
    end

    self.simd_shuffle(input_block)

    0.upto(n - 1) do |i|
      # V_i <- X
      0.upto(2 * r * 16) do |j|
        out_seq_write_memory[2 * r * 16 * i + j] = input_block[j]
      end

      if false
        # TODO: ROM support
      elsif (flags & YESCRYPT_RW) != 0 && i > 1
        if i >= 1 << 30
          # We need this because our integerify() isn't fully implemented. See
          # the comment there for reasons why.
          raise ArgumentError.new("Value if i is too big for our integerify(), in sMix1")
        end
        j = self.wrap(self.integerify(r, input_block), i)
        # X <- X XOR V_j
        0.upto(2 * r * 16 - 1) do |k|
          input_block[k] ^= out_seq_write_memory[2 * r * 16 * j + k]
        end
      end

      # X <- H(X)

      if sbox.nil?
        self.blockmix_salsa8(r, input_block)
      else
        self.blockmix_pwxform(r, input_block, sbox)
      end
    end

    self.simd_unshuffle(input_block)
  end

  def self.sMix2(r, input_block, n, nloop, seq_write_memory, flags, sbox)
    if !r.is_a?(Integer) || r <= 0 ||
       !input_block.is_a?(Array) || input_block.count != 2 * r * 16 ||
       !n.is_a?(Integer) || n <= 0 ||
       !nloop.is_a?(Integer) || nloop < 0 ||
       !seq_write_memory.is_a?(Array) || seq_write_memory.count < 2 * r * 16 * n
      raise ArgumentError.new("Bad arguments to sMix2.")
    end

    self.simd_shuffle(input_block)

    0.upto(nloop - 1) do |i|
      if false
        # TODO: ROM support
      else
        if n >= 1 << 30
          # We need this because our integerify() isn't fully implemented. See
          # the comment there for reasons why.
          raise ArgumentError.new("Value if i is too big for our integerify(), in sMix2")
        end
        j = self.integerify(r, input_block) & (n - 1)

        # X <- X XOR V_j
        0.upto(2 * r * 16 - 1) do |k|
          input_block[k] ^= seq_write_memory[2 * r * 16 * j + k]
        end

        if (flags & YESCRYPT_RW) != 0
          0.upto(2 * r * 16 - 1) do |k|
            seq_write_memory[2 * r * 16 * j + k] = input_block[k]
          end
        end
      end

      if sbox.nil?
        self.blockmix_salsa8(r, input_block)
      else
        self.blockmix_pwxform(r, input_block, sbox)
      end
    end

    self.simd_unshuffle(input_block)
  end

  def self.blockmix_pwxform(r, b, sbox)
    if !r.is_a?(Integer) || r <= 0 || !b.is_a?(Array) || b.count != 2 * r * 16 || !sbox.is_a?(Array)
      raise ArgumentError.new("Bad arguments to blockmix_pwxform.");
    end

    # The number of pwx-size blocks in the input.
    r1 = 2 * r * 16 / PWXWORDS

    # Grab the last pwx-size block.
    x = b[PWXWORDS * (r1 - 1), PWXWORDS]

    # Loop over all of the pwx-size blocks.
    0.upto(r1 - 1) do |i|
      # If there's more than one pwx-size block.
      if r1 > 1
        # XOR the ith pwx-block into X
        0.upto(PWXWORDS - 1) do |j|
          x[j] ^= b[PWXWORDS * i + j]
        end
      end

      # X <- pwxform(X)
      self.pwxform(x, sbox)

      # Store X into the ith pwx-block
      0.upto(PWXWORDS - 1) do |j|
        b[i * PWXWORDS + j] = x[j]
      end
    end

    # Below, we operate on 64-byte blocks instead of pwx-size blocks.

    i = (r1 - 1) * PWXWORDS / 16

    bi = b[i * 16, 16]
    self.salsa20_8_core_ints(bi)
    0.upto(15) do |j|
      b[i * 16 + j] = bi[j]
    end

    i += 1
    while i < 2 * r
      0.upto(15) do |j|
        bi[j] = b[i * 16 + j] ^ bi[j]
      end
      self.salsa20_8_core_ints(bi)
      0.upto(15) do |j|
        b[i*16 + j] = bi[j]
      end
    end
  end

  def self.pwxform(b, sbox)
    0.upto(PWXROUNDS - 1) do |i|
      0.upto(PWXGATHER - 1) do |j|
        xl = b[2*j*PWXSIMPLE + LO]
        xh = b[2*j*PWXSIMPLE + HI]

        p0 = (xl & SMASK) / (PWXSIMPLE * 8)
        p1 = (xh & SMASK) / (PWXSIMPLE * 8)

        0.upto(PWXSIMPLE - 1) do |k|
          bjklo = b[2 * (j * PWXSIMPLE + k) + LO]
          bjkhi = b[2 * (j * PWXSIMPLE + k) + HI]

          s0p0k = sbox[2 * (p0 * PWXSIMPLE + k) + LO] |
                  (sbox[2 * (p0 * PWXSIMPLE + k) + HI] << 32)
          s1p1k = sbox[sbox.count/2 + 2 * (p1 * PWXSIMPLE + k) + LO] |
                  (sbox[sbox.count / 2 + 2 * (p1 * PWXSIMPLE + k) + HI] << 32)

          result = (((bjkhi * bjklo) + s0p0k) ^ s1p1k) & 0xffffffffffffffff
          b[2 * (j * PWXSIMPLE + k) + LO] = result & 0xffffffff
          b[2 * (j * PWXSIMPLE + k) + HI] = (result >> 32) & 0xffffffff
        end
      end
    end
  end

  # x is an array of 32-bit integers.
  def self.simd_shuffle_block(x, offset = 0)
    tmp = Array.new(16)
    0.upto(15) do |i|
      tmp[i] = x[offset + i * 5 % 16]
    end
    0.upto(15) do |i|
      x[offset + i] = tmp[i]
    end
  end

  # x is an array of 32-bit integers.
  def self.simd_unshuffle_block(x, offset = 0)
    tmp = Array.new(16)
    0.upto(15) do |i|
      tmp[i * 5 % 16] = x[offset + i]
    end
    0.upto(15) do |i|
      x[offset + i] = tmp[i]
    end
  end

  # b is an array of 32-bit integers whose length is divisible by 16
  def self.simd_shuffle(b)
    if !b.is_a?(Array) || b.count % 16 != 0
      raise ArgumentError.new("Bad arguments to simd_unshuffle.")
    end

    0.upto(b.count / 16 - 1) do |i|
      self.simd_shuffle_block(b, 16*i)
    end
  end

  # b is an array of 32-bit integers whose length is divisible by 16
  def self.simd_unshuffle(b)
    if !b.is_a?(Array) || b.count % 16 != 0
      raise ArgumentError.new("Bad arguments to simd_unshuffle.")
    end

    0.upto(b.count / 16 - 1) do |i|
      self.simd_unshuffle_block(b, 16*i)
    end
  end

  # b is an array of 32-bit integers whose length is divisible by 16
  def self.integerify(r, b)
    # I'm intentionally *not* getting the full 64 bits here.
    # The first reason is that it's code that's unlikely to be exercised in
    # practice, and unlikely to be tested. The second reason is that, even on
    # a 64-bit system, whether or not the result is a Fixnum or Bignum leaks one
    # bit, and that could be used to construct a faster verifier.
    return b[16 * (2 * r - 1)]
  end

  # b is an array of 32-bit integers of size 2 * r * 16
  def self.blockmix_salsa8(r, b)
    if !r.is_a?(Integer) || r <= 0 || !b.is_a?(Array) || b.count != 2*r*16
      raise ArgumentError.new("Bad arguments to blockmix_salsa8")
    end

    x = b[16 * (2*r - 1), 16]

    y = Array.new(16 * 2 * r)

    0.upto(2 * r - 1) do |i|
      0.upto(15) do |j|
        x[j] ^= b[16*i + j]
      end
      self.salsa20_8_core_ints(x)
      if i % 2 == 0
        0.upto(15) do |j|
          y[16 * (i/2) + j] = x[j]
        end
      else
        0.upto(15) do |j|
          y[16 * (r + (i - 1)/2) + j] = x[j]
        end
      end
    end

    0.upto(b.count - 1) do |i|
      b[i] = y[i]
    end
  end

  def self.salsa20_8_core_ints(x)
    self.simd_unshuffle_block(x)

    copy = x.dup

    8.step(1, -2) do |i|
          x[ 4] ^= self.rot((x[ 0]+x[12]) & 0xffffffff, 7);  x[ 8] ^= self.rot((x[ 4]+x[ 0]) & 0xffffffff, 9);
          x[12] ^= self.rot((x[ 8]+x[ 4]) & 0xffffffff,13);  x[ 0] ^= self.rot((x[12]+x[ 8]) & 0xffffffff,18);
          x[ 9] ^= self.rot((x[ 5]+x[ 1]) & 0xffffffff, 7);  x[13] ^= self.rot((x[ 9]+x[ 5]) & 0xffffffff, 9);
          x[ 1] ^= self.rot((x[13]+x[ 9]) & 0xffffffff,13);  x[ 5] ^= self.rot((x[ 1]+x[13]) & 0xffffffff,18);
          x[14] ^= self.rot((x[10]+x[ 6]) & 0xffffffff, 7);  x[ 2] ^= self.rot((x[14]+x[10]) & 0xffffffff, 9);
          x[ 6] ^= self.rot((x[ 2]+x[14]) & 0xffffffff,13);  x[10] ^= self.rot((x[ 6]+x[ 2]) & 0xffffffff,18);
          x[ 3] ^= self.rot((x[15]+x[11]) & 0xffffffff, 7);  x[ 7] ^= self.rot((x[ 3]+x[15]) & 0xffffffff, 9);
          x[11] ^= self.rot((x[ 7]+x[ 3]) & 0xffffffff,13);  x[15] ^= self.rot((x[11]+x[ 7]) & 0xffffffff,18);
          x[ 1] ^= self.rot((x[ 0]+x[ 3]) & 0xffffffff, 7);  x[ 2] ^= self.rot((x[ 1]+x[ 0]) & 0xffffffff, 9);
          x[ 3] ^= self.rot((x[ 2]+x[ 1]) & 0xffffffff,13);  x[ 0] ^= self.rot((x[ 3]+x[ 2]) & 0xffffffff,18);
          x[ 6] ^= self.rot((x[ 5]+x[ 4]) & 0xffffffff, 7);  x[ 7] ^= self.rot((x[ 6]+x[ 5]) & 0xffffffff, 9);
          x[ 4] ^= self.rot((x[ 7]+x[ 6]) & 0xffffffff,13);  x[ 5] ^= self.rot((x[ 4]+x[ 7]) & 0xffffffff,18);
          x[11] ^= self.rot((x[10]+x[ 9]) & 0xffffffff, 7);  x[ 8] ^= self.rot((x[11]+x[10]) & 0xffffffff, 9);
          x[ 9] ^= self.rot((x[ 8]+x[11]) & 0xffffffff,13);  x[10] ^= self.rot((x[ 9]+x[ 8]) & 0xffffffff,18);
          x[12] ^= self.rot((x[15]+x[14]) & 0xffffffff, 7);  x[13] ^= self.rot((x[12]+x[15]) & 0xffffffff, 9);
          x[14] ^= self.rot((x[13]+x[12]) & 0xffffffff,13);  x[15] ^= self.rot((x[14]+x[13]) & 0xffffffff,18);
    end

    0.upto(15) do |i|
      x[i] = (copy[i] + x[i]) & 0xffffffff
    end

    self.simd_shuffle_block(x)
  end

  def self.rot(int, rot)
    ((int << rot) | ((int >> (32 - rot)) & ((1 << rot) - 1))) & 0xffffffff
  end

end
