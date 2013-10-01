##  GPG4Browsers - An OpenPGP implementation in javascript
##  Copyright (C) 2011 Recurity Labs GmbH
##  
##  This library is free software; you can redistribute it and/or
##  modify it under the terms of the GNU Lesser General Public
##  License as published by the Free Software Foundation; either
##  version 2.1 of the License, or (at your option) any later version.
##  
##  This library is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##  Lesser General Public License for more details.
##  
##  You should have received a copy of the GNU Lesser General Public
##  License along with this library; if not, write to the Free Software
##  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
## 
## @class
## @classdesc Implementation of the String-to-key specifier (RFC4880 3.7)
##  String-to-key (S2K) specifiers are used to convert passphrase strings
##  into symmetric-key encryption/decryption keys.  They are used in two
##  places, currently: to encrypt the secret part of private keys in the
##  private keyring, and to convert passphrases to encryption keys for
##  symmetrically encrypted messages.
##

#======================================================================

triplesec = require 'triplesec'
C = require('./const').openpgp
{alloc,SHA256} = require './hash'

#======================================================================

class S2K

  #----------------------

  _count : (c, bias) -> (16 + (c & 15)) << ((c >> 4) + bias)

  #----------------------
  
  constructor : () ->
    @hash = SHA256

  #----------------------

  set_hash_algorithm : (which) ->
    unless (@hash = alloc which)?
      console.warn "No such hash: #{which}; defaulting to SHA-256"
      @hash = SHA256

  #----------------------
  
  # 
  # Parsing function for a string-to-key specifier (RFC 4880 3.7).
  # @param {Buffer} input Payload of string-to-key specifier
  # @param {Integer} position Position to start reading from the input string
  # @return {openpgp_type_s2k} Object representation
  # 
  read : (input, position) ->
    mypos = position
    @type = input.readUInt8 mypos++
    match = false

    switch @type  
      when 0 # Simple S2K
        #Octet 1: hash algorithm
        @set_hash_algorithm(input.readUInt8(mypos++))
        @s2kLength = 1
        match = true

      when 1 # Salted S2K
        # Octet 1: hash algorithm
        @set_hash_algorithm(input.readUInt8(mypos++))

        # Octets 2-9: 8-octet salt value
        @salt = input[mypos...(mypos+8)]
        mypos += 8
        @s2kLength = 9
        match = true

      when 3 # Iterated and Salted S2K
        # Octet 1: hash algorithm
        @set_hash_algorithm(input.readUInt8(mypos++))

        # Octets 2-9: 8-octet salt value
        @salt = input[mypos...(mypos+8)]
        mypos += 8
        @s2kLength = 9

        # Octet 10: count, a one-octet, coded value
        @EXPBIAS = 6
        c = input.readUInt8 mypos++
        @count = @_count c, @EXPBIAS
        @s2kLength = 10
        match = true


      when 101
        if input[(mypos+1)...(mypos+4)] is "GNU"
          @set_hash_algorithm(input.readUInt8(mypos++))
          mypos += 3  # GNU
          gnuExtType = 1000 + input.readUInt8 mypos++
          match = true
          if gnuExtType == 1001
            @type = gnuExtType
            @s2kLength = 5
            # GnuPG extension mode 1001 -- don't write secret key at all
          else
            console.warn "unknown s2k gnu protection mode! #{gnuExtType}"

    if not match
      console.warn("unknown s2k type! #{@type}")
      null
    else
      @
  
  #----------------------
  
  # 
  # writes an s2k hash based on the inputs.  Only allows type 3, which
  # is iterated/salted. Also default to SHA256.
  #
  # @return {Buffer} Produced key of hashAlgorithm hash length
  # 
  write : (passphrase, salt, c) ->
    @type = type = 3 
    @salt = salt
    @count = @_count c, 6
    @s2kLength = 10
    @produce_key passphrase

  #----------------------
  
  #
  # Produces a key using the specified passphrase and the defined 
  # hashAlgorithm 
  # @param {Buffer} passphrase Passphrase containing user input -- this is
  #   the UTF-8 encoded version of the input passphrase.
  # @return {Buffer} Produced key with a length corresponding to 
  # hashAlgorithm hash length
  #
  produce_key : (passphrase, numBytes) ->
    ret = switch @type
      when C.s2k.plain then @hash passphrase
      when C.s2k.salt  then @hash Buffer.concat [ @salt, passphrase ]
      when C.s2k.salt_iter
        seed = Buffer.concat [ @salt, passphrase ]
        n    = Math.ceil (@count / seed.length)
        isp  = Buffer.concat( seed for i in [0...n])[0...@count]
        console.warn "hash input -> "
        console.warn isp.toString 'hex'
        console.warn "len -> #{isp.length}"
        console.warn "pw -> #{passphrase.toString 'utf8'} ; salt -> #{@salt.toString 'hex'}"
        
        # This if accounts for RFC 4880 3.7.1.1 -- If hash size is greater than block size, 
        # use leftmost bits.  If blocksize larger than hash size, we need to rehash isp and prepend with 0.
        if numBytes? and numBytes in [24,32]
          key = @hash isp
          Buffer.concat [ key, @hash(Buffer.concat([(new Buffer [0]), isp ]))]
          console.warn "in numBytes 24,32; nb = #{numBytes}"
        else
          console.warn "free and clean"
          @hash isp
      else null
    console.warn "returned key -> "
    console.warn ret.toString 'hex'
    ret

#======================================================================

exports.S2K = S2K 

#======================================================================

