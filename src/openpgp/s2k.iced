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
C = require('../const').openpgp
{alloc,SHA256} = require '../hash'

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
  # @param {SlicerBuffer} input A slicer-buffer wrapper around the payload
  # @return {openpgp_type_s2k} Object representation
  # 
  read : (slice) ->
    @type = slice.read_uint8()

    switch @type  
      when C.s2k.plain # Simple S2K
        #Octet 1: hash algorithm
        @set_hash_algorithm slice.read_uint8()

      when C.s2k.salt # Salted S2K
        # Octet 1: hash algorithm
        @set_hash_algorithm slice.read_uint8()

        # Octets 2-9: 8-octet salt value
        @salt = slice.read_buffer 8

      when C.s2k.salt_iter # Iterated and Salted S2K
        # Octet 1: hash algorithm
        @set_hash_algorithm slice.read_uint8()

        # Octets 2-9: 8-octet salt value
        @salt = slice.read_buffer 8

        # Octet 10: count, a one-octet, coded value
        @EXPBIAS = 6
        c = slice.read_uint8()
        @count = @_count c, @EXPBIAS

      when C.s2k.gnu
        if input.read_buffer(3).toString('utf8') is "GNU"
          @set_hash_algorithm @read_uint8()
          gnuExtType = 1000 + input.read_uint8()
          match = true
          # GnuPG extension mode 1001 -- don't write secret key at all
          @type = gnuExtType if gnuExtType == 1001
          else throw new "unknown s2k gnu protection mode! #{gnuExtType}"
        else throw new "Malformed GNU-extension"
      else
        throw new Error "unknown s2k type! #{@type}"
    @
  
  #----------------------
  
  # 
  # writes an s2k hash based on the inputs.  Only allows type 3, which
  # is iterated/salted. Also default to SHA256.
  #
  # @return {Buffer} Produced key of hashAlgorithm hash length
  # 
  write : (passphrase, salt, c, keysize) ->
    @type = type = 3 
    @salt = salt
    @count = @_count c, 6
    @s2kLength = 10
    @produce_key passphrase, keysize

  #----------------------
  
  #
  # Produces a key using the specified passphrase and the defined 
  # hashAlgorithm 
  # @param {Buffer} passphrase Passphrase containing user input -- this is
  #   the UTF-8 encoded version of the input passphrase.
  # @return {Buffer} Produced key with a length corresponding to 
  # hashAlgorithm hash length
  #
  produce_key : (passphrase, numBytes = 16) ->
    ret = switch @type
      when C.s2k.plain then @hash passphrase
      when C.s2k.salt  then @hash Buffer.concat [ @salt, passphrase ]
      when C.s2k.salt_iter
        seed = Buffer.concat [ @salt, passphrase ]
        n    = Math.ceil (@count / seed.length)
        isp  = Buffer.concat( seed for i in [0...n])[0...@count]
        
        # This if accounts for RFC 4880 3.7.1.1 -- If hash size is greater than block size, 
        # use leftmost bits.  If blocksize larger than hash size, we need to rehash isp and prepend with 0.
        if numBytes? and numBytes in [24,32]
          key = @hash isp
          Buffer.concat [ key, @hash(Buffer.concat([(new Buffer [0]), isp ]))]
        else
          @hash isp
      else null
    ret[0...numBytes]

#======================================================================

exports.S2K = S2K 

#======================================================================

