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
{alloc,SHA256,streamers} = require '../hash'

#======================================================================

class S2K

  #----------------------

  _count : (c, bias) -> (16 + (c & 15)) << ((c >> 4) + bias)

  #----------------------

  constructor : () ->
    @hash = SHA256
    @streamer = streamers.SHA256()

  #----------------------

  set_hash_algorithm : (which) ->
    if (@hash = alloc which)?
      @streamer = streamers[@hash.algname]()
    else
      console.warn "No such hash: #{which}; defaulting to SHA-256"
      @hash = SHA256
      @streamer = streamers.SHA256()

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
        @read_gnu_extensions slice

      else
        throw new Error "unknown s2k type! #{@type}"
    @

  #--------------------
  # Read the GNU extensions to S2K format
  # For now, only useful when reading a dummy primary
  # key
  read_gnu_extensions : (slice) ->

    # XXX I believe this is a version, but I don't know for sure.
    # We should probably check it against 0x2.
    version = slice.read_uint8()

    if (id = (buf = slice.read_buffer(3)).toString('utf8')) is "GNU"
      gnu_ext_type = slice.read_uint8() + 1000
      switch gnu_ext_type
        when 1001
          @type = C.s2k.gnu_dummy
        else
          throw new Error "unknown s2k gnu protection mode: #{gnu_ext_type}"
    else
      throw new Error "Malformed GNU-extension: #{ext}"

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

  # Returns T/F if it's a dummy key (and there's no secret key here)
  is_dummy : () -> (@type is C.s2k.gnu_dummy)

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
        key = iterated_s2k { alg : @hash.algname, seed, @count }

        # This if accounts for RFC 4880 3.7.1.1 -- If hash size is greater than block size,
        # use leftmost bits.  If blocksize larger than hash size, we need to rehash isp and prepend with 0.
        if numBytes? and numBytes in [24,32]
          prefix = new Buffer [0]
          key2 = iterated_s2k { alg : @hash.algname, seed, @count, prefix}
          Buffer.concat [ key, key2 ]
        else
          key
      else null
    ret[0...numBytes]

#======================================================================

_iterated_s2k_cache = {}

iterated_s2k = ({alg, seed, count, prefix}) ->
  k = "#{alg}-#{seed.toString('base64')}-#{count}"
  k += "-#{prefix.toString('base64')}" if prefix?
  return val if (val = _iterated_s2k_cache[k])?

  streamer = streamers[alg]()
  streamer.update(prefix) if prefix?
  bigbuf = Buffer.concat( seed for i in [0...0x1000] )
  tot = 0
  while tot + bigbuf.length <= count
    streamer.update bigbuf
    tot += bigbuf.length
  rem = count - tot
  n = Math.ceil (rem / seed.length)
  rembuf = Buffer.concat( seed for i in [0...n] )
  ret = streamer rembuf[0...rem]
  _iterated_s2k_cache[k] = ret
  ret

#======================================================================

class SecretKeyMaterial

  constructor : () ->
    @s2k_convention = null
    @s2k = null
    @iv = null
    @cipher = null
    @payload = null

  is_dummy : () -> @s2k? and @s2k.is_dummy()
  has_private : () -> not @is_dummy()
  is_locked : () -> (@s2k_convention isnt C.s2k_convention.none) and not(@is_dummy())

#======================================================================

exports.S2K = S2K
exports.SecretKeyMaterial = SecretKeyMaterial

#======================================================================

