
{Packet} = require './base'
K = require('../../const').kb

#=================================================================

class KeyBundle extends Packet

  constructor : ( {@primary, @subkeys, @tag}) ->
    @primary or= {}
    @subkeys or= []

  frame_packet : () ->
    body = { @primary, @subkeys }
    super @tag, body 

#=================================================================

class PublicKeyBundle extends KeyBundle
  constructor : ({primary, subkeys}) ->
    super { primary, subkeys, tag : K.packet_tags.public_key_bundle }

#=================================================================

class PrivateKeyBundle extends KeyBundle
  constructor : ({primary, subkeys}) ->
    super { primary, subkeys, tag : K.packet_tags.private_key_bundle }

#=================================================================

exports.PublicKeyBundle = PublicKeyBundle
exports.PrivateKeyBundle = PrivateKeyBundle

#=================================================================

