
{read_base64,box,unbox} = require './keybase/encode'
kpkts = require './keybase/packet/all'

#=================================================================

class KeybaseEngine extends Engine

  constructor : ({primary, subkeys, userids}) ->
    super { primary, subkeys, userids }

  #--------

  key : (k) -> k._keybase

  #-----

  _check_can_sign : (keys,cb) ->
    err = null
    for k in keys when not err?
      err = new Error "cannot sign; don't have private key" unless k.key.can_sign()
    cb err

  #-----

  _v_allocate_key_packet : (key) ->
    unless key._keybase?
      key._keybase = new kpkts.KeyMaterial { 
        key : key.key, 
        timestamp : key.lifespan.generated }

  #-----

  _v_self_sign_primary : ({asp}, cb) ->
    esc = make_esc cb, "KeybaseEngine::_v_self_sign_primary"
    await @_check_can_sign [@primary], esc defer()
    p = new kpkts.SelfSign { key_wrapper : @primary, userid : @userids.get_keybase() }
    await p.sign { asp, include_body : true }, esc defer @self_sig
    cb null

  #-----

  _v_sign_subkey : ({asp, subkey}, cb) ->
    esc = make_esc cb, "KeybaseEngine::_v_sign_subkey"
    subkey._keybase_sigs = {}
    await @_check_can_sign [ @primary, subkey ], esc defer()
    p = new kpkts.Subkey { subkey }
    await p.sign { asp, include_body : true }, esc defer subkey._keybase_sigs.fwd
    p = new kpkts.SubkeyReverse { subkey }
    await p.sign { asp , include_body : true }, esc defer subkey._keybase_sigs.rev
    cb null

  #-----

  export_keys : (opts, cb) ->
    opts.tag = if opts.private then K.packet_tags.private_key_bundle else K.packet_tags.public_key_bundle
    ret = new kpkts.KeyBundle.alloc opts
    esc = make_esc cb, "KeybaseEngine::export_keys"
    await @primary._keybase.export_key opts, esc defer primary
    ret.set_primary {
      key : primary
      sig : @self_sig
    }
    for k in @subkeys
      await k._keybase.export_key opts, esc defer key
      ret.push_subkey {
        key : key
        sigs :
          forward : k._keybase_sigs.fwd
          reverse : k._keybase_sigs.rev
      }
    cb null, ret.frame_packet()

#=================================================================