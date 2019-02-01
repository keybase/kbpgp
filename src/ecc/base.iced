{SlicerBuffer} = require '../openpgp/buffer'
{alloc_by_nbits,alloc_by_oid,alloc_by_name} = require './curves'

#===========================================================================

exports.BaseEccKey = class BaseEccKey

  #----------------

  constructor : ({@curve, @R}) ->

  #----------------

  serialize : () ->
    oid = @curve.oid
    Buffer.concat [
      Buffer.from([ oid.length ]),
      oid,
      @curve.point_to_mpi_buffer(@R)
    ]

  #----------------

  @_alloc : (klass, raw) ->
    sb = new SlicerBuffer raw
    pre = sb.rem()
    l = sb.read_uint8()
    oid = sb.read_buffer(l)
    [err, curve] = alloc_by_oid oid
    throw err if err?
    [err, R] = curve.mpi_point_from_slicer_buffer sb
    throw err if err?
    pub = new klass { curve, R}
    pub.read_params sb
    len = pre - sb.rem()
    return [ pub, len ]

  #----------------

  @alloc : (klass, raw) ->
    pub = len = err = null
    try [pub, len] = BaseEccKey._alloc klass, raw
    catch e then err = e
    return [err, pub, len]

  #----------------

  validity_check : (cb) -> cb null

#===========================================================================

exports.generate = ({nbits, asp, curve_name, Pair }, cb) ->
  ret = null
  if curve_name
    [err,curve] = alloc_by_name curve_name
  else
    [err,curve] = alloc_by_nbits nbits
  unless err?
    await curve.generate defer { x, R }
    pub = new Pair.Pub { curve, R }
    priv = new Pair.Priv { pub, x }
    ret = new Pair { pub, priv }
  cb err, ret

#===========================================================================

