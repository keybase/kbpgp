
exports.buffer_shift_right = (T,cb) ->
  byte_string = "70fa4a33c12271aa61863380a1b09704d6b15b12a268273d15f1b53fb18eebd7654b20540e394540"
  bufs = for i in [0...byte_string.length] by 8
    new Buffer(byte_string[i...(i+8)], 'hex')
  cb()


