
{burn} = require './burner'
processor = require './processor'
{SignatureEngine} = require('./sigeng')

#-----------------------------

exports.box = burn
exports.unbox = processor.do_message
exports.SignatureEngine = SignatureEngine

#-----------------------------

