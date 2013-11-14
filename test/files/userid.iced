
{UserId} = require '../../src/keywrapper'

exports.test_parse = (T,cb) ->
  test = "Hello Bird (fish) <cat@dog.jay>"
  uiw = new UserId { openpgp : test }
  T.equal uiw.components.username, "Hello Bird", "username correct"
  T.equal uiw.components.comment, "fish", "comment is right"
  T.equal uiw.components.email, "cat@dog.jay", "email is right"
  cb()

exports.test_make = (T,cb) ->
  username = "Max Krohn"
  comment = "boo-ya-ka-sha"
  email = "m@max.com"
  uiw = UserId.make { username, comment, email}
  T.equal uiw.openpgp, "#{username} (#{comment}) <#{email}>", "expanded properly"
  cb()
