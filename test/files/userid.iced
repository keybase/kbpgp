
{UserID} = require '../../lib/openpgp/packet/userid'

exports.test_parse = (T,cb) ->
  test = "Hello Bird (fish) <cat@dog.jay>"
  uid = new UserID test 
  T.equal uid.components.username, "Hello Bird", "username correct"
  T.equal uid.components.comment, "fish", "comment is right"
  T.equal uid.components.email, "cat@dog.jay", "email is right"
  cb()

exports.test_make = (T,cb) ->
  username = "Max Krohn"
  comment = "boo-ya-ka-sha"
  email = "m@max.com"
  uid = UserID.make { username, comment, email}
  T.equal uid.utf8(), "#{username} (#{comment}) <#{email}>", "expanded properly"
  cb()
