zlib = require 'zlib-browserify'
{JXG} = require './jsxcompressor'

x = Buffer.from """m8DLzMDEqP9AxtXZ45Yl4+mXSQxBWYXm1VwKCkp5ibmpSlYKMKCUnVSQXqCkA5JKSS1OLsosKMnMzwOpUPJOrUxKLE5VL1YIcA9Q8MwtyEnNTc0rSQQrAOvITq0szy9KKYYaGK2UXFRZUJKvpKOgBDYVrAJkhpJCLFhDYmlJRn4R3H4l38SK8tScHAXvovwMqJllqUXFUBeAlRjoGegZQqRyMpNT84pT4daBPAQULqksSEUy0jMErBrILC3KQXhVSQkoWAtxRm5iZp6SAkJKTz8nM0kfJKqXVQwNjMyi1OSS/KJMoHUKQKVQu4DqQBrBNMg8sNqM/NzUgsR0mCOUMkpKCqz09dMzSzJKk/SS83P1ocGgjxTaSaXpxcgRAdJUjEeXfmZxcWkq1HVFqQX5xZlA51WCjUANCCWgEahBcOAeSAyP4XogLXD/pKQWpOalpOYlgz0P93tBKdDaxORscADY2Roiayhzwa4nqSi/vDi1KDOtEqxLC+au5Pyc/KJiVDFg7KbolqQWl0AtAMW8OUyyBJgyc1KLU5PBkjDHI0ShypLyUOST8lAMT85PS0tN1YUkc1TL84HpPjezGE00JTW1QDe1sDQxB92pxRheAtuQWlQETN8I95vBZKuAKUYXIzRAIchVy9XJJMPCwMjEwMbKBMqoDFycArDcy7CH/7/L3fLFJnt1BJTufGa5KJXDO/9H7pOiohNeSnH2a+0mrtPuOBmQILhgV2BXh/0OZcHFxX82/T5xRddJeVdS1z52VZ4vT2f++O/OXrAh5k5hk3Hqz7WvX50p07Q2nfh5Q3t+/YMdjjbv/T6Gmr59EvUwQOVk/OvZ708diVya6m9dV95aIvnipFKuXiY/9wPDYNu4JAm+lhVKPX4qyhF78rQOneEq/h489aiQ48otjq/rXt9+/qJy/tqbsrY8K/bnm52cfm5f46yHt8W2KP1c/DCobe553TmHPErf7d2y4IVh5/7c+HM9hlEei1fv3fvuzHXl41pXW/ufcVW9ms1TG+DK1dt7/PWaWOWTC8w3vrPSebl759IZd4xNclTtsq4FzivPEU7Itv69NmO/z3yGtbsV5nuIMnlVBGdv7X8z92xUSoWEUs8rXS3jMrML127sNt7fL2eQndX4KbRBKk89bm2Y0KGVYhFRGvfOlb/fMIlvnkLIpGKDV5f0LfaER075MTmhPmuhcaB46+2Cc9YhD+5+9fQTrkvp5JHqjz0/dwEL78MSuz8nclIuGHTuF5BMUWT2PLs5y9dIpZjn2l33Jmbm7SZRDJsYimO52pzLpM/V6GhslNL1Csn3UpSpWrZJi6XjBd/Enaus7pnHvJ++2ftmpbL+BgbZmCmLJaIkG61v2tncEJ9k81pc5Jjlyzrjsw1VIssd0/Oqug0A""", 'base64'


#j = new JXG.Util.Unzip(x)
#console.log j.deflate()[0][0]
x = Buffer.concat [Buffer.from([ 0x78, 0x9c ]), x ]
console.log x.toString('binary')
await zlib.inflate x, defer err, msg
console.log err
console.log msg.toString 'utf8'

