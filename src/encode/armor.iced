
strip = (x) ->
  lines = x.split /\n/
  out = (line for line in lines when line.match /\S/)
  out.join '\n'

console.log strip """

fooo


boo

booobies
doobies jdjsd iosjdfoi sjdfo isdjfsodij

xooosefoisdfo ijsdfo ijsdfo ijsfoij

"""