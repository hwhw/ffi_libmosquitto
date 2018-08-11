local function check(condition, ...)
  if condition then return condition end
  io.stderr:write(string.format(...), "\n")
  os.exit(1)
end

check(#arg >= 1, "usage:\n  "..arg[0].." <topic> [<server> [<port> [<username> [<password>]]]]")

local mq = require"mosquitto"
io.stderr:write("libmosquitto version "..table.concat({mq.lib_version()}, ".").."\n")

local client = mq.new("ffi_mosquitto example")

if arg[4] then
  client:username_pw_set(arg[4], arg[5])
end

client:connect(arg[2], arg[3])

client:subscribe_message_callback(arg[1], nil, function(message)
  print(message)
end)

client:loop_forever()
