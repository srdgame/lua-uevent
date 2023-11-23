local uevent = require 'uevent'

local conn = uevent.new(function(msg)
	print('xxxxx')
	print('RECV', msg)
end)

while true do
	local r, err = conn:run()
	if not r then
		print(err)
	end
end

print('closed')
