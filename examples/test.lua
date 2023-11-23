local uevent = require 'uevent'

local conn = uevent.new(function(msg)
	if string.lower(string.sub(msg, 1, 7)) == 'libudev' then
		-- Skip libudev message
		return
	end

	local t = {}
	for w in string.gmatch(msg, "%g+") do
		t[#t + 1] = w
	end
	local t1 = t[1]
	local action, path = string.match(t1, "^([^@]+)@(.+)")
	print(action, path)
	local tmsg = {}
	for i, v in ipairs(t) do
		if i ~= 1 then
			local key, val = string.match(v, '(.-)=(.+)')
			tmsg[key] = val
			print(key, val)
		end
	end
end)

while true do
	local r, err = conn:run()
	if not r then
		print(err)
	end
end

print('closed')
