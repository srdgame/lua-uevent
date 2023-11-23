ALL: lua_uevent.c
	# gcc -O2 -fPIC -shared -o uevent.so $< -llua5.4 -I/usr/include/lua5.4
	gcc -g -fPIC -shared -o luevent.so $< -llua5.4 -I/usr/include/lua5.4

