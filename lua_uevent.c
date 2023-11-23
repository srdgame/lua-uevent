#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include <lua.h>
#include <lauxlib.h>

#ifndef MODNAME_NAME
#define MODNAME_NAME "uevent"
#endif

#ifndef MOD_VERSION
#define MOD_VERSION "0.1.0"
#endif

#define UEVENT_HANDLE "UEVENT_HANDLE_KEY"
#define UEVENT_MSG_LEN 8192

static void ERROR_ABORT(int x, const char* s) {
	fprintf(stderr, "%d : %s\n", x, s);
	exit(-1);
}

typedef struct {
	lua_State* state;
	int callback;
} conn_callback_t;

typedef struct {
	conn_callback_t * callback;
	pthread_t thread;
	pthread_mutex_t lock; 
	int sock;
	int closed;
	int env;
	struct data_list_node *data_head;
	struct data_list_node *data_tail;
} uevent_conn_t;

typedef struct {
	int len;
	void* data;
	uevent_conn_t* conn;
} uevent_data_t;

typedef struct data_list_node {
	uevent_data_t data;
	struct data_list_node *next;
} data_list_node_t;

typedef struct uevent_conn_node {
	uevent_conn_t * conn;
	struct uevent_conn_node *next;
} uevent_conn_node_t;

uevent_conn_node_t* conn_list_head = NULL;
uevent_conn_node_t* conn_list_tail = NULL;
pthread_mutex_t conn_list_mutex = PTHREAD_MUTEX_INITIALIZER;

static int uevent_failmsg(lua_State *L, const char *err, const char *m) {
	lua_pushnil(L);
	lua_pushliteral(L, "UEVENT: ");
	lua_pushstring(L, err);
	lua_pushstring(L, m);
	lua_concat(L, 3);
	return 2;
}


#if !defined LUA_VERSION_NUM || LUA_VERSION_NUM==501
# define lua_pushglobaltable(L) lua_pushvalue(L, LUA_GLOBALSINDEX)
/*
** Adapted from Lua 5.2.0
*/
void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup) {
	luaL_checkstack(L, nup, "too many upvalues");
	for (; l->name != NULL; l++) {	/* fill the table with given functions */
		int i;
		for (i = 0; i < nup; i++)	/* copy upvalues to the top */
			lua_pushvalue(L, -nup);
		lua_pushstring(L, l->name);
		lua_pushcclosure(L, l->func, nup);	/* closure with those upvalues */
		lua_settable(L, -(nup + 3));
	}
	lua_pop(L, nup);	/* remove upvalues */
}
#endif

static int traceback (lua_State *L) {
	if (!lua_isstring(L, 1))  /* 'message' not a string? */
		return 1;  /* keep it intact */
	lua_pushglobaltable(L);
	lua_getfield(L, -1, "debug");
	lua_remove(L, -2);
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return 1;
	}
	lua_getfield(L, -1, "traceback");
	if (!lua_isfunction(L, -1)) {
		lua_pop(L, 2);
		return 1;
	}
	lua_pushvalue(L, 1);  /* pass error message */
	lua_pushinteger(L, 2);  /* skip this function and traceback */
	lua_call(L, 2, 1);  /* call debug.traceback */
	return 1;
}

static void uevent_check_callback(lua_State* L, conn_callback_t *cb, int index)
{
	luaL_checktype(L, index, LUA_TFUNCTION);
	luaL_unref(L, LUA_REGISTRYINDEX, cb->callback);
	lua_pushvalue(L, index);
	cb->callback = luaL_ref(L, LUA_REGISTRYINDEX);
}

static void uevent_call_callback(lua_State* L, conn_callback_t* cb, int nargs) {
	int ref = cb->callback;
	if (ref == LUA_NOREF) {
		lua_pop(L, nargs);
	} else {
		// Get the traceback function in case of error
		lua_pushcfunction(L, traceback);
		// And insert it before the args if there are any.
		if (nargs) {
			lua_insert(L, -1 - nargs);
		}
		// Get the callback
		lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
		// And insert it before the args if there are any.
		if (nargs) {
			lua_insert(L, -1 - nargs);
		}

		if (lua_pcall(L, nargs, 0, -2 - nargs)) {
			fprintf(stderr, "Uncaught Error: %s\n", lua_tostring(L, -1));
			exit(-1);
		}
		// Remove the traceback function
		lua_pop(L, 1);
	}
}


/*
** Check for valid connection.
*/
static uevent_conn_t *get_connection (lua_State *L) {
	uevent_conn_t *conn = (uevent_conn_t *)luaL_checkudata (L, 1, UEVENT_HANDLE);
	luaL_argcheck (L, conn != NULL, 1, "connection expected");
	luaL_argcheck (L, !conn->closed, 1, "connection is closed");
	return conn;
}

static int uevent_gc(lua_State *L)
{
	uevent_conn_t* conn = get_connection(L);

	if (conn != NULL && !(conn->closed)) {
		/* Nullify structure fields. */
		conn->closed = 1;
		luaL_unref (L, LUA_REGISTRYINDEX, conn->env);
		conn->env = LUA_NOREF;

		if (conn->sock >= 0) {
			close(conn->sock);
			conn->sock = -1;
		}

		pthread_mutex_lock(&conn->lock);

		data_list_node_t* node = conn->data_head;
		while (node) {
			free(node->data.data);
			free(node);
			node = node->next;
		}
		conn->data_head = NULL;
		conn->data_tail = NULL;

		pthread_mutex_unlock(&conn->lock);

		if (conn->callback) {
			luaL_unref (L, LUA_REGISTRYINDEX, conn->callback->callback);
			conn->callback = NULL;
		}
		pthread_join(conn->thread, NULL);
		pthread_mutex_destroy(&conn->lock);
	}
	return 0;
}

static int uevent_close (lua_State *L) {
	uevent_conn_t* conn = get_connection(L);
	if (conn->closed) {
		lua_pushboolean (L, 0);
		return 1;
	}
	uevent_gc(L);
	lua_pushboolean (L, 1);
	return 1;
}

static int uevent_check_handle(lua_State *L) {
	uevent_conn_t* conn = get_connection(L);

	if (conn->sock > 0 ) {
		char err_msg[100];
		sprintf(err_msg, "socket [%d]", conn->sock);
		return uevent_failmsg(L, "UEVENT handle failure: ", err_msg);
	}
	lua_pushboolean (L, 1);
	return 1;
}

static void process_data(uevent_data_t* data)
{
	if (!data->conn || data->conn->closed) {
		// printf("%s: conn nil or closed\n", __func__);
		return;
	}

	lua_State* L = data->conn->callback->state;
	if (!L) {
		// printf("%s: luaState nil\n", __func__);
		return;
	}

	/*
	lua_newtable(L);
	lua_pushinteger(L, 1);
	lua_setfield(L, -2, "a1");
	*/

	lua_pushlstring(L, data->data, data->len);

	// uevent_call_callback(L, data->conn->callback, 2);
	uevent_call_callback(L, data->conn->callback, 1);
}

static int uevent_run(lua_State *L)
{
	uevent_conn_t* conn = get_connection(L);
	if (conn == NULL || conn->closed){
		return uevent_failmsg(L, "UEVENT connection closed", strerror(errno));
	}

	if (pthread_mutex_lock(&conn->lock) != 0) {
		return uevent_failmsg(L, "UEVENT mutex_lock error", strerror(errno));
	}

	data_list_node_t* node = conn->data_head;
	if (node != NULL) {
		// printf("%s: process data list\n", __func__);
		while (node) {
			process_data(&node->data);
			free(node->data.data);
			free(node);
			node = node->next;
		}
		conn->data_head = NULL;
		conn->data_tail = NULL;
	}

	if (pthread_mutex_unlock(&conn->lock) != 0) {
		return uevent_failmsg(L, "UEVENT mutex_unlock error", strerror(errno));
	}
	lua_pushboolean (L, 1);
	return 1;
}

static int uevent_tostring (lua_State *L) {
	char buff[100];
	uevent_conn_t* conn = get_connection(L);
	if (conn->closed)
		strcpy (buff, "closed");
	else
		sprintf (buff, "%p", (void *)conn);
	lua_pushfstring (L, "%s (%s)", lua_tostring(L,lua_upvalueindex(1)), buff);
	return 1;
}

static const struct luaL_Reg api_funcs[] = {
	{ "__gc", uevent_gc },
	{ "close", uevent_close },
	{ "run", uevent_run },
	{ NULL, NULL},
};

static void push_conn_data(uevent_conn_t* conn, char* buf, int len)
{
	data_list_node_t *node = (data_list_node_t*)malloc(sizeof(data_list_node_t));
	char* msg = (char*)malloc(sizeof(char) * (len + 2));

	memcpy(msg, buf, len);
	msg[len] = '\0';
	msg[len+1] = '\0';

	node->data.data = msg;
	node->data.len = len + 2;
	node->data.conn = conn;
	node->next = NULL;

	if (pthread_mutex_lock(&conn->lock) != 0) {
		// printf("%s: mutex_lock error\n", __func__);
		free(msg);
		return;
	}

	// Add to connection
	if (conn->data_head == NULL) {
		conn->data_head = node;
		conn->data_tail = node;
	} else {
		conn->data_tail->next = node;
		conn->data_tail = node;
	}

	if (pthread_mutex_unlock(&conn->lock) != 0) {
		// printf("%s: mutex_unlock error\n", __func__);
		return;
	}
	// printf("%s: push conn data\n", __func__);
}

static void* connection_proc(void* arg)
{
    uevent_conn_t *conn = (uevent_conn_t *)arg;
    int device_fd = conn->sock;
    char msg[UEVENT_MSG_LEN+2];

	struct sockaddr_nl sa = {0};
    struct msghdr hdr = {0};
    struct iovec iov = {0};
    ssize_t len = 0;

    iov.iov_base = msg;
    iov.iov_len = UEVENT_MSG_LEN;

    hdr.msg_name = &sa;
    hdr.msg_namelen = sizeof(sa);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    // printf("%s: device_fd = %d\n", __func__, device_fd);

    while (1) {
        len = recvmsg(device_fd, &hdr, 0);
		// printf("%s: device_fd = %d recevied msg %ld\n", __func__, device_fd, len);

        if (len <= 0) {
            break;
        }

        if (hdr.msg_flags & MSG_TRUNC) {
			// printf("%s: skip truncated message %d\n", __func__, len);
            continue;
        }

        if (sa.nl_groups == 0x0 || (sa.nl_groups == 0x1 && sa.nl_pid)) {
			// printf("%s: skip group message %d\n", __func__, sa.nl_groups, sa.nl_pid);
            continue;
        }

		push_conn_data(conn, msg, len);
	}
    // printf("%s: exit\n", __func__);
}

static int create_netlink(lua_State *L, uevent_conn_t* conn, unsigned int groups)
{
	struct sockaddr_nl addr;
    int sz = 64 * 1024;
	int family = PF_NETLINK;
	int type = SOCK_DGRAM; //SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
	int nl_type = NETLINK_KOBJECT_UEVENT;
	int sockfd = -1;
	
	memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = groups;

	sockfd = socket(family, type, nl_type);
	if (sockfd < 0)
		return uevent_failmsg(L, "cannot create netlink socket.", strerror(errno));

	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));
	if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		return uevent_failmsg(L, "bind error ", strerror(errno));

	conn->sock = sockfd;

    if(pthread_mutex_init(&(conn->lock), NULL) != 0) {
		return uevent_failmsg(L, "create lock failed ", strerror(errno));
	}

	if (pthread_create(&conn->thread, NULL, connection_proc, conn) != 0) {
		return uevent_failmsg(L, "create thread failed ", strerror(errno));
	}

	return 1;
}

static int create_connection (lua_State *L,  conn_callback_t *callback, int env, unsigned int groups) {
	uevent_conn_t *conn = (uevent_conn_t *)lua_newuserdata(L, sizeof(uevent_conn_t));
	luaL_getmetatable (L, UEVENT_HANDLE);
	lua_setmetatable (L, -2);

	/* fill in structure */
	conn->callback = callback;
	conn->closed = 0;
	conn->env = LUA_NOREF;
	lua_pushvalue(L, env);
	conn->env = luaL_ref(L, LUA_REGISTRYINDEX);

	conn->data_head = NULL;
	conn->data_tail = NULL;

	return create_netlink(L, conn, groups);
}

static int env_connect_new(lua_State *L)
{
	unsigned int groups = 0xffffffff;

	conn_callback_t* cb = (conn_callback_t*) malloc(sizeof(conn_callback_t));
	cb->state = L;
	cb->callback = LUA_NOREF;

	groups = luaL_optnumber(L, 2, 0xffffffff);
	// printf("[UEVENT] Groups: %02x\n", groups);

	uevent_check_callback(L, cb, 1);

	return create_connection(L, cb, 1, groups);
}

static int env_getpid(lua_State *L)
{
	int pid = getpid();
	lua_pushinteger(L, pid);
	return 1;
}

static int lua_uevent_init_meta(lua_State *L)
{
	if (!luaL_newmetatable(L, UEVENT_HANDLE))
		return 0;
	luaL_setfuncs(L, api_funcs, 0);

	/* define metamethods */
	lua_pushliteral (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushliteral (L, "__tostring");
	lua_pushstring (L, UEVENT_HANDLE);
	lua_pushcclosure (L, uevent_tostring, 1);
	lua_settable (L, -3);

	lua_pushliteral (L, "__metatable");
	lua_pushliteral (L, "UEVENT: you're not allowed to get this metatable");
	lua_settable (L, -3);

	lua_pop(L, 1);

	return 1;
}

static const struct luaL_Reg env_funcs[] = {
	{ "new", env_connect_new },
	{ "getpid", env_getpid },
	{ NULL, NULL },
};

typedef struct {
	const char *name;
	int value;
} lua_uevent_int_const;

static int lua_uevent_new(lua_State *L)
{
	lua_uevent_init_meta(L);

	// Create vistek_data module 
	lua_newtable(L);

	// Register env functions
	luaL_setfuncs(L, env_funcs, 0);

	/* Set uevent.null */
	lua_pushlightuserdata(L, NULL);
	lua_setfield(L, -2, "null");

	/* Set module name / version fields */
	lua_pushliteral(L, MODNAME_NAME);
	lua_setfield(L, -2, "_NAME");
	lua_pushliteral(L, MOD_VERSION);
	lua_setfield(L, -2, "_VERSION");

	return 1;
}

void uevent_cleanup()
{
	// TODO:
}

int luaopen_luevent(lua_State *L) {
	atexit(uevent_cleanup);

	int ret = lua_uevent_new(L);

	return ret;
}
