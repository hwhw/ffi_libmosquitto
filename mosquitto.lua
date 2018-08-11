-- Copyright (c) 2018 Hans-Werner Hilse <hwhilse@gmail.com>
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy of
-- this software and associated documentation files (the "Software"), to deal in
-- the Software without restriction, including without limitation the rights to
-- use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
-- of the Software, and to permit persons to whom the Software is furnished to do
-- so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

local ffi=require"ffi"
local bit=require"bit"

ffi.cdef[[
static const int MOSQ_LOG_NONE = 0x00;
static const int MOSQ_LOG_INFO = 0x01;
static const int MOSQ_LOG_NOTICE = 0x02;
static const int MOSQ_LOG_WARNING = 0x04;
static const int MOSQ_LOG_ERR = 0x08;
static const int MOSQ_LOG_DEBUG = 0x10;
static const int MOSQ_LOG_SUBSCRIBE = 0x20;
static const int MOSQ_LOG_UNSUBSCRIBE = 0x40;
static const int MOSQ_LOG_WEBSOCKETS = 0x80;
static const int MOSQ_LOG_ALL = 0xFFFF;

static const int MOSQ_MQTT_ID_MAX_LENGTH = 23;

static const int MQTT_PROTOCOL_V31 = 3;
static const int MQTT_PROTOCOL_V311 = 4;

enum mosq_err_t {
	MOSQ_ERR_CONN_PENDING = -1,
	MOSQ_ERR_SUCCESS = 0,
	MOSQ_ERR_NOMEM = 1,
	MOSQ_ERR_PROTOCOL = 2,
	MOSQ_ERR_INVAL = 3,
	MOSQ_ERR_NO_CONN = 4,
	MOSQ_ERR_CONN_REFUSED = 5,
	MOSQ_ERR_NOT_FOUND = 6,
	MOSQ_ERR_CONN_LOST = 7,
	MOSQ_ERR_TLS = 8,
	MOSQ_ERR_PAYLOAD_SIZE = 9,
	MOSQ_ERR_NOT_SUPPORTED = 10,
	MOSQ_ERR_AUTH = 11,
	MOSQ_ERR_ACL_DENIED = 12,
	MOSQ_ERR_UNKNOWN = 13,
	MOSQ_ERR_ERRNO = 14,
	MOSQ_ERR_EAI = 15,
	MOSQ_ERR_PROXY = 16,
	MOSQ_ERR_PLUGIN_DEFER = 17,
	MOSQ_ERR_MALFORMED_UTF8 = 18
};

enum mosq_opt_t {
	MOSQ_OPT_PROTOCOL_VERSION = 1,
	MOSQ_OPT_SSL_CTX = 2,
	MOSQ_OPT_SSL_CTX_WITH_DEFAULTS = 3,
};

struct mosquitto_message{
	int mid;
	char *topic;
	void *payload;
	int payloadlen;
	int qos;
	bool retain;
};

struct mosquitto;

int mosquitto_lib_version(int *major, int *minor, int *revision);
int mosquitto_lib_init(void);
int mosquitto_lib_cleanup(void);
struct mosquitto *mosquitto_new(const char *id, bool clean_session, void *obj);
void mosquitto_destroy(struct mosquitto *mosq);
int mosquitto_reinitialise(struct mosquitto *mosq, const char *id, bool clean_session, void *obj);
int mosquitto_will_set(struct mosquitto *mosq, const char *topic, int payloadlen, const void *payload, int qos, bool retain);
int mosquitto_will_clear(struct mosquitto *mosq);
int mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password);
int mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive);
int mosquitto_connect_bind(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address);
int mosquitto_connect_async(struct mosquitto *mosq, const char *host, int port, int keepalive);
int mosquitto_connect_bind_async(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address);
int mosquitto_connect_srv(struct mosquitto *mosq, const char *host, int keepalive, const char *bind_address);
int mosquitto_reconnect(struct mosquitto *mosq);
int mosquitto_reconnect_async(struct mosquitto *mosq);
int mosquitto_disconnect(struct mosquitto *mosq);
int mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain);
int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos);
int mosquitto_unsubscribe(struct mosquitto *mosq, int *mid, const char *sub);
int mosquitto_message_copy(struct mosquitto_message *dst, const struct mosquitto_message *src);
void mosquitto_message_free(struct mosquitto_message **message);
void mosquitto_message_free_contents(struct mosquitto_message *message);
int mosquitto_loop(struct mosquitto *mosq, int timeout, int max_packets);
int mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets);
int mosquitto_loop_start(struct mosquitto *mosq);
int mosquitto_loop_stop(struct mosquitto *mosq, bool force);
int mosquitto_socket(struct mosquitto *mosq);
int mosquitto_loop_read(struct mosquitto *mosq, int max_packets);
int mosquitto_loop_write(struct mosquitto *mosq, int max_packets);
int mosquitto_loop_misc(struct mosquitto *mosq);
bool mosquitto_want_write(struct mosquitto *mosq);
int mosquitto_threaded_set(struct mosquitto *mosq, bool threaded);
int mosquitto_opts_set(struct mosquitto *mosq, enum mosq_opt_t option, void *value);
int mosquitto_tls_set(struct mosquitto *mosq,
		const char *cafile, const char *capath,
		const char *certfile, const char *keyfile,
		int (*pw_callback)(char *buf, int size, int rwflag, void *userdata));
int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value);
int mosquitto_tls_opts_set(struct mosquitto *mosq, int cert_reqs, const char *tls_version, const char *ciphers);
int mosquitto_tls_psk_set(struct mosquitto *mosq, const char *psk, const char *identity, const char *ciphers);
void mosquitto_connect_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int));
void mosquitto_connect_with_flags_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int, int));
void mosquitto_disconnect_callback_set(struct mosquitto *mosq, void (*on_disconnect)(struct mosquitto *, void *, int));
void mosquitto_publish_callback_set(struct mosquitto *mosq, void (*on_publish)(struct mosquitto *, void *, int));
void mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *));
void mosquitto_subscribe_callback_set(struct mosquitto *mosq, void (*on_subscribe)(struct mosquitto *, void *, int, int, const int *));
void mosquitto_unsubscribe_callback_set(struct mosquitto *mosq, void (*on_unsubscribe)(struct mosquitto *, void *, int));
void mosquitto_log_callback_set(struct mosquitto *mosq, void (*on_log)(struct mosquitto *, void *, int, const char *));
int mosquitto_reconnect_delay_set(struct mosquitto *mosq, unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff);
int mosquitto_max_inflight_messages_set(struct mosquitto *mosq, unsigned int max_inflight_messages);
void mosquitto_message_retry_set(struct mosquitto *mosq, unsigned int message_retry);
void mosquitto_user_data_set(struct mosquitto *mosq, void *obj);


int mosquitto_socks5_set(struct mosquitto *mosq, const char *host, int port, const char *username, const char *password);


const char *mosquitto_strerror(int mosq_errno);
const char *mosquitto_connack_string(int connack_code);
int mosquitto_sub_topic_tokenise(const char *subtopic, char ***topics, int *count);
int mosquitto_sub_topic_tokens_free(char ***topics, int count);
int mosquitto_topic_matches_sub(const char *sub, const char *topic, bool *result);
int mosquitto_topic_matches_sub2(const char *sub, size_t sublen, const char *topic, size_t topiclen, bool *result);
int mosquitto_pub_topic_check(const char *topic);
int mosquitto_pub_topic_check2(const char *topic, size_t topiclen);
int mosquitto_sub_topic_check(const char *topic);
int mosquitto_sub_topic_check2(const char *topic, size_t topiclen);

struct libmosquitto_will {
	char *topic;
	void *payload;
	int payloadlen;
	int qos;
	bool retain;
};
struct libmosquitto_auth {
	char *username;
	char *password;
};
struct libmosquitto_tls {
	char *cafile;
	char *capath;
	char *certfile;
	char *keyfile;
	char *ciphers;
	char *tls_version;
	int (*pw_callback)(char *buf, int size, int rwflag, void *userdata);
	int cert_reqs;
};
int mosquitto_subscribe_simple(
		struct mosquitto_message **messages,
		int msg_count,
		bool want_retained,
		const char *topic,
		int qos,
		const char *host,
		int port,
		const char *client_id,
		int keepalive,
		bool clean_session,
		const char *username,
		const char *password,
		const struct libmosquitto_will *will,
		const struct libmosquitto_tls *tls);
int mosquitto_subscribe_callback(
		int (*callback)(struct mosquitto *, void *, const struct mosquitto_message *),
		void *userdata,
		const char *topic,
		int qos,
		const char *host,
		int port,
		const char *client_id,
		int keepalive,
		bool clean_session,
		const char *username,
		const char *password,
		const struct libmosquitto_will *will,
		const struct libmosquitto_tls *tls);

int mosquitto_validate_utf8(const char *str, int len);
void *mosquitto_userdata(struct mosquitto *mosq);
]]

local L = ffi.load("mosquitto")

-- constants are available in the returned object
local lib = {
  LOG_NONE = L.MOSQ_LOG_NONE,
  LOG_INFO = L.MOSQ_LOG_INFO,
  LOG_NOTICE = L.MOSQ_LOG_NOTICE,
  LOG_WARNING = L.MOSQ_LOG_WARNING,
  LOG_ERR = L.MOSQ_LOG_ERR,
  LOG_DEBUG = L.MOSQ_LOG_DEBUG,
  LOG_SUBSCRIBE = L.MOSQ_LOG_SUBSCRIBE,
  LOG_UNSUBSCRIBE = L.MOSQ_LOG_UNSUBSCRIBE,
  LOG_WEBSOCKETS = L.MOSQ_LOG_WEBSOCKETS,
  LOG_ALL = L.MOSQ_LOG_ALL,

  MQTT_ID_MAX_LENGTH = L.MOSQ_MQTT_ID_MAX_LENGTH,

  MQTT_PROTOCOL_V31 = L.MQTT_PROTOCOL_V31,
  MQTT_PROTOCOL_V311 = L.MQTT_PROTOCOL_V311,

  ERR_CONN_PENDING = L.MOSQ_ERR_CONN_PENDING,
  ERR_SUCCESS = L.MOSQ_ERR_SUCCESS,
  ERR_NOMEM = L.MOSQ_ERR_NOMEM,
  ERR_PROTOCOL = L.MOSQ_ERR_PROTOCOL,
  ERR_INVAL = L.MOSQ_ERR_INVAL,
  ERR_NO_CONN = L.MOSQ_ERR_NO_CONN,
  ERR_CONN_REFUSED = L.MOSQ_ERR_CONN_REFUSED,
  ERR_NOT_FOUND = L.MOSQ_ERR_NOT_FOUND,
  ERR_CONN_LOST = L.MOSQ_ERR_CONN_LOST,
  ERR_TLS = L.MOSQ_ERR_TLS,
  ERR_PAYLOAD_SIZE = L.MOSQ_ERR_PAYLOAD_SIZE,
  ERR_NOT_SUPPORTED = L.MOSQ_ERR_NOT_SUPPORTED,
  ERR_AUTH = L.MOSQ_ERR_AUTH,
  ERR_ACL_DENIED = L.MOSQ_ERR_ACL_DENIED,
  ERR_UNKNOWN = L.MOSQ_ERR_UNKNOWN,
  ERR_ERRNO = L.MOSQ_ERR_ERRNO,
  ERR_EAI = L.MOSQ_ERR_EAI,
  ERR_PROXY = L.MOSQ_ERR_PROXY,
  ERR_PLUGIN_DEFER = L.MOSQ_ERR_PLUGIN_DEFER,
  ERR_MALFORMED_UTF8 = L.MOSQ_ERR_MALFORMED_UTF8,

  OPT_PROTOCOL_VERSION = L.MOSQ_OPT_PROTOCOL_VERSION,
  OPT_SSL_CTX = L.MOSQ_OPT_SSL_CTX,
  OPT_SSL_CTX_WITH_DEFAULTS = L.MOSQ_OPT_SSL_CTX_WITH_DEFAULTS
}

-- internal helper, checks results for errors
local function check(result)
  if result ~= L.MOSQ_ERR_SUCCESS then
    error(ffi.string(L.mosquitto_strerror(result)), result)
  end
  return result
end

-- metatable for client struct
local M = {__index={}, state={}}

function M:__gc()
  M.state[self] = nil
  L.mosquitto_destroy(self)
end

function M.__index:state()
  local state = M.state[self]
  if not state then
    state = {}
    M.state[self] = state
  end
  return state
end

-- see C API documentation for all the following functions
-- (hint: see the mosquitto.h header file)
--
-- In general, they are corresponding, with the notable exception that the
-- pointer to the client struct is set automatically.
-- We do some very basic error checking here and are also setting defaults
-- where sensible, mostly following the defaults that libmosquitto uses
-- anyway.
-- Binary blob parameter tuples (pointer plus length) are consolidated to
-- a single string parameter as Lua strings have an explicit length.
-- Where there are return values for which pointers have to be given
-- as an argument in the C API, this is not the case here. Instead, you
-- do not need to provide anything and the function will just return
-- the values.
-- Freeing memory is done automatically by proper setup of callbacks
-- for the garbage collector or simply copying the values.

function M.__index:reinitialize(id, clean_session)
  return check(L.mosquitto_reinitialize(self, id, clean_session or true, nil))
end

function M.__index:will_set(topic, payload, qos, retain)
  assert(topic)
  payload = payload or "1"
  return check(L.mosquitto_will_set(self, topic, string.len(payload), payload, qos or 0, retain or false))
end

function M.__index:will_clear()
  return check(L.mosquitto_will_clear(self))
end

function M.__index:username_pw_set(username, password)
  assert(username)
  assert(password)
  return check(L.mosquitto_username_pw_set(self, username, password))
end

function M.__index:connect(host, port, keepalive)
  return check(L.mosquitto_connect(self, host or "localhost", port or 1883, keepalive or 59))
end

function M.__index:connect_bind(host, port, keepalive, bind_address)
  assert(bind_address)
  return check(L.mosquitto_connect_bind(self, host or "localhost", port or 1883, keepalive or 59), bind_address)
end

function M.__index:connect_async(host, port, keepalive)
  return check(L.mosquitto_connect_async(self, host or "localhost", port or 1883, keepalive or 59))
end

function M.__index:connect_bind_async(host, port, keepalive, bind_address)
  assert(bind_address)
  return check(L.mosquitto_connect_bind_async(self, host or "localhost", port or 1883, keepalive or 59), bind_address)
end

function M.__index:connect_srv(host, port, keepalive, bind_address)
  assert(bind_address)
  return check(L.mosquitto_connect_srv(self, host or "localhost", port or 1883, keepalive or 59), bind_address)
end

function M.__index:reconnect()
  return check(L.mosquitto_reconnect(self))
end

function M.__index:reconnect_async()
  return check(L.mosquitto_reconnect_async(self))
end

function M.__index:disconnect()
  return check(L.mosquitto_disconnect(self))
end

function M.__index:publish(topic, payload, qos, retain)
  assert(topic)
  payload = payload or "1"
  local p_mid = ffi.new("int[1]")
  local res = check(L.mosquitto_publish(self, p_mid, topic, string.len(payload), payload, qos or 0, retain or false))
  return p_mid[0], res
end

function M.__index:subscribe(sub, qos)
  assert(sub)
  local p_mid = ffi.new("int[1]")
  local res = check(L.mosquitto_subscribe(self, p_mid, sub, qos or 0))
  return p_mid[0], res
end

function M.__index:unsubscribe(sub)
  assert(sub)
  local p_mid = ffi.new("int[1]")
  local res = check(L.mosquitto_unsubscribe(self, p_mid, sub))
  return p_mid[0], res
end

function M.__index:loop(timeout, max_packets)
  return check(L.mosquitto_loop(self, timeout or -1, max_packets or 1))
end

function M.__index:loop_forever(timeout, max_packets)
  return check(L.mosquitto_loop_forever(self, timeout or -1, max_packets or 1))
end

function M.__index:loop_start()
  return check(L.mosquitto_loop_start(self))
end

function M.__index:loop_stop(force)
  return check(L.mosquitto_loop_stop(self, force or true))
end

function M.__index:socket()
  return L.mosquitto_socket(self)
end

function M.__index:loop_read(max_packets)
  return L.mosquitto_loop_read(self, max_packets or 1)
end

function M.__index:loop_write(max_packets)
  return L.mosquitto_loop_write(self, max_packets or 1)
end

function M.__index:loop_misc()
  return L.mosquitto_loop_misc(self)
end

function M.__index:want_write()
  return L.mosquitto_want_write(self)
end

function M.__index:threaded_set(threaded)
  return L.mosquitto_threaded_set(self, threaded or false)
end

function M.__index:opts_set(option, value)
  assert(option)
  return L.mosquitto_opts_set(self, option, value)
end

function M.__index:tls_set(cafile, capath, certfile, keyfile, pwcallback)
  assert(cafile or capath)
  assert((certfile and keyfile) or (not certfile and not keyfile))
  return check(L.mosquitto_tls_set(self, cafile, capath, certfile, keyfile, pwcallback))
end

function M.__index:tls_insecure_set(value)
  return check(L.mosquitto_tls_insecure_set(self, value or false))
end

function M.__index:tls_opts_set(cert_reqs, tls_version, ciphers)
  return check(L.mosquitto_tls_opts_set(self, cert_reqs or 1, tls_version, ciphers))
end

function M.__index:tls_psk_set(psk, identity, ciphers)
  assert(psk)
  assert(identity)
  return check(L.mosquitto_tls_psk_set(self, psk, identity, ciphers))
end

function M.__index:connect_callback_set(on_connect)
  return L.mosquitto_connect_callback_set(self, on_connect)
end

function M.__index:disconnect_callback_set(on_disconnect)
  return L.mosquitto_disconnect_callback_set(self, on_disconnect)
end

function M.__index:publish_callback_set(on_publish)
  return L.mosquitto_publish_callback_set(self, on_publish)
end

function M.__index:message_callback_set(on_message)
  return L.mosquitto_message_callback_set(self, on_message)
end

function M.__index:subscribe_callback_set(on_subscribe)
  return L.mosquitto_subscribe_callback_set(self, on_subscribe)
end

function M.__index:unsubscribe_callback_set(on_unsubscribe)
  return L.mosquitto_unsubscribe_callback_set(self, on_unsubscribe)
end

function M.__index:log_callback_set(on_log)
  return L.mosquitto_log_callback_set(self, on_log)
end

function M.__index:reconnect_delay_set(reconnect_delay, reconnect_delay_max, reconnect_exponential_backoff)
  return check(L.mosquitto_reconnect_delay_set(self, reconnect_delay or 1, reconnect_delay_max or reconnect_delay or 1, reconnect_exponential_backoff or false))
end

function M.__index:max_inflight_messages_set(max_inflight_messages)
  return check(L.mosquitto_max_inflight_messages_set(self, max_inflight_messages or 20))
end

function M.__index:message_retry_set(message_retry)
  -- no-op in libmosquitto
  return L.mosquitto_message_retry_set(self, message_retry)
end

--[[ unsupported/not needed, use upvalues in Lua
function M.__index:user_data_set(user_data)
  return L.mosquitto_user_data_set(self, user_data)
end
]]

function M.__index:socks5_set(host, port, username, password)
  assert(host)
  assert(port)
  return L.mosquitto_socks5_set(self, host, port, username, password)
end

--[[ the following methods are not part of the C API ]]--

function M.__index:connect_callback_set_wrapper(on_connect)
  return self:connect_callback_set(function(_, _, rc) on_connect(rc) end)
end

function M.__index:disconnect_callback_set_wrapper(on_disconnect)
  return self:disconnect_callback_set(function(_, _, rc) on_disconnect(rc) end)
end

function M.__index:publish_callback_set_wrapper(on_publish)
  return self:publish_callback_set(function(_, _, mid) on_publish(mid) end)
end

function M.__index:message_callback_set_wrapper(on_message)
  return self:message_callback_set(function(_, _, message) on_publish(message:copy()) end)
end

function M.__index:subscribe_callback_set_wrapper(on_subscribe)
  return self:subscribe_callback_set(function(_, _, mid, qos_count, granted_qos) on_subscribe(mid, qos_count, granted_qos) end)
end

function M.__index:unsubscribe_callback_set_wrapper(on_unsubscribe)
  return self:unsubscribe_callback_set(function(_, _, mid) on_unsubscribe(mid) end)
end

function M.__index:log_callback_set_wrapper(on_log)
  return self:log_callback_set(function(_, _, level, str) on_log(level, ffi.string(str)) end)
end

-- even higher level wrappers
function M.__index:subscribe_callback(sub, qos, on_subscribe)
  local state = self:state().on_subscribe
  if not state then
    state = {}
    self:subscribe_callback_set(function(_, _, mid, qos_count, granted_qos)
      local func = state[mid]
      if func then func(qos_count, granted_qos) end
      state[mid] = nil
    end)
    self:state().on_subscribe = state
  end
  local mid = self:subscribe(sub, qos)
  state[mid] = on_subscribe
end

function M.__index:subscribe_message_callback(sub, qos, on_message)
  local state = self:state().on_message
  if not state then
    -- set up client specific wrapper function
    state = {}
    self:message_callback_set(function(_, _, message)
      for _, subscription in ipairs(state) do
        if lib.topic_matches_sub(subscription[1], message.topic) then
          if not subscription[2](message) then break end
        end
      end
    end)
    self:state().on_message = state
  end
  self:subscribe_callback(sub, qos, function(qos_count, granted_qos)
    table.insert(state, {sub, on_message})
  end)
end

ffi.metatype("struct mosquitto", M)


local Msg = { __index={} }

-- explicit free, no garbage collection hook since libmosquitto frees
-- the messages it hands to callbacks itself and this would probably
-- result in a double-free in those cases.
function Msg.__index:free()
  return L.mosquitto_message_free(self)
end

function Msg.__index:free_contents()
  return L.mosquitto_message_free_contents(self)
end

-- create a copy of a message
-- the copy will be left alone (i.e. not freed) by libmosquitto.
-- A hook for the garbage collector is set up, though, so you do
-- not need to free it explicitly. If you do, however, you need
-- to disable the garbage collector hook by calling
-- ffi.gc(<copy>, nil) before freeing explicitly.
function Msg.__index:copy()
  local copy = ffi.new("struct mosquitto_message [1]")
  check(L.mosquitto_message_copy(copy, self))
  return ffi.gc(copy[0], self.free)
end

-- convenience helper
function Msg:__tostring()
  return string.format(
    "[mid: %x, topic: <%s>, payload: <%s>, qos: %d, retain: %s]",
    self.mid,
    ffi.string(self.topic),
    ffi.string(self.payload, self.payloadlen),
    self.qos,
    self.retain and "true" or "false"
  )
end

ffi.metatype("struct mosquitto_message", Msg)

-- setup and teardown of the library
L.mosquitto_lib_init()
setmetatable(lib, {__gc = function() L.mosquitto_lib_cleanup() end })

function lib.lib_version()
  local p_v1 = ffi.new("int[1]")
  local p_v2 = ffi.new("int[1]")
  local p_v3 = ffi.new("int[1]")
  L.mosquitto_lib_version(p_v1, p_v2, p_v3)
  return p_v1[0], p_v2[0], p_v3[0]
end

function lib.new(id, clean_session)
  local client = L.mosquitto_new(id, clean_session or true, nil)
  if client == nil then
    error("error creating mosquitto client")
  end
  return client
end

function lib.strerror(mosq_errno)
  return L.mosquitto_strerror(mosq_errno)
end

function lib.connack_string(connack_code)
  return L.mosquitto_connack_string(connack_code)
end

function lib.sub_topic_tokenise(subtopic)
  assert(subtopic)
  local p_topics = ffi.new("char**[1]")
  local p_count = ffi.new("int[1]")
  check(L.mosquitto_sub_topic_tokenise(subtopic, p_topics, p_count))
  local topics = {}
  for i=0,(p_count[0]-1) do
    table.insert(topics, ffi.string(p_topics[0][i]))
  end
  L.mosquitto_sub_topic_tokens_free(p_topics, p_count[0])
  return topics
end

function lib.topic_matches_sub(sub, topic)
  assert(sub)
  assert(topic)
  local p_result = ffi.new("bool[1]")
  check(L.mosquitto_topic_matches_sub(sub, topic, p_result))
  return p_result[0]
end

function lib.pub_topic_check(topic)
  -- no error generation here
  local ret = L.mosquitto_pub_topic_check(topic)
  return (ret == L.MOSQ_ERR_SUCCESS), ret
end

function lib.sub_topic_check(topic)
  -- no error generation here
  local ret = L.mosquitto_sub_topic_check(topic)
  return (ret == L.MOSQ_ERR_SUCCESS), ret
end

-- TODO: no wrapper yet for the functions
-- mosquitto_subscribe_simple
-- mosquitto_subscribe_callback

function lib.validate_utf8(str)
  -- no error generation here
  local ret = L.mosquitto_validate_utf8(str, string.len(str))
  return (ret == L.MOSQ_ERR_SUCCESS), ret
end

return lib
