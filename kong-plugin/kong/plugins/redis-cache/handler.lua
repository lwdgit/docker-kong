local BasePlugin = require "kong.plugins.base_plugin"
local CacheHandler = BasePlugin:extend()
local responses = require "kong.tools.responses"
local req_get_method = ngx.req.get_method

local redis = require "resty.redis"
local resty_lock = require "resty.lock"

local cjson_decode = require("cjson").decode
local cjson_encode = require("cjson").encode

local lock_dict = ngx.shared['kong'] and 'kong' or 'kong_locks' -- lua 三元表达式写法 ngx.shared['kong_cache'] ? 'kong_cache' : 'cache_locks'

local function cacheable_request(method, uri, conf)
  if method ~= "GET" then
    return false
  end
  
  if conf.uris == nil then
    return true
  end
  
  for _,v in ipairs(conf.uris) do
    if string.match(uri, "^"..v.."$") then
      return true
    end
  end

  return false
end

local function get_cache_key(uri, headers, query_params, conf)
  local cache_key = uri
  
  table.sort(query_params)
  for _,param in ipairs(conf.vary_by_query_string_parameters) do
    local query_value = query_params[param]
    if query_value then
      if type(query_value) == "table" then
        table.sort(query_value)
        query_value = table.concat(query_value, ",")
      end
      ngx.log(ngx.NOTICE, "varying cache key by query string ("..param..":"..query_value..")")
      cache_key = cache_key..":"..param.."="..query_value
    end
  end

  table.sort(headers)
  for _,header in ipairs(conf.vary_by_headers) do
    local header_value = headers[header]
    if header_value then
      if type(header_value) == "table" then
        table.sort(header_value)
        header_value = table.concat(header_value, ",")
      end
      ngx.log(ngx.NOTICE, "varying cache key by matched header ("..header..":"..header_value..")")
      cache_key = cache_key..":"..header.."="..header_value
    end
  end

  for _,cookie_name in ipairs(conf.vary_by_cookies) do
    local cookie_value = ngx.var['cookie_'..cookie_name]
    if cookie_value then
      ngx.log(ngx.NOTICE, "varying cache key by matched cookie ("..cookie_name..":"..cookie_value..")")
      cache_key = cache_key..":"..cookie_name.."="..cookie_value
    end
  end
  
  return conf.cache_prefix.."::"..cache_key
end

local function json_decode(json)
  if json then
    local status, res = pcall(cjson_decode, json)
    if status then
      return res
    end
  end
end

local function json_encode(table)
  if table then
    local status, res = pcall(cjson_encode, table)
    if status then
      return res
    end
  end
end

local function connect_to_redis(conf)
  local red = redis:new()
  
  red:set_timeout(conf.redis_timeout)
  
  local ok, err = red:connect(conf.redis_host, conf.redis_port)
  if err then
    return nil, err
  end

  if conf.redis_password and conf.redis_password ~= "" then
    local ok, err = red:auth(conf.redis_password)
    if err then
      return nil, err
    end
  end

  if conf.redis_db ~= 0 then
    local ok, err = red:select(conf.redis_db)
    if err then
      return nil, err
    end
  end
  
  return red
end

local function red_set(premature, key, header, body, conf, lock_instance)
  local red, err = connect_to_redis(conf)
  if err then
      ngx.log(ngx.ERR, "failed to connect to Redis: ", err)
  end

  red:init_pipeline()
  red:hmset(key, 'header', header, 'body', body, 'create_at', os.time())
  if conf.expire_time then
    red:expire(key, conf.expire_time)
  end
  local results, err = red:commit_pipeline()
  if err then
    ngx.log(ngx.ERR, "failed to commit the pipelined requests: ", err)
  end
  lock_instance:unlock()
  local ok, err = red:set_keepalive(10000, 100)
  if not ok then
    ngx_log(ngx.ERR, "failed to set Redis keepalive: ", err)
    return nil, err
  end
end

local function red_get(key, conf)
  local red, err = connect_to_redis(conf)
  if err then
    ngx.log(ngx.ERR, "failed to connect to Redis: ", err)
    return
  end

  local cached_val, err = red:hmget(key, 'header', 'body', 'create_at')
  
  if not cached_val then
    ngx.log(ngx.ERR, "failed to get redis cache: ", key, " => ", err)
    return
  end
  return unpack(cached_val)
end

function CacheHandler:new()
  CacheHandler.super.new(self, "response-cache")
end

function set_response(content)
  ngx.header['X-Via'] = 'rcc'
  ngx.print(content)
  return responses.send_HTTP_OK()
end

function CacheHandler:access(conf)
  CacheHandler.super.access(self)
  
  local uri = ngx.var.uri
  if not cacheable_request(req_get_method(), uri, conf) then
    ngx.log(ngx.NOTICE, "not cacheable")
    return
  end
  
  local cache_key = get_cache_key(uri, ngx.req.get_headers(), ngx.req.get_uri_args(), conf)

  local header, body, create_at = red_get(cache_key, conf)
  if create_at ~= ngx.null and create_at ~= nil and (os.time() - create_at < conf.refresh_time) then
    local val = json_decode(header)
    for k,v in pairs(val) do
      ngx.header[k] = v
    end
    ngx.ctx.cache_body = body
  end

  -- create lock
  local lock_instance, err = resty_lock:new(lock_dict, {
    timeout = lock_timeout
  })

  if err then
    ngx.log(ngx.ERR, "failed to create lock: ", err)
  end

  local elapsed, err = lock_instance:lock(cache_key)

  if elapsed ~= 0 then -- elapsed 标志为0表示新建的lock
    local header, body = red_get(cache_key, conf)
    if header and header ~= ngx.null then
      ngx.log(ngx.NOTICE, "cache hit")
      local val = json_decode(header)
      for k,v in pairs(val) do
        ngx.header[k] = v;
      end
      lock_instance:unlock()
      ngx.ctx.cache_body = body
    end
    return
  end

  ngx.log(ngx.NOTICE, "cache miss")
  ngx.ctx.response_cache = {
    cache_key = cache_key,
    lock_instance = lock_instance,
    header_flag = 'rcp'
  }
end

function CacheHandler:header_filter(conf)
  CacheHandler.super.header_filter(self)

  local ctx = ngx.ctx.response_cache
  if not ctx then
    return
  end
  ctx.headers = ngx.resp.get_headers()
  ngx.header['X-Via'] = ctx.header_flag -- 通过x-via标志缓存插件是否生效
end

function CacheHandler:body_filter(conf)
  CacheHandler.super.body_filter(self)

  if ngx.ctx.cache_body then
    return set_response(ngx.ctx.cache_body)
  end

  local ctx = ngx.ctx.response_cache
  if not ctx or ngx.status ~= 200 then
    return
  end

  local chunk = ngx.arg[1]
  local eof = ngx.arg[2]
  
  local res_body = ctx and ctx.res_body or ""
  res_body = res_body .. (chunk or "")
  ctx.res_body = res_body
  if eof then
    ngx.timer.at(0, red_set, ctx.cache_key, json_encode(ctx.headers), ctx.res_body, conf, ctx.lock_instance)
  end
end

return CacheHandler
