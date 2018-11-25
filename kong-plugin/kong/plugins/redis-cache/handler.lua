local BasePlugin = require "kong.plugins.base_plugin"
local responses = require "kong.tools.responses"
local cjson = require 'cjson'
local redis = require "resty.redis"
local resty_lock = require "resty.lock"

local CacheHandler = BasePlugin:extend()

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local headersMap = {
  ["server"] = "Server",
  ["date"] = "Date",
  ["content-encoding"] = "Content-Encoding",
  ["location"] = "Location",
  ["refresh"] = "Refresh",
  ["last-modified"] = "Last-Modified",
  ["content-range"] = "Content-Range",
  ["accept-ranges"] = "Accept-Ranges",
  ["www-authenticate"] = "WWW-Authenticate",
  ["expires"] = "Expires",
  ["e-tag"] = "E-Tag",
  ["etag"] = "ETag",
  ["content-length"] = "Content-Length",
  ["content-type"] = "Content-Type",
  ["cache-control"] = "Cache-Control"
}

local LOG_COLOR = {
  [ngx.ERR] = '\27[31m',
  [ngx.NOTICE] = '\27[33m'
}

local req_get_method = ngx.req.get_method
local lock_dict = ngx.shared['kong'] and 'kong' or 'kong_locks' -- lua 三元表达式写法 ngx.shared['kong_cache'] ? 'kong_cache' : 'cache_locks'

local function json_decode(json)
  if json then
    local status, res = pcall(cjson_decode, json)
    if status then
      return res
    end
  end
end

local function log(logType, ...)
  local info = debug.getinfo(3, "Sl")
  local lineinfo = info.short_src .. ":" .. info.currentline
  local logstr = '[REDIS CACHE => ' .. lineinfo .. ':'
  for _, v in pairs({...}) do
    if (v == nil) then
      logstr = logstr .. ' nil'
    elseif type(v) == "table" then
      logstr = logstr .. ' ' .. cjson_encode(v)
    else
      logstr = logstr .. ' ' .. tostring(v)
    end
  end

  ngx.log(logType, string.format("%s %s %s", LOG_COLOR[logType], logstr, "\27[0m"))
end

local function error(...)
  log(ngx.ERR, ...)
end

local function notice(...)
  log(ngx.NOTICE, ...)
end

local function cacheable_request(method, uri, conf)
  if method ~= "GET" then
    return false
  end
  
  if conf.uris == nil then
    return true
  end
  
  for _, v in ipairs(conf.uris) do
    if string.match(uri, "^"..v.."$") then
      return true
    end
  end

  return false
end

local function get_cache_key(uri, headers, query_params, conf)
  local cache_key = uri
  
  -- table.sort(query_params)
  for _, param in ipairs(conf.vary_by_query) do
    local query_value = query_params[param]
    if query_value then
      if type(query_value) == "table" then
        -- table.sort(query_value)
        query_value = table.concat(query_value, ",")
      end
      notice("varying cache key by query string ("..param..":"..query_value..")")
      cache_key = cache_key..":"..param.."="..query_value
    end
  end

  -- table.sort(headers)
  for _, header in ipairs(conf.vary_by_headers) do
    local header_value = headers[header]
    if header_value then
      if type(header_value) == "table" then
        -- table.sort(header_value)
        header_value = table.concat(header_value, ",")
      end
      notice("varying cache key by matched header ("..header..":"..header_value..")")
      cache_key = cache_key..":"..header.."="..header_value
    end
  end

  for _, cookie_name in ipairs(conf.vary_by_cookies) do
    local cookie_value = ngx.var['cookie_'..cookie_name]
    if cookie_value then
      notice("varying cache key by matched cookie ("..cookie_name..":"..cookie_value..")")
      cache_key = cache_key..":"..cookie_name.."="..cookie_value
    end
  end
  
  return conf.cache_prefix.."::"..cache_key
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

local function red_set(premature, ctx, conf)
  local red, err = connect_to_redis(conf)
  if err then
    error("failed to connect to Redis: ", err)
  end

  red:init_pipeline()
  red:hmset(ctx.cache_key, 'header', ctx.headers, 'body', ctx.res_body, 'updated_at', ctx.updated_at)
  if conf.expire_time then
    red:expire(ctx.cache_key, conf.expire_time)
  end
  local results, err = red:commit_pipeline()
  if err then
    error("failed to commit the pipelined requests: ", err)
  end
  ctx.lock_instance:unlock()
  local ok, err = red:set_keepalive(10000, 100)
  if not ok then
    error("failed to set Redis keepalive: ", err)
    return nil, err
  end
end

local function red_get(key, conf)
  local red, err = connect_to_redis(conf)
  if err then
    error("failed to connect to Redis: ", err)
    return
  end

  local cached_val, err = red:hmget(key, 'header', 'body', 'updated_at')
  
  if not cached_val then
    error("failed to get redis cache: ", key, " => ", err)
    return
  end
  return unpack(cached_val)
end

function CacheHandler:new()
  CacheHandler.super.new(self, "response-cache")
end

function set_response(status, content)
  ngx.header['X-Via'] = 'rcc'
  ngx.print(content)
  -- return responses.send_HTTP_OK()
  notice('response status', status)
  return ngx.exit(status)
end

function CacheHandler:access(conf)
  CacheHandler.super.access(self)
  
  local uri = ngx.var.uri
  if not cacheable_request(req_get_method(), uri, conf) then
    notice("not cacheable")
    return
  end
  
  local req_headers = ngx.req.get_headers()
  local cache_key = get_cache_key(uri, req_headers, ngx.req.get_uri_args(), conf)

  local header, body, updated_at = red_get(cache_key, conf)
  if updated_at ~= ngx.null and updated_at ~= nil and (ngx.now() - updated_at < conf.refresh_time) then
    local headers = json_decode(header)

    for k, v in pairs(headers) do
      ngx.header[k] = v
    end

    local ifNoneMatch = req_headers['If-None-Match']

    if conf.use_etag and ifNoneMatch and ifNoneMatch == headers['ETag'] then
      set_response(304) -- 不需要 return
    else
      set_response(200, body) -- 不需要 return
    end
  end

  -- create lock
  local lock_instance, err = resty_lock:new(lock_dict, {
    timeout = lock_timeout
  })

  if err then
    error("failed to create lock: ", err)
  end

  local elapsed, err = lock_instance:lock(cache_key)

  if elapsed ~= 0 then -- elapsed 标志为0表示新建的lock
    local header, body = red_get(cache_key, conf)
    if header and header ~= ngx.null then
      notice("cache hit")
      local val = json_decode(header)
      for k, v in pairs(val) do
        ngx.header[k] = v;
      end
      lock_instance:unlock()
      return set_response(200, body)
    end
    return
  end

  notice("cache miss")
  ngx.ctx.response_cache = {
    cache_key = cache_key,
    lock_instance = lock_instance,
    header_flag = 'rcp',
    updated_at = ngx.now()
  }
end

function CacheHandler:header_filter(conf)
  CacheHandler.super.header_filter(self)

  local ctx = ngx.ctx.response_cache
  if not ctx then
    return
  else
    if conf.use_etag then
      ngx.header['ETag'] = ngx.md5(ctx.cache_key .. ngx.now())
      ngx.header['Last-Modified'] = ngx.http_time(ngx.now())
      ngx.header['Expires'] = ngx.http_time(ngx.now() + conf.refresh_time)
    end

    local headers = ngx.resp.get_headers()
    -- 去除不能缓存的变量
    headers['connection'] = nil
    headers['Date'] = nil

    -- -- 将被 resty 转换过的 key 转换回来， 参考 https://github.com/openresty/lua-nginx-module/blob/master/src/ngx_http_lua_headers_out.c
    -- for k, v in pairs(headers) do
    --   if headersMap[k] then
    --     headers[headersMap[k]] = v
    --     headers[k] = nil
    --   end
    -- end
    ctx.headers = json_encode(headers)
    ngx.header['X-Via'] = ctx.header_flag -- 通过x-via标志缓存插件是否生效
  end
end

function CacheHandler:body_filter(conf)
  CacheHandler.super.body_filter(self)

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
    ngx.timer.at(0, red_set, ctx, conf)
  end
end

return CacheHandler
