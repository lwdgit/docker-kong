return {
  no_consumer = true,
  fields = {
    cache_prefix = { type = "string", default = "redis_cache", required = true },
    uris = { type = "array", default = { "/.*" }, required = true }, -- 生效URI，可设置正则
    vary_by_query = { type = "array", default = {} }, -- query_string 筛选
    vary_by_headers = { type = "array", default = {} }, -- header筛选
    vary_by_cookies = { type = "array", default = {} }, -- cookie筛选
    use_etag = { type = "boolean", default = true },
    refresh_time = { type = "number", default = 3600 }, -- 内容更新时间 120s
    expire_time = { type = "number", default = 7200 },  -- 缓存失效时间，1小时
    redis_host = { type = "string", default = "localhost", required = true },
    redis_port = { type = "number", default = 6379 },
    redis_db = { type = "number", default = 0 },
    redis_password = { type = "string" },
    redis_timeout = { type = "number", default = 2000 },
    lock_timeout = { type = "number", default = 3 }
  }
}