return {
  no_consumer = true,
  fields = {
    cache_policy = {
      type = "table",
      schema = {
        fields = {
          uris = { type = "array", default = { "/.*" }, required = true }, -- 生效URI，可设置正则
          vary_by_query = { type = "array", default = {} }, -- query_string 筛选
          vary_by_headers = { type = "array", default = {} }, -- header筛选
          vary_by_cookies = { type = "array", default = {} }, -- cookie筛选
          cache_prefix = { type = "string", default = "redis_cache", required = true } -- 缓存 key 前缀
        }
      }
    },
    redis_config = {
      type = "table",
      schema = {
        fields = {
          redis_host = { type = "string", default = "localhost", required = true },
          redis_port = { type = "number", default = 6379, required = true },
          redis_db = { type = "number", default = 0, required = true },
          redis_password = { type = "string" },
          redis_timeout = { type = "number", default = 2000 }
        }
      }
    },
    use_etag = { type = "boolean", default = false },
    user_cache = { type = "boolean", default = true },
    refresh_time = { type = "number", default = 3600 }, -- 内容更新时间 120s
    expire_time = { type = "number", default = 7200 },  -- 缓存失效时间，1小时
    lock_timeout = { type = "number", default = 3 } -- 竞争锁失效时长，用于避免缓存风暴问题，视接口自身响应速度而定，一般为接口平均响应速度的2-3倍
  }
}