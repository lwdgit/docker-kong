local function validate_url(value)
  local parsed_url = url.parse(value)
  if parsed_url.scheme and parsed_url.host then
    parsed_url.scheme = parsed_url.scheme:lower()
    if not (parsed_url.scheme == "http" or parsed_url.scheme == "https") then
      return false, "Supported protocols are HTTP and HTTPS"
    end
  end

  return true
end

return {
  meta = {
    description = '第三方 oauth 登录插件，默认支持 Github，你可以根据默认配置进行修改。如你的应用需要知道当前用户登录的 email 或 id，直接从请求头读取即可，如 request.headers.user_email 。'
  },
  fields = {
    use_watermark = { type = 'boolean', default = false },
    use_cookie = { type = 'boolean', default = false },
    basic = {
      type = 'table',
      schema = {
        fields = {
          app_secret = { type = 'string', required = true },
          app_id = { type = 'string', required = true },
          callback_url = { type = 'url', required = true, func = validate_url, default = 'https://yourdomain/oauth/callback' },
          authorize_url = { type = 'url', required = true, func = validate_url, default = 'https://github.com/login/oauth/authorize' },
          token_url = { type = 'url', required = true, func = validate_url, default = 'https://github.com/login/oauth/access_token' },
          user_url  = { type = 'url', required = true, func = validate_url, default = 'https://api.github.com/user' },
          logout_url = { type = 'url', required = true, func = validate_url, default = 'https://github.com/logout' }
        }
      }
    },
    store = {
      type = 'table',
      schema = {
        fields = {
          user_id_name = { type = 'string', default = 'user_id', required = true },
          user_email_name = { type = 'string', default = 'user_email', required = true }
        }
      }
    },
    acl = {
      type = 'table',
      schema = {
        fields = {
          email_blacklist = { type = "array" },
          email_whitelist = { type = "array" }
        }
      }
    },
    login_path = { type = 'string' },
    logout_path = { type = 'string', default = '/sign_out' }
  },
  self_check = function(schema, plugin_t, dao, is_updating)
    -- perform any custom verification
    return true
  end
}