local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

-- load the base plugin object and create a subclass
local plugin = require("kong.plugins.base_plugin"):extend()
local utils = require('kong.tools.utils')
local cjson = require "cjson"
local http = require "resty.http"
local Session = require "resty.session"
local water_mark = require "kong.plugins.oauth.watermark"

function is_html_body(content_type)
  return content_type and string.find(string.lower(content_type), "text/html", nil, true)
end

-- constructor
function plugin:new()
  plugin.super.new(self, plugin_name)
end

---[[ runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)
  plugin.super.access(self)

  local httpc = http.new()  
  local m, error = ngx.re.match(plugin_conf.basic.callback_url, "^(https?://[^/]+)(/[^?#]+)")
  local domain, redirect_path = m[1], m[2]
  
  if plugin_conf.logout_path and plugin_conf.basic.logout_url and ngx.var.uri == plugin_conf.logout_path then
    local session = Session.start()
    session:destroy()
    if (plugin_conf.use_cookie) then
      local cookie_id = store.user_id_name .. '=; path=/;'
      local cookie_email = store.user_email_name .. '=; path=/;'
      ngx.header['Set-Cookie'] = { cookie_id, cookie_email }
    end
    return ngx.redirect(plugin_conf.basic.logout_url .. '?referrer=' .. (ngx.var.http_referer or (domain .. ngx.var.cookie_kong_oauth_entry) or domain))
  elseif ngx.var.uri == redirect_path and ngx.var.arg_code then
    local res, err = httpc:request_uri(plugin_conf.basic.token_url, {
      method = "POST",
      body = "client_id=" .. plugin_conf.basic.app_id .. "&client_secret=" .. plugin_conf.basic.app_secret .. "&grant_type=authorization_code&code=" .. ngx.var.arg_code .. "&redirect_uri=" .. plugin_conf.basic.callback_url,
      headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["Accept"] = "application/json"
      },
      ssl_verify = false,
      keepalive_timeout = 60,
      keepalive_pool = 10
    })

    if not res then
      ngx.say("failed to request: ", err)
      return
    end
    local data = cjson.decode(res.body)
      if data.access_token then
        local res, err = httpc:request_uri(plugin_conf.basic.user_url, {
        method = "GET",
        headers = {
          ["Authorization"] = "Bearer " .. data.access_token,
          ["Accept"] = "application/json"
        },
        ssl_verify = false,
        keepalive_timeout = 60,
        keepalive_pool = 10
      })

      if not res then
        ngx.say("failed to request: ", err)
        return
      end
      local profile = cjson.decode(res.body)
      local session = Session.start()

      session.data.id = profile.id
      session.data.email = profile.email
      session:save()
    end
    return ngx.redirect(ngx.var.cookie_kong_oauth_entry or '/')
  else
    local basic, acl, store, use_cookie = plugin_conf.basic, plugin_conf.acl, plugin_conf.store, plugin_conf.use_cookie
    local session = Session.open()

    if session.data and session.data.email then
      if (acl and (
          (acl.email_blacklist and next(acl.email_blacklist) and utils.table_contains(acl.email_blacklist, session.data.email))
          or (acl.email_whitelist and next(acl.email_whitelist) and not utils.table_contains(acl.email_whitelist, session.data.email))
      )) then
        return ngx.exit(403)
      end
      ngx.req.set_header(store.user_id_name, session.data.id)
      ngx.req.set_header(store.user_email_name, session.data.email)

      if (use_cookie) then
        ngx.log(ngx.ERR, "id ", session.data.id, " ", store.user_id_name)
        local cookie_id = store.user_id_name .. '=' .. session.data.id .. '; path=/;'
        local cookie_email = store.user_email_name .. '=' .. session.data.email .. '; path=/;'
        ngx.header['Set-Cookie'] = { cookie_id, cookie_email }
      end
    elseif not login_path or ngx.var.request_uri == login_path then
      ngx.header['Set-Cookie'] = 'kong_oauth_entry=' .. ngx.var.request_uri .. '; path=/; max-age=300; httpOnly=true;'
      return ngx.redirect(basic.authorize_url .. '?client_id=' .. basic.app_id .. '&response_type=code&state=&redirect_uri=' .. basic.callback_url)
    end
  end
end --]]

function plugin:header_filter(conf)
  plugin.super.header_filter(self)
  if conf.use_watermark and is_html_body(ngx.header['content-type']) then
    ngx.ctx.can_add_watermark = 1
  end
  ngx.header['content-length'] = nil
end

function plugin:body_filter(conf)
  plugin.super.body_filter(self)
  if not ngx.ctx.can_add_watermark then return end

  local eof = ngx.arg[2]
  if eof then
    local session = Session.open()
    if session.data and session.data.email then
      ngx.arg[1] = ngx.arg[1] .. water_mark.make_mask(session.data.email)
    end
  end
end

-- set the plugin priority, which determines plugin execution order
plugin.PRIORITY = 1000

-- return our plugin object
return plugin
