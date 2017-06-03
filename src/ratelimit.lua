local redis = require "resty.redis"
local cjson = require "cjson"
local cache = redis:new()
local proxyredis = redis:new()

local ok, err = cache:connect("ratelimit-test.kn51nf.ng.0001.usw1.cache.amazonaws.com", 6379)
if not ok then
    ngx.log(ngx.CRIT, 'RL:: DANGER!!! Error connecting to redis. Aborting...', err)
    ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end

local ok, err = proxyredis:connect("ratelimit-test.kn51nf.ng.0001.usw1.cache.amazonaws.com", 6379)
if not ok then
    ngx.log(ngx.ERR, 'RL:: Cannot connect to proxyredis from ratelimiting. Continuing...', err)
end


local function process_request(cache, counter_key)
    local trim_ts = ngx.now() - 60000 -- 60 seconds

    -- start multi 
    local ok, err = cache:multi()
    if not ok then
        ngx.log(ngx.ERR, "RL:: Failed to run multi: ", err)
        return nil
    end

    -- use sorted set 
    cache:zremrangebyscore(counter_key, 0, trim_ts)
    cache:zcard(counter_key)
    cache:zadd(counter_key, ngx.now(), ngx.now())
    cache:expire(counter_key, 60)  -- 60 seconds


    local result, err = cache:exec()
    if not result then
        ngx.log(ng.ERR, "RL:: Failed to run multi/exec: ", err)
        return nil
    else
        return result
    end
end

local function eval_request(result, limit)
    if not result or not result[2] then
        ngx.log(ngx.ERR, "RL:: Invalid results from multi/exec: ", err, "- result type ", type(result))
        return -1
    else 
        if tonumber(result[2]) >= tonumber(limit) then
            -- block request
            return 1
        else 
            return 0
        end
    end

    -- should not reach here
    return -2
end

local function send_deny_response()
    ngx.status = ngx.HTTP_TOO_MANY_REQUESTS  
    ngx.say(cjson.encode({ error = "rate limit exceeded" }))  
end

local function map_sub_to_parent_authid(sub_auth_id)
    if string.sub(sub_auth_id, 1, 2) == "SA" then
        local auth_cache_key = string.format("auth:%s", sub_auth_id)
        local parent_auth_id = proxyredis:hget(auth_cache_key, "parent_sid")
        if not parent_auth_id or type(parent_auth_id) ~= "string" then
            ngx.log(ngx.ERR, "RL:: Failed to fetch parent account Id for subaccount auth Id: ", sub_auth_id)
            return sub_auth_id
        end

        return parent_auth_id
    end

    return sub_auth_id
end

local function get_lookup_key(auth_id)
    local uri = ngx.var.request_uri
    local method = ngx.req.get_method()
    auth_id = map_sub_to_parent_authid(auth_id)
    -- check for special params in url
    if uri:find("([Call]+)([status=]+)") then
        -- look at hardcoded keys
        return string.format("rl:%s:%s:/callstatus/", auth_id, method)
    end
    -- discard url after 4 verbs, we can't possibly match all patterns
    local v,v2,orig_auth_id,v3 = uri:match("([^/]+)/([^/]+)/([^/]+)/([^/]+)")
    -- replace orig auth id for lookup key
    local lookup_key = string.format("rl:%s:%s:/%s/%s/%s/%s/",auth_id,method,v,v2, auth_id,v3)
    return lookup_key
end

local headers = ngx.req.get_headers()
local auth = headers.Authorization

local function get_auth_credentials(header)
	local credentials_decoded = ngx.decode_base64(header:match(".%w+%s(%w+.)"))
	return credentials_decoded:match("(.*):(.*)")
end

if auth then
    -- we have an auth header
    local auth_id, auth_token = get_auth_credentials(auth)

    -- get configured limit value for auth Id and URI
    limit_key = get_lookup_key(auth_id)
    limit, err = cache:get(limit_key)
    if not limit or type(limit) == "userdata" then
        ngx.log(ngx.ERR, "RL:: Failed to fetch limit for auth Id/url: ", err)

        -- fetch limit from defaults
        limit_key = get_lookup_key("default")
        limit, err = cache:get(limit_key)
        if not limit or type(limit) == "userdata" then
            ngx.log(ngx.ERR, "RL:: can't fetch ANY default limit for auth Id/url: ", err)
            limit = 10  -- hard code limit to continue
        end
    end

    local counter_key = limit_key .. ":c"
    local result = process_request(cache, counter_key)

    res = eval_request(result, limit)
    if res > 0 then
        ngx.log(ngx.ALERT, "RL:: Rate limit exceeded for ", auth_id, " blocking access to resource ", ngx.var.request_uri)
        send_deny_response()
        return
    elseif res < 0 then
        -- auth id based fiterling fail, fallback to ip based blocking
        ngx.log(ngx.CRIT, "RL:: Auth ID based rateliming failing for request: ", ngx.var.request_uri)
    end
end

-- Fall-thru: we need to use ip based rate limiting
-- fetch ip address rl config 
local ip = ngx.var.remote_addr

-- get configured limit value for ip address
limit, err = cache:get("rl:ip")
if not limit or type(limit) == "userdata" then
    ngx.log(ngx.ERR, "RL:: Failed to fetch limit for ip address: ", err)
    limit = 10  -- hard code limit, just in case
end

local ip_key = "rl:" .. ip  .. ":c"
local result = process_request(cache, ip_key)

res = eval_request(result, limit)
if res > 0 then
    ngx.log(ngx.ALERT, "RL:: Rate limit exceeded for ", ip, " blocking access to resource ", ngx.var.request_uri)
    send_deny_response()
    return
elseif res < 0 then 
    -- even IP based limiting failed
    ngx.log(ngx.CRIT, "RL:: Last resort IP based rateliming failing for request: ", ngx.var.request_uri)
end


