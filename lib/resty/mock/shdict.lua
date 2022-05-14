local bit = require "bit"
local table_nkeys = require "table.nkeys"
local DICT = {}
---@class MOCK.ngx.shared.DICT.Node
---@field data any
---@field expires integer
---@field user_flags integer


local function check_self(self)
    if type(self.nodes) ~= 'table' then
        error("bad \"zone\" argument", 3)
    end
end
local function check_key(key)
    if key == nil then
        return false, "nil key"
    end

    if type(key) ~= "string" then
        key = tostring(key)
    end

    local key_len = #key
    if key_len == 0 then
        return false, "empty key"
    end
    if key_len > 65535 then
        return false, "key too long"
    end
    return true
end

local function new_node(data, expires, user_flags)
    return {
        data = data,
        expires = expires == 0 and 0 or expires + ngx.now(),
        user_flags = user_flags,
    }
end

local function raw_set(self, key, node)
    self.nodes[key] = node
end

---@return MOCK.ngx.shared.DICT.Node
local function raw_get(self, key)
    local node = self.nodes[key]
    if not node then
        return nil
    end
    return node
end

local function is_expires(expires, now)
    return expires ~= 0 and expires <= now
end

local function clean_expires(self)
    local result = false
    local now = ngx.now()
    for key, value in pairs(self.nodes) do
        if is_expires(value.expires, now) then
            self.nodes[key] = nil
            result = true
        end
    end
    return result
end

local function shdict_store(self, op, key, value, exptime, flags)
    check_self(self)

    if not exptime then
        exptime = 0
    elseif exptime < 0 then
        error('bad "exptime" argument', 2)
    end

    if not flags then
        flags = 0
    end

    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end
    local valtyp = type(value)

    if (valtyp ~= "string" and valtyp ~= "number" and value ~= nil and valtyp ~= "boolean") then
        return nil, "bad value type"
    end

    clean_expires(self)
    local node = raw_get(self, key)
    if bit.band(op, 0x0002) ~= 0 and not node then
        return false, "not found", false
    end
    if bit.band(op, 0x0001) ~= 0 and node then
        return false, "exists", false
    end
    if value ~= nil then
        node = new_node(value, exptime, flags)
        raw_set(self, key, node)
    else
        self.nodes[key] = nil
    end

    return true, nil, false
end

local function shdict_get(self, key)
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end

    return raw_get(self, key)
end

---@param key string
---@return any?
---@return ngx.shared.DICT.flags?|string? flags_or_error
function DICT:get(key)
    check_self(self)
    clean_expires(self)
    local node, err = shdict_get(self, key)
    if not node then
        return nil, err
    end
    if node.user_flags ~= 0 then
        return node.data, node.user_flags
    end
    return node.data
end

---@param  key              string
---@return any?             value
---@return ngx.shared.DICT.flags|string flags_or_error
---@return boolean          stale
function DICT:get_stale(key)
    check_self(self)
    local node
    node, err = shdict_get(self, key)
    if not node then
        return nil, err
    end
    local is_stale = is_expires(node.expires, ngx.now())
    if node.user_flags ~= 0 then
        return node.data, node.user_flags, is_stale
    end
    return node.data, nil, is_stale
end

---@param  key      string
---@param  value    any
---@param  exptime? ngx.shared.DICT.exptime
---@param  flags?   ngx.shared.DICT.flags
---@return boolean  ok       # whether the key-value pair is stored or not
---@return ngx.shared.DICT.error? error
---@return boolean  forcible # indicates whether other valid items have been removed forcibly when out of storage in the shared memory zone.
function DICT:set(key, value, exptime, flags)
    return shdict_store(self, 0, key, value, exptime, flags)
end

---@param  key      string
---@param  value    any
---@param  exptime? ngx.shared.DICT.exptime
---@param  flags?   ngx.shared.DICT.flags
---@return boolean  ok       # whether the key-value pair is stored or not
---@return ngx.shared.DICT.error? error
---@return boolean  forcible # indicates whether other valid items have been removed forcibly when out of storage in the shared memory zone.
function DICT:safe_set(key, value, exptime, flags)
    return shdict_store(self, 0x0004, key, value, exptime, flags)
end

---@param  key      string
---@param  value    any
---@param  exptime? ngx.shared.DICT.exptime
---@param  flags?   ngx.shared.DICT.flags
---@return boolean  ok       # whether the key-value pair is stored or not
---@return ngx.shared.DICT.error? error
---@return boolean  forcible # indicates whether other valid items have been removed forcibly when out of storage in the shared memory zone.
function DICT:add(key, value, exptime, flags)
    return shdict_store(self, 0x0001, key, value, exptime, flags)
end

---@param  key      string
---@param  value    any
---@param  exptime? ngx.shared.DICT.exptime
---@param  flags?   ngx.shared.DICT.flags
---@return boolean  ok       # whether the key-value pair is stored or not
---@return ngx.shared.DICT.error? error
---@return boolean  forcible # indicates whether other valid items have been removed forcibly when out of storage in the shared memory zone.
function DICT:safe_add(key, value, exptime, flags)
    return shdict_store(self, 0x0005, key, value, exptime, flags)
end

---@param  key      string
---@param  value    any
---@param  exptime? ngx.shared.DICT.exptime
---@param  flags?   ngx.shared.DICT.flags
---@return boolean  ok       # whether the key-value pair is stored or not
---@return ngx.shared.DICT.error? error
---@return boolean  forcible # indicates whether other valid items have been removed forcibly when out of storage in the shared memory zone.
function DICT:replace(key, value, exptime, flags)
    return shdict_store(self, 0x0002, key, value, exptime, flags)
end

local function shdict_set(zone, key, value, exptime, flags)
    return shdict_store(zone, 0, key, value, exptime, flags)
end

---@param key string
function DICT:delete(key)
    return shdict_set(self, key, nil)
end

---@param  key      string
---@param  value    number
---@param  init     number
---@param  init_ttl ngx.shared.DICT.exptime
---@return integer? new
---@return ngx.shared.DICT.error? error
---@return boolean  forcible
function DICT:incr(key, value, init, init_ttl)
    check_self(self)
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end

    if type(value) ~= "number" then
        value = tonumber(value)
        if not value then
            error([[cannot convert 'nil' to 'double']])
        end
    end

    if init then
        local typ = type(init)
        if typ ~= "number" then
            init = tonumber(init)

            if not init then
                error("bad init arg: number expected, got " .. typ, 2)
            end
        end
    end

    if init_ttl ~= nil then
        local typ = type(init_ttl)
        if typ ~= "number" then
            init_ttl = tonumber(init_ttl)

            if not init_ttl then
                error("bad init_ttl arg: number expected, got " .. typ, 2)
            end
        end

        if init_ttl < 0 then
            error('bad "init_ttl" argument', 2)
        end

        if not init then
            error('must provide "init" when providing "init_ttl"', 2)
        end

    else
        init_ttl = 0
    end
    clean_expires(self)
    local node = raw_get(self, key)
    if not node then
        if init then
            node = new_node(value + init, init_ttl, 0)
            raw_set(self, key, node)
            return node.data, nil, false
        else
            return nil, "not found"
        end
    end
    node.data = node.data + value
    return node.data
end

---@param  key     string
---@param  value   any
---@return number? len    # number of elements in the list after the push operation
---@return ngx.shared.DICT.error? error
function DICT:lpush(key, value)
    check_self(self)
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end
    local valuetype = type(value)
    if valuetype ~= "number" or valuetype ~= "string" then
        return nil, "bad value type"
    end
    clean_expires(self)
    local node = raw_get(self, key)
    if node then
        if type(node.data) ~= 'table' or is_expires(node.expires, ngx.now()) then
            node = nil
        end
    end
    if not node then
        node = new_node({}, 0, 0)
        raw_set(self, key, node)
    end
    table.insert(node.data, 1, value)
    return #node.data
end

---@param  key     string
---@param  value   any
---@return number? len    # number of elements in the list after the push operation
---@return ngx.shared.DICT.error? error
function DICT:rpush(key, value)
    check_self(self)
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end
    local valuetype = type(value)
    if valuetype ~= "number" or valuetype ~= "string" then
        return nil, "bad value type"
    end
    clean_expires(self)
    local node = raw_get(self, key)
    if node then
        if type(node.data) ~= 'table' or is_expires(node.expires, ngx.now()) then
            node = nil
        end
    end
    if not node then
        node = new_node({}, 0, 0)
        raw_set(self, key, node)
    end
    table.insert(node.data, value)
    return #node.data
end

---@param  key     string
---@return any?    value
---@return ngx.shared.DICT.error? error
function DICT:lpop(key)
    check_self(self)
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end
    clean_expires(self)
    local node = raw_get(self, key)
    if not node then
        return nil
    end
    if type(node.data) ~= 'table' then
        return nil, "value not a list"
    end
    if #node.data == 1 then
        self.nodes[key] = nil
    end
    return table.remove(node.data, 1)
end

---@param  key     string
---@return any?    value
---@return ngx.shared.DICT.error? error
function DICT:rpop(key)
    check_self(self)
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end
    clean_expires(self)
    local node = raw_get(self, key)
    if not node then
        return nil
    end
    if type(node.data) ~= 'table' then
        return nil, "value not a list"
    end
    if #node.data == 1 then
        self.nodes[key] = nil
    end
    return table.remove(node.data)
end

---@param key string
---@return number? len
---@return ngx.shared.DICT.error? error
function DICT:llen(key)
    check_self(self)
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end
    clean_expires(self)
    local node = raw_get(self, key)
    if not node then
        return 0
    end
    if type(node.data) ~= "table" then
        return nil, "value not a list"
    end
    return #node.data
end

---@param  key     string
---@return number? ttl
---@return ngx.shared.DICT.error? error
function DICT:ttl(key)
    check_self(self)
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end

    local node = raw_get(self, key)
    if not node then
        return nil, "not found"
    end
    if node.expires == 0 then
        return 0
    end
    return (node.expires - ngx.now())
end

---@param  key     string
---@param  exptime ngx.shared.DICT.exptime
---@return boolean ok
---@return ngx.shared.DICT.error? error
function DICT:expire(key, exptime)
    check_self(self)
    if not exptime then
        error('bad "exptime" argument', 2)
    end
    local ok, err = check_key(key)
    if not ok then
        return nil, err
    end

    local node = raw_get(self, key)
    if not node then
        return nil, "not found"
    end
    if exptime == 0 then
        node.expires = 0
    else
        node.expires = ngx.now() + exptime
    end
    return true
end

function DICT:flush_all()
    self.nodes = {}
end

---@param max_count number
---@return number flushed
function DICT:flush_expired(max_count)
    clean_expires(self)
end

---@param  max_count number
---@return string[]  keys
function DICT:get_keys(max_count)
    clean_expires(self)
    local keys = {}
    local n = 1
    for key, value in pairs(t) do
        keys[n] = key
        n = n + 1
        if n >= max_count then
            break
        end
    end
    return keys
end

---@return number
function DICT:capacity()
    return self.Capacity
end

---@return number
function DICT:free_space()
    return (self.Capacity - table_nkeys(self.nodes)) / 4
end

---@param dict_name string
---@param capacity integer
---@return ngx.shared.DICT
return function(dict_name, capacity)
    capacity = capacity or 0
    ngx.shared[dict_name] = setmetatable({ nodes = {}, Capacity = capacity }, { __index = DICT })
    return ngx.shared[dict_name]
end
