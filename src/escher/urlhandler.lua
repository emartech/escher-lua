-- Escher URL Handler library
-- based on neturl.lua (Bertrand Mansion, 2011-2013; License MIT)
--
-- @module urlhandler
-- @alias M

local M = {}

local function decode(str)
	local str = str:gsub('+', ' ')
	return (str:gsub("%%(%x%x)", function(c)
			return string.char(tonumber(c, 16))
	end))
end

local function encode(str)
	return (str:gsub("([^A-Za-z0-9%_%.%-%~])", function(v)
			return string.upper(string.format("%%%02x", string.byte(v)))
	end))
end

function M.parse(url)
	local comp = {}
	M.setQuery(comp, "")

	local url = tostring(url or '')
	url = url:gsub('%?(.*)', function(v)
		M.setQuery(comp, v)
		return ''
	end)
	comp.path = url

	setmetatable(comp, {
		__index = M,
		__tostring = M.build}
	)
	return comp
end

function M.buildQuery(tab)
  query = {}
  for _, q in ipairs(tab) do
    name = encode(q[1])
    value = encode(q[2])
		table.insert(query, string.format('%s=%s', name, value))
  end
  table.sort(query)
  return table.concat(query, "&")
end

function M.parseQuery(str)
	local values = {}
  for m in str:gmatch("[^&]+") do
    key, val = m:match("([^=]+)=?(.*)")
		local key = decode(key)
		key = key:gsub('=+.*$', "")
    val = val or ''
		val = val:gsub('^=+', "")
		table.insert(values, { key, decode(val) })
	end
	setmetatable(values, { __tostring = M.buildQuery })
	return values
end

function M:setQuery(query)
	self.queryParts = M.parseQuery(query)
  self.query = M.buildQuery(self.queryParts)
	return query
end

local function absolutePath(path)
	path = path:gsub("([^/]*%./)", function (s)
		if s ~= "./" then return s else return "" end
	end)

	local reduced
	while reduced ~= path do
		reduced = path
		path = string.gsub(reduced, "([^/]*/%.%./)", function (s)
			if s ~= "../../" then return "" else return s end
		end)
	end
	path = string.gsub(path, "([^/]*/%.%.?)$", function (s)
		if s ~= "../.." then return "" else return s end
	end)

	local reduced
	while reduced ~= path do
		reduced = path
		path = string.gsub(reduced, '^/?%.%./', '')
	end
	return '/' .. path
end

function M:normalize()
	self.path = absolutePath(self.path)
	self.path = string.gsub(self.path, "//+", "/")
	return self
end

return M
