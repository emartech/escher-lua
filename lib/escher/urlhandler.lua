-- Escher URL Handler library
-- based on neturl.lua (Bertrand Mansion, 2011-2013; License MIT)
--
-- @module urlhandler
-- @alias M

local M = {}

local legal = {
	["-"] = true, ["_"] = true, ["."] = true, ["!"] = true,
	["~"] = true, ["*"] = true, ["'"] = true, ["("] = true,
	[")"] = true, [":"] = true, ["@"] = true, ["&"] = true,
	["="] = true, ["+"] = true, ["$"] = true, [","] = true,
	[";"] = true
}

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

local function encodeValue(str)
	local str = encode(str)
	return str:gsub('%%20', '+')
end

local function encodeSegment(s)
	local legalEncode = function(c)
		if legal[c] then
			return c
		end
		return encode(c)
	end
	return s:gsub('([^a-zA-Z0-9])', legalEncode)
end

function M.buildQuery(tab)
  table.sort(tab, function(a,b) return a[1]<b[1] end)
  query = {}
  for _, q in ipairs(tab) do
    name = encodeValue(q[1])
    value = encodeValue(q[2])
    if value ~= "" then
			query[#query+1] = string.format('%s=%s', name, value)
		else
			query[#query+1] = name
		end
  end
  return table.concat(query, "&")
end

function M.parseQuery(str)
	local values = {}
	for key,val in str:gmatch(string.format('([^%q=]+)(=*[^%q=]*)', '&', '&')) do
		local key = decode(key)
		key = key:gsub('=+.*$', "")
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

local function absolutePath(base_path, relative_path)
	if string.sub(relative_path, 1, 1) == "/" then
		return '/' .. string.gsub(relative_path, '^[%./]+', '')
	end
	local path = base_path
	if relative_path ~= "" then
		path = '/'..path:gsub("[^/]*$", "")
	end
	path = path .. relative_path
	path = path:gsub("([^/]*%./)", function (s)
		if s ~= "./" then return s else return "" end
	end)
	path = string.gsub(path, "/%.$", "/")
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

--- normalize a url path following some common normalization rules
-- described on <a href="http://en.wikipedia.org/wiki/URL_normalization">The URL normalization page of Wikipedia</a>
-- @return the normalized path
function M:normalize()
	self.path = absolutePath(self.path, "")
	self.path = string.gsub(self.path, "//+", "/")
	return self
end

return M
