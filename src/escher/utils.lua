
local function split(str, separator)
  local pieces = {}
  local i = 1

  for matched in string.gmatch(str, "([^" .. separator .. "]+)") do
    pieces[i] = matched
    i = i + 1
  end

  return pieces
end

local function merge(target, ...)
  if not target then return target end

  for _, obj in pairs({...}) do
    if obj then
      for k, v in pairs(obj) do
        target[k] = v
      end
    end
  end

  return target
end

local function contains(table, element)
  for _, value in pairs(table) do
    if value:lower() == element:lower() then
      return true
    end
  end

  return false
end

local function trim(str)
  return string.match(str, "^%s*(.-)%s*$")
end

local function toLongDate(date)
  return date:fmt("%Y%m%dT%H%M%SZ")
end

local function toShortDate(date)
  return date:fmt("%Y%m%d")
end

return {
  split = split,
  merge = merge,
  contains = contains,
  trim = trim,
  toLongDate = toLongDate,
  toShortDate = toShortDate
}
