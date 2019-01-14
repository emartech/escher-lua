
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

return {
  contains = contains,
  trim = trim
}
