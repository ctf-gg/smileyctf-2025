local module = {}
module.__index = module

setmetatable(module, {
    __call = function(self, ...)
        return self.print(...)
    end
})

local cowsay_template = [[
 %s
< %s >
 %s

        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
]]

function module.print(text)
    print(module.format(text))
end

function module.format(text)
    text = tostring(text)
    -- limit to 40 characters
    -- validate utf8
    local len = utf8.len(text)
    if len == nil then
        return nil
    end

    if len > 40 then
        local offset = utf8.offset(text, 41)
        text = string.sub(text, 1, offset - 1) .. "..."
        len = 43
    end

    local top = string.rep("_", len + 2)
    local bottom = string.rep("-", len + 2)

    return cowsay_template:format(top, text, bottom)
end

return module
