local ffi          = require "ffi"
local ffi_cdef     = ffi.cdef
local ffi_load     = ffi.load
local ffi_gc       = ffi.gc
local ffi_new      = ffi.new
local ffi_str      = ffi.string
local ffi_typeof   = ffi.typeof
local ffi_cast     = ffi.cast
local C            = ffi.C
local select       = select
local setmetatable = setmetatable
local tonumber     = tonumber

ffi_cdef[[
struct macaroon;
struct macaroon_verifier;
enum macaroon_returncode {
    MACAROON_SUCCESS          = 2048,
    MACAROON_OUT_OF_MEMORY    = 2049,
    MACAROON_HASH_FAILED      = 2050,
    MACAROON_INVALID          = 2051,
    MACAROON_TOO_MANY_CAVEATS = 2052,
    MACAROON_CYCLE            = 2053,
    MACAROON_BUF_TOO_SMALL    = 2054,
    MACAROON_NOT_AUTHORIZED   = 2055,
    MACAROON_NO_JSON_SUPPORT  = 2056
};
         struct macaroon* macaroon_create(const unsigned char* location, size_t location_sz, const unsigned char* key, size_t key_sz, const unsigned char* id, size_t id_sz, enum macaroon_returncode* err);
                     void macaroon_destroy(struct macaroon* M);
                      int macaroon_validate(const struct macaroon* M);
         struct macaroon* macaroon_add_first_party_caveat(const struct macaroon* M, const unsigned char* predicate, size_t predicate_sz, enum macaroon_returncode* err);
         struct macaroon* macaroon_add_third_party_caveat(const struct macaroon* M, const unsigned char* location, size_t location_sz, const unsigned char* key, size_t key_sz, const unsigned char* id, size_t id_sz, enum macaroon_returncode* err);
                 unsigned macaroon_num_third_party_caveats(const struct macaroon* M);
                      int macaroon_third_party_caveat(const struct macaroon* M, unsigned which, const unsigned char** location, size_t* location_sz, const unsigned char** identifier, size_t* identifier_sz);
         struct macaroon* macaroon_prepare_for_request(const struct macaroon* M, const struct macaroon* D, enum macaroon_returncode* err);
struct macaroon_verifier* macaroon_verifier_create();
                     void macaroon_verifier_destroy(struct macaroon_verifier* V);
                      int macaroon_verifier_satisfy_exact(struct macaroon_verifier* V, const unsigned char* predicate, size_t predicate_sz, enum macaroon_returncode* err);
                      int macaroon_verifier_satisfy_general(struct macaroon_verifier* V, int (*general_check)(void* f, const unsigned char* pred, size_t pred_sz), void* f, enum macaroon_returncode* err);
                      int macaroon_verify(const struct macaroon_verifier* V, const struct macaroon* M, const unsigned char* key, size_t key_sz, struct macaroon** MS, size_t MS_sz, enum macaroon_returncode* err);
                     void macaroon_location(const struct macaroon* M, const unsigned char** location, size_t* location_sz);
                     void macaroon_identifier(const struct macaroon* M, const unsigned char** identifier, size_t* identifier_sz);
                     void macaroon_signature(const struct macaroon* M, const unsigned char** signature, size_t* signature_sz);
                   size_t macaroon_serialize_size_hint(const struct macaroon* M);
                      int macaroon_serialize(const struct macaroon* M, char* data, size_t data_sz, enum macaroon_returncode* err);
         struct macaroon* macaroon_deserialize(const char* data, enum macaroon_returncode* err);
                   size_t macaroon_inspect_size_hint(const struct macaroon* M);
                      int macaroon_inspect(const struct macaroon* M, char* data, size_t data_sz, enum macaroon_returncode* err);
         struct macaroon* macaroon_copy(const struct macaroon* M, enum macaroon_returncode* err);
                      int macaroon_cmp(const struct macaroon* M, const struct macaroon* N);
           typedef void * macaroon_callback;
]]

local lib = ffi_load "macaroons"
local rc = ffi_new "enum macaroon_returncode[1]"
local cp = ffi_new "const unsigned char*[1]"
local ip = ffi_new "const unsigned char*[1]"
local sz = ffi_new "size_t[1]"
local iz = ffi_new "size_t[1]"
local cb = ffi_typeof "int (*)(const unsigned char*, size_t pred_sz)"
local mcrn_t = ffi_typeof "struct macaroon*[?]"
local char_t = ffi_typeof "char[?]"
local errors = {}
errors[lib.MACAROON_OUT_OF_MEMORY]    = "Out of memory"
errors[lib.MACAROON_HASH_FAILED]      = "Hash failed"
errors[lib.MACAROON_INVALID]          = "Invalid"
errors[lib.MACAROON_TOO_MANY_CAVEATS] = "Too many caveats"
errors[lib.MACAROON_CYCLE]            = "Cycle"
errors[lib.MACAROON_BUF_TOO_SMALL]    = "Buffer too small"
errors[lib.MACAROON_NOT_AUTHORIZED]   = "Not authorized"
errors[lib.MACAROON_NO_JSON_SUPPORT]  = "No JSON support"

local function general_check(f, pred, pred_sz)
    if ffi_cast(cb, f)(pred, pred_sz) == 0 then
        return -1
    end
    return 0
end

local verifier = {}
verifier.__index = verifier

function verifier:verify(macaroon, key, ...)
    local n = select("#", ...)
    if n == 0 then
        local s = lib.macaroon_verify(self.context, macaroon.context, key, #key, nil, 0, rc)
        local r = tonumber(rc[0])
        rc[0] = lib.MACAROON_SUCCESS
        if s ~= 0 then
            if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
                return nil, errors[r] or "Verify failed"
            else
                return nil, "Verify failed"
            end
        end
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or r
        end
    else
        local ms = ffi_new(mcrn_t, n)
        for i=1, n do
            ms[i-1] = select(i, ...).context
        end
        local s = lib.macaroon_verify(self.context, macaroon.context, key, #key, ms, n, rc)
        local r = tonumber(rc[0])
        rc[0] = lib.MACAROON_SUCCESS
        if s ~= 0 then
            if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
                return nil, errors[r] or "Verify failed"
            else
                return nil, "Verify failed"
            end
        end
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or r
        end
    end
    return true
end

function verifier:satisfy_exact(predicate)
    local s = lib.macaroon_verifier_satisfy_exact(self.context, predicate, #predicate, rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if s ~= 0 then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Verifier unsatisfied error"
        else
            return nil, "Verifier unsatisfied error"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return self
end

function verifier:satisfy_general(func)
    local s = lib.macaroon_verifier_satisfy_general(self.context, general_check, ffi_cast(cb, func), rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if s ~= 0 then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Verifier unsatisfied error"
        else
            return nil, "Verifier unsatisfied error"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return self
end

local macaroons = {}

function macaroons:__eq(macaroon)
    return lib.macaroon_cmp(self.context, macaroon.context) == 0
end

function macaroons:__index(k)
    if k == "location" then
        lib.macaroon_location(self.context, cp, sz)
        return ffi_str(cp[0], sz[0])
    elseif k == "identifier" then
        lib.macaroon_identifier(self.context, cp, sz)
        return ffi_str(cp[0], sz[0])
    elseif k == "signature" then
        lib.macaroon_signature(self.context, cp, sz)
        return ffi_str(cp[0], sz[0])
    elseif k == "third_party_caveats" then
        local n = lib.macaroon_num_third_party_caveats(self.context)
        local t = {}
        if n > 0 then
            for i = 0, n - 1 do
                local s = lib.macaroon_third_party_caveat(self.context, i, cp, sz, ip, iz)
                if s ~= 0 then
                    return nil, errors[s] or s
                end
                t[i+1] = { location = ffi_str(cp[0], sz[0]), id = ffi_str(ip[0], iz[0]) }
            end
        end
        return t
    else
        return macaroons[k]
    end
end

function macaroons.create(location, key, id)
    local context = lib.macaroon_create(location, #location, key, #key, id, #id, rc)
    local r = tonumber(rc[0])
    rc[0] = 0
    if context == nil then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Unable to create macaroon"
        else
            return nil, "Unable to create macaroon"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return setmetatable({ context = ffi_gc(context, lib.macaroon_destroy) }, macaroons)
end

function macaroons.deserialize(data)
    local context = lib.macaroon_deserialize(data, rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if context == nil then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Deserialize failed"
        else
            return nil, "Deserialize failed"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return setmetatable({ context = ffi_gc(context, lib.macaroon_destroy) }, macaroons)
end

function macaroons.verifier()
    local context = lib.macaroon_verifier_create()
    if context == nil then
        return nil, "Unable to create verifier"
    end
    return setmetatable({ context = ffi_gc(context, lib.macaroon_verifier_destroy) }, verifier)
end

function macaroons:serialize()
    local n = lib.macaroon_serialize_size_hint(self.context)
    local b = ffi_new(char_t, n)
    local s = lib.macaroon_serialize(self.context, b, n, rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if s ~= 0 then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Serialize failed"
        else
            return nil, "Serialize failed"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return ffi_str(b)
end

function macaroons:inspect()
    local n = lib.macaroon_inspect_size_hint(self.context)
    local b = ffi_new(char_t, n)
    local s = lib.macaroon_inspect(self.context, b, n, rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if s ~= 0 then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Inspect failed"
        else
            return nil, "Inspect failed"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return ffi_str(b)
end

function macaroons:add_first_party_caveat(predicate)
    local context = lib.macaroon_add_first_party_caveat(self.context, predicate, #predicate, rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if context == nil then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Unable to add first party caveat"
        else
            return nil, "Unable to add first party caveat"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return setmetatable({ context = ffi_gc(context, lib.macaroon_destroy) }, macaroons)
end

function macaroons:add_third_party_caveat(location, key, id)
    local context = lib.macaroon_add_third_party_caveat(self.context, location, #location, key, #key, id, #id, rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if context == nil then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Unable to add third party caveat"
        else
            return nil, "Unable to add third party caveat"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return setmetatable({ context = ffi_gc(context, lib.macaroon_destroy) }, macaroons)
end

function macaroons:prepare_for_request(d)
    local context = lib.macaroon_prepare_for_request(self.context, d.context, rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if context == nil then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Unable to prepare for request"
        else
            return nil, "Unable to prepare for request"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return setmetatable({ context = ffi_gc(context, lib.macaroon_destroy) }, macaroons)
end

function macaroons:copy()
    local context = lib.macaroon_copy(self.context, rc)
    local r = tonumber(rc[0])
    rc[0] = lib.MACAROON_SUCCESS
    if context == nil then
        if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
            return nil, errors[r] or "Unable to copy macaroon"
        else
            return nil, "Unable to copy macaroon"
        end
    end
    if r ~= 0 and r ~= lib.MACAROON_SUCCESS then
        return nil, errors[r] or r
    end
    return setmetatable({ context = ffi_gc(context, lib.macaroon_destroy) }, macaroons)
end

function macaroons:validate()
    return lib.macaroon_validate(self.context) == 0
end

return macaroons