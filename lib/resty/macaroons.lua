local ffi          = require "ffi"
local ffi_cdef     = ffi.cdef
local ffi_load     = ffi.load
local ffi_gc       = ffi.gc
local ffi_new      = ffi.new
local ffi_str      = ffi.string
local ffi_typeof   = ffi.typeof
local setmetatable = setmetatable

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
// TODO: implement binding: struct macaroon* macaroon_prepare_for_request(const struct macaroon* M, const struct macaroon* D, enum macaroon_returncode* err);
struct macaroon_verifier* macaroon_verifier_create();
                     void macaroon_verifier_destroy(struct macaroon_verifier* V);
                      int macaroon_verifier_satisfy_exact(struct macaroon_verifier* V, const unsigned char* predicate, size_t predicate_sz, enum macaroon_returncode* err);
// TODO: implement binding: int macaroon_verifier_satisfy_general(struct macaroon_verifier* V, int (*general_check)(void* f, const unsigned char* pred, size_t pred_sz), void* f, enum macaroon_returncode* err);
                      int macaroon_verify(const struct macaroon_verifier* V, const struct macaroon* M, const unsigned char* key, size_t key_sz, struct macaroon** MS, size_t MS_sz, enum macaroon_returncode* err);
                     void macaroon_location(const struct macaroon* M, const unsigned char** location, size_t* location_sz);
                     void macaroon_identifier(const struct macaroon* M, const unsigned char** identifier, size_t* identifier_sz);
                     void macaroon_signature(const struct macaroon* M, const unsigned char** signature, size_t* signature_sz);
                   size_t macaroon_serialize_size_hint(const struct macaroon* M);
                      int macaroon_serialize(const struct macaroon* M, char* data, size_t data_sz, enum macaroon_returncode* err);
         struct macaroon* macaroon_deserialize(const char* data, enum macaroon_returncode* err);
                   size_t macaroon_inspect_size_hint(const struct macaroon* M);
                      int macaroon_inspect(const struct macaroon* M, char* data, size_t data_sz, enum macaroon_returncode* err);
// TODO: implement binding: struct macaroon* macaroon_copy(const struct macaroon* M, enum macaroon_returncode* err);
// TODO: implement binding: int macaroon_cmp(const struct macaroon* M, const struct macaroon* N);
]]

local lib = ffi_load "macaroons"

local rc = ffi_new "enum macaroon_returncode[1]"
local cp = ffi_new "const unsigned char*[1]"
local ip = ffi_new "const unsigned char*[1]"
local sz = ffi_new "size_t[1]"
local iz = ffi_new "size_t[1]"
local char_t = ffi_typeof "char[?]"

local verifier = {}

verifier.__index = verifier

-- TODO: optional arguments not implemented
function verifier:verify(macaroon, key)
    if lib.macaroon_verify(self.context, macaroon.context, key, #key, nil, 0, rc) ~= 0 then
        return nil, "TODO: error message"
    end
    if rc[0] ~= 0 and rc[0] ~= lib.MACAROON_SUCCESS then
        return nil, "TODO: error message"
    end
    return true
end

function verifier:satisfy_exact(predicate)
    if lib.macaroon_verifier_satisfy_exact(self.context, predicate, #predicate, rc) ~= 0 then
        return nil, "TODO: error message"
    end
    if rc[0] ~= 0 and rc[0] ~= lib.MACAROON_SUCCESS then
        return nil, "TODO: error message"
    end
    return self
end

local macaroons = {}

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
                if lib.macaroon_third_party_caveat(self.context, i, cp, sz, ip, iz) ~= 0 then
                    return nil, "TODO: error message"
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
    local context = ffi_gc(lib.macaroon_create(location, #location, key, #key, id, #id, rc), lib.macaroon_destroy)
    if rc[0] ~= 0 and rc[0] ~= lib.MACAROON_SUCCESS then
        return nil, "TODO: error message"
    end
    return setmetatable({ context = context }, macaroons)
end

function macaroons.deserialize(data)
    local context = ffi_gc(lib.macaroon_deserialize(data, rc), lib.macaroon_destroy)
    if rc[0] ~= lib.MACAROON_SUCCESS then
        return nil, "TODO: error message"
    end
    return setmetatable({ context = context }, macaroons)
end

function macaroons.verifier()
    return setmetatable({ context = ffi_gc(lib.macaroon_verifier_create(), lib.macaroon_verifier_destroy) }, verifier)
end

function macaroons:serialize()
    local n = lib.macaroon_serialize_size_hint(self.context)
    local b = ffi_new(char_t, n)
    local s = lib.macaroon_serialize(self.context, b, n, rc)
    -- TODO: check return code s
    return ffi_str(b)
end

function macaroons:inspect()
    local n = lib.macaroon_inspect_size_hint(self.context)
    local b = ffi_new(char_t, n)
    local s = lib.macaroon_inspect(self.context, b, n, rc)
    -- TODO: check return code s
    return ffi_str(b)
end

function macaroons:add_first_party_caveat(predicate)
    -- TODO: error checking
    return setmetatable({ context = ffi_gc(lib.macaroon_add_first_party_caveat(self.context, predicate, #predicate, rc), lib.macaroon_verifier_destroy) }, macaroons)
end

function macaroons:add_third_party_caveat(location, key, id)
    -- TODO: error checking
    return setmetatable({ context = ffi_gc(lib.macaroon_add_third_party_caveat(self.context, location, #location, key, #key, id, #id, rc), lib.macaroon_verifier_destroy) }, macaroons)

end

function macaroons:validate()
    return lib.macaroon_validate(self.context) == 0
end

return macaroons