local filesystem = require "filesystem"
local ed25519 = require "ccryptolib.ed25519"
local container = require "container"
local util = require "util"

local chain = {}

---@param cert X509
---@param certList X509[]
---@param roots X509[]
---@return boolean trusted
---@return string|nil reason
local function chain_validate_internal(cert, certList, roots)
    -- Find the issuing certificate
    local parent, isRoot
    for _, v in ipairs(certList) do
        if util.compareNames(v.toBeSigned.subject, cert.toBeSigned.issuer) then parent, isRoot = v, false end
    end
    for _, v in ipairs(roots) do
        if util.compareNames(v.toBeSigned.subject, cert.toBeSigned.issuer) then parent, isRoot = v, true end
    end
    if not parent then return false, "Could not find path to root" end -- No known parent
    -- Verify the signature of the certificate
    local der = container.encodeX509InnerCertificate(cert)
    if parent.toBeSigned.subjectPublicKeyInfo.algorithm.type.string ~= container.signatureAlgorithmOIDs.ED25519 then
        return false, "Certificate has unsupported signature type"
    end
    if not ed25519.verify(parent.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data, der, cert.signature.data) then
        return false, "Could not verify signature of certificate"
    end
    -- If this is a root certificate, we made it
    if isRoot then return true end
    -- Otherwise, make sure this isn't self-signed so we don't end up in an infinite loop
    if util.compareNames(cert.toBeSigned.subject, cert.toBeSigned.issuer) then return false, "Chain certificate is self-signed" end
    -- Continue validating with the parent
    return chain_validate_internal(parent, certList, roots)
end

--- Validates a certificate up to a root of trust.
---@param cert X509 The certificate to start at
---@param certList? X509[] Additional certificates that may be in the chain of trust
---@param rootPath? string The path to the root certificate store (defaults to "/etc/certs")
---@param additionalRoots? X509[] Additional root certificates to trust
---@return boolean trusted Whether the certificate can be trusted
---@return string|nil reason If not trusted, a reason why the certificate failed to validate
function chain.validate(cert, certList, rootPath, additionalRoots)
    checkArg(1, cert, "table")
    checkArg(2, certList, "table", "nil")
    rootPath = checkArg(3, rootPath, "string", "nil") or "/etc/certs"
    checkArg(4, additionalRoots, "table", "nil")
    local roots = {}
    if additionalRoots then
        for _, v in ipairs(additionalRoots) do roots[#roots+1] = v end
    end
    if rootPath ~= "" and filesystem.isDirectory(rootPath) then
        for p in filesystem.list(rootPath) do
            if not filesystem.isDirectory(filesystem.concat(rootPath, p)) then
                local file = io.open(filesystem.concat(rootPath, p), "rb")
                if file then
                    local data = file:read("*a")
                    file:close()
                    if data:match("^%-%-%-%-%-BEGIN") then data = container.decodePEM(data) end
                    local ok, c = pcall(container.loadX509, data)
                    if ok then roots[#roots+1] = c end
                end
            end
        end
    end
    return chain_validate_internal(cert, certList or {}, roots)
end

return chain
