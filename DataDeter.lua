-- raihan ganteng

-- linux-adapted syntax and usage

-- DataDeter.lua
-- wrapper module of DataStoreService, in order to controlling with full-control of Data Stores.
-- this module is designed for manual-use, all of controls are yours.
-- place ModuleScript in ServerScriptService. require only on server.

-- kalo misal ada masalah, lapor aja ke gw, chat @raihanaufal_77 in instagram
-- if you got some problems, just report the problem to me, chat @raihanaufal_77 in instagram

-- dibuat oleh RaihanMan18
-- created by RaihanMan18

--[[
	/ @DataDeter

DataDeter.lua — Overview & Usage



  Here's a quick note on the syntax and usage that’s been adjusted for Linux.
  Make sure to place the ModuleScript in ServerScriptService and only require it on the server.

========================================================
  Created by: RaihanMan18 (@raihanaufal_77 on Instagram)
  Version: 1.0.0+ (feature-complete: core functionality of DataDeter, WAL, backup, messaging,
           exclusive binding, HMAC-SHA256 signing, session tokens, locks)
  Last edited: 2025-08-27
  Repository: Add this file to your private GitHub (avoid committing server secrets)
========================================================

@Summary:

DataDeter is a fully-featured wrapper on top of Roblox’s DataStoreService,
offering total manual control, added durability, and protection (WAL, dual-write, backup,
signed snapshots).

It's designed specifically for server-side usage; don’t require it from the client.
Key focus areas: security (HMAC SHA256 signatures/derived keys), durability
(WAL + backup + replication), and exclusive binding per player that
prevents other servers from overwriting data through the DataDeter flow.


=====================================================================================================================
@Public API (Quick Summary)


DataDeter.SetServerSecret(secret: string, security_level?: number)
  -> Sets the server secret (minimum 32 characters recommended, better 64 chars or more) and security level (0..100).


DataDeter.GenerateServerSecret(security_level?: number) -> string
  -> Generates a derived server secret for you (remember to store it securely).


DataDeter.InDataInfo(dataName: string, dataScope?: string, options?: table) -> DataDeterInfo
  -> Create/access a DataDeter Info (a grouping for a datastore).


DataDeterInfo:GetPlayerData(keyOrId, callbacks?) -> DeterPlayerData
  -> Retrieve per-key store (typically player.UserId).

DataDeterInfo:PrintInfo() -> Prints metadata about the info.
=====================================================================================================================




=====================================================================================================================
@DeterPlayerData methods:
-> :Get() -> Returns a table or nil.
-> :Save(data) -> Queues and ensures durable write (dual_write/WAL).
-> :ForceSave(data) -> Performs synchronous durable write.
-> :SaveCAS(data, expected_version) -> Compare-and-swap save method.
-> :Detach(attempts?) -> Atomic delete (primary + backup + WAL + audit) + unbind.
-> :Recover() -> Attempts WAL/backup recovery to primary.
-> :ConcileUp(localData, resolver?) -> Merges local with remote data using a resolver (old, local).
-> :RegisterValidator(name, fn) / :ValidateWith(name, data)
-> :StartSession(playerOrId) -> Returns token and signature.
-> :SaveWithToken(token, data, signature) -> Validates session token.
-> :AcquireSessionLock(ownerId, timeout) / :ReleaseSessionLock(ownerId) / :IsLocked().
-> :ListenToRelease(cb) -> Callback executed when lock is released.
-> :SmartCleanCache(intervalSeconds) -> Starts cache cleaner for this key.
-> :Flush() -> Forces saving of cached dirty data.
-> :Reload() -> Fetches fresh data from primary datastore.
-> :BindData(playerOrUserId) -> Binds key exclusively to this server (atomically).
-> :Unbind() / :IsBound().
-> :Publish(action, payload) -> Publishes signed message via MessagingService.
-> :OnRemote(action, handler) -> Subscribes to signed messages (handler(payload, meta)).
-> Callbacks include: OnObtain, OnSave, OnUpdate, FailedOver, OnBinding, OnUnbind, OnDetaching, OnRelease.
=====================================================================================================================


=====================================================================================================================
!Important Concepts & Behaviors

security_level (0..100):
  Determines the key derivation cost (rounds) and strength of the final derived key.
  Higher values mean stronger signing but also consume more CPU per signing (recommended between 70 and 90 for production).

server_secret:
  This is the root secret kept only on the server side. NEVER commit it to a public repository.
  Use an environment secret manager or set it in a single initialization script:
    ``` DataDeter.SetServerSecret("DD_SECRET", 80). ```

signatures:
  Tokens/messages are signed using HMAC-SHA256 with derived keys based on the security level.
  Messages also include timestamp and replay-window checks.

bind exclusivity:
  BindData will conduct an atomic UpdateAsync to store _meta.bound = { owner, token, at }.
  The owner is expected to keep the token in memory; only writes presenting that token via UpdateAsync will succeed.
  Other servers using DataDeter will be denied by the module if a token mismatch is detected.
  Binding has a configurable expiry (bind_expiry) to avoid permanent deadlocks.

durability:
  WAL (write-ahead log) + backup datastore work together to reduce the risk of data loss.
  dual_write attempts to write to the primary store first, then the backup; WAL records pending writes to allow recovery.

recovery:
  Use store:Recover() when you spot inconsistencies or after an incident; recovery utilizes WAL/backup.

validators:
  Register domain rules using info:RegisterValidator(name, fn), then validate prior to saving to prevent exploits.
  Default Options (High-Level; Check Module Code for Full DEFAULT_OPTIONS):
```
local DEFAULT_OPTIONS = {
  cache_ttl = 300,
  default_save_attempts = 5,
  clean_interval = 60,
  enable_checksums = true,
  max_payload_size = 50 * 1024,
  require_session_token = false,
  session_ttl = 600,
  enable_audit = false,
  backup_enabled = true,
  wal_enabled = true,
  wal_max_entries = 50,
  backup_ds_suffix = "_backup",
  wal_ds_suffix = "_wal",
  replication_enabled = true,
  replication_interval = 300,
  require_token_signature = true,
  security_level = 50,
  messaging_enabled = true,
  messaging_namespace = "DataDeter",
  bind_expiry = 246060, -- seconds (24 hours)
  bind_save_timeout = 5, -- seconds to wait on PlayerRemoving / BindToClose
  bind_save_attempts = 6,
  backup_sign_with_bind = true,
}
```
=====================================================================================================================


=====================================================================================================================
@Examples (Server-Side)

Initialization (Server Init):
```
  local dd = require(game.ServerScriptService.DataDeter)
  dd.SetServerSecret("<very-long-secret-from-env>", 80)

  local info = dd.InDataInfo("PlayerProfile", "global", { security_level = 80, wal_enabled = true, backup_enabled = true }) 
```

Bind + AutoSave on Leave:
```
  local store = info:GetPlayerData(player.UserId)
  store:BindData(player) -- exclusive ownership

  local t = store:Get() or { coins = 0 }
  t.coins = t.coins + 1
  store:Save(t) -- owner server succeeds; others will be refused.
```

CAS (Atomic Money Transfer):
```
  local data = store:Get()
  local expected = data._meta and data._meta.version or 0

  data.coins = data.coins - cost
  local ok, msg = store:SaveCAS(data, expected)

  if not ok then -- handle conflict / retry
      warn("data couldnt be saved: " .. err)
  end
```

Cross-Server Handoff (Session Token + Messaging):
```
  -- Source server:
    local token, sig = store:StartSession(player)
    store:Publish("handoff", { token = token, sig = sig, target = "server-b" })
```

&&

```
-- Target server: on remote message (datadeter verifies signature)

store:OnRemote("handoff", function(payload, meta) end)
-- Then SaveWithToken(token, data, sig) if needed.

```

Admin Safe-Delete:
```
  local store = info:GetPlayerData(targetUserId)
  store:Detach() -- atomically removes primary + backup + WAL + audit, and unbinds.
```
=====================================================================================================================


Security Recommendations (Do This or Face Consequences)
  -> Never commit server secret to Git. Use environment variables or a secret manager.
  -> Production security_level: 70-90. 95+ only if you carefully benchmark CPU load.
  -> Enable WAL + backup for crucial games.
  -> Use RegisterValidator for inventories, purchases, and any client-supplied data.
  -> Limit who can call Detach/ForceSave (should be server-side admin only).
  -> Monitor save failure rates and queue depth; alerts mean you need to investigate.
  -> Consider a short bind_expiry to prevent orphaned binds from blocking forever (plus renew on save).


File structure:

/DataDeter/
├─ src/DataDeter.lua
├─ examples/server_init.lua
├─ examples/player_handlers.lua
├─ README.md
└─ LICENSE



Changelog (Short)


v1.0.0 2025-08-27: Feature complete — HMAC-SHA256 signing, key derivation, WAL + backup,
binding exclusivity, messaging integration, session tokens, CAS, validators,
atomic bind/unbind, and persistent safe shutdowns.


=====================================================================================================================
Debugging / Troubleshooting:

  If you encounter "checksum mismatch" warnings, it indicates that stored _meta.checksum does not match the recalculated value. Investigate possible corruption or manual edits.
  If binding fails with "already_bound": check the primary datastore's _meta.bound for the owner/token/at.
  If autosave fails on shutdown: verify bind_save_timeout and the existence of WAL/backup for recovery.
=====================================================================================================================


Use verbose logs during initial testing (but disable verbose in production).

Contribution & Contact
  Found a bug or have a feature request? Reach out to me: @raihanaufal_77 on Instagram.
  Contributions are welcome; please follow the established code style.



Legal / Final Notes:
  DataDeter aids in making DataStore usage safer and more predictable, but it can’t prevent someone with full server access (or direct datastore access) from tampering with the raw data stores.
  This module offers protection within the DataDeter ecosystem and solid guarantees when all servers use the module as intended.


Thanks for using DataDeter.
Dear, RaihanMan18.

]]

--]]

-- DataDeter.lua
-- Place in ServerScriptService. Require only on server.
-- The things I've changed: BindData();

local HttpService = game:GetService("HttpService")
local DataStoreService = game:GetService("DataStoreService")
local RunService = game:GetService("RunService")
local MessagingService = game:GetService("MessagingService")
local Players = game:GetService("Players")

local DataDeter = {}
DataDeter.__index = DataDeter




-- ===== configuration =====
local DEFAULT_OPTIONS = {
	cache_ttl = 300,
	default_save_attempts = 5,
	clean_interval = 60,
	max_key_length = 50,
	key_name_limit = 20,
	enable_checksums = true,
	max_payload_size = 50 * 1024,
	require_server_only = true,
	lock_attempts = 6,
	lock_wait = 0.5,
	reconcile_attempts = 3,
	reconcile_delay = 0.2,
	require_session_token = false,
	session_ttl = 600,
	enable_audit = false,
	audit_max_entries = 50,
	server_secret = nil,
	backup_enabled = true,
	wal_enabled = true,
	wal_max_entries = 50,
	backup_ds_suffix = "_backup",
	wal_ds_suffix = "_wal",
	replication_enabled = true,
	replication_interval = 300,
	require_token_signature = true,
	security_level = 50,
	messaging_enabled = false,
	messaging_namespace = "DataDeter",
	messaging_debug = false,
	nonce_tracking = true,
	nonce_ttl = 300,
	replay_window = 120,
	_metrics_interval = 5,
	bind_expiry = 60 * 60 * 24, -- default: 24 hours
	bind_save_timeout = 5,
	bind_save_attempts = 6,
	backup_sign_with_bind = true, -- sign backup snapshots with bind token
}


-- internal
local _infos = {}

local _cache = {}

local _saveQueues = {}

local _sessions = {}

local _boundRegistry = {}

local _bindtoclose_registered = false



-- ===== helpers =====
local function assert_string(val, name)
  
	if typeof(val) ~= "string" then

		error(name .. " must be a string")
    
	end
  
end


local function clamp(n, a, b) return math.max(a, math.min(b, n)) end


local function HttpEncode(t)
  
	local ok, s = pcall(function() return HttpService:JSONEncode(t) end)
  
	if ok then return s end
  
	return nil
  
end


local function fnv1a_hex(str)
  
	local hash = 2166136261
  
	for i = 1, #str do
    
		hash = bit32.bxor(hash, string.byte(str, i))
    
		hash = (hash * 16777619) % 4294967296
    
	end
  
	return string.format("%08x", hash)
  
end


local function build_key(dataName, dataScope, id)
  
	local namepart = tostring(dataName or "")
  
	if #namepart > DEFAULT_OPTIONS.key_name_limit then
    
		namepart = string.sub(namepart, 1, DEFAULT_OPTIONS.key_name_limit)
    
	end
  
	local idpart = tostring(id or "")
  
	local hashed = fnv1a_hex(idpart)
  
	local key = namepart .. "_" .. hashed

  
	if #key > DEFAULT_OPTIONS.max_key_length then
    
		key = string.sub(key, 1, DEFAULT_OPTIONS.max_key_length)
    
	end
  
	return key
  
end


local function deep_clone(obj, seen)
  
	seen = seen or {}
  
	if type(obj) ~= "table" then return obj end
  
	if seen[obj] then return seen[obj] end
  
	local out = {}
  
	seen[obj] = out
  
	for k, v in pairs(obj) do
    
		out[deep_clone(k, seen)] = deep_clone(v, seen)
    
	end
  
	return out
  
end


local function raw_checksum(obj)
  
  -- json
	local ok, json = pcall(function() return HttpService:JSONEncode(obj) end)
  
	if not ok then return nil end
  
	local hash = 2166136261
  
	for i = 1, #json do
    
		hash = bit32.bxor(hash, string.byte(json, i))
    
		hash = (hash * 16777619) % 4294967296
    
	end
  
	return string.format("%08x", hash)
  
end


local function compute_checksum_excluding_meta(obj)
  
	local copy = deep_clone(obj)
  
	if type(copy) == "table" then copy._meta = nil end
  
	return raw_checksum(copy)
  
end


local function safeAttempt(func, attempts)
  
	attempts = attempts or DEFAULT_OPTIONS.default_save_attempts
  
	local lastErr
  
	for i = 1, attempts do
    
		local ok, err = pcall(func)
    
		if ok then return true, nil end
    
		lastErr = err
    
		local backoff = math.min((2 ^ i) + math.random() * 0.5, 10)
    
		task.wait(backoff)
    
	end
  
	return false, lastErr
  
end


local function validate_payload_size(tbl, maxBytes)
  
	maxBytes = maxBytes or DEFAULT_OPTIONS.max_payload_size
  
	local ok, json = pcall(function() return HttpService:JSONEncode(tbl) end)
  
	if not ok then return false, "unable to JSONEncode" end
  
	if #json > maxBytes then return false, string.format("payload size %d > allowed %d", #json, maxBytes) end
  
	return true
  
end


local function enqueue_save(key, fn)
  
	local q = _saveQueues[key]
  
	if not q then q = {busy = false, pending = {}}; _saveQueues[key] = q end
  
	table.insert(q.pending, fn)
  
	if not q.busy then
    
		q.busy = true
    
		task.spawn(function()
        
			while #q.pending > 0 do
          
				local job = table.remove(q.pending, 1)
          
				local ok, err = pcall(job)
          
				if not ok then warn("DataDeter: save job failed for key", key, err) end
          
			end
        
			q.busy = false
        
		end)
    
	end

end


local function start_cache_cleaner(interval)
  
	interval = interval or DEFAULT_OPTIONS.clean_interval
  
	task.spawn(function()
      
		while true do
        
			task.wait(interval)
        
			local now = os.time()
        
			for infoId, byKey in pairs(_cache) do
          
				for key, entry in pairs(byKey) do
            
					if entry.ts and (now - entry.ts) > DEFAULT_OPTIONS.cache_ttl then
              
						if entry._dirty and entry._savefn then
                
							entry._dirty = nil
                
							enqueue_save(key, entry._savefn)
                
						end
              
						byKey[key] = nil
              
					end
            
				end
          
			end
        
		end
      
	end)
  
end


-- === SHA256 + HMAC-SHA256 (pure-lua) ===
local function sha256(msg)
  
  -- combinations
  
	local K = {
    
		0x428a2f98,  0x71374491,  0xb5c0fbcf,  0xe9b5dba5,  0x3956c25b,  0x59f111f1,  0x923f82a4,  0xab1c5ed5,
		0xd807aa98,  0x12835b01,  0x243185be,  0x550c7dc3,  0x72be5d74,  0x80deb1fe,  0x9bdc06a7,  0xc19bf174,
		0xe49b69c1,  0xefbe4786,  0x0fc19dc6,  0x240ca1cc,  0x2de92c6f,  0x4a7484aa,  0x5cb0a9dc,  0x76f988da,
		0x983e5152,  0xa831c66d,  0xb00327c8,  0xbf597fc7,  0xc6e00bf3,  0xd5a79147,  0x06ca6351,  0x14292967,
		0x27b70a85,  0x2e1b2138,  0x4d2c6dfc,  0x53380d13,  0x650a7354,  0x766a0abb,  0x81c2c92e,  0x92722c85,
		0xa2bfe8a1,  0xa81a664b,  0xc24b8b70,  0xc76c51a3,  0xd192e819,  0xd6990624,  0xf40e3585,  0x106aa070,
		0x19a4c116,  0x1e376c08,  0x2748774c,  0x34b0bcb5,  0x391c0cb3,  0x4ed8aa4a,  0x5b9cca4f,  0x682e6ff3,
		0x748f82ee,  0x78a5636f,  0x84c87814,  0x8cc70208,  0x90befffa,  0xa4506ceb,  0xbef9a3f7,  0xc67178f2,
	}

  -- encryptions, hashing, etc.
  
	local function ROTR(n, x) return bit32.rshift(x, n) + bit32.lshift(x, 32 - n, 0) end
  
	local function SHR(n, x) return bit32.rshift(x, n) end
  
	local function Ch(x,y,z) return bit32.bxor(bit32.band(x,y), bit32.band(bit32.bnot(x), z)) end
  
	local function Maj(x,y,z) return bit32.bxor(bit32.bxor(bit32.band(x,y), bit32.band(x,z)), bit32.band(y,z)) end
  
	local function BSIG0(x) return bit32.bxor(ROTR(2,x), bit32.bxor(ROTR(13,x), ROTR(22,x))) end
  
	local function BSIG1(x) return bit32.bxor(ROTR(6,x), bit32.bxor(ROTR(11,x), ROTR(25,x))) end
  
	local function SSIG0(x) return bit32.bxor(ROTR(7,x), bit32.bxor(ROTR(18,x), SHR(3,x))) end
  
	local function SSIG1(x) return bit32.bxor(ROTR(17,x), bit32.bxor(ROTR(19,x), SHR(10,x))) end

  
	local msg_len = #msg
  
	local bit_len_hi = 0
  
	local bit_len_lo = msg_len * 8
  
	local padding = string.char(128) .. string.rep(string.char(0), (56 - ((msg_len + 1) % 64)) % 64)
  
	local len_hi = string.char(bit32.band(bit_len_hi, 0xFF), bit32.band(bit32.rshift(bit_len_hi,8),0xFF), bit32.band(bit32.rshift(bit_len_hi,16),0xFF), bit32.band(bit32.rshift(bit_len_hi,24),0xFF))
  
	local len_lo = string.char(bit32.band(bit_len_lo,0xFF), bit32.band(bit32.rshift(bit_len_lo,8),0xFF), bit32.band(bit32.rshift(bit_len_lo,16),0xFF), bit32.band(bit32.rshift(bit_len_lo,24),0xFF))
  
	local M = msg .. padding .. len_hi .. len_lo
  

	local H = { 0x6a09e667,  0xbb67ae85,  0x3c6ef372,  0xa54ff53a,  0x510e527f,  0x9b05688c,  0x1f83d9ab,  0x5be0cd19 }

  
	for i = 1, #M, 64 do
    
		local w = {}
    
		for t = 0, 15 do
      
			local j = i + t*4
      
			w[t] = bit32.lshift(string.byte(M, j),24) + bit32.lshift(string.byte(M, j+1),16) + bit32.lshift(string.byte(M, j+2),8) + string.byte(M, j+3)
      
		end

    
		for t = 16, 63 do
      
			w[t] = (SSIG1(w[t-2]) + w[t-7] + SSIG0(w[t-15]) + w[t-16]) % 4294967296
      
		end

    
		local a,b,c,d,e,f,g,h = unpack(H)

    
		for t = 0, 63 do
      
			local T1 = (h + BSIG1(e) + Ch(e,f,g) + K[t+1] + w[t]) % 4294967296
      
			local T2 = (BSIG0(a) + Maj(a,b,c)) % 4294967296
      
			h = g
      
			g = f
      
			f = e
      
			e = (d + T1) % 4294967296
      
			d = c
      -- ah, you found me
			c = b
      
			b = a
      
			a = (T1 + T2) % 4294967296
      
		end

    
		H[1] = (H[1] + a) % 4294967296
    
		H[2] = (H[2] + b) % 4294967296
    
		H[3] = (H[3] + c) % 4294967296
    
		H[4] = (H[4] + d) % 4294967296
    
		H[5] = (H[5] + e) % 4294967296
    
		H[6] = (H[6] + f) % 4294967296
    
		H[7] = (H[7] + g) % 4294967296
    
		H[8] = (H[8] + h) % 4294967296
    
	end
  

local function tohex(n)
    
		return string.format("%08x", n)
    
	end
  
	return table.concat({tohex(H[1]),tohex(H[2]),tohex(H[3]),tohex(H[4]),tohex(H[5]),tohex(H[6]),tohex(H[7]),tohex(H[8])})

end

local function hex_to_raw(hex)
  
	local out = {}
  -- x
	for i = 1, #hex, 2 do
    
		table.insert(out, string.char(tonumber(hex:sub(i,i+1),16)))
    
	end
  
	return table.concat(out)
  
end


local function hmac_sha256(key, msg)
  
	if #key > 64 then key = sha256(key) end
  
	if #key < 64 then key = key .. string.rep(string.char(0), 64 - #key) end
  
	local o_key_pad = {}
  
	local i_key_pad = {}

  
	for i = 1, #key do
    
		local b = string.byte(key, i)
    
		table.insert(o_key_pad, string.char(bit32.bxor(b, 0x5c)))
    
		table.insert(i_key_pad, string.char(bit32.bxor(b, 0x36)))
    
	end

  
	o_key_pad = table.concat(o_key_pad)
  
	i_key_pad = table.concat(i_key_pad)
  
	local inner = sha256(i_key_pad .. msg)
  
	local inner_raw = hex_to_raw(inner)
  
	local outer = sha256(o_key_pad .. inner_raw)
  
	return outer
  
end


-- === key derivation && secret generation ===

local function derive_key(secret, security_level)
  
	local level = clamp(tonumber(security_level) or DEFAULT_OPTIONS.security_level, 0, 100)
  
	local rounds = 1 + math.floor(level / 10)
  
	local k = tostring(secret or "")

  
	for i = 1, rounds do
    
		k = sha256(k .. ":" .. tostring(level) .. ":" .. tostring(i))
    
	end
  
	return k
  
end


local function generate_secret(security_level)
  
	local level = clamp(tonumber(security_level) or DEFAULT_OPTIONS.security_level, 0, 100)
  
	local target_bytes = 16 + math.floor(level * 1.2)
  
	local out = {}

  
	while #table.concat(out) < target_bytes do
    
		table.insert(out, HttpService:GenerateGUID(false))
    
	end

  
	local s = table.concat(out)
  
	return sha256(s .. ":gen:" .. tostring(level))
  
end

-- === durability core (wal, dual-write, recovery, detach) ===

local function wal_push(info, key, wal_entry)
  
	if not info.options.wal_enabled then return true end
  
	local walKey = key .. (info.options.wal_ds_suffix or DEFAULT_OPTIONS.wal_ds_suffix)
  
	local ok, err = pcall(function()
      
		info._wal_ds:UpdateAsync(walKey, function(old)
          
			old = old or {}
          
			table.insert(old, 1, wal_entry)
          
			if #old > (info.options.wal_max_entries or DEFAULT_OPTIONS.wal_max_entries) then
            
            
				for i = #old, (info.options.wal_max_entries or DEFAULT_OPTIONS.wal_max_entries) + 1, -1 do
              
					table.remove(old, i)
              
				end
            
            
			end
          
			return old
          
		end)
      
	end)
  
	if not ok then warn("DataDeter: wal_push failed", err); return false end
  
	return true
  
end


local function wal_pop_processed(info, key, processed_id)

	if not info.options.wal_enabled then return true end
  
	local walKey = key .. (info.options.wal_ds_suffix or DEFAULT_OPTIONS.wal_ds_suffix)
  
	local ok, err = pcall(function()
      
		info._wal_ds:UpdateAsync(walKey, function(old)
          
			old = old or {}
          
			local out = {}

          
			for _, v in ipairs(old) do
            
				if v.id ~= processed_id then table.insert(out, v) end
            
			end
          
			return out
          
		end)
      
	end)
  
	if not ok then warn("DataDeter: wal_pop_processed failed", err); return false end
  
	return true
  
end


local function dual_write(info, key, toStore)
  
	local t0 = tick()
  
	local wal_id = HttpService:GenerateGUID(false)
  
	local wal_entry = { id = wal_id, at = os.time(), data = toStore }
  
	local pushed = wal_push(info, key, wal_entry)
  
	if not pushed then
    
		if info._metrics then info._metrics.save_fail_count = (info._metrics.save_fail_count or 0) + 1 end
    
		return false, "wal_push_failed"
    
	end
  

	local primary_ok, primary_err = safeAttempt(function()
      
		info.ds:UpdateAsync(key, function(old) return toStore end)
      
	end, info.options.default_save_attempts)

  
	local latency_ms = (tick() - t0) * 1000
  
	if info._metrics then
    
		info._metrics.save_count = (info._metrics.save_count or 0) + 1
    
		info._metrics.save_latency_sum = (info._metrics.save_latency_sum or 0) + latency_ms
    
		info._metrics.save_latency_count = (info._metrics.save_latency_count or 0) + 1
    
		info._metrics.avg_save_latency = (info._metrics.save_latency_sum / info._metrics.save_latency_count)
    
	end
  

	if not primary_ok then
    
		if info.options.backup_enabled and info._backup_ds then
      
			local backup_ok, backup_err = safeAttempt(function()
          
				info._backup_ds:UpdateAsync(key, function(old) return toStore end)
          
			end, info.options.default_save_attempts)

      
			if not backup_ok then
        
				if info._metrics then info._metrics.save_fail_count = (info._metrics.save_fail_count or 0) + 1 end
        
				return false, "both_primary_and_backup_failed"
        
			end

      
			if info._metrics then info._metrics.save_recovery_count = (info._metrics.save_recovery_count or 0) + 1 end
      
			return false, "primary_failed_but_backup_ok"
      
		end

    
		if info._metrics then info._metrics.save_fail_count = (info._metrics.save_fail_count or 0) + 1 end
    
		return false, primary_err
    
	end


	if info.options.backup_enabled and info._backup_ds then
    
		safeAttempt(function()
        
			info._backup_ds:UpdateAsync(key, function(old) return toStore end)
        
		end, info.options.default_save_attempts)
    
	end

  
	wal_pop_processed(info, key, wal_id)
  
	if info._metrics then info._metrics.save_success_count = (info._metrics.save_success_count or 0) + 1 end
  
	return true
  
end

-- my eyes are burned now, so i won't add empty lines from here right then.

local function recover_from_wal(info, key)
	if not info.options.wal_enabled then return true end
	local walKey = key .. (info.options.wal_ds_suffix or DEFAULT_OPTIONS.wal_ds_suffix)
	local ok, entries = pcall(function() return info._wal_ds:GetAsync(walKey) end)
	if not ok then warn("DataDeter: recover_from_wal GetAsync failed", entries); return false end
	entries = entries or {}
	local recovered = false
	for i = #entries, 1, -1 do
		local e = entries[i]
		local ok2, err2 = pcall(function()
			info.ds:UpdateAsync(key, function(old) return e.data end)
		end)
		if ok2 then
			wal_pop_processed(info, key, e.id)
			recovered = true
		end
	end
	return recovered
end

local function start_replication(info)
	if not info.options.replication_enabled or not info.options.backup_enabled or not info._backup_ds then return end
	task.spawn(function()
		while true do
			task.wait(info.options.replication_interval or DEFAULT_OPTIONS.replication_interval)
			local byKey = _cache[info._id]
			if not byKey then continue end
			for key, entry in pairs(byKey) do
				if entry and entry.value then
					local ok, err = pcall(function()
						info._backup_ds:UpdateAsync(key, function(old) return entry.value end)
					end)
					if not ok then warn("DataDeter: replication snapshot failed", key, err) end
				end
			end
			continue
		end
	end)
end

-- ===== messaging primitives with nonce tracking and debug =====
local function messaging_publish(info, action, payload)
	if not info.options.messaging_enabled then return false, "messaging_disabled" end
	local topic = (info.options.messaging_namespace or DEFAULT_OPTIONS.messaging_namespace) .. ":" .. info._id
	local meta = { action = action, key = info._key, at = os.time(), level = info.options.security_level or DEFAULT_OPTIONS.security_level, nonce = HttpService:GenerateGUID(false) }
	local unsigned = HttpService:JSONEncode({ meta = meta, payload = payload })
	local secret = info.options.server_secret or DEFAULT_OPTIONS.server_secret
	local derived = derive_key(secret, info.options.security_level or DEFAULT_OPTIONS.security_level)
	local sig = hmac_sha256(derived, unsigned)
	local envelope = { meta = meta, payload = payload, sig = sig }
	local encoded = HttpService:JSONEncode(envelope)
	local ok, err = pcall(function() MessagingService:PublishAsync(topic, encoded) end)
	if not ok then return false, err end
	-- metrics
	if info._metrics then
		info._metrics.publish_count = (info._metrics.publish_count or 0) + 1
		info._metrics.last_publish = os.time()
	end
	if info.options.messaging_debug then print("DataDeter: published", topic, unsigned) end
	return true
end

local function messaging_subscribe(info)
	if not info.options.messaging_enabled then return nil end
	local topic = (info.options.messaging_namespace or DEFAULT_OPTIONS.messaging_namespace) .. ":" .. info._id
	local sub = nil
	local handlers = info._remote_handlers or {}
	info._seen_nonces = info._seen_nonces or {}
	info._nonce_index = info._nonce_index or {}
	sub = MessagingService:SubscribeAsync(topic, function(message)
		local raw = message.Data or message
		local ok, decoded = pcall(function() return HttpService:JSONDecode(raw) end)
		if not ok or type(decoded) ~= "table" then warn("DataDeter: messaging decode failed", raw); return end
		local meta = decoded.meta
		local payload = decoded.payload
		local sig = decoded.sig
		local secret = info.options.server_secret or DEFAULT_OPTIONS.server_secret
		local derived = derive_key(secret, info.options.security_level or DEFAULT_OPTIONS.security_level)
		local unsigned = HttpService:JSONEncode({ meta = meta, payload = payload })
		local expected = hmac_sha256(derived, unsigned)
		if expected ~= sig then warn("DataDeter: incoming message signature mismatch", info._id, meta and meta.action); return end
		if info.options.messaging_debug then print("DataDeter: incoming verified", meta.action, unsigned) end
		-- replay/nonce mitigation
		if info.options.nonce_tracking and meta and meta.nonce then
			local now = os.time()
			if info._seen_nonces[meta.nonce] then return end
			if meta.at and math.abs(now - meta.at) > (info.options.replay_window or DEFAULT_OPTIONS.replay_window) then warn("DataDeter: incoming message expired", info._id); return end
			info._seen_nonces[meta.nonce] = now
			table.insert(info._nonce_index, 1, meta.nonce)
			while #info._nonce_index > 1000 do local n = table.remove(info._nonce_index); info._seen_nonces[n] = nil end
		end
		-- dispatch to handlers
		for action, list in pairs(handlers) do
			if action == meta.action then
				for _, cb in ipairs(list) do pcall(cb, payload, meta) end
			end
		end
	end)
	info._messaging_sub = sub
	info._remote_handlers = handlers
	-- nonce cleanup task
	if info.options.nonce_tracking then
		if not info._nonce_cleanup then
			info._nonce_cleanup = true
			task.spawn(function()
				while info._nonce_cleanup do
					task.wait(math.max(60, info.options.nonce_ttl or 300))
					local now = os.time()
					for i = #info._nonce_index, 1, -1 do
						local n = info._nonce_index[i]
						local t = info._seen_nonces[n]
						if not t or (now - t) > (info.options.nonce_ttl or DEFAULT_OPTIONS.nonce_ttl) then
							info._seen_nonces[n] = nil
							table.remove(info._nonce_index, i)
						end
					end
				end
			end)
		end
	end
	return sub
end

-- ===== factories & core implementation =====
local function NewInfo(dataName, dataScope, options)
	local info = setmetatable({}, {__index = DataDeter})
	info.dataName = tostring(dataName)
	info.dataScope = dataScope and tostring(dataScope) or nil
	info.options = options or {}
	for k, v in pairs(DEFAULT_OPTIONS) do if info.options[k] == nil then info.options[k] = v end end
	info.ds = DataStoreService:GetDataStore(info.dataName, info.dataScope)
	info._locks_ds = DataStoreService:GetDataStore(info.dataName .. "_locks", info.dataScope)
	if info.options.backup_enabled then
		info._backup_ds = DataStoreService:GetDataStore(info.dataName .. (info.options.backup_ds_suffix or DEFAULT_OPTIONS.backup_ds_suffix), info.dataScope)
	end
	if info.options.wal_enabled then
		info._wal_ds = DataStoreService:GetDataStore(info.dataName .. (info.options.wal_ds_suffix or DEFAULT_OPTIONS.wal_ds_suffix), info.dataScope)
	end
	info._audit_ds = info.options.enable_audit and DataStoreService:GetDataStore(info.dataName .. "_audit", info.dataScope) or nil
	info._id = info.dataName .. ":" .. (info.dataScope or "__default")
	if not _cache[info._id] then _cache[info._id] = {} end
	info._validators = {}
	info._lock_watchers = {}
	-- metrics container
	info._metrics = {
		save_count = 0,
		save_success_count = 0,
		save_fail_count = 0,
		save_recovery_count = 0,
		save_latency_sum = 0,
		save_latency_count = 0,
		avg_save_latency = 0,
		publish_count = 0,
		last_publish = nil,
		heartbeat = 1,
		last_heartbeat_at = os.time(),
		-- internal for smoothing/scaling / forecasting
		raw_ema_max = 1,
		raw_ema = 0,
		prev_save_count = 0,
		prev_publish_count = 0,
		ema_alpha = 0.15,
		-- forecasting
		save_rate_ema = 0,
		save_trend = 0,
		prev_save_rate = 0,
		predicted_save_rate_60 = 0,
		pred_confidence = 0.5,
	}
	-- ensure server secret exists
	if not info.options.server_secret and DEFAULT_OPTIONS.server_secret then info.options.server_secret = DEFAULT_OPTIONS.server_secret end
	if not info.options.server_secret then info.options.server_secret = generate_secret(info.options.security_level) end
	-- start messenger
	if info.options.messaging_enabled then pcall(function() messaging_subscribe(info) end) end
	start_replication(info)

	-- periodic metrics sampler (EMA smoothing + simple trend forecast)
	task.spawn(function()
		local interval = info.options._metrics_interval or DEFAULT_OPTIONS._metrics_interval
		local trend_alpha = 0.08 -- smoothing for trend
		while true do
			task.wait(interval)
			local byKey = _cache[info._id]
			local mq = 0
			if byKey then
				for k, v in pairs(byKey) do
					if v and v._savefn then mq = mq + (v._dirty and 1 or 0) end
				end
			end

			-- recent rates
			local now = os.time()
			local delta_save = (info._metrics.save_count or 0) - (info._metrics.prev_save_count or 0)
			local delta_pub = (info._metrics.publish_count or 0) - (info._metrics.prev_publish_count or 0)
			info._metrics.prev_save_count = info._metrics.save_count or 0
			info._metrics.prev_publish_count = info._metrics.publish_count or 0

			local save_rate = delta_save / math.max(1, interval) -- ops/sec
			local pub_rate = delta_pub / math.max(1, interval)

			-- update EMA for save_rate
			local alpha = info._metrics.ema_alpha or 0.15
			info._metrics.save_rate_ema = (alpha * save_rate) + ((1 - alpha) * (info._metrics.save_rate_ema or 0))

			-- update trend as EMA of rate differences
			local rate_diff = save_rate - (info._metrics.prev_save_rate or 0)
			info._metrics.save_trend = (trend_alpha * rate_diff) + ((1 - trend_alpha) * (info._metrics.save_trend or 0))
			info._metrics.prev_save_rate = save_rate

			-- predict save_rate for 60s horizon (linear approx)
			local predicted = info._metrics.save_rate_ema + (info._metrics.save_trend * 60)
			info._metrics.predicted_save_rate_60 = math.max(predicted, 0)

			-- confidence metric: based on variance proxy (higher ema_alpha -> lower confidence) and security level
			local conf_base = clamp(1 - (alpha * 2), 0.1, 0.95)
			local sec = clamp(tonumber(info.options.security_level or DEFAULT_OPTIONS.security_level) or 0, 0, 100)
			local sec_penalty = 1 - (sec / 200) -- higher security slightly lowers capacity confidence
			info._metrics.pred_confidence = clamp(conf_base * sec_penalty, 0.05, 0.99)

			-- scoring for heartbeat
			local fail_penalty = (info._metrics.save_fail_count or 0) * 5
			local latency_penalty = (info._metrics.avg_save_latency or 0) / 10
			local raw = mq * 150 + save_rate * 80 + pub_rate * 60 + fail_penalty + latency_penalty

			-- EMA smoothing for raw
			local alpha_raw = info._metrics.ema_alpha or 0.15
			info._metrics.raw_ema = (alpha_raw * raw) + ((1 - alpha_raw) * (info._metrics.raw_ema or 0))

			-- dynamic decaying max for normalization
			info._metrics.raw_ema_max = math.max((info._metrics.raw_ema_max or 1) * 0.96, info._metrics.raw_ema)

			local denom = math.max(1, info._metrics.raw_ema_max)
			local normalized_load = info._metrics.raw_ema / denom
			local sensitivity = 1 + (sec / 300)
			normalized_load = clamp(normalized_load * sensitivity, 0, 1)

			local x = normalized_load * 12
			local logistic = 1 / (1 + math.exp(- (x - 6)))
			local inv = 1 - logistic
			local heartbeat = math.floor(clamp(inv * 999 + 1, 1, 1000))

			info._metrics.heartbeat = heartbeat
			info._metrics.last_heartbeat_at = now
		end
	end)

	-- expose two info-level helpers
	function info:GetHeartbeat()
		local mlocal = info._metrics
		if not mlocal then return 1 end
		return tonumber(mlocal.heartbeat or 1)
	end

	function info:GetSize()
		local total = 0
		local byKey = _cache[info._id]
		if not byKey then return 0 end
		for key, entry in pairs(byKey) do
			if entry and entry.value then
				local ok, json = pcall(function() return HttpService:JSONEncode(entry.value) end)
				if ok and type(json) == "string" then total = total + #json end
			end
		end
		return total
	end

	function info:GetMonitor()
		-- precise, smoothed snapshot of metrics and short-term forecast
		local m = info._metrics
		if not m then return nil end
		local snapshot = {
			id = info._id,
			dataName = info.dataName,
			dataScope = info.dataScope,
			heartbeat = m.heartbeat,
			last_heartbeat_at = m.last_heartbeat_at,
			cache_size_bytes = info:GetSize(),
			save_count = m.save_count,
			save_success_count = m.save_success_count,
			save_fail_count = m.save_fail_count,
			avg_save_latency_ms = m.avg_save_latency,
			save_rate_per_sec = m.save_rate_ema,
			publish_rate_per_sec = ((m.publish_count or 0) - (m.prev_publish_count or 0)) / math.max(1, info.options._metrics_interval or DEFAULT_OPTIONS._metrics_interval),
			predicted_save_rate_per_min = m.predicted_save_rate_60 * 60,
			predicted_ops_per_min = (m.predicted_save_rate_60 + ( ((m.publish_count or 0) - (m.prev_publish_count or 0)) / math.max(1, info.options._metrics_interval or DEFAULT_OPTIONS._metrics_interval) )) * 60,
			prediction_confidence = m.pred_confidence,
			security_level = info.options.security_level,
			queue_depth_estimate = (function()
				local qd = 0
				local byKey = _cache[info._id]
				if byKey then for k, v in pairs(byKey) do if v and v._savefn and v._dirty then qd = qd + 1 end end end
				return qd
			end)(),
			timestamp = os.time(),
		}
		return snapshot
	end

	return info
end

local function push_audit(info, key, entry)
	if not info._audit_ds then return end
	local ok, err = pcall(function()
		info._audit_ds:UpdateAsync(key .. "_audit", function(old)
			old = old or {}
			table.insert(old, 1, entry)
			if #old > (info.options.audit_max_entries or DEFAULT_OPTIONS.audit_max_entries) then
				for i = #old, (info.options.audit_max_entries or DEFAULT_OPTIONS.audit_max_entries) + 1, -1 do
					table.remove(old, i)
				end
			end
			return old
		end)
	end)
	if not ok then warn("DataDeter: audit push failed", err) end
end

local function NewStore(info, rawKey, opts)
	local store = {}
	store._info = info
	store._rawKey = rawKey
	store._key = build_key(info.dataName, info.dataScope, rawKey)
	store._ds = info.ds
	store._cache = _cache[info._id]
	store._callbacks = { OnUpdate = {}, OnSave = {}, OnObtain = {}, FailedOver = {}, OnRelease = {}, OnLoading = {}, OnDetaching = {}, OnBinding = {}, OnUnbind = {} }
	store._attached = false
	store._bind_token = nil
	store._boundPlayer = nil
	store._boundConnections = {}

	opts = opts or {}
	if opts and opts.OnObtain then table.insert(store._callbacks.OnObtain, opts.OnObtain) end
	if opts and opts.OnSave then table.insert(store._callbacks.OnSave, opts.OnSave) end
	if opts and opts.FailedOver then table.insert(store._callbacks.FailedOver, opts.FailedOver) end
	if opts and opts.OnLoading then table.insert(store._callbacks.OnLoading, opts.OnLoading) end
	if opts and opts.OnDetaching then table.insert(store._callbacks.OnDetaching, opts.OnDetaching) end
	if opts and opts.OnBinding then table.insert(store._callbacks.OnBinding, opts.OnBinding) end
	if opts and opts.OnUnbind then table.insert(store._callbacks.OnUnbind, opts.OnUnbind) end
	
	local methods = {}

	local function dispatch(list, ...)
		for _, cb in ipairs(list) do
			local ok, err = pcall(cb, ...)
			if not ok then warn("DataDeter callback error", err) end
		end
	end

	local function ensure_server_and_validate_caller(caller)
		if info.options.require_server_only and RunService:IsClient() then
			error("DataDeter: must be required server-side only")
		end
		if typeof(caller) == "Instance" and caller:IsA("Player") and tonumber(store._rawKey) then
			if tonumber(store._rawKey) ~= caller.UserId then error("DataDeter: caller player mismatch vs store rawKey") end
		end
	end
	
	local function attempt_atomic_bind_ds(info, key, pid, bind_token)
		local ok, res = pcall(function()
			return info.ds:UpdateAsync(key, function(old)
				old = old or {}
				old._meta = old._meta or {}
				local bound = old._meta.bound
				if bound and bound.token then
					if info.options.bind_expiry and bound.at and (os.time() - bound.at) > info.options.bind_expiry then
						-- expired -> allow overwrite
					else
						-- someone else holds it -> keep old
						return old
					end
				end
				old._meta.bound = { owner = pid, token = bind_token, at = os.time() }
				return old
			end)
		end)
		if not ok then return false, res end
		-- verify
		if res and res._meta and res._meta.bound and res._meta.bound.token == bind_token then return true end
		return false, "already_bound"
	end
	
	-- internal: unbind atomically only if token matches
	local function attempt_atomic_unbind_ds(info, key, bind_token)
		local ok, res = pcall(function()
			return info.ds:UpdateAsync(key, function(old)
				if not old or not old._meta or not old._meta.bound then return old end
				if old._meta.bound.token ~= bind_token then return old end
				old._meta.bound = nil
				return old
			end)
		end)
		if not ok then return false, res end
		-- check resulting value: if bound removed -> success
		if not res then return true end
		if not res._meta or not res._meta.bound then return true end
		-- still bound (token mismatch or other) -> detect token mismatch
		if res._meta.bound and res._meta.bound.token and res._meta.bound.token ~= bind_token then
			return false, "token_mismatch"
		end
		return false, "unbind_failed"
	end
	
	

	local function sign_token(token)
		local secret = info.options.server_secret or DEFAULT_OPTIONS.server_secret
		if not secret then return nil end
		local derived = derive_key(secret, info.options.security_level)
		return hmac_sha256(derived, token .. ":" .. store._key)
	end

	function methods:StartSession(playerOrId)
		local pid = type(playerOrId) == "number" and playerOrId or (typeof(playerOrId) == "Instance" and playerOrId:IsA("Player") and playerOrId.UserId)
		if not pid then error("StartSession requires player or playerId") end
		local token = HttpService:GenerateGUID(false)
		local expiry = os.time() + (info.options.session_ttl or DEFAULT_OPTIONS.session_ttl)
		local signature = sign_token(token)
		_sessions[token] = { playerId = pid, key = store._key, expiry = expiry, signature = signature }
		return token, signature
	end

	function methods:EndSession(token)
		_sessions[token] = nil
		return true
	end

	local function validate_session(token, signature)
		if not token then return false end
		local s = _sessions[token]
		if not s then return false end
		if s.expiry < os.time() then _sessions[token] = nil; return false end
		if s.key ~= store._key then return false end
		if info.options.require_token_signature and signature and s.signature and signature ~= s.signature then return false end
		return s
	end
	
	local function persist_store_immediately(store)
		local info = store._info
		local key = store._key
		_cache[info._id] = _cache[info._id] or {}
		local entry = _cache[info._id][key]
		if not entry or not entry.value then return false, "no_cached_data" end
		local toStore = deep_clone(entry.value)
		toStore._meta = toStore._meta or {}
		toStore._meta.updated_at = os.time()
		toStore._meta.version = (toStore._meta.version or 0) + 1
		if info.options.enable_checksums then toStore._meta.checksum = compute_checksum_excluding_meta(toStore) end


		local attempts = info.options.bind_save_attempts or DEFAULT_OPTIONS.bind_save_attempts
		local timeout = info.options.bind_save_timeout or DEFAULT_OPTIONS.bind_save_timeout
		local startTime = os.clock()
		
		-- if bound: enforce token via UpdateAsync with retries
		if store._bind_token then
			for i = 1, attempts do
				local ok, res = pcall(function()
					return info.ds:UpdateAsync(key, function(old)
						old = old or {}
						old._meta = old._meta or {}
						local bound = old._meta.bound
						if bound and bound.token and bound.token ~= store._bind_token then
							-- ownership lost; abort
							return old
						end
						-- preserve binding metadata
						toStore._meta.bound = old._meta.bound
						return toStore
					end)
				end)
				
				if ok and res and res._meta and res._meta.version == toStore._meta.version then
					-- Write applied: also write backup (signed) if available
					_cache[info._id][key] = { value = toStore, ts = os.time() }
					-- try backup write (best-effort)
					if info.options.backup_enabled and info._backup_ds then
						pcall(function()
							local backupKey = key .. (info.options.backup_ds_suffix or DEFAULT_OPTIONS.backup_ds_suffix)
							local snapshot = deep_clone(toStore)
							-- attach a signature to backup so owners can prove it
							if info.options.backup_sign_with_bind and store._bind_token and hmac_sha256 then
								snapshot._meta = snapshot._meta or {}
								snapshot._meta.backup_sig = hmac_sha256(store._bind_token, HttpEncode(snapshot) or "")
							end
							info._backup_ds:UpdateAsync(backupKey, function(old) return snapshot end)
						end)
						pcall(function() for _, cb in ipairs(store._callbacks and store._callbacks.OnSave or {}) do cb(toStore, store) end end)
						return true
					end
					
					-- if timed out, break
					if (os.clock() - startTime) >= timeout then break end
						task.wait(0.12 * i)
					end
				end
			
			return false, "persist_failed_or_conflict"
		else
			-- not bound: enqueue dual_write non-blocking
			local job = function()
				if type(dual_write) == "function" then
					local ok2, err2 = dual_write(info, key, toStore)
					if not ok2 then warn("DataDeter: dual_write failed in persist_store_immediately", err2) end
				else
					pcall(function() info.ds:UpdateAsync(key, function() return toStore end) end)
				end
			end
			enqueue_save(key, job)
			_cache[info._id][key] = { value = toStore, ts = os.time() }
			return true
		end
	end
	
	local function register_bindtoclose()
		if _bindtoclose_registered then return end
		_bindtoclose_registered = true
		local ok, err = pcall(function()
			local binder = game.BindToClose or (RunService and RunService.BindToClose)
			if type(binder) == "function" then
				binder(game, function()
					-- loop through bound registry and attempt persist (best-effort)
					for infoId, map in pairs(_boundRegistry) do
						for k, s in pairs(map) do
							pcall(function()
								-- try longer timeout here to improve chance on shutdown
								local prev_timeout = s._info.options.bind_save_timeout
								s._info.options.bind_save_timeout = math.max(5, prev_timeout or 5)
								persist_store_immediately(s)
								s._info.options.bind_save_timeout = prev_timeout
							end)
						end
					end
				end)
			end
		end)
		if not ok then warn("DataDeter: BindToClose registration failed", err) end
	end
	
	-- BindData: exclusive atomic bind + stronger bind token
	function store:BindData(player)
		local pid = (type(player) == "number" and player) or (typeof(player) == "Instance" and player:IsA("Player") and player.UserId)
		if not pid then error("BindData expects Player or userId") end
		if store._attached then dispatch(store._callbacks.OnBinding, store); return true end
		local raw = HttpService:GenerateGUID(false)
		local derived = derive_key(info.options.server_secret, info.options.security_level)
		local bind_token = hmac_sha256(derived, raw .. ":" .. store._key .. ":bind")
		local ok, err = attempt_atomic_bind_ds(info, store._key, pid, bind_token)
		if not ok then dispatch(store._callbacks.FailedOver, "already_binded", store._key); return false, err end
		-- success
		store._bind_token = bind_token
		store._attached = true
		_boundRegistry[info._id] = _boundRegistry[info._id] or {}
		_boundRegistry[info._id][store._key] = store
		
		-- connect player remove handler that waits for persist until timeout
		local playerInstance = (typeof(player) == "Instance") and player or Players:GetPlayerByUserId(pid)
		store._boundPlayer = playerInstance
		local handler = function(rem)
			if rem.UserId ~= pid then return end
			local start = os.clock()
			local timeout = info.options.bind_save_timeout or DEFAULT_OPTIONS.bind_save_timeout
			local ok2, err2
			repeat
				ok2, err2 = persist_store_immediately(store)
				if ok2 then break end
				if (os.clock() - start) >= timeout then break end
				task.wait(0.12)
			until false
			if not ok2 then dispatch(store._callbacks.FailedOver, "bind_save_failed"); warn("DataDeter: bind-save failed on PlayerRemoving", store._key, err2) end
		end

		store._boundConnections.playerRemoving = Players.PlayerRemoving:Connect(handler)
		if playerInstance then
			store._boundConnections.instanceAncestry = playerInstance.AncestryChanged:Connect(function(_, parent) if not parent then persist_store_immediately(store) end end)
		end
		-- register BindToClose once
		register_bindtoclose()
		dispatch(store._callbacks.OnBinding, store)
		return true
	end
	
	function methods:IsBound()
		return store._attached == true
	end


	function store:Unbind()
		if not store._bind_token then
			-- nothing bound locally; try clearing registry
			store._attached = false
			store._boundPlayer = nil
			if _boundRegistry[info._id] then _boundRegistry[info._id][store._key] = nil end
			dispatch(store._callbacks.OnUnbind, store)
			return true
		end
		local ok, err = attempt_atomic_unbind_ds(info, store._key, store._bind_token)
		if not ok then warn("DataDeter: Unbind failed", store._key, err); return false, err end
		-- success locally cleanup
		store._bind_token = nil
		store._attached = false
		store._boundPlayer = nil
		if store._boundConnections then for _, c in pairs(store._boundConnections) do if c and typeof(c.Disconnect) == "function" then pcall(function() c:Disconnect() end) end end end
		store._boundConnections = {}
		if _boundRegistry[info._id] then _boundRegistry[info._id][store._key] = nil end
		dispatch(store._callbacks.OnUnbind, store)
		return true
	end
	
	-- lock functions
	function methods:AcquireSessionLock(ownerId, timeout)
		ownerId = ownerId or HttpService:GenerateGUID(false)
		timeout = timeout or 10
		local lockKey = self._key .. "_lock"
		local attempts = self._info.options.lock_attempts or DEFAULT_OPTIONS.lock_attempts
		for i = 1, attempts do
			local ok, res = pcall(function()
				return self._info._locks_ds:UpdateAsync(lockKey, function(old)
					old = old or {}
					local now = os.time()
					if (not old.owner) or (old.expiry and old.expiry <= now) then
						return { owner = ownerId, expiry = now + timeout }
					end
					return old
				end)
			end)
			if ok and res and res.owner == ownerId then return true, ownerId end
			task.wait((self._info.options.lock_wait or DEFAULT_OPTIONS.lock_wait) * i)
		end
		dispatch(self._callbacks.FailedOver, "lock_acquire_failed", self._key)
		return false, "unable to acquire lock"
	end

	function methods:ReleaseSessionLock(ownerId)
		local lockKey = self._key .. "_lock"
		local ok, res = pcall(function()
			return self._info._locks_ds:UpdateAsync(lockKey, function(old)
				old = old or {}
				if old.owner == ownerId then return {} end
				return old
			end)
		end)
		if not ok then warn("DataDeter: ReleaseSessionLock failed", res); dispatch(self._callbacks.FailedOver, "lock_release_failed", self._key)
		else
			local watchers = self._info._lock_watchers[self._key]
			if watchers then for _, cb in ipairs(watchers) do pcall(cb, self._key) end end
			dispatch(self._callbacks.OnRelease, ownerId, self._key)
		end
		return ok
	end

	function methods:IsLocked()
		local lockKey = self._key .. "_lock"
		local ok, res = pcall(function() return self._info._locks_ds:GetAsync(lockKey) end)
		if not ok then warn("DataDeter: IsLocked Get failed", res); return false end
		if res and res.owner and res.expiry and res.expiry > os.time() then return true, res.owner end
		return false
	end

	function methods:ListenToRelease(cb)
		if type(cb) ~= "function" then error("ListenToRelease expects function") end
		self._info._lock_watchers[self._key] = self._info._lock_watchers[self._key] or {}
		table.insert(self._info._lock_watchers[self._key], cb)
	end
	
	function methods:ChangeData(savedDataName, value, caller)
		if type(savedDataName) ~= "string" then error("ChangeData expects string") end
		caller = caller or nil
		
		local okData, dataObtains = pcall(function()
			return methods.Get(self, caller)
		end)
		if okData then
			if dataObtains[savedDataName] then
				dataObtains[savedDataName] = value
				
				caller = typeof(caller) == "Instance" and caller:IsA("Player") and caller
				local locked, owner = methods.AcquireSessionLock(self, caller.UserId, 10)
				if locked then
					local success, err = pcall(function()
						methods.ForceSave(self, dataObtains)
					end) 
					
					if success then
						dispatch(self._callbacks.OnUpdate, dataObtains, self._key, self)
						methods.ReleaseSessionLock(self, owner)

						return true
					else
						dispatch(self._callbacks.FailedOver, "change_failed", self._key)
						methods.ReleaseSessionLock(self, owner)

						warn("DataDeter: ChangeData failed to save", self._key, err)
					end
					
				end
				return true
			end
		end
		
		return false
	end

	function methods:OnUpdate(cb) table.insert(self._callbacks.OnUpdate, cb) end
	function methods:OnSave(cb) table.insert(self._callbacks.OnSave, cb) end
	function methods:OnObtain(cb) table.insert(self._callbacks.OnObtain, cb) end
	function methods:FailedOver(cb) table.insert(self._callbacks.FailedOver, cb) end
	function methods:OnRelease(cb) table.insert(self._callbacks.OnRelease, cb) end
	function methods:OnLoading(cb) table.insert(self._callbacks.OnLoading, cb) end
	function methods:OnDetaching(cb) table.insert(self._callbacks.OnDetaching, cb) end
	function methods:OnBinding(cb) table.insert(self._callbacks.OnBinding, cb) end
	function methods:OnUnbind(cb) table.insert(self._callbacks.OnUnbind, cb) end
	
	-- Get: call OnLoading before performing read and before OnObtain
	function methods:Get(caller)
		if caller then ensure_server_and_validate_caller(caller) end
		-- dispatch loading
		dispatch(self._callbacks.OnLoading, self)
		local entry = self._cache[self._key]
		if entry and entry.value then
			dispatch(self._callbacks.OnObtain, entry.value, self)
			return entry.value
		end
		local ok, res = pcall(function() return self._ds:GetAsync(self._key) end)
		if not ok then warn("DataDeter: GetAsync failed", self._key, res); dispatch(self._callbacks.FailedOver, "get_failed", self._key, res); return nil end
		local final = res or {}
		if self._info.options.enable_checksums and type(final) == "table" and final._meta and final._meta.checksum then
			local cs = final._meta.checksum
			local calc = compute_checksum_excluding_meta(final)
			if calc ~= cs then warn("DataDeter: checksum mismatch for key", self._key); dispatch(self._callbacks.FailedOver, "checksum_mismatch", self._key) end
		end
		self._cache[self._key] = { value = final, ts = os.time() }
		dispatch(self._callbacks.OnObtain, final, self)
		return final
	end

	function methods:GetDeter(caller, attempts)
		caller = caller or nil
		attempts = attempts or 5

		local attempt = 0

		local ok, data
		repeat
			ok, data = pcall(function()
				return methods.Get(self, caller)
			end)

			if not ok then
				attempt += 1
			end

			task.wait(3)
		until ok or attempt == 5

		if attempt == 5 then
			warn("DataDeter: GetDeter failed after 5 attempts for key " .. self._key)
			return
		end

		return ok, data
	end
	
	function methods:ForceSave(dataInfo, attempts)
		if type(dataInfo) ~= "table" then error("ForceSave expects table") end
		local okSize, errMsg = validate_payload_size(dataInfo, self._info.options.max_payload_size)
		if not okSize then error("payload too large: ".. tostring(errMsg)) end
		attempts = attempts or self._info.options.default_save_attempts
		local toStore = deep_clone(dataInfo)
		toStore._meta = toStore._meta or {}
		toStore._meta.updated_at = os.time()
		toStore._meta.version = (toStore._meta.version or 0) + 1
		if self._info.options.enable_checksums then
			local cs = compute_checksum_excluding_meta(toStore)
			toStore._meta.checksum = cs
		end
		local ok, err = dual_write(self._info, self._key, toStore)
		if not ok then warn("DataDeter: ForceSave durable write failed", err); dispatch(self._callbacks.FailedOver, "save_failed", self._key, err); return false end
		self._cache[self._key] = self._cache[self._key] or {}
		self._cache[self._key].value = toStore
		self._cache[self._key].ts = os.time()
		dispatch(self._callbacks.OnSave, toStore, self)
		push_audit(self._info, self._key, { kind = "force_save", at = os.time(), data = toStore })
		return true
	end

	function methods:SaveCAS(dataInfo, expected_version)
		if type(dataInfo) ~= "table" then error("SaveCAS expects table") end
		local toStore = deep_clone(dataInfo)
		toStore._meta = toStore._meta or {}
		toStore._meta.updated_at = os.time()
		toStore._meta.version = (toStore._meta.version or 0) + 1
		if self._info.options.enable_checksums then
			toStore._meta.checksum = compute_checksum_excluding_meta(toStore)
		end

		local ok, res = pcall(function()
			return self._ds:UpdateAsync(self._key, function(old)
				old = old or {}
				local v = old._meta and old._meta.version or 0
				if v ~= (expected_version or 0) then
					return old
				end
				return toStore
			end)
		end)
		if not ok then warn("DataDeter: SaveCAS UpdateAsync error", res); dispatch(self._callbacks.FailedOver, "save_failed", self._key, res); return false, "update_error" end
		local newver = (res and res._meta and res._meta.version) or 0
		if newver == toStore._meta.version then
			self._cache[self._key] = { value = toStore, ts = os.time() }
			dispatch(self._callbacks.OnSave, toStore, self)
			push_audit(self._info, self._key, { kind = "save_cas", at = os.time(), data = toStore })
			return true, "saved"
		else
			dispatch(self._callbacks.OnUpdate, res, self)
			push_audit(self._info, self._key, { kind = "cas_conflict", at = os.time(), existing = res })
			return false, "conflict"
		end
	end

	function methods:Save(dataInfo, attempts)
		if type(dataInfo) ~= "table" then error("Save expects table") end
		local okSize, errMsg = validate_payload_size(dataInfo, self._info.options.max_payload_size)
		if not okSize then error("payload too large: ".. tostring(errMsg)) end
		local toStore = deep_clone(dataInfo)
		toStore._meta = toStore._meta or {}
		toStore._meta.updated_at = os.time()
		toStore._meta.version = (toStore._meta.version or 0) + 1
		if self._info.options.enable_checksums then
			toStore._meta.checksum = compute_checksum_excluding_meta(toStore)
		end

		local saveJob = function()
			local ok, err = dual_write(self._info, self._key, toStore)
			if not ok then warn("DataDeter: failed durable save key", self._key, err); dispatch(self._callbacks.FailedOver, "save_failed", self._key, err)
			else
				dispatch(self._callbacks.OnSave, toStore, self)
				push_audit(self._info, self._key, { kind = "save", at = os.time(), data = toStore })
				-- optionally broadcast the save to other servers
				if self._info.options.messaging_enabled then pcall(function() messaging_publish(self._info, "save", { key = self._key, data = toStore }) end) end
			end
		end

		self._cache[self._key] = self._cache[self._key] or {}
		self._cache[self._key].value = toStore
		self._cache[self._key].ts = os.time()
		self._cache[self._key]._savefn = saveJob
		self._cache[self._key]._dirty = true
		enqueue_save(self._key, saveJob)
	end

	function methods:SaveWithToken(token, dataInfo, signature)
		if self._info.options.require_session_token then
			local s = validate_session(token, signature)
			if not s then error("invalid or expired session token") end
		end
		return methods.Save(self, dataInfo)
	end

	function methods:ConcileUp(localData, resolver)
		resolver = resolver or nil
		local attempts = self._info.options.reconcile_attempts or DEFAULT_OPTIONS.reconcile_attempts
		for i = 1, attempts do
			local ok, res = pcall(function()
				return self._ds:UpdateAsync(self._key, function(old)
					old = old or {}
					local merged
					if resolver then merged = resolver(old, localData) else merged = old end
					merged._meta = merged._meta or {}
					merged._meta.updated_at = os.time()
					merged._meta.version = (merged._meta.version or 0) + 1
					if self._info.options.enable_checksums then
						merged._meta.checksum = compute_checksum_excluding_meta(merged)
					end
					return merged
				end)
			end)
			if ok then dispatch(self._callbacks.OnUpdate, res, self); push_audit(self._info, self._key, { kind = "concile", at = os.time(), data = res }); return true, res end
			task.wait(self._info.options.reconcile_delay or DEFAULT_OPTIONS.reconcile_delay)
		end
		dispatch(self._callbacks.FailedOver, "concile_failed", self._key)
		push_audit(self._info, self._key, { kind = "concile_failed", at = os.time() })
		return false, "concile_failed"
	end
	
	function methods:SmartCleanCache(intervalTime)
		intervalTime = type(intervalTime) == "number" and intervalTime or self._info.options.clean_interval
		task.spawn(function()
			while task.wait(intervalTime) do
				local entry = self._cache[self._key]
				if entry and entry._dirty and entry._savefn then
					entry._dirty = nil
					enqueue_save(self._key, entry._savefn)
				end
				if entry and entry.ts and (os.time() - entry.ts) > self._info.options.cache_ttl then
					self._cache[self._key] = nil
					break
				end
			end
		end)
	end

	function methods:Flush()
		local entry = self._cache[self._key]
		if entry and entry._savefn then entry._dirty = nil; enqueue_save(self._key, entry._savefn) end
		-- optional broadcast flush/save
		if self._info.options.messaging_enabled then pcall(function() messaging_publish(self._info, "flush", { key = self._key }) end) end
	end

	-- Broadcast that save should happen on other servers when flushing
	function methods:BroadcastSaveOnFlush()
		self:OnSave(function(data)
			if self._info.options.messaging_enabled then pcall(function() messaging_publish(self._info, "save_broadcast", { key = self._key, data = data }) end) end
		end)
	end

	function methods:Reload()
		local ok, res = pcall(function() return self._ds:GetAsync(self._key) end)
		if not ok then warn("DataDeter: Reload GetAsync failed for", self._key, res); dispatch(self._callbacks.FailedOver, "reload_failed", self._key, res); return nil end
		self._cache[self._key] = { value = (res or {}), ts = os.time() }
		return self._cache[self._key].value
	end
	
	function methods:RegisterValidator(name, fn)
		if type(name) ~= "string" or type(fn) ~= "function" then error("RegisterValidator(name, fn) expected") end
		self._info._validators[name] = fn
	end

	function methods:ValidateWith(name, data)
		local fn = self._info._validators[name]
		if not fn then error("validator not found: " .. tostring(name)) end
		local ok, reason = pcall(fn, data)
		if not ok then return false, reason end
		return true
	end

	function methods:Detach(attempts)
		-- dispatch OnDetaching
		dispatch(self._callbacks.OnDetaching, self)
		attempts = attempts or (self._info.options.default_save_attempts or DEFAULT_OPTIONS.default_save_attempts)
		local okPrimary, errPrimary = safeAttempt(function()
			self._ds:RemoveAsync(self._key)
		end, attempts)
		local okBackup = true
		if self._info.options.backup_enabled and self._info._backup_ds then
			okBackup = safeAttempt(function()
				self._info._backup_ds:RemoveAsync(self._key)
			end, attempts)
		end
		if self._info.options.wal_enabled and self._info._wal_ds then
			safeAttempt(function()
				self._info._wal_ds:RemoveAsync(self._key .. (self._info.options.wal_ds_suffix or DEFAULT_OPTIONS.wal_ds_suffix))
			end, attempts)
		end
		if self._info._audit_ds then
			safeAttempt(function()
				self._info._audit_ds:RemoveAsync(self._key .. "_audit")
			end, attempts)
		end
		if self._cache[self._info._id] then self._cache[self._info._id][self._key] = nil end
		-- publish detach to other servers
		if self._info.options.messaging_enabled then pcall(function() messaging_publish(self._info, "detach", { key = self._key }) end) end
		
		methods.Unbind(self)
		return okPrimary and okBackup
	end
	
	function methods:Recover()
		local recovered = recover_from_wal(self._info, self._key)
		if recovered then return true end
		if self._info.options.backup_enabled and self._info._backup_ds then
			local ok, b = pcall(function() return self._info._backup_ds:GetAsync(self._key) end)
			if ok and b then
				local ok2, err2 = pcall(function() self._info.ds:UpdateAsync(self._key, function() return b end) end)
				if not ok2 then warn("DataDeter: recovery primary update failed", err2) else return true end
			end
		end
		return false
	end

	-- messaging helpers on store
	function methods:Publish(action, payload)
		local ok, err = messaging_publish(self._info, action, { key = self._key, payload = payload })
		if not ok then warn("DataDeter: Publish failed", err) end
		return ok, err
	end

	function methods:OnRemote(action, cb)
		if type(cb) ~= "function" then error("OnRemote expects function") end
		local handlers = self._info._remote_handlers or {}
		handlers[action] = handlers[action] or {}
		table.insert(handlers[action], cb)
		self._info._remote_handlers = handlers
		if not self._info._messaging_sub then pcall(function() messaging_subscribe(self._info) end) end
	end

	return setmetatable(store, {__index = methods})
end

-- ===== public api =====
function DataDeter.SetServerSecret(secret, security_level)
	if type(secret) ~= "string" then error("server secret must be string") end
	DEFAULT_OPTIONS.server_secret = secret
	if security_level then DEFAULT_OPTIONS.security_level = clamp(tonumber(security_level) or DEFAULT_OPTIONS.security_level, 0, 100) end
end

function DataDeter.GenerateServerSecret(security_level)
	local s = generate_secret(security_level or DEFAULT_OPTIONS.security_level)
	DEFAULT_OPTIONS.server_secret = s
	DEFAULT_OPTIONS.security_level = clamp(tonumber(security_level) or DEFAULT_OPTIONS.security_level, 0, 100)
	return s
end

function DataDeter.InDataInfo(dataName, dataScope, options)
	assert_string(dataName, "dataName")
	if dataScope ~= nil then assert_string(dataScope, "dataScope") end
	if options ~= nil and typeof(options) ~= "table" and typeof(options) ~= "Instance" then error("options must be a table, Instance, or nil") end
	options = options or {}
	local id = tostring(dataName) .. ":" .. tostring(dataScope or "__default")
	if _infos[id] then return _infos[id] end
	local info = NewInfo(dataName, dataScope, options)
	function info:GetPlayerData(playerNameID, opts)
		assert(playerNameID ~= nil, "playerNameID required")
		return NewStore(info, playerNameID, opts)
	end
	function info:PrintInfo()
		print("DataDeter Info -> ", info.dataName, info.dataScope)
		print("security_level ->", info.options.security_level)
		print("messaging ->", info.options.messaging_enabled)
		print("heartbeat ->", info:GetHeartbeat())
		print("approx size ->", info:GetSize(), "bytes (cache-based)")
	end
	
	_infos[id] = info
	return info
end

function DataDeter.PrintHelp()
	print("== DataDeter help ==")
	print("usage examples:")
	print("local dd = require(path.to.DataDeter)")
	print("dd.SetServerSecret('<long-random-secret>', 80)")
	print("or: local secret = dd.GenerateServerSecret(90)")
	print("local info = dd.InDataInfo('PlayerData','global')")
	print("print(info:GetHeartbeat())  -- 1..1000, higher => healthier (lower load)")
	print("print(info:GetSize())       -- approximate byte size from cache")
	print("local store = info:GetPlayerData(player.UserId)")
	print("store:OnLoading(function(s) print('loading', s._key) end)")
	print("store:OnDetaching(function(s) print('detaching', s._key) end)")
	print("store:OnRemote('save', function(payload, meta) print('remote save', payload) end)")
	print("store:Publish('save', { coins = 10 })  -- broadcast to other servers (signed)")
	print("store:Save(t) or store:ForceSave(t)")
	print("store:Detach()  -- delete user data from datastore (primary + backup + wal + audit)")
	print("store:StartSession(player) -> token, signature")
	print("store:SaveWithToken(token, data, signature)")
	print("store:Recover() -> attempts recovery via WAL/backup")
	print("-- Monitoring: dd.GetMonitor() or info:GetMonitor() returns smoothed metrics + short-term forecast")
end

-- new: GetMonitor (global or per-info)
function DataDeter.GetMonitor(infoName, dataScope)
	-- if provided, returns snapshot for that info; otherwise returns table of snapshots for all infos
	if infoName and type(infoName) == "string" then
		local id = tostring(infoName) .. ":" .. tostring(dataScope or "__default")
		local info = _infos[id]
		if not info then return nil, "info_not_found" end
		return info:GetMonitor()
	end
	local out = {}
	for id, info in pairs(_infos) do
		local ok, snap = pcall(function() return info:GetMonitor() end)
		if ok and snap then out[id] = snap end
	end
	return out
end

-- helping value base to obtain saved data and change its value
function DataDeter.SetValue(data, value_base, starterValue, valueTypeOfTable, saveInterval, caller)
	assert(typeof(data) == "table", "'data' must be the set of GetPlayerData()")
	assert(typeof(value_base) == "Instance" and value_base:IsA("ValueBase"), "'value_base' must be the base of value instance")
	assert(typeof(starterValue) == "table", "'starterValue' must be table of starter table value for first data appearance")
	assert(typeof(valueTypeOfTable) == "string", "'valueTypeOfTable' causes invalid parameter of table data")
	
	saveInterval = saveInterval or 30
	caller = caller or nil
	
	local ok, datas = pcall(function()
		return data:Get(caller)
	end)
	
	if not ok then
		warn("cannot obtain data", datas)
		datas = {}
		return
	end
	datas = datas or starterValue
	
	local function SavingDataMethod(plr : Player)
		local getData = datas[valueTypeOfTable]
		if value_base then
			datas[valueTypeOfTable] = value_base.Value
		end
		
		local sessionLock, owner = data:AcquireSessionLock(plr.UserId, 5)
		if sessionLock then
			local success, err = pcall(function()
				data:ForceSave(datas)
			end)
			data:ReleaseSessionLock(owner)
			if not success then
				warn("cannot save data", err)
				return
			end
		end
	end
	
	Players.PlayerRemoving:Connect(SavingDataMethod)
	game:BindToClose(function()
		for _, v in ipairs(Players:GetPlayers()) do
			SavingDataMethod(v)
		end
	end)
	
	task.spawn(function()
		while task.wait(saveInterval) do
			for _, v in ipairs(Players:GetPlayers()) do
				SavingDataMethod(v)
			end
		end
	end)
end

DataDeter._internal = { build_key = build_key, cache = _cache, _infos = _infos, _sessions = _sessions }

start_cache_cleaner(DEFAULT_OPTIONS.clean_interval) -- ur mom

-- here we are, thanks for the journey

return DataDeter
