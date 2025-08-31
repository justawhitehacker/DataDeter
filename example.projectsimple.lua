-- RaihanMan18
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerStorage = game:GetService("ServerStorage")
local Players = game:GetService("Players")

local mods = ServerStorage:WaitForChild("Modules")
local DataDeter = require(mods.DataDeter)

DataDeter.SetServerSecret("MyHandsAreFullOfSinsButCouldIForgiveMyselfToGodForMyBadBehavioursInThisWorld?", 75) -- global security_level to 75

local plrData = DataDeter.InDataInfo("PlayersData", "global", {
    security_level = 75,
    require_session_token = true,
    require_token_signature = true,
    backup_enabled = true,
    wal_enabled = true
})

Players.PlayerAdded:Connect(function(plr)
    local user = "session_data->" .. plr.UserId
    local playerData = plrData:GetPlayerData(user)

    -- callback if failed
    playerData:FailedOver(function(err)
        warn("DataDeter's error expected: " .. err)
    end)

    -- lanjut nanti lek, mau tidur dulu
end)

Players.PlayerRemoving:Connect(function(plr)
    local user = "session_data->" .. plr.UserId
    local playerData = plrData:GetPlayerData(user)

    -- callback if failed
    playerData:FailedOver(function(err)
        warn("DataDeter's error expected: " .. err)
    end)

    -- lanjut nanti lek, mau tidur dulu
end)

