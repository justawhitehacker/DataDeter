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

-- fires when player is joining the game
Players.PlayerAdded:Connect(function(plr)
    local user = "session_data->" .. plr.UserId
    local playerData = plrData:GetPlayerData(user)

    -- callback if failed
    playerData:FailedOver(function(err)
        warn("DataDeter's error expected: " .. err)
    end)

    local ok, datas = pcall(function()
        return playerData:Get(plr)
    end)
    if not ok then
        warn("data cannot be obtained")
        datas = {}
    end
    datas = datas or {}

    local lockSuccess, ownerId = playerData:AcquireSessionLock(user, 5)
    if lockSuccess then
        local ok, err = pcall(function()
            -- forcing save data, serialize objects
            playerData:ForceSave(datas)        
        end)
        playerData:ReleaseSessionLock(ownerId)
        if not ok then warn("data cannot be saved: " .. err) end
    else
        warn("data session cannot be locked")
    end       

    local objectsCount = datas.data_counts

    local baseModel = Instance.new("Model")
    baseModel.Name = plr.Name .. "_base"
    baseModel.Parent = workspace.WorldBlock
        
    -- deserialize objects
    task.spawn(function()
        for i = 1, objectsCount do
            local obj = datas.objects[i]

            local pos = Vector3.new(obj.pos.x,    obj.pos.y,    obj.pos.z)
            local rVec = Vector3.new(obj.rightvec.x,    obj.rightvec.y,    obj.rightvec.z)
            local uVec = Vector3.new(obj.upvec.x,    obj.upvec.y,    obj.upvec.z)
                    
            local part = Instance.new("Part")
            part.Name = obj.name
            part.CFrame = CFrame.fromMatrix(pos, rVec, uVec)
            part.Anchored = true
            part.CanCollide = true
            part.Color = Color3.fromRGB(obj.color.r, obj.color.g, obj.color.b)
            part.Size = Vector3.new(obj.size.x, obj.size.y, obj.size.z)
            part.Parent = baseModel
        end

        local previousPlace = datas.previous_place_cframe

        local pos = Vector3.new(previousPlace.x,    previousPlace.y,    previousPlace.z)        
        
        local rightVec = Vector3.new(previousPlace.right_vec.x,    previousPlace.right_vec.y,    previousPlace.right_vec.z)
        local upVec = Vector3.new(previousPlace.up_vec.x,    previousPlace.up_vec.y,    previousPlace.up_vec.z)

        -- roblox automatically calculating for cross product, but i did manual instead
        local lookVec = rightVec:Cross(upVec).Unit -- i used cross product then normalize vector manually, you can skip this line
                
        -- base translations
        baseModel:PivotTo(CFrame.fromMatrix(pos, rightVec, upVec, lookVec))
    end)

    -- at best counter
    playerData:BindData(plr)
    playerData:SmartCleanCache(15)
end)


