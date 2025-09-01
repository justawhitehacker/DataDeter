-- RaihanMan18

-- i made this example, you can copy this example code and custom your own
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerStorage = game:GetService("ServerStorage")
local Players = game:GetService("Players")

local Events = ReplicatedStorage:WaitForChild("Events")
local BlockPlaced = Events:FindFirstChild("BlockPlacedEvent")

local mods = ServerStorage:WaitForChild("Modules")
local DataDeter = require(mods.DataDeter)

DataDeter.SetServerSecret("TOP-SECRET", 75) -- global security_level to 75, set the server secret

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
    if not ok or typeof(datas) ~= "table" then
        warn("data cannot be obtained")
        datas = {}
    end
    datas = datas or {}

    local bindOK, errBind = playerData:BindData(plr)
    if not bindOK then
        warn("data cannot be binded due to: " .. tostring(errBind))
    end

    local objectsCount = tonumber(datas.obj_count) or 0
    local objs = datas.objects or {}

    local baseModel = Instance.new("Model")
    baseModel.Name = plr.Name .. "_base"
    baseModel.Parent = workspace.WorldBlock
        
    -- deserialize objects
    task.spawn(function()
        local countBatch = 0
        for i = 1, objectsCount do
            local obj = objs[i]

            local pos = Vector3.new(obj.pos and obj.pos.x or 0,    obj.pos and obj.pos.y or 0,    obj.pos and obj.pos.z or 0)
            local rVec = Vector3.new(obj.rightvec and obj.rightvec.x or 1,    obj.rightvec and obj.rightvec.y or 0,    obj.rightvec and obj.rightvec.z or 0)
            local uVec = Vector3.new(obj.upvec and obj.upvec.x or 0,    obj.upvec and obj.upvec.y or 1,    obj.upvec and obj.upvec.z or 0)
                    
            local part = Instance.new("Part")
            part.Name = obj.name
            part.CFrame = CFrame.fromMatrix(pos, rVec, uVec)
            part.Anchored = true
            part.CanCollide = true
            if obj.color and typeof(obj.color) == "table" then
                local color = obj.color
                part.Color = Color3.fromRGB(color.r, color.g, color.b)
            end
            part.Size = Vector3.new(obj.size and obj.size.x or 1, obj.size and obj.size.y or 1, obj.size and obj.size.z or 1)
            part.Parent = baseModel

            countBatch = countBatch + 1
            if countBatch >= 30 then
                task.wait()
                countBatch = 0 -- reset counter
            end
        end

        local previousPlace = datas.previous_place_cframe
        if not previousPlace or not previousPlace.right_vec or not previousPlace.up_vec then return end

        local pos = Vector3.new(previousPlace.x,    previousPlace.y,    previousPlace.z)        
        
        local rightVec = Vector3.new(previousPlace.right_vec.x,    previousPlace.right_vec.y,    previousPlace.right_vec.z)
        local upVec = Vector3.new(previousPlace.up_vec.x,    previousPlace.up_vec.y,    previousPlace.up_vec.z)

        -- roblox automatically calculating for cross product, but i did manual instead
        local lookVec = rightVec:Cross(upVec).Unit -- i used cross product then normalize vector manually, you can skip this line
                
        -- base translations
        baseModel:PivotTo(CFrame.fromMatrix(pos, rightVec, upVec))
    end)

    -- saving the loaded base, to prevent data loss
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

    -- at best counter
    playerData:SmartCleanCache(15)
end)

-- block placed event
BlockPlaced.OnServerEvent:Connect(function(player, targetHitPos, targetHitNormal, targetHitInstance)
    local user = "session_data->" .. player.UserId
    local playerData = plrData:GetPlayerData(user)

    local function snapToGrid(pos, size)
        return Vector3.new(
            math.floor(pos.X / size.X + 0.5) * size.X,
            math.floor(pos.Y / size.Y + 0.5) * size.Y,
            math.floor(pos.Z / size.Z + 0.5) * size.Z
        )
    end

    local function normalizePos(normal, size)
        -- lanjut nanti lek
    end

    playerData:FailedOver(function(err)
        warn("player data error happened: " .. err)
    end)

    playerData:OnSave(function()
        print("data saved after block placed!")
    end)

    local token, signature = playerData:StartSession(plr)
    local okLock, ownerId = playerData:AcquireSessionLock(user, 5)
    if okLock then
        local ok, err = pcall(function()
            playerData:SaveWithToken(token, ..., signature)
        end)
        if not ok then warn("data failed to save due to: " .. err) end
        playerData:ReleaseSessionLock(ownerId)
        playerData:EndSession(token)
    else
        warn("session lock failed due")
    end
end)


