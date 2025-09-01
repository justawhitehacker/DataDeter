-- RaihanMan18

-- i made this example, you can copy this example code and custom your own
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerStorage = game:GetService("ServerStorage")
local Players = game:GetService("Players")

local Events = ReplicatedStorage:WaitForChild("Events")
local BlockPlaced = Events:WaitForChild("BlockPlacedEvent")
local Objects = ReplicatedStorage:WaitForChild("Objects")

local mods = ServerStorage:WaitForChild("Modules")
local DataDeter = require(mods.DataDeter)
local sec = require(mods.Secret)

DataDeter.SetServerSecret(sec, 75) -- global security_level to 75, set the server secret

local plrData = DataDeter.InDataInfo("PlayersData", "global", {
    security_level = 75,
    require_session_token = true,
    require_token_signature = true,
    backup_enabled = true,
    wal_enabled = true
})

-- fires when player is joining the game
Players.PlayerAdded:Connect(function(plr)
    local playerData = plrData:GetPlayerData(plr.UserId)

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
            if not obj or typeof(obj) ~= "table" then continue end

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
                part.Color = Color3.new(color.r or 1, color.g or 0, color.b or 0)
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
    local lockSuccess, ownerId = playerData:AcquireSessionLock(nil, 5)
    local token, signature = playerData:StartSession(plr)
    if lockSuccess then
        local ok, err = pcall(function()
            -- forcing save data, serialize objects
            playerData:SaveWithToken(token, datas, signature)
        end)
        playerData:ReleaseSessionLock(ownerId)
        if not ok then warn("data cannot be saved: " .. err) end
    else
        warn("data session cannot be locked")
    end       

    -- at best counter
    playerData:SmartCleanCache(15)
end)

Players.PlayerRemoving:Connect(function(plr)
    local playerData = plrData:GetPlayerData(plr.UserId)

    if playerData then
        playerData:Flush()
    end
end)

-- block placed event
BlockPlaced.OnServerEvent:Connect(function(player, targetHitPos, targetHitNormal, targetHitInstance, rotationX, rotationY)
    if typeof(targetHitPos) ~= "Vector3" or typeof(targetHitNormal) ~= "Vector3" or typeof(targetHitInstance) ~= "Instance" then
        return
    end

    if typeof(rotationX) ~= "number" or (rotationX < -90 and rotationX > 90) then
        return
    end
    rotationX = math.floor(rotationX)

    if typeof(rotationY) ~= "number" or (rotationY < -90 and rotationY > 90) then
        return
    end
    rotationY = math.floor(rotationY)
        
    local playerData = plrData:GetPlayerData(player.UserId)

    local ok, datas = pcall(function()
        return playerData:Get(player)
    end)
    if not ok or typeof(datas) ~= "table" then
        warn("data cannot be obtained")
        datas = {}
    end

    local objCount = datas.obj_count and tonumber(datas.obj_count) or 0
    local objs = datas.objects or {}

    local obj = objs[objCount + 1] or {}
    objs[objCount + 1] = obj

    local function snapToGrid(pos, size)
        return math.floor(pos / size + 0.5) * size
    end

    local function normalizePos(normal, size)
        return Vector3.new(
            (normal.X ~= 0) and (normal.X * (size.X / 2)) or 0,
            (normal.Y ~= 0) and (normal.Y * (size.Y / 2)) or 0,
            (normal.Z ~= 0) and (normal.Z * (size.Z / 2)) or 0
        )
    end

    playerData:FailedOver(function(err)
        warn("player data error happened: " .. err)
    end)

    playerData:OnSave(function()
        print("data saved after block placed!")
    end)

    local blockUnclone = Objects:FindFirstChild("Block")
    if not blockUnclone then return end

    local modelBase = workspace.WorldBlock:FindFirstChild(player.Name .. "_base")
    if not modelBase then return end
        
    local block = blockUnclone:Clone()
    block.Parent = modelBase
    block.Name = block.Name .. tostring(objCount)
    block.Color = Color3.new(1, 0, 0)
    block.Size = Vector3.new(3, 3, 3)
    
    local rotate = CFrame.Angles(math.rad(rotationX or 0), math.rad(rotationY or 0), 0)
    targetHitNormal = normalizePos(targetHitNormal, block.Size)
    targetHitPos = Vector3.new(
        snapToGrid(targetHitPos.X + targetHitNormal.X, block.Size.X / 2),
        snapToGrid(targetHitPos.Y + targetHitNormal.Y, block.Size.Y / 2),
        snapToGrid(targetHitPos.Z + targetHitNormal.Z, block.Size.Z / 2)
    )
        
    block.CFrame = CFrame.new(targetHitPos) * rotate

    obj.color = { r = block.Color.R, g = block.Color.G, b = block.Color.B }
    obj.size = { x = block.Size.X, y = block.Size.Y, z = block.Size.Z }
    obj.pos = { x = block.Position.X, y = block.Position.Y, z = block.Position.Z }
    obj.rightvec = { x = block.CFrame.RightVector.X, y = block.CFrame.RightVector.Y, z = block.CFrame.RightVector.Z }
    obj.upvec = { x = block.CFrame.UpVector.X, y = block.CFrame.UpVector.Y, z = block.CFrame.UpVector.Z }

    local prevPlace = datas.previous_place_cframe or {}
    local pivot = modelBase:GetPivot()

    prevPlace.x = pivot.Position.X
    prevPlace.y = pivot.Position.Y
    prevPlace.z = pivot.Position.Z

    prevPlace.right_vec = { x = pivot.RightVector.X, y = pivot.RightVector.Y, z = pivot.RightVector.Z }
    prevPlace.up_vec = { x = pivot.UpVector.X, y = pivot.UpVector.Y, z = pivot.UpVector.Z }
    
    datas.obj_count = (tonumber(datas.obj_count) or 0) + 1 
    

    local token, signature = playerData:StartSession(player)
    local okLock, ownerId = playerData:AcquireSessionLock(nil, 5)
    if okLock then
        local ok, err = pcall(function()
            playerData:SaveWithToken(token, datas, signature)
        end)
        if not ok then warn("data failed to save due to: " .. err) end
        playerData:ReleaseSessionLock(ownerId)
        playerData:EndSession(token)
    else
        warn("session lock failed")
    end
end)


