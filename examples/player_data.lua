local DataDeter = require(path.to.DataDeter)

-- data info container variable
local dataInfo = _G.DataInfo

local Players = game:GetService("Players")

-- this is optional, callbacks
local actions = 
{
  OnSave = function()
      print("Data saved!")
  end,
  
  OnObtain = function()
      print("Data obtained!")
  end,

  OnRelease = function()
      print("Session released!")
  end,
  
  FailedOver = function(err)
    print("DataDeter's error expected by:", err)
  end,
  
  OnLoading = function()
      print("Data is loading...")
  end,

  OnBinding = function()
      print("Data binded!")
  end,
}

Players.PlayerAdded:Connect(function(plr)
    local user = plr.UserId
    if not dataInfo then return end

    local playerData = dataInfo:GetPlayerData(user, actions)

    local ok, datas = pcall(function()
        -- you just can not use player in parameter, it's optional, caller for player who called the data obtain, prevents over-writing data
        -- callbacks action for OnLoading should be called here.
        return playerData:Get(plr)
    end)
    if not ok then
       warn("data failed to obtain")
       datas = {}
    end

    -- callbacks action for OnObtain should be called after 
    datas = datas or { money = 10, level = 1, offline = os.time() }

    -- when session lock is failed, it attempts six times or until succesful
    local lockStatus, ownerId = playerData:AcquireSessionLock(user, 6)
    if lockStatus then
      
        local ok, err = pcall(function()
            -- you can use Save() too, but better use ForceSave for this.
            playerData:ForceSave(datas)
        end)
      
        playerData:ReleaseSessionLock(ownerId)
        -- callbacks action for OnRelease should be called.

        if not ok then warn("saving failed due to: " .. err) end
        -- callbacks action for OnSave should be called.
    else
        warn("session lock failed, attempting to lock the session again...")
    end

    -- you can use plr.UserId also, binding data to player with exclusive data-writing.
    -- callbacks action for OnBinding should be called here, if this were not binding before. If it already binded, FailedOver called instead.
    playerData:BindData(plr)
    -- data binding will auto-save player's data from force shutdown, kicking, or leaving the experience.
    -- also, this would not be over-written, and binding the data to player exclusively.

    -- configurations for players from data
    local config = Instance.new("Folder")
    config.Name = "PlayerConfig"

    -- moneyyyyyyy
    local money = Instance.new("IntValue")
    money.Name = "Money"
    money.Value = datas.money
    money.Parent = config

    -- levelllll
    local level = Instance.new("IntValue")
    level.Name = "Level"
    level.Value = datas.level
    level.Parent = config

    config.Parent = plr

    -- cache will be cleaned in interval of 15 seconds.
    playerData:SmartCleanCache(15)
end)
