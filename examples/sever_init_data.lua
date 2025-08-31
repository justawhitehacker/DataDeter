-- server script for initialize datadeter
local DataDeter = require(path.to.DataDeter)
DataDeter.SetServerSecret("ILoveToUseMyHandsToPrayForGod,notLettingMyselfBecomeADisgraceInTheEyesOfGod") -- recommended use 32 chars, better 64 chars or more.
DataDeter.GenerateServerSecret(75) -- better 60..92, 100 compromises your cpu

-- using global variable for dataInf9 (you can use everything to make global variable securely)
_G.DataInfo = {
  playerData = DataDeter.InDataInfo("PlayerData", "_global", {
      security_level 75,
      require_session_token = true,
      require_token_signature = true,
      backup_enabled = true,
      wal_enabled = true
  })
}
