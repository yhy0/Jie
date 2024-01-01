package conf

import (
    folderutil "github.com/projectdiscovery/utils/folder"
    "path/filepath"
)

/**
  @author: yhy
  @since: 2023/2/1
  @desc: //TODO
**/

var GlobalConfig = &Config{}

var ConfigFile string

// FilePath 一些配置文件的默认位置
var FilePath string

func init() {
    homedir := folderutil.HomeDirOrDefault("")

    userCfgDir := filepath.Join(homedir, ".config")

    FilePath = filepath.Join(userCfgDir, "Jie")
}
