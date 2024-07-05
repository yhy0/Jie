package conf

import (
    folderutil "github.com/projectdiscovery/utils/folder"
    wappalyzer "github.com/projectdiscovery/wappalyzergo"
    "path/filepath"
)

/**
  @author: yhy
  @since: 2023/2/1
  @desc: //TODO
**/

var GlobalConfig = &Config{}

var ConfigFile string

var NoProgressBar bool

// FilePath 一些配置文件的默认位置
var FilePath string

var Wappalyzer *wappalyzer.Wappalyze

func init() {
    homedir := folderutil.HomeDirOrDefault("")
    
    userCfgDir := filepath.Join(homedir, ".config")
    
    FilePath = filepath.Join(userCfgDir, "Jie")
}
