package output

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/mgutz/ansi"
	"github.com/yhy0/Jie/logging"
)

/**
  @author: yhy
  @since: 2023/1/4
  @desc: //TODO
**/

var OutChannel = make(chan VulMessage)

type VulMessage struct {
	DataType string  `json:"data_type"`
	VulData  VulData `json:"vul_data"`
	Plugin   string  `json:"plugin"`
	Level    string  `json:"level"`
}

type VulData struct {
	CreateTime string `json:"create_time"`
	Target     string `json:"target"`
	Ip         string `json:"ip"`
	Method     string `json:"method"`
	Param      string `json:"param"`
	Payload    string `json:"payload"`
	Request    string `json:"request"`
	Response   string `json:"response"`
}

func (vul *VulMessage) PrintScreen() string {
	var screen []string
	screen = append(screen, aurora.Red(fmt.Sprintf("[Vuln: %s]", vul.Plugin)).String())
	screen = append(screen, ansi.Color(fmt.Sprintf("[Vuln: %s]", vul.Plugin), "red+b"))
	screen = append(screen, ansi.Color(fmt.Sprintf("Level: %s", vul.Level), "red+b"))
	screen = append(screen, ansi.Color(fmt.Sprintf("Target: %s", vul.VulData.Target), "red+b"))

	if vul.VulData.Ip != "" {
		screen = append(screen, ansi.Color(fmt.Sprintf("Ip: %s", vul.VulData.Ip), "red+b"))
	}
	if vul.VulData.Method != "" {
		screen = append(screen, ansi.Color(fmt.Sprintf("Method: %s", vul.VulData.Method), "red+b"))
	}
	if vul.VulData.Param != "" {
		screen = append(screen, ansi.Color(fmt.Sprintf("Param: %s", vul.VulData.Param), "red+b"))
	}

	if vul.VulData.Payload != "" {
		screen = append(screen, ansi.Color(fmt.Sprintf("Payload: %s", vul.VulData.Payload), "red+b"))
	}

	var res = ""
	for i := 0; i < len(screen); i++ {
		res += fmt.Sprintf("%s\n ", screen[i])
	}
	return res
}

// 漏洞级别
//Critical
//High
//Medium
//Low

//type VulMessage struct {
//	VulData struct {
//		CreateTime time.Time `json:"create_time"`
//		Detail     struct {
//			Addr  string `json:"addr"`
//			Extra struct {
//				Links []string `json:"links"`
//				Param struct {
//					Key      string `json:"key"`
//					Position string `json:"position"`
//					Value    string `json:"value"`
//				} `json:"param"`
//			} `json:"extra"`
//			Payload  string      `json:"payload"`
//			SnapShot [][2]string `json:"snapshot"`
//		} `json:"detail"`
//		Plugin string `json:"plugin"`
//		Target struct {
//			Params []struct {
//				Path     string `json:"path"`
//				Position string `json:"position"`
//			} `json:"params"`
//			Url string `json:"url"`
//		} `json:"target"`
//	} `json:"vul_data"`
//	DataType string `json:"data_type"`
//}

func Tesss() {
	logging.Logger.Infoln("================")
}
