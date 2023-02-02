package output

import (
	"fmt"
)

/**
  @author: yhy
  @since: 2023/1/4
  @desc: //TODO
**/

var OutChannel = make(chan VulMessage)

// 漏洞等级
var (
	Low      = "Low"
	High     = "High"
	Medium   = "Medium"
	Critical = "Critical"
)

type VulMessage struct {
	DataType string  `json:"data_type"`
	VulData  VulData `json:"vul_data"`
	Plugin   string  `json:"plugin"`
	Level    string  `json:"level"`
}

type VulData struct {
	CreateTime  string `json:"create_time"`
	Target      string `json:"target"`
	Ip          string `json:"ip"`
	Method      string `json:"method"`
	Param       string `json:"param"`
	Payload     string `json:"payload"`
	Description string `json:"description"`
	Request     string `json:"request"`
	Response    string `json:"response"`
}

func (vul *VulMessage) PrintScreen() string {
	var screen []string
	screen = append(screen, fmt.Sprintf("[Vuln: %s]", vul.Plugin))
	screen = append(screen, fmt.Sprintf("Level: %s", vul.Level))
	screen = append(screen, fmt.Sprintf("Target: %s", vul.VulData.Target))

	if vul.VulData.Ip != "" {
		screen = append(screen, fmt.Sprintf("Ip: %s", vul.VulData.Ip))
	}
	if vul.VulData.Method != "" {
		screen = append(screen, fmt.Sprintf("Method: %s", vul.VulData.Method))
	}
	if vul.VulData.Param != "" {
		screen = append(screen, fmt.Sprintf("Param: %s", vul.VulData.Param))
	}

	if vul.VulData.Payload != "" {
		screen = append(screen, fmt.Sprintf("Payload: %s", vul.VulData.Payload))
	}
	if vul.VulData.Description != "" {
		screen = append(screen, fmt.Sprintf("Description: %s", vul.VulData.Description))
	}

	var res = ""
	for i := 0; i < len(screen); i++ {
		res += fmt.Sprintf("%s\n ", screen[i])
	}
	return "\n" + res
}

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
