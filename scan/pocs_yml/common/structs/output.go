package structs

import (
	"github.com/yhy0/Jie/logging"
	"os"
)

type Output interface {
	Write(result Result)
}

type StandardOutput struct{}

func (o *StandardOutput) Write(result Result) {
	return
}

type FileOutput struct {
	F    *os.File
	Json bool
}

func (o *FileOutput) Write(result Result) {
	var row string
	if o.Json {
		row = result.JSON()
	} else {
		row = result.STR()
		if result.SUCCESS() {
			row = "[+] " + row
		} else {
			row = "[-] " + row
		}
	}

	_, err := o.F.WriteString(row + "\n")
	if err != nil {
		logging.Logger.Errorf("Can't write file '%s': %#v", o.F.Name(), err)
	}

}
