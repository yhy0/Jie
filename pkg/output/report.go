package output

import (
	_ "embed"
	"github.com/yhy0/logging"
	"os"
	"text/template"
)

/**
   @author yhy
   @since 2023/9/18
   @desc //TODO
**/

//go:embed vulnReport.tmpl
var vulnReportTmpl []byte

func GenerateVulnReport(filename string) {
	vulMessages := make([]VulMessage, 0)

	for vulMessage := range VulMessageChan {
		// Append the received vulMessage to the list
		vulMessages = append(vulMessages, vulMessage)

		// Create the output file
		outputFile, err := os.Create(filename)
		if err != nil {
			logging.Logger.Errorln("Error creating output file:", err)
			return
		}

		// Execute the template and write the output to the file
		tmpl, err := template.New("vuln_report").Parse(string(vulnReportTmpl))
		if err != nil {
			logging.Logger.Errorln("Error parsing template:", err)
			return
		}

		err = tmpl.Execute(outputFile, struct {
			VulnMessages []VulMessage
		}{
			VulnMessages: vulMessages,
		})
		if err != nil {
			logging.Logger.Errorln("Error executing template:", err)
			return
		}

		outputFile.Close()
	}
}
