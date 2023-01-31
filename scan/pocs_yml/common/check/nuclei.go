package check

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/yhy0/Jie/logging"
	nuclei_structs "github.com/yhy0/Jie/scan/pocs_yml/nuclei/structs"
)

func executeNucleiPoc(target string, poc *nuclei_structs.Poc) (results []*output.ResultEvent, isVul bool, err error) {
	isVul = false

	logging.Logger.Debugf("Run Nuclei Poc [%s] for %s", poc.Info.Name, target)

	e := poc.Executer
	results = make([]*output.ResultEvent, 0, e.Requests())

	err = e.ExecuteWithResults(contextargs.NewWithInput(target), func(result *output.InternalWrappedEvent) {
		if len(result.Results) > 0 {
			isVul = true
		}
		results = append(results, result.Results...)
	})

	if len(results) == 0 {
		results = append(results, &output.ResultEvent{TemplateID: poc.ID, Matched: target})
	}
	return results, isVul, err
}
