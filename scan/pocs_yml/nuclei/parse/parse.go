package parse

import (
	"context"
	"embed"
	"errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	nucli_templates "github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/scan/pocs_yml/nuclei/structs"
	"github.com/yhy0/Jie/scan/pocs_yml/nuclei/templates"
	"time"
)

var (
	ExecuterOptions protocols.ExecuterOptions
)

func InitExecuterOptions(rate int, timeout int, proxy string) {
	fakeWriter := structs.FakeWrite{}

	progress := &structs.FakeProgress{}
	o := types.Options{
		RateLimit:               rate,
		BulkSize:                25,
		TemplateThreads:         25,
		HeadlessBulkSize:        10,
		HeadlessTemplateThreads: 10,
		Timeout:                 timeout,
		Retries:                 1,
		MaxHostError:            30,
		Proxy:                   []string{proxy},
	}
	// loading the proxy server list from file or cli and test the connectivity
	if err := loadProxyServers(&o); err != nil {
		logging.Logger.Errorln(err)
	}

	err := protocolinit.Init(&o)

	if err != nil {
		logging.Logger.Errorln("Nuclei InitExecuterOptions error")
		return
	}

	catalog := disk.NewCatalog("")
	ExecuterOptions = protocols.ExecuterOptions{
		Output:      &fakeWriter,
		Options:     &o,
		Progress:    progress,
		Catalog:     catalog,
		RateLimiter: ratelimit.New(context.Background(), uint(rate), time.Second),
	}
}

func ParsePoc(filename string) (*structs.Poc, error) {
	var err error
	poc, err := nucli_templates.Parse(filename, nil, ExecuterOptions)
	if err != nil {
		return nil, err
	}
	if poc == nil {
		return nil, nil
	}
	if poc.ID == "" {
		return nil, errors.New("Nuclei poc id can't be nil")
	}
	return poc, nil
}

// Parse 通过 embed.FS 加载默认文件
func Parse(filename string, pocs embed.FS) (*structs.Poc, error) {
	poc, err := templates.Parse(filename, nil, ExecuterOptions, pocs)
	if err != nil {
		return nil, err
	}
	if poc == nil {
		return nil, nil
	}
	if poc.ID == "" {
		return nil, errors.New("Nuclei poc id can't be nil")
	}

	return (*structs.Poc)(poc), nil
}
