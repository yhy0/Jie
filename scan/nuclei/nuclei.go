package nuclei

/**
  @author: yhy
  @since: 2023/2/1
  @desc: https://github.com/projectdiscovery/nuclei/blob/main/v2/examples/simple.go
**/

import (
	"context"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/external/customtemplates"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	JieOutput "github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/util"
	"os"
	"path"
	"sync"
	"time"
)

var updateLock sync.Mutex

func Scan(c *input.CrawlResult) {
	// todo payload 可以考虑和基础的信息扫描、 fuzz分开，防止被 waf 检测到发大量 payload 被封
	templates, tags := generateTemplates(c.Fingerprints)

	// 扫描结果获取
	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		JieOutput.OutChannel <- JieOutput.VulMessage{
			DataType: "web_vul",
			Plugin:   "POC",
			VulData: JieOutput.VulData{
				CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
				Target:      c.Target,
				Ip:          event.IP,
				Param:       event.TemplateURL,
				Request:     event.Request,
				Response:    event.Response,
				Payload:     fmt.Sprintf("[TemplateID]: %s  [CURLCommand]: %s", event.TemplateID, event.CURLCommand),
				Description: event.Info.Description,
			},
			Level: util.FirstToUpper(event.Info.SeverityHolder.Severity.String()),
		}

	}

	nuclei(c, templates, tags, outputWriter)

}

func nuclei(c *input.CrawlResult, templates []string, tags []string, outputWriter *testutils.MockOutputWriter) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()
	home, _ := os.UserHomeDir()
	defaultOpts := &types.Options{
		Targets:       []string{c.Target},
		Proxy:         []string{conf.GlobalConfig.WebScan.Proxy},
		AutomaticScan: false, // 根据识别到的指纹自动映射标签扫描
		Templates:     templates,
		ExcludedTemplates: []string{
			"vulnerabilities/generic/cors-misconfig.yaml", // cors
			"technologies/",
			"fuzzing/wordpress-plugins-detect.yaml",
			"fuzzing/wordpress-themes-detect.yaml",
		},
		ExcludeTags:                []string{"dos", "tech"},
		TemplatesDirectory:         path.Join(home, "nuclei-templates"),
		Workflows:                  []string{},
		Tags:                       tags,
		RemoteTemplateDomainList:   []string{"api.nuclei.sh"},
		JSON:                       false,
		JSONRequests:               false,
		MaxRedirects:               10,
		CustomHeaders:              []string{},
		InteractshURL:              "",
		InteractshToken:            "",
		ProjectPath:                "",
		InteractionsCacheSize:      5000,
		InteractionsEviction:       60,
		InteractionsPollDuration:   5,
		InteractionsCoolDownPeriod: 5,
		RateLimit:                  80,
		BulkSize:                   25,
		TemplateThreads:            25,
		HeadlessBulkSize:           10,
		HeadlessTemplateThreads:    10,
		Timeout:                    5,
		Retries:                    1,
		MaxHostError:               30,
		PageTimeout:                20,
		Debug:                      false,
		ProxyInternal:              false,
		StatsInterval:              5,
		Metrics:                    false,
		UpdateTemplates:            true, // 更新模板
	}

	// 防止多个进程一起更新、下载模板，加锁
	updateOptions := &Runner{
		options: defaultOpts,
	}
	// parse the runner.options.GithubTemplateRepo and store the valid repos in runner.customTemplateRepos
	updateOptions.customTemplates = customtemplates.ParseCustomTemplates(defaultOpts)
	updateLock.Lock()
	updateOptions.updateTemplates()
	updateLock.Unlock()

	protocolstate.Init(defaultOpts)
	protocolinit.Init(defaultOpts)

	// 只在 option 中指定代理并不行, nuclei 会对 proxy 代理进行处理，最终使用的是 types.ProxyURL 或 types.ProxySocksURL, 这里直接将原方法执行一般
	if err := loadProxyServers(defaultOpts); err != nil {
		fmt.Println(err)
	}
	defaultOpts.Targets = []string{c.Target}

	defaultOpts.ExcludeTags = config.ReadIgnoreFile().Tags

	interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		logging.Logger.Errorf("Could not create interact client: %s\n", err)
		return
	}
	defer interactClient.Close()

	catalog := disk.NewCatalog(path.Join(home, "nuclei-templates"))
	executerOpts := protocols.ExecuterOptions{
		Output:          outputWriter,
		Options:         defaultOpts,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
		Interactsh:      interactClient,
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
	}
	engine := core.New(defaultOpts)
	engine.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		logging.Logger.Errorf("Could not create workflow loader: %s\n", err)
		return
	}
	executerOpts.WorkflowLoader = workflowLoader

	configObject, err := config.ReadConfiguration()
	if err != nil {
		logging.Logger.Errorf("Could not read config: %s\n", err)
		return
	}
	store, err := loader.New(loader.NewConfig(defaultOpts, configObject, catalog, executerOpts))
	if err != nil {
		logging.Logger.Errorf("Could not create loader client: %s\n", err)
		return
	}
	store.Load()

	inputArgs := []*contextargs.MetaInput{{Input: c.Target}}

	_ = engine.Execute(store.Templates(), &inputs.SimpleInputProvider{Inputs: inputArgs})
	engine.WorkPool().Wait() // Wait for the scan to finish
}
