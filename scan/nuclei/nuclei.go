package nuclei

/**
  @author: yhy
  @since: 2023/2/1
  @desc: https://github.com/projectdiscovery/nuclei/blob/main/v2/examples/simple.go
	todo 去除目录爆破等规则，目录爆破通过 bbscan 进行测试
**/

import (
	"context"
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
	JieOutput "github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/logging"
	"os"
	"path"
	"sync"
	"time"
)

var updateLock sync.Mutex

func Scan(target string, fingerprints []string) {
	// todo payload 可以考虑和基础的信息扫描、 fuzz分开，防止被 waf 检测到发大量 payload 被封
	templates, tags := generateTemplates(fingerprints)

	// 扫描结果获取
	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		JieOutput.OutChannel <- JieOutput.VulMessage{
			DataType: "web_vul",
			Plugin:   "POC",
			VulnData: JieOutput.VulnData{
				CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
				Target:      target,
				Ip:          event.IP,
				Param:       event.TemplateURL,
				Request:     event.Request,
				Response:    event.Response,
				Payload:     event.TemplateID,
				CURLCommand: event.CURLCommand,
				Description: event.Info.Description,
			},
			Level: util.FirstToUpper(event.Info.SeverityHolder.Severity.String()),
		}
	}

	nuclei(target, templates, tags, outputWriter)
}

func nuclei(target string, templates []string, tags []string, outputWriter *testutils.MockOutputWriter) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()
	home, _ := os.UserHomeDir()
	defaultOpts := &types.Options{
		Targets:       []string{target},
		AutomaticScan: false, // 根据识别到的指纹自动映射标签扫描
		Templates:     templates,
		ExcludedTemplates: []string{
			"vulnerabilities/generic/cors-misconfig.yaml", // cors
			"technologies/",
			"fuzzing/wordpress-plugins-detect.yaml",
			"fuzzing/wordpress-themes-detect.yaml",
		},
		ExcludeTags:                []string{"dos", "tech"},
		NewTemplatesDirectory:      path.Join(home, "nuclei-templates"),
		Workflows:                  []string{},
		Tags:                       tags,
		RemoteTemplateDomainList:   []string{"api.nuclei.sh"},
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

	if conf.GlobalConfig.WebScan.Proxy != "" {
		defaultOpts.Proxy = []string{}
		// 只在 option 中指定代理并不行, nuclei 会对 proxy 代理进行处理，最终使用的是 types.ProxyURL 或 types.ProxySocksURL, 这里直接将原方法执行一遍
		if err := loadProxyServers(defaultOpts); err != nil {
			logging.Logger.Errorln(err)
		}
	}

	update(defaultOpts)

	protocolstate.Init(defaultOpts)
	protocolinit.Init(defaultOpts)

	defaultOpts.ExcludeTags = config.ReadIgnoreFile().Tags

	interactOpts := interactsh.DefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		logging.Logger.Errorf("Could not create interact client: %s", err)
		return
	}
	defer interactClient.Close()

	catalog := disk.NewCatalog(path.Join(home, "nuclei-templates"))
	executerOpts := protocols.ExecutorOptions{
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

	defer executerOpts.RateLimiter.Stop()

	engine := core.New(defaultOpts)
	engine.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		logging.Logger.Errorf("Could not create workflow loader: %s", err)
		return
	}
	executerOpts.WorkflowLoader = workflowLoader

	store, err := loader.New(loader.NewConfig(defaultOpts, catalog, executerOpts))
	if err != nil {
		logging.Logger.Errorf("Could not create loader client: %s", err)
		return
	}
	store.Load()

	inputArgs := []*contextargs.MetaInput{{Input: target}}

	_ = engine.Execute(store.Templates(), &inputs.SimpleInputProvider{Inputs: inputArgs})
	engine.WorkPool().Wait() // Wait for the scan to finish
}

// update 模板更新、下载
func update(defaultOpts *types.Options) {
	// 防止多个进程一起更新、下载模板，加锁
	// parse the runner.options.GithubTemplateRepo and store the valid repos in runner.customTemplateRepos
	ctm, err := customtemplates.NewCustomTemplatesManager(defaultOpts)
	if err != nil {
		logging.Logger.Errorln(err)
	}

	updateLock.Lock()
	// Check for template updates and update if available
	// if custom templates manager is not nil, we will install custom templates if there is fresh installation
	tm := &TemplateManager{CustomTemplates: ctm}
	if err := tm.FreshInstallIfNotExists(); err != nil {
		logging.Logger.Warnf("failed to install nuclei templates: %s\n", err)
	}
	if err := tm.UpdateIfOutdated(); err != nil {
		logging.Logger.Warnf("failed to update nuclei templates: %s\n", err)
	}

	if config.DefaultConfig.NeedsIgnoreFileUpdate() {
		if err := UpdateIgnoreFile(); err != nil {
			logging.Logger.Warnf("failed to update nuclei ignore file: %s\n", err)
		}
	}

	// we automatically check for updates unless explicitly disabled
	// this print statement is only to inform the user that there are no updates
	if !config.DefaultConfig.NeedsTemplateUpdate() {
		logging.Logger.Infof("No new updates found for nuclei templates")
	}
	// manually trigger update of custom templates
	if ctm != nil {
		ctm.Update(context.TODO())
	}

	updateLock.Unlock()
}
