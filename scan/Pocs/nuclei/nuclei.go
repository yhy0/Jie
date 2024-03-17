package nuclei

/**
  @author: yhy
  @since: 2023/2/1
  @desc: https://github.com/projectdiscovery/nuclei/blob/main/v2/examples/simple.go
    todo 去除目录爆破等规则，目录爆破通过 dir 进行测试
**/

import (
    "context"
    "github.com/logrusorgru/aurora"
    "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
    "github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
    "github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
    "github.com/projectdiscovery/nuclei/v3/pkg/core"
    "github.com/projectdiscovery/nuclei/v3/pkg/external/customtemplates"
    "github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
    parsers "github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
    "github.com/projectdiscovery/nuclei/v3/pkg/output"
    "github.com/projectdiscovery/nuclei/v3/pkg/protocols"
    "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
    "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
    "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
    "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
    "github.com/projectdiscovery/nuclei/v3/pkg/reporting"
    "github.com/projectdiscovery/nuclei/v3/pkg/templates"
    "github.com/projectdiscovery/nuclei/v3/pkg/testutils"
    "github.com/projectdiscovery/nuclei/v3/pkg/types"
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
    ft, tags := generateTemplates(fingerprints)
    
    // 扫描结果获取
    outputWriter := testutils.NewMockOutputWriter(false)
    
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
        return
    }
    
    nuclei(target, ft, tags, outputWriter)
}

func nuclei(target string, ft []string, tags []string, outputWriter *testutils.MockOutputWriter) {
    cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
    defer cache.Close()
    
    mockProgress := &testutils.MockProgressClient{}
    
    reportingClient, err := reporting.New(&reporting.Options{}, "", false)
    if err != nil {
        return
    }
    defer reportingClient.Close()
    
    defaultOpts := &types.Options{
        Targets:                    []string{target},
        Proxy:                      []string{conf.GlobalConfig.Http.Proxy},
        AutomaticScan:              false, // 根据识别到的指纹自动映射标签扫描
        MaxRedirects:               10,
        InteractionsCacheSize:      5000,
        InteractionsEviction:       60,
        InteractionsPollDuration:   5,
        InteractionsCoolDownPeriod: 5,
        RateLimit:                  150,
        BulkSize:                   25,
        TemplateThreads:            25,
        HeadlessBulkSize:           10,
        HeadlessTemplateThreads:    10,
        Timeout:                    5,
        Retries:                    1,
        MaxHostError:               30,
        ResponseReadSize:           10 * 1024 * 1024,
        ResponseSaveSize:           1024 * 1024,
        PageTimeout:                20,
        StatsInterval:              5,
        Debug:                      false,
        Verbose:                    false,
    }
    
    if conf.GlobalConfig.Http.Proxy != "" {
        // 只在 option 中指定代理并不行, nuclei 会对 proxy 代理进行处理，最终使用的是 types.ProxyURL 或 types.ProxySocksURL, 这里直接将原方法执行一遍
        if err := loadProxyServers(defaultOpts); err != nil {
            logging.Logger.Errorln(err)
        }
    }
    
    _ = protocolstate.Init(defaultOpts)
    _ = protocolinit.Init(defaultOpts)
    
    if len(conf.GlobalConfig.WebScan.Poc) > 0 {
        defaultOpts.Templates = conf.GlobalConfig.WebScan.Poc
        defaultOpts.UpdateTemplates = false
    } else {
        defaultOpts.Templates = ft
        defaultOpts.UpdateTemplates = true
        defaultOpts.ExcludedTemplates = []string{
            "vulnerabilities/generic/cors-misconfig.yaml", // cors
            "technologies/",
            "fuzzing/wordpress-plugins-detect.yaml",
            "fuzzing/wordpress-themes-detect.yaml",
        }
        defaultOpts.Tags = tags
        defaultOpts.ExcludeTags = append(config.ReadIgnoreFile().Tags, []string{"dos", "tech"}...)
        update(defaultOpts)
    }
    
    interactOpts := interactsh.DefaultOptions(outputWriter, reportingClient, mockProgress)
    interactClient, err := interactsh.New(interactOpts)
    if err != nil {
        logging.Logger.Errorf("Could not create interact client: %s", err)
        return
    }
    defer interactClient.Close()
    
    home, _ := os.UserHomeDir()
    catalog := disk.NewCatalog(path.Join(home, "nuclei-templates"))
    rateLimiter := ratelimit.New(context.Background(), 150, time.Second)
    defer rateLimiter.Stop()
    executeOpts := protocols.ExecutorOptions{
        Output:          outputWriter,
        Options:         defaultOpts,
        Progress:        mockProgress,
        Catalog:         catalog,
        IssuesClient:    reportingClient,
        RateLimiter:     rateLimiter,
        Interactsh:      interactClient,
        HostErrorsCache: cache,
        Colorizer:       aurora.NewAurora(true),
        ResumeCfg:       types.NewResumeCfg(),
        Parser:          templates.NewParser(),
    }
    
    engine := core.New(defaultOpts)
    engine.SetExecuterOptions(executeOpts)
    
    workflowLoader, err := parsers.NewLoader(&executeOpts)
    if err != nil {
        logging.Logger.Errorf("Could not create workflow loader: %s", err)
        return
    }
    executeOpts.WorkflowLoader = workflowLoader
    
    store, err := loader.New(loader.NewConfig(defaultOpts, catalog, executeOpts))
    if err != nil {
        logging.Logger.Errorf("Could not create loader client: %s", err)
        return
    }
    store.Load()
    
    _ = engine.Execute(store.Templates(), provider.NewSimpleInputProviderWithUrls(target))
    engine.WorkPool().Wait() // Wait for the scan to finish
}

// update 模板更新、下载
func update(defaultOpts *types.Options) {
    updateLock.Lock()
    // 防止多个进程一起更新、下载模板，加锁
    // parse the runner.options.GithubTemplateRepo and store the valid repos in runner.customTemplateRepos
    ctm, err := customtemplates.NewCustomTemplatesManager(defaultOpts)
    if err != nil {
        logging.Logger.Errorln(err)
    }
    
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
            logging.Logger.Warnf("failed to update nuclei ignore file: %s", err)
        }
    }
    
    // we automatically check for updates unless explicitly disabled
    // this print statement is only to inform the user that there are no updates
    if !config.DefaultConfig.NeedsTemplateUpdate() {
        logging.Logger.Warnf("No new updates found for nuclei templates")
    }
    // manually trigger update of custom templates
    if ctm != nil {
        ctm.Update(context.TODO())
    }
    
    updateLock.Unlock()
}
