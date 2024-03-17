package crawler

import (
    "github.com/projectdiscovery/katana/pkg/engine"
    "github.com/projectdiscovery/katana/pkg/engine/hybrid"
    "github.com/projectdiscovery/katana/pkg/engine/standard"
    "github.com/projectdiscovery/katana/pkg/output"
    "github.com/projectdiscovery/katana/pkg/types"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/logging"
    "math"
)

/**
  @author: yhy
  @since: 2024/3/17
  @desc: //TODO
**/

// 默认过滤的后缀名
var extensionFilter = []string{
    ".css", ".png", ".gif", ".jpg", ".mp4", ".mp3", ".mng", ".pct", ".bmp", ".jpeg", ".pst", ".psp", ".ttf",
    ".tif", ".tiff", ".ai", ".drw", ".wma", ".ogg", ".wav", ".ra", ".aac", ".mid", ".au", ".aiff",
    ".dxf", ".eps", ".ps", ".svg", ".3gp", ".asf", ".asx", ".avi", ".mov", ".mpg", ".qt", ".rm",
    ".wmv", ".m4a", ".bin", ".xls", ".xlsx", ".ppt", ".pptx", ".doc", ".docx", ".odt", ".ods", ".odg",
    ".odp", ".exe", ".zip", ".rar", ".tar", ".gz", ".iso", ".rss", ".pdf", ".dll", ".ico",
    ".gz2", ".apk", ".crt", ".woff", ".map", ".woff2", ".webp", ".less", ".dmg", ".bz2", ".otf", ".swf",
    ".flv", ".mpeg", ".dat", ".xsl", ".csv", ".cab", ".exif", ".wps", ".m4v", ".rmvb",
}

func Katana(target string, headless bool, show bool, out func(result output.Result)) {
    // todo 作为库，还有 bug，这里有的参数根本不起作用，先自行处理
    options := &types.Options{
        MaxDepth:        3,             // Maximum depth to crawl
        FieldScope:      "fqdn",        //  rdn: 爬取范围为根域名和所有子域(默认), dn:搜索范围为域名关键字 fqdn:爬取范围为给定子(域)
        BodyReadSize:    math.MaxInt,   // Maximum response size to read
        Timeout:         10,            // Timeout is the time to wait for request in seconds
        Concurrency:     10,            // Concurrency is the number of concurrent crawling goroutines
        Parallelism:     10,            // Parallelism is the number of urls processing goroutines
        Delay:           0,             // Delay is the delay between each crawl requests in seconds
        RateLimit:       150,           // Maximum requests to send per second
        Strategy:        "depth-first", // Visit strategy (depth-first, breadth-first)
        OnResult:        out,
        Headless:        headless,
        Proxy:           conf.GlobalConfig.Http.Proxy,
        ExtensionFilter: extensionFilter,
    }
    if options.Headless {
        options.ShowBrowser = show
        options.UseInstalledChrome = false
    }
    
    crawlerOptions, err := types.NewCrawlerOptions(options)
    if err != nil {
        logging.Logger.Fatal(err.Error())
    }
    defer crawlerOptions.Close()
    
    var crawler engine.Engine
    
    switch {
    case options.Headless:
        crawler, err = hybrid.New(crawlerOptions)
    default:
        crawler, err = standard.New(crawlerOptions)
    }
    
    if err != nil {
        logging.Logger.Fatal("could not create standard crawler", err.Error())
    }
    
    defer crawler.Close()
    
    err = crawler.Crawl(target)
    if err != nil {
        logging.Logger.Warnf("Could not crawl %s: %s", target, err.Error())
    }
}
