package conf

/**
   @author yhy
   @since 2023/11/15
   @desc 注意 json 别名不能是_ - viper 好像不识别这种的，最好是驼峰式
**/

type Config struct {
    Debug      bool       `json:"debug"`
    Options    Options    `json:"options"`
    Passive    Passive    `json:"passive"`
    Http       Http       `json:"http"`
    Plugins    Plugins    `json:"plugins"`
    WebScan    WebScan    `json:"webScan"`
    Reverse    Reverse    `json:"reverse"`
    SqlmapApi  Sqlmap     `json:"sqlmapApi"`
    Mitmproxy  Mitmproxy  `json:"mitmproxy"`
    Collection Collection `json:"collection"`
}

type WebScan struct {
    Poc  []string `json:"poc"`
    Craw string   `json:"craw"`
    Show bool     `json:"show"`
}

type Options struct {
    Target     string // target URLs/hosts to scan
    TargetFile string
    Targets    []string
    Output     string
    Mode       string
    S2         S2
    Shiro      Shiro
}

type Http struct {
    Proxy           string            `json:"proxy"`   // http/socks5 proxy to use
    Timeout         int               `json:"timeout"` // Timeout is the seconds to wait for a response from the server.
    MaxConnsPerHost int               `json:"maxConnsPerHost"`
    RetryTimes      int               `json:"retryTimes"`
    AllowRedirect   int               `json:"allowRedirect"`
    VerifySSL       bool              `json:"verifySSL"`
    MaxQps          int               `json:"maxQps"` // MaxQps is the maximum number of queries per second.
    Headers         map[string]string `json:"headers"`
    ForceHTTP1      bool              `json:"forceHTTP1"` // 强制指定使用 http/1.1
}

type Passive struct {
    ProxyPort string `mapstructure:"port" json:"port"`
    WebPort   string `mapstructure:"webPort" json:"webPort"`
    WebUser   string `mapstructure:"webUser" json:"webUser"`
    WebPass   string `mapstructure:"webPass" json:"webPass"`
}

type S2 struct {
    Mode        string
    Name        string
    Body        string
    CMD         string
    ContentType string
}

type Shiro struct {
    Mode     string
    Cookie   string
    Platform string
    Key      string
    KeyMode  string
    Gadget   string
    CMD      string
    Echo     string
}

// Plugins 插件配置
type Plugins struct {
    BruteForce struct {
        Web                bool   `json:"web"`
        Service            bool   `json:"service"`
        UsernameDictionary string `json:"usernameDict"`
        PasswordDictionary string `json:"passwordDict"`
    } `json:"bruteForce"`
    
    CmdInjection struct {
        Enabled bool `json:"enabled"`
    } `json:"cmdInjection"`
    
    CrlfInjection struct {
        Enabled bool `json:"enabled"`
    } `json:"crlfInjection"`
    
    XSS struct {
        Enabled           bool `json:"enabled"`
        DetectXssInCookie bool `json:"detectXssInCookie"`
    } `json:"xss"`
    
    Sql struct {
        Enabled               bool `json:"enabled"`
        BooleanBasedDetection bool `json:"booleanBasedDetection"`
        TimeBasedDetection    bool `json:"timeBasedDetection"`
        ErrorBasedDetection   bool `json:"errorBasedDetection"`
        DetectInCookie        bool `json:"detectInCookie"`
    } `json:"sql"`
    
    SqlmapApi Sqlmap `json:"sqlmapApi"`
    
    XXE struct {
        Enabled bool `json:"enabled"`
    } `json:"xxe"`
    
    SSRF struct {
        Enabled bool `json:"enabled"`
    } `json:"ssrf"`
    
    BBscan struct {
        Enabled bool `json:"enabled"`
    } `json:"bbscan"`
    
    Jsonp struct {
        Enabled bool `json:"enabled"`
    } `json:"jsonp"`
    
    Log4j struct {
        Enabled bool `json:"enabled"`
    } `json:"log4j"`
    
    ByPass403 struct {
        Enabled bool `json:"enabled"`
    } `json:"bypass403"`
    
    Fastjson struct {
        Enabled bool `json:"enabled"`
    } `json:"fastjson"`
    
    NginxAliasTraversal struct {
        Enabled bool `json:"enabled"`
    } `json:"nginxAliasTraversal"`
    
    Poc struct {
        Enabled bool `json:"enabled"`
    } `json:"poc"`
    
    Nuclei struct {
        Enabled bool `json:"enabled"`
    } `json:"nuclei"`
    
    Archive struct {
        Enabled bool `json:"enabled"`
    } `json:"archive"`
    
    IIS struct {
        Enabled bool `json:"enabled"`
    } `json:"iis"`
    
    PortScan struct {
        Enabled bool `json:"enabled"`
    } `json:"portScan"`
}

// Reverse dnslog 配置，使用 dig.pm https://github.com/yumusb/DNSLog-Platform-Golang
type Reverse struct {
    Host   string `json:"host"`
    Domain string `json:"domain"`
}

// Sqlmap Sqlmap API 配置
type Sqlmap struct {
    Enabled  bool   `json:"enabled"`  // 是否开启 sqlmap api
    Url      string `json:"url"`      // SQLMap API 服务器地址
    Username string `json:"username"` // SQLMap API 用户名
    Password string `json:"password"` // SQLMap API 密码
}

// Collection 信息收集中的正则
type Collection struct {
    Domain    []string `json:"domain"`
    IP        []string `json:"ip"`
    Phone     []string `json:"phone"`
    Email     []string `json:"email"`
    IDCard    []string `json:"idCard"`
    API       []string `json:"api"`
    Url       []string `json:"url"`
    UrlFilter []string `json:"urlFilter"`
    Other     []string `json:"other"`
}

type Mitmproxy struct {
    BasicAuth struct {
        Username string `json:"username"`
        Password string `json:"password"`
        Header   string `json:"header"`
    } `json:"basicAuth"`
    Exclude      []string `json:"exclude"`      // Exclude 排除扫描的域名
    Include      []string `json:"include"`      // Include 只扫描的域名
    FilterSuffix string   `json:"filterSuffix"` // 排除的后缀
}
