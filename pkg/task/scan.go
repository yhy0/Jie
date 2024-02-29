package task

import (
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/scan"
    "path"
    "strings"
    "sync"
)

/**
  @author: yhy
  @since: 2023/10/19
  @desc: 扫描逻辑
    - PerFile 针对每个文件，包括参数啥的
    - PerFolder 针对url的目录，会分隔目录分别访问
    - PerServer 对每个domain的
**/

var wgLock sync.Mutex

func (t *Task) Run(in *input.CrawlResult) {
    // 加锁，防止 panic: sync: WaitGroup is reused before previous Wait has returned，不知道为啥还会出现这个错误
    wgLock.Lock()
    go func() {
        t.ScanTask[in.Host].Wg.Add()
        defer t.ScanTask[in.Host].Wg.Done()
        t.PerServer(in)
    }()
    go func() {
        t.ScanTask[in.Host].Wg.Add()
        defer t.ScanTask[in.Host].Wg.Done()
        t.PerFolder(in)
    }()
    go func() {
        t.ScanTask[in.Host].Wg.Add()
        defer t.ScanTask[in.Host].Wg.Done()
        t.PerFile(in)
    }()
    
    t.ScanTask[in.Host].Wg.Wait()
    wgLock.Unlock()
}

// PerServer 针对每个域名，只会执行一次
func (t *Task) PerServer(in *input.CrawlResult) {
    // 将要扫描的目标url 单独抽离出来，而不是更改 in 中的 url 的值，in 是一个指针，改变会影响到其他的扫描
    // 不管第一次传入的是不是 http://examples.com 这种主域名格式，都只会取域名转换为这种 http://examples.com，进行一次扫描
    target := in.ParseUrl.Scheme + "://" + strings.TrimRight(strings.TrimRight(in.ParseUrl.Host, ":443"), ":80")
    
    for _, plugin := range scan.PerServerPlugins {
        if t.ScanTask[in.Host].PerServer[plugin.Name()] {
            continue
        }
        lock.Lock()
        t.ScanTask[in.Host].PerServer[plugin.Name()] = true
        lock.Unlock()
        if conf.Plugin[plugin.Name()] {
            t.ScanTask[in.Host].Wg.Add()
            go func(p scan.Addon) {
                defer t.ScanTask[in.Host].Wg.Done()
                p.Scan(target, "/", in, t.ScanTask[in.Host].Client)
            }(plugin)
        }
    }
}

func (t *Task) PerFolder(in *input.CrawlResult) {
    // 获取路径的扩展名
    ext := path.Ext(in.ParseUrl.Path)
    
    var parentDir = in.ParseUrl.Path
    // 如果有扩展名，则获取父目录
    if ext != "" {
        parentDir = path.Dir(in.ParseUrl.Path)
    }
    
    // 说明是主目录，PerServer 已经扫描过了，这里跳过
    if parentDir == "/" {
        return
    }
    
    // 多个目录需要分割， 对每层目录都要扫描
    paths := strings.Split(parentDir, "/")
    
    // 最后加上分割前的目录
    paths = append(paths, parentDir)
    for _, p := range paths {
        // 重新构建 URL 字符串
        target := in.ParseUrl.Scheme + "://" + in.ParseUrl.Host + parentDir
        
        for _, plugin := range scan.PerFolderPlugins {
            // 说明这个目录整体都扫描过了，跳过
            if t.ScanTask[in.Host].PerFolder[plugin.Name()+"_"+parentDir] {
                continue
            }
            lock.Lock()
            t.ScanTask[in.Host].PerFolder[plugin.Name()+"_"+parentDir] = true
            lock.Unlock()
            // 说明拆分的目录扫描了，跳过
            if t.ScanTask[in.Host].PerFolder[plugin.Name()+"_"+p] {
                continue
            }
            lock.Lock()
            t.ScanTask[in.Host].PerFolder[plugin.Name()+"_"+p] = true
            lock.Unlock()
            if conf.Plugin[plugin.Name()] {
                t.ScanTask[in.Host].Wg.Add()
                go func(a scan.Addon, targetUrl, path string) {
                    defer t.ScanTask[in.Host].Wg.Done()
                    a.Scan(targetUrl, p, in, t.ScanTask[in.Host].Client)
                }(plugin, target, p)
            }
        }
    }
}

// PerFile 针对每个链接, 去重的操作不在这里进行，具体的逻辑在插件内部实现
func (t *Task) PerFile(in *input.CrawlResult) {
    // 这里就不用单独抽离 url 了，插件内部并不会改变这个值,所有的插件内部都最好不要更改任何 in 中的值
    for _, plugin := range scan.PerFilePlugins {
        if conf.Plugin[plugin.Name()] {
            // 防止创建过多的协程
            t.ScanTask[in.Host].Wg.Add()
            go func(p scan.Addon) {
                defer t.ScanTask[in.Host].Wg.Done()
                p.Scan(in.Url, "", in, t.ScanTask[in.Host].Client)
            }(plugin)
        }
    }
}
