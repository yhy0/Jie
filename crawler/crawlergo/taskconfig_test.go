package crawlergo_test

import (
    "github.com/yhy0/Jie/crawler/crawlergo"
    "github.com/yhy0/Jie/crawler/crawlergo/config"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

func TestTaskConfigOptFunc(t *testing.T) {
    // 测试 https://github.com/Qianlitp/crawlergo/pull/101 修改的代码
    var taskConf crawlergo.TaskConfig
    for _, fn := range []crawlergo.TaskConfigOptFunc{
        crawlergo.WithTabRunTimeout(config.TabRunTimeout),
        crawlergo.WithMaxTabsCount(config.MaxTabsCount),
        crawlergo.WithMaxCrawlCount(config.MaxCrawlCount),
        crawlergo.WithDomContentLoadedTimeout(config.DomContentLoadedTimeout),
        crawlergo.WithEventTriggerInterval(config.EventTriggerInterval),
        crawlergo.WithBeforeExitDelay(config.BeforeExitDelay),
        crawlergo.WithEventTriggerMode(config.DefaultEventTriggerMode),
        crawlergo.WithIgnoreKeywords(config.DefaultIgnoreKeywords),
    } {
        fn(&taskConf)
    }

    // 应该都要等于默认配置
    assert.Equal(t, taskConf.TabRunTimeout, config.TabRunTimeout)
    assert.Equal(t, taskConf.MaxTabsCount, config.MaxTabsCount)
    assert.Equal(t, taskConf.MaxCrawlCount, config.MaxCrawlCount)
    assert.Equal(t, taskConf.DomContentLoadedTimeout, config.DomContentLoadedTimeout)
    assert.Equal(t, taskConf.EventTriggerInterval, config.EventTriggerInterval)
    assert.Equal(t, taskConf.BeforeExitDelay, config.BeforeExitDelay)
    assert.Equal(t, taskConf.EventTriggerMode, config.DefaultEventTriggerMode)
    assert.Equal(t, taskConf.IgnoreKeywords, config.DefaultIgnoreKeywords)

    // 重设超时时间
    taskConf.TabRunTimeout = time.Minute * 5

    // 企图覆盖自定义的时间, 不应该允许, 程序初始化时只能配置一次, 先由用户配置
    crawlergo.WithTabRunTimeout(time.Second * 5)(&taskConf)
    assert.NotEqual(t, taskConf.TabRunTimeout, time.Second*5)
    assert.NotEqual(t, taskConf.TabRunTimeout, config.TabRunTimeout)
}
