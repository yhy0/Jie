package headless

import (
	_ "embed"
	"fmt"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	stringsutil "github.com/projectdiscovery/utils/strings"
	ps "github.com/shirou/gopsutil/v3/process"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/logging"
	"go.uber.org/multierr"
	"net/url"
	"os"
)

/**
  @author: yhy
  @since: 2023/3/13
  @desc: //TODO
**/

var RodHeadless *Crawler

type Crawler struct {
	Browser      *rod.Browser
	previousPIDs map[int32]struct{} // track already running PIDs
	tempDir      string
}

func Rod() {
	dataStore, err := os.MkdirTemp("", "katana-*")
	if err != nil {
		logging.Logger.Errorln("could not create temporary directory")
	}
	previousPIDs := findChromeProcesses()
	chromeLauncher := launcher.New().
		Leakless(false).
		Set("disable-gpu", "true").
		Set("ignore-certificate-errors", "true").
		Set("ignore-certificate-errors", "1").
		Set("disable-crash-reporter", "true").
		//Set("disable-notifications", "true"). // todo 如果禁用通知，会导致 https://bot.sannysoft.com/ 不是全绿，不知道有什么影响，先注释
		Set("hide-scrollbars", "true").
		Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
		Set("mute-audio", "true").
		Set("disable-images", "true").
		Set("disable-popup-blocking", "true").
		Delete("use-mock-keychain").
		UserDataDir(dataStore)
	//Delete("use-mock-keychain").

	// 显示 ui
	chromeLauncher = chromeLauncher.Headless(true)

	chromeLauncher.Set("no-sandbox", "true")

	if conf.GlobalConfig.WebScan.Proxy != "" {
		proxyURL, err := url.Parse(conf.GlobalConfig.WebScan.Proxy)
		if err != nil {
			logging.Logger.Errorln(err)
		} else {
			chromeLauncher.Set("proxy-server", proxyURL.String())
		}

	}

	launcherURL, err := chromeLauncher.Launch()
	if err != nil {
		logging.Logger.Fatalln(err)
	}

	browser := rod.New().ControlURL(launcherURL)
	if browserErr := browser.Connect(); browserErr != nil {
		logging.Logger.Errorln(err)
	}
	RodHeadless = &Crawler{
		Browser:      browser,
		previousPIDs: previousPIDs,
		tempDir:      dataStore,
	}
}

// Close closes the crawler process
func (c *Crawler) Close() error {
	if err := c.Browser.Close(); err != nil {
		return err
	}

	if err := os.RemoveAll(c.tempDir); err != nil {
		return err
	}
	return c.killChromeProcesses()
}

// killChromeProcesses any and all new chrome processes started after
// headless process launch.
func (c *Crawler) killChromeProcesses() error {
	var errs []error
	processes, _ := ps.Processes()

	for _, process := range processes {
		// skip non-chrome processes
		if !isChromeProcess(process) {
			continue
		}

		// skip chrome processes that were already running
		if _, ok := c.previousPIDs[process.Pid]; ok {
			continue
		}

		if err := process.Kill(); err != nil {
			errs = append(errs, err)
		}
	}

	return multierr.Combine(errs...)
}

// isChromeProcess checks if a process is chrome/chromium
func isChromeProcess(process *ps.Process) bool {
	name, _ := process.Name()
	executable, _ := process.Exe()
	return stringsutil.ContainsAny(name, "chrome", "chromium") || stringsutil.ContainsAny(executable, "chrome", "chromium")
}

// findChromeProcesses finds chrome process running on host
func findChromeProcesses() map[int32]struct{} {
	processes, _ := ps.Processes()
	list := make(map[int32]struct{})
	for _, process := range processes {
		if isChromeProcess(process) {
			list[process.Pid] = struct{}{}
			if ppid, err := process.Ppid(); err == nil {
				list[ppid] = struct{}{}
			}
		}
	}
	return list
}
