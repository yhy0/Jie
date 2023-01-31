package pocs_yml

import (
	"embed"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/util"
	"path/filepath"
	"strings"

	nuclei_parse "github.com/yhy0/Jie/scan/pocs_yml/nuclei/parse"
	nuclei_structs "github.com/yhy0/Jie/scan/pocs_yml/nuclei/structs"
	xray_parse "github.com/yhy0/Jie/scan/pocs_yml/xray/parse"
	xray_structs "github.com/yhy0/Jie/scan/pocs_yml/xray/structs"
)

//go:embed xrayFiles
var XrayPocs embed.FS

//go:embed nucleiFiles
var NucleiPocs embed.FS

// LoadPocs 读取pocs
func LoadPocs(pocs *[]string) (map[string]xray_structs.Poc, map[string]nuclei_structs.Poc) {
	xrayPocMap := make(map[string]xray_structs.Poc)
	nucleiPocMap := make(map[string]nuclei_structs.Poc)

	// 加载poc函数
	LoadPoc := func(pocFile string) {
		if util.Exists(pocFile) && util.IsFile(pocFile) {
			pocPath, err := filepath.Abs(pocFile)
			if err != nil {
				logging.Logger.Fatalf("Get poc filepath error: " + pocFile)
			}
			logging.Logger.Debugf("Load poc file: %v", pocFile)

			xrayPoc, err := xray_parse.ParsePoc(pocPath)
			if err == nil {
				xrayPocMap[pocPath] = *xrayPoc
				return
			}
			nucleiPoc, err := nuclei_parse.ParsePoc(pocPath)

			if err == nil {
				nucleiPocMap[pocPath] = *nucleiPoc
				return
			}

			if err != nil {
				logging.Logger.Debugf("Poc[%s] Parse error", pocFile)
			}

		} else {
			logging.Logger.Debugf("Poc file not found: '%v'", pocFile)
		}
	}

	if len(*pocs) == 0 { // 没有指定 poc, 则使用内置的默认 poc
		entries, err := XrayPocs.ReadDir("xrayFiles")
		if err != nil {
			logging.Logger.Fatalln(err)
		}
		for _, entry := range entries {
			xrayPoc, err := xray_parse.Parse(entry.Name(), XrayPocs)
			if err != nil {
				logging.Logger.Errorln(err)
				continue
			}
			xrayPocMap["xrayFiles/"+entry.Name()] = *xrayPoc
		}

		entries, err = NucleiPocs.ReadDir("nucleiFiles")
		if err != nil {
			logging.Logger.Fatalln(err)
		}

		for _, entry := range entries {
			nucleiPoc, err := nuclei_parse.Parse(entry.Name(), NucleiPocs)
			if err != nil {
				logging.Logger.Errorln(err)
				continue
			}

			nucleiPocMap["nucleiFiles/"+entry.Name()] = *nucleiPoc
		}

	} else {
		for _, pocFile := range *pocs {
			if funk.Contains(pocFile, "*") || !funk.Contains(pocFile, ".yml") {
				logging.Logger.Debugf("Load from poc path: %v", pocFile)

				pocFiles, err := filepath.Glob(pocFile)
				if err != nil {
					logging.Logger.Fatalf("Path glob match error: "+err.Error(), 6)
				}
				for _, _pocFile := range pocFiles {
					// 只解析yml或yaml文件
					if strings.HasSuffix(_pocFile, ".yml") || strings.HasSuffix(_pocFile, ".yaml") {
						LoadPoc(_pocFile)
					}
				}
			}
			LoadPoc(pocFile)
		}
	}

	logging.Logger.Infof("Load [%d] xray poc(s), [%d] nuclei poc(s)", len(xrayPocMap), len(nucleiPocMap))

	return xrayPocMap, nucleiPocMap
}

func FilterPocs(tags []string, xrayPocMap map[string]xray_structs.Poc, nucleiPocMap map[string]nuclei_structs.Poc) (map[string]xray_structs.Poc, map[string]nuclei_structs.Poc) {
	for k, poc := range xrayPocMap {
		for _, tag := range tags {
			if !strings.Contains(poc.Detail.Tags, tag) {
				delete(xrayPocMap, k)
				break
			}
		}
	}

	// nuclei tag 不区分大小写
	for k, poc := range nucleiPocMap {
		for _, tag := range tags {
			if !strings.Contains(poc.Info.Tags.String(), strings.ToLower(tag)) {
				delete(nucleiPocMap, k)
				break
			}
		}
	}

	return xrayPocMap, nucleiPocMap
}
