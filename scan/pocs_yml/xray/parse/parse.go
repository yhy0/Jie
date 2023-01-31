package parse

import (
	"embed"
	"errors"
	"fmt"
	"github.com/yhy0/Jie/scan/pocs_yml/xray/structs"
	"os"
	"sync"

	"gopkg.in/yaml.v2"
)

var PocPool = sync.Pool{
	New: func() interface{} {
		return new(structs.Poc)
	},
}

func ParsePoc(filename string) (*structs.Poc, error) {
	poc := PocPool.Get().(*structs.Poc)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err != nil {
		return nil, err
	}

	err = yaml.NewDecoder(f).Decode(poc)

	if err != nil {
		return nil, err
	}
	if poc.Name == "" {
		return nil, errors.New(fmt.Sprintf("Xray poc[%s] name can't be nil", filename))
	}

	if poc.Transport == "" {
		poc.Transport = "http"
	}
	return poc, nil
}

func Parse(filename string, pocs embed.FS) (*structs.Poc, error) {
	poc := PocPool.Get().(*structs.Poc)

	yamlFile, err := pocs.ReadFile("xrayFiles/" + filename)

	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, poc)
	if err != nil {
		return nil, err
	}
	if poc.Name == "" {
		return nil, errors.New(fmt.Sprintf("Xray poc[%s] name can't be nil", filename))
	}

	if poc.Transport == "" {
		poc.Transport = "http"
	}
	return poc, nil
}
