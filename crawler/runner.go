package crawler

import (
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/yhy0/Jie/crawler/katana/pkg/engine"
	"github.com/yhy0/Jie/crawler/katana/pkg/engine/hybrid"
	"github.com/yhy0/Jie/crawler/katana/pkg/engine/parser"
	"github.com/yhy0/Jie/crawler/katana/pkg/engine/standard"
	"github.com/yhy0/Jie/crawler/katana/pkg/types"
	"go.uber.org/multierr"
)

/**
  @author: yhy
  @since: 2023/6/7
  @desc: //TODO
**/

// Runner creates the required resources for crawling
// and executes the crawl process.
type Runner struct {
	crawlerOptions *types.CrawlerOptions
	stdin          bool
	Crawler        engine.Engine
	Options        *types.Options
}

// New returns a new crawl runner structure
func New(options *types.Options) (*Runner, error) {
	if err := validateOptions(options); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not validate options")
	}
	if options.FormConfig != "" {
		if err := readCustomFormConfig(options); err != nil {
			return nil, err
		}
	}
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create crawler options")
	}

	parser.InitWithOptions(options)

	var crawler engine.Engine

	switch {
	case options.Headless:
		crawler, err = hybrid.New(crawlerOptions)
	default:
		crawler, err = standard.New(crawlerOptions)
	}
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create standard crawler")
	}
	runner := &Runner{Options: options, stdin: fileutil.HasStdin(), crawlerOptions: crawlerOptions, Crawler: crawler}

	return runner, nil
}

// Close closes the runner releasing resources
func (r *Runner) Close() error {
	return multierr.Combine(
		r.Crawler.Close(),
		r.crawlerOptions.Close(),
	)
}
