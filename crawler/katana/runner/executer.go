package runner

import (
	errorutil "github.com/projectdiscovery/utils/errors"
	"github.com/remeh/sizedwaitgroup"
	"github.com/yhy0/Jie/logging"
)

// ExecuteCrawling executes the crawling main loop
func (r *Runner) ExecuteCrawling() error {
	inputs := r.parseInputs()
	if len(inputs) == 0 {
		return errorutil.New("no input provided for crawling")
	}

	defer r.crawler.Close()

	wg := sizedwaitgroup.New(r.options.Parallelism)
	for _, input := range inputs {
		wg.Add()

		go func(input string) {
			defer wg.Done()

			if err := r.crawler.Crawl(input); err != nil {
				logging.Logger.Debugf("Could not crawl %s: %s", input, err)
			}
		}(input)
	}
	wg.Wait()
	return nil
}
