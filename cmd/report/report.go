package main

import (
	"flag"
	"fmt"

	"github.com/e-conomic/gcr-smi/pkg/gcr"
	"github.com/e-conomic/gcr-smi/pkg/smi"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	project              = flag.String("project", "my-project-name", "Google Project ID")
	root                 = flag.String("root", "eu.gcr.io", "GCR Root")
	image                = flag.String("image", "", "Optionally limit report to just this image")
	tag                  = flag.String("tag", "master", "Docker tag to report on")
	loglevel             = zap.LevelFlag("loglevel", zapcore.InfoLevel, "loglevel")
	smiURL               = flag.String("smi_url", "https://example.com/", "Url for the SMI rest point")
	smiAgent             = flag.String("smi_agent", "123e4567-e89b-12d3-a456-426655440000", "GUID to identify the agent")
	smiSubService        = flag.String("smi_sub_service", "123e4567-e89b-12d3-a456-426655440000", "GUID to identify the sub-service")
	smiAuth              = flag.String("smi_auth", "ZXhhbXBsZQ==", "SMI Shared Secret Auth")
	smiComponentFixable  = flag.String("smi_com_fixable", "8b64d917-e072-438e-9789-030b6ea0fd54", "GUID for fixable vulnz")
	smiComponentMajor    = flag.String("smi_com_major", "2ff09b14-57e3-43ba-a4a5-07d310f36c2d", "GUID for major vulnz")
	smiComponentModerate = flag.String("smi_com_moderate", "f46b2e3e-3aa4-44d1-9fd7-7cfa7a0bf68f", "GUID for moderate vulnz")
)

func do() error {
	if *project == "my-project-name" {
		return fmt.Errorf("You must set project, smi_url, smi_agent, smi_sub_service, smi_auth arguments")
	}

	lconf := zap.NewProductionConfig()
	lconf.Level.SetLevel(*loglevel)
	logger, err := lconf.Build()
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(logger)

	reponame := *project
	if *image != "" {
		reponame = reponame + "/" + *image
	}
	images, err := gcr.FindImage(*root, reponame, *tag)
	if err != nil {
		return err
	}

	zap.L().Info("images", zap.Strings("images", images))

	results := &gcr.Results{}

	for _, imagehash := range images {
		zap.L().Info("found latest image", zap.String("image", imagehash))
		occs, e := gcr.ListVulns(*project, imagehash)
		if e != nil {
			return e
		}
		err = gcr.CountVulns(results, occs)
		if err != nil {
			return err
		}
	}

	zap.L().Info("completed report", zap.Reflect("results", results))

	err = smi.Update(smi.Field{
		Agent:      *smiAgent,
		Component:  *smiComponentFixable,
		Multiplier: results.Fixable,
		SubService: *smiSubService,
	}, *smiURL, *smiAuth)
	if err != nil {
		return err
	}

	err = smi.Update(smi.Field{
		Agent:      *smiAgent,
		Component:  *smiComponentMajor,
		Multiplier: results.Major30Days,
		SubService: *smiSubService,
	}, *smiURL, *smiAuth)
	if err != nil {
		return err
	}

	err = smi.Update(smi.Field{
		Agent:      *smiAgent,
		Component:  *smiComponentModerate,
		Multiplier: results.Moderate90Days,
		SubService: *smiSubService,
	}, *smiURL, *smiAuth)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()
	if err := do(); err != nil {
		panic(err)
	}
}
