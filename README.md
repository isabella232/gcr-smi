# GCR SMI Reporting Tool

### Building

```bash
go build cmd/report/report.go
```

### Usage

Run report and set set project, smi_url, smi_agent, smi_sub_service, smi_auth arguments

```bash
$ ./report --help
Usage of ./report:
  -image string
    	Optionally limit report to just this image
  -loglevel value
    	loglevel
  -project string
    	Google Project ID (default "my-project-name")
  -root string
    	GCR Root (default "eu.gcr.io")
  -smi_agent string
    	GUID to identify the agent (default "123e4567-e89b-12d3-a456-426655440000")
  -smi_auth string
    	SMI Shared Secret Auth (default "ZXhhbXBsZQ==")
  -smi_com_fixable string
    	GUID for fixable vulnz (default "8b64d917-e072-438e-9789-030b6ea0fd54")
  -smi_com_major string
    	GUID for major vulnz (default "2ff09b14-57e3-43ba-a4a5-07d310f36c2d")
  -smi_com_moderate string
    	GUID for moderate vulnz (default "f46b2e3e-3aa4-44d1-9fd7-7cfa7a0bf68f")
  -smi_sub_service string
    	GUID to identify the sub-service (default "123e4567-e89b-12d3-a456-426655440000")
  -smi_url string
    	Url for the SMI rest point (default "https://example.com/")
  -tag string
    	Docker tag to report on (default "master")
```

