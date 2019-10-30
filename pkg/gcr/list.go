package gcr

import (
	"bytes"
	"context"
	"fmt"
	"time"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1beta1"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/api/iterator"
	grafeas "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	packpb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/package"
)

var (
	// JSONPbMarshaller is the marshaller used for serializing protobuf messages.
	// If needed, this variable can be reassigned with a different marshaller with the same Marshal() signature.
	JSONPbMarshaller = &jsonpb.Marshaler{}
)

type jsonpbObjectMarshaler struct {
	pb proto.Message
}

func (j *jsonpbObjectMarshaler) MarshalLogObject(e zapcore.ObjectEncoder) error {
	// ZAP jsonEncoder deals with AddReflect by using json.MarshalObject. The same thing applies for consoleEncoder.
	return e.AddReflected("msg", j)
}

func (j *jsonpbObjectMarshaler) MarshalJSON() ([]byte, error) {
	b := &bytes.Buffer{}
	if err := JSONPbMarshaller.Marshal(b, j.pb); err != nil {
		return nil, fmt.Errorf("jsonpb serializer failed: %v", err)
	}
	return b.Bytes(), nil
}

func FindImage(root, project, tag string) ([]string, error) {
	repoName := fmt.Sprintf("%s/%s", root, project)
	repo, err := name.NewRepository(repoName)
	if err != nil {
		return nil, err
	}

	auth, err := google.NewEnvAuthenticator()
	if err != nil {
		return nil, err
	}

	out := make([]string, 0)

	filterTags := func(repo name.Repository, tags *google.Tags, err error) error {
		if err != nil {
			return err
		}
	FindTag:
		for digest, manifest := range tags.Manifests {
			for _, t := range manifest.Tags {
				if t == tag {
					out = append(out, fmt.Sprintf("%s@%s", repo, digest))
					break FindTag
				}
			}
		}
		return nil
	}
	if err := google.Walk(repo, filterTags, google.WithAuth(auth)); err != nil {
		return nil, err
	}
	return out, nil
}

func ListVulns(project, image string) (*containeranalysis.OccurrenceIterator, error) {
	ctx := context.Background()
	client, err := containeranalysis.NewGrafeasV1Beta1Client(ctx)
	if err != nil {
		return nil, err
	}

	resourceURL := "https://" + image

	req := &grafeas.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", project),
		Filter: fmt.Sprintf("resourceUrl = %q kind = %q", resourceURL, "VULNERABILITY"),
	}

	zap.L().Debug("request", zap.Stringer("ListOccurrencesRequest", req))

	res := client.ListOccurrences(ctx, req)
	return res, nil
}

type Results struct {
	Total          int
	Fixable        int
	Major30Days    int
	Moderate90Days int
}

func CountVulns(running *Results, occs *containeranalysis.OccurrenceIterator) error {
	if running == nil {
		return fmt.Errorf("results input was nil")
	}

	var occur *grafeas.Occurrence
	var err error
	for {
		occur, err = occs.Next()
		if err == iterator.Done {
			break
		} else if err != nil {
			return err
		}

		// Add the vulnerability to the running totals
		running.Total++

		if vuln := occur.GetVulnerability(); vuln != nil {
			if packs := vuln.GetPackageIssue(); len(packs) > 0 {
				pack := packs[0]
				if pack.GetFixedLocation().GetVersion().GetKind() != packpb.Version_MAXIMUM {
					var relatedURL string
					if len(vuln.GetRelatedUrls()) > 0 {
						relatedURL = vuln.RelatedUrls[0].GetUrl()
					}
					zap.L().Info("package needs fixing",
						zap.Object("occurrence", &jsonpbObjectMarshaler{pb: occur}),
						zap.String("resource", occur.GetResource().GetUri()),
						zap.Float32("cvss", vuln.GetCvssScore()),
						zap.String("package", pack.GetAffectedLocation().GetPackage()),
						zap.Stringer("severity", vuln.GetSeverity()),
						zap.String("related", relatedURL),
					)
					running.Fixable++
					created := time.Now()
					if unix := occur.GetCreateTime().GetSeconds(); unix != 0 {
						created = time.Unix(unix, 0)
					}
					switch pack.GetSeverityName() {
					case "CRITICAL", "HIGH":
						if created.Before(time.Now().Add(-30 * 24 * time.Hour)) {
							running.Major30Days++
						}
					case "MEDIUM":
						if created.Before(time.Now().Add(-90 * 24 * time.Hour)) {
							running.Moderate90Days++
						}
					}
				}
			}
		}
	}
	return nil
}
