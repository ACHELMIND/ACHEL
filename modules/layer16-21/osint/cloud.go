package osint

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/angel-platform/angel/pkg/logger"
)

type CloudRecon struct {
	config *OSINTConfig
	log    *logger.Logger
	mu     sync.RWMutex
	client *http.Client
}

func NewCloudRecon(config *OSINTConfig) *CloudRecon {
	return &CloudRecon{
		config: config,
		log:    logger.New("cloud-recon", logger.LevelInfo),
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

func (c *CloudRecon) AWSBucketEnum(region string) ([]BucketInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.Info("AWS bucket enumeration for region: %s", region)

	buckets := make([]BucketInfo, 0)

	commonBuckets := []string{
		"backup", "logs", "data", "assets", "config",
		"secrets", "keys", "database", "media", "uploads",
		"static", "cdn", "archive", "temp", "dev",
		"staging", "production", "test", "deploy", "ci",
	}

	for _, name := range commonBuckets {
		bucketURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com", name, region)
		resp, err := c.client.Head(bucketURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				buckets = append(buckets, BucketInfo{
					Name:   name,
					Region: region,
					Public: resp.StatusCode == 200,
				})
			}
		}
	}

	c.log.Info("Found %d potential buckets in %s", len(buckets), region)
	return buckets, nil
}

func (c *CloudRecon) AzureBlobEnum(account string) ([]BlobInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.Info("Azure blob enumeration for account: %s", account)

	blobs := make([]BlobInfo, 0)

	url := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", account)
	resp, err := c.client.Get(url)
	if err != nil {
		return blobs, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		c.log.Info("Azure storage account %s is accessible", account)
	}

	return blobs, nil
}

func (c *CloudRecon) GCPBucketEnum(project string) ([]BucketInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.Info("GCP bucket enumeration for project: %s", project)

	buckets := make([]BucketInfo, 0)

	commonBuckets := []string{
		"backup", "logs", "data", "assets", "config",
		"secrets", "media", "uploads", "static", "archive",
	}

	for _, name := range commonBuckets {
		bucketURL := fmt.Sprintf("https://storage.googleapis.com/%s", name)
		resp, err := c.client.Head(bucketURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				buckets = append(buckets, BucketInfo{
					Name:   name,
					Public: true,
				})
			}
		}
	}

	c.log.Info("Found %d potential buckets for project %s", len(buckets), project)
	return buckets, nil
}

func (c *CloudRecon) ReconCloud(target string) (*CloudResult, error) {
	result := &CloudResult{}

	ips, err := net.LookupHost(target)
	if err == nil && len(ips) > 0 {
		ip := ips[0]

		if strings.HasPrefix(ip, "18.") || strings.HasPrefix(ip, "52.") || strings.HasPrefix(ip, "54.") {
			c.log.Info("Detected AWS infrastructure for %s", target)
			awsResult, err := c.AWSBucketEnum("us-east-1")
			if err == nil {
				result.AWS = &AWSResult{Buckets: awsResult}
			}
		}

		if strings.HasPrefix(ip, "13.") || strings.HasPrefix(ip, "40.") {
			c.log.Info("Detected Azure infrastructure for %s", target)
			azureResult, err := c.AzureBlobEnum(target)
			if err == nil {
				result.Azure = &AzureResult{Blobs: azureResult}
			}
		}

		if strings.HasPrefix(ip, "34.") || strings.HasPrefix(ip, "35.") {
			c.log.Info("Detected GCP infrastructure for %s", target)
			gcpResult, err := c.GCPBucketEnum(target)
			if err == nil {
				result.GCP = &GCPResult{Buckets: gcpResult}
			}
		}
	}

	return result, nil
}

func (c *CloudRecon) CheckMetadataService() (string, error) {
	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://metadata.google.internal/computeMetadata/v1/",
	}

	for _, url := range metadataURLs {
		resp, err := c.client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				return url, nil
			}
		}
	}

	return "", fmt.Errorf("no metadata service found")
}
