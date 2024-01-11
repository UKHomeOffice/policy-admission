package kubecertmanager

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/localstack"
)

const (
	accesskey = "a"
	secretkey = "b"
	token     = "c"
	region    = "us-east-1"
)

func awsSession(ctx context.Context, l *localstack.LocalStackContainer) (*session.Session, error) {
	mappedPort, err := l.MappedPort(ctx, nat.Port("4566/tcp"))
	if err != nil {
		return &session.Session{}, err
	}

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		return &session.Session{}, err
	}
	defer provider.Close()

	host, err := provider.DaemonHost(ctx)
	if err != nil {
		return &session.Session{}, err
	}

	awsConfig := &aws.Config{
		Region:                        aws.String(region),
		CredentialsChainVerboseErrors: aws.Bool(true),
		Credentials:                   credentials.NewStaticCredentials(accesskey, secretkey, token),
		S3ForcePathStyle:              aws.Bool(true),
		Endpoint:                      aws.String(fmt.Sprintf("http://%s:%d", host, mappedPort.Int())),
	}

	return session.NewSession(awsConfig)
}

func TestGetRoute53HostedDomains(t *testing.T) {
	ctx := context.Background()

	container, err := localstack.RunContainer(ctx,
		testcontainers.WithImage("localstack/localstack:3.0.2"),
	)
	require.Nil(t, err)

	session, err := awsSession(ctx, container)
	require.Nil(t, err)

	r53 := route53.New(session)

	t.Run("route53 test", func(t *testing.T) {
		for i := 0; i < 210; i++ {
			name := strconv.Itoa(i) + "foobar.com"
			callerRef := "1"
			_, err = r53.CreateHostedZone(&route53.CreateHostedZoneInput{
				Name:            &name,
				CallerReference: &callerRef,
			})
			require.Nil(t, err)
		}

		resp, err := getRoute53HostedDomains(r53)
		require.Nil(t, err)
		// This doesn't work as AWS does, we expect this to return a max of 100 items
		assert.Equal(t, 100, len(resp))
	})
}
