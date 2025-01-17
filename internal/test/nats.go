package test

import (
	"context"
	"fmt"
	"io"

	"github.com/testcontainers/testcontainers-go"
	tcnats "github.com/testcontainers/testcontainers-go/modules/nats"
)

type NatsContainerOpts struct {
	Image  string    // image tag, default: "nats:latest"
	Config io.Reader // nats server configuration - passed as nats.conf into container, default nil
}

var defaultNatsContainerOpts = NatsContainerOpts{
	Image:  "nats:latest",
	Config: nil,
}

type NatsContainer struct {
	c        *tcnats.NATSContainer
	endpoint string
}

func NewNatsContainer(ctx context.Context, opts NatsContainerOpts) (NatsContainer, error) {
	opts = opts.defaults()

	var tcopts []testcontainers.ContainerCustomizer
	if opts.Config != nil {
		tcopts = append(tcopts, tcnats.WithConfigFile(opts.Config))
	}

	natsContainer, err := tcnats.Run(ctx, opts.Image, tcopts...)
	if err != nil {
		return NatsContainer{}, fmt.Errorf("run %s container: %w", opts.Image, err)
	}
	natsEndpoint, err := natsContainer.Endpoint(ctx, "")
	if err != nil {
		return NatsContainer{}, fmt.Errorf("get %s container endpoint: %w", opts.Image, err)
	}
	return NatsContainer{
		c:        natsContainer,
		endpoint: natsEndpoint,
	}, nil
}

func (tc NatsContainer) Endpoint() string {
	return tc.endpoint
}

func (tc NatsContainer) Terminate() error {
	return testcontainers.TerminateContainer(tc.c)
}

func (opts NatsContainerOpts) defaults() NatsContainerOpts {
	if opts.Image == "" {
		opts.Image = defaultNatsContainerOpts.Image
	}
	return opts
}
