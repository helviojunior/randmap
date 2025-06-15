package readers

import (
    //"net/url"
    "net"

    "github.com/helviojunior/randmap/pkg/models"
)

// Options are global github.com/helviojunior/randmaprandmap options
type Options struct {
    // Logging is logging options
    Logging Logging

    ExcludeFilterList []net.IPNet

    IncludeFilterList []net.IPNet

    FilterList []string

    StoreTempInWorkspace bool

    Services []models.Service

    HostsPerScan int

    PortsPerScan int

    SameSubnet int

    IncludeSaas bool

    MinSubnet int
}

// Logging is log related options
type Logging struct {
    // Debug display debug level logging
    Debug bool
    // Debug display debug level logging
    DebugDb bool
    // LogScanErrors log errors related to scanning
    LogScanErrors bool
    // Silence all logging
    Silence bool
}

// NewDefaultOptions returns Options with some default values
func NewDefaultOptions() *Options {
    return &Options{
        Logging: Logging{
            Debug:         true,
            LogScanErrors: true,
        },
        ExcludeFilterList: []net.IPNet{},
        IncludeFilterList: []net.IPNet{},
        StoreTempInWorkspace: false,
        Services: []models.Service{},
    }
}