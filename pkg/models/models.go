package models

import (
    "sort"
    "fmt"
    "net"
    "math/rand"
    "time"

    //"github.com/helviojunior/randmap/internal/tools"
)

type ScanMap struct {
    Hosts         []net.IP       `json:"hosts"`
    Services      []Service      `json:"services"`
    IpFile        string         `json:"ip_file"`
    PortFile      string         `json:"port_file"`
}

type Service struct {
    Name          string         `json:"name"`
    Port          int            `json:"port"`
    Protocol      string         `json:"protocol"`
    OpenFrequency float32        `json:"open_frequency"`
}

func (s *Service) String() string {
    if s.Protocol == "udp" {
        return fmt.Sprintf("U:%d", s.Port)
    }else{
        return fmt.Sprintf("T:%d", s.Port)
    }
}

func GetTopServices(number int, tcp bool, udp bool, sortByFrequency bool) []Service {
    var tmpSvc = []Service{}
    for _, svc := range nmap_services {
        if (tcp && svc.Protocol == "tcp") || (udp && svc.Protocol == "udp"){
            tmpSvc = append(tmpSvc, svc)
        }
    }
    if sortByFrequency {
        sort.Slice(tmpSvc, func(i, j int) bool {
            return tmpSvc[i].OpenFrequency > tmpSvc[j].OpenFrequency
        })
    }else{
        sort.Slice(tmpSvc, func(i, j int) bool {
            return tmpSvc[i].Port > tmpSvc[j].Port
        })
    }
    if len(tmpSvc) >= number {
        return tmpSvc[:number]
    }
    return tmpSvc
}

func GetServicesFromList(ports []int, tcp bool, udp bool) []Service {
    var tmpSvc = []Service{}
    for _, port := range ports {
        found := false
        for _, svc := range nmap_services {
            if port == svc.Port && ((tcp && svc.Protocol == "tcp") || (udp && svc.Protocol == "udp")){
                tmpSvc = append(tmpSvc, svc)
                found = true
            }
        }
        if !found {
            if tcp {
                tmpSvc = append(tmpSvc, Service{
                    Name : "unknown",
                    Port : port,
                    Protocol : "tcp",
                    OpenFrequency : 1,
                })
            }
            if udp {
                tmpSvc = append(tmpSvc, Service{
                    Name : "unknown",
                    Port : port,
                    Protocol : "udp",
                    OpenFrequency : 1,
                })
            }
        }
    }
    sort.Slice(tmpSvc, func(i, j int) bool {
        return tmpSvc[i].OpenFrequency < tmpSvc[j].OpenFrequency
    })
    return tmpSvc
}

func ShuffleServices(services []Service) {
    rand.Seed(time.Now().UnixNano())
    rand.Shuffle(len(services), func(i, j int) {
        services[i], services[j] = services[j], services[i]
    })
}

type NoDataError struct {
	Message string
}

func (e NoDataError) Error() string {
	return e.Message
}
