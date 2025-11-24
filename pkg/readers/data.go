package readers

import (
    "fmt"
    "net"
    "os"
    "strings"
    "path/filepath"
    "encoding/json"
    "bufio"
    "io"
    "sort"
    "encoding/binary"

    "github.com/helviojunior/randmap/internal/tools"
    "github.com/helviojunior/randmap/pkg/log"
    "github.com/helviojunior/randmap/pkg/database"
    "github.com/helviojunior/randmap/pkg/models"
    resolver "github.com/helviojunior/gopathresolver"
    enumdns_run "github.com/helviojunior/enumdns/pkg/runner"
    enumdns_models "github.com/helviojunior/enumdns/pkg/models"
    certcrawler_models "github.com/helviojunior/certcrawler/pkg/models"
    netcalc "github.com/helviojunior/pcapraptor/pkg/netcalc"

    "github.com/lair-framework/go-nmap"
    "database/sql"
    "gorm.io/gorm/clause"
)

// Runner is a runner that probes web targets using a driver
type DataReader struct {

    // options for the Runner to consider
    options Options

    //EnumDNS database files
    enumdnsFiles []string

    //Cert Crawler database files
    certcrawlerFiles []string

    //NMAP database files
    nmapFiles []string

    textFiles []string
}

func NewDataReader(opts Options) (*DataReader, error) {
    return &DataReader{
        enumdnsFiles: []string{ },
        options: opts,
    }, nil
}

func (r *DataReader) AddDatabase(filePath string) error {
    file, err := resolver.ResolveFullPath(filePath)
    if err != nil {
        return err
    }

    if strings.ToLower(filepath.Ext(filePath)) == ".xml" {
        _, err := r.getNmapXML(filePath)
        if err != nil {
            return err
        }

        //OK is an valid NMAP XML
        r.nmapFiles = append(r.nmapFiles, filePath)

    }else if strings.ToLower(filepath.Ext(filePath)) == ".txt" {
       
        r.textFiles = append(r.textFiles, filePath)

    }else{

        conn, err := database.Connection("sqlite:///"+ file, false, r.options.Logging.DebugDb)
        if err != nil {
            return err
        }

        appName := database.GetDbApplication(conn)

        switch appName {
        case "enumdns":
            r.enumdnsFiles = append(r.enumdnsFiles, filePath)
        case "certcrawler":
            r.certcrawlerFiles = append(r.certcrawlerFiles, filePath)
        case "":
            log.Debug("Invalid database", "file", filePath, "err", "application_info table does not exists or is empty")
        default:
            log.Debug("Invalid database", "file", filePath, "application", appName, "err", "Unknown application")
        }
    }

    return nil
}

func (r *DataReader) GenerateScanFiles(outputPath string) error {
    //
    //certificates := r.GetCertificates()

    /*
    for _, c := range certificates {
        log.Debug("Cert 2", "c", c)
    }*/

    subnetList := []netcalc.SubnetData{}
    saasSubnetList := []netcalc.SubnetData{}
    hasIgnored := false

    for _, eDNS := range r.enumdnsFiles {
        log.Info("Reading EnumDNS file", "file", eDNS)
        regCount := 0
        conn, err := database.Connection(fmt.Sprintf("sqlite:///%s", eDNS), true, false)
        if err != nil {
            return err
        }
        defer database.CloseDB(conn)

        var rResults *sql.Rows

        sqlHosts := ""

        /*
        NOTE: DO NOT Filter here! We need this information to filter out the same /24 subnet
        if !r.options.IncludeSaas {
            sqlHosts += " AND (saas_product = '' or saas_product is null)"
        }
        */
        if len(r.options.FilterList) > 0 {
            sqlHosts += r.prepareSQL([]string{"fqdn", "ptr"})
        }
        rResults, err = conn.Model(&enumdns_models.Result{}).Preload(clause.Associations).Where("[exists] = 1 AND (ipv4 != '') " + sqlHosts).Rows()
        if err != nil {
            return err
        }

        defer rResults.Close()
        var resultItem enumdns_models.Result
        for rResults.Next() {

            conn.ScanRows(rResults, &resultItem)

            ip := net.ParseIP(resultItem.IPv4)
            if ip == nil {
                log.Debugf("Invalid IP (%s)", resultItem.IPv4)
                continue
            }

            regCount++

            ptr := strings.Trim(resultItem.Ptr, ".")
            hostName := strings.Trim(resultItem.FQDN, ".")

            isValid, isSaas := r.CheckHostEntry(ip, ptr, hostName)
            if isSaas {
                hasIgnored = true
                netcalc.AddSlice(&saasSubnetList, netcalc.NewSubnetFromIPMask(ip, 24))
                log.Debug("Host ignored: identified as SaaS address.", "ip", ip)
            }
            if isValid {
                regCount++
                netcalc.AddSlice(&subnetList, netcalc.NewSubnetFromIPMask(ip, r.options.MinSubnet))
            }
        
        }
    
        log.Infof("Processed %d hosts", regCount)
        
    }

    for _, c := range r.certcrawlerFiles {
        log.Info("Reading CertCrawler file", "file", c)
        regCount := 0
        newRegCount := 0
        conn, err := database.Connection(fmt.Sprintf("sqlite:///%s", c), true, false)
        if err != nil {
            return err
        }

        defer database.CloseDB(conn)

        var rHosts *sql.Rows

        if len(r.options.FilterList) > 0 {
            var ids = []int{}
            sqlHosts := r.prepareSQL([]string{"h.ptr", "cn.name"})

            if err := conn.Raw("SELECT distinct h.id from hosts_certs as hc inner join cert_names as cn on cn.certificate_id = hc.certificate_id inner join hosts as h on h.id = hc.host_id WHERE cn.name != '' " + sqlHosts).Find(&ids).Error; err == nil {
            
                rHosts, err = conn.Model(&certcrawler_models.Host{}).Preload(clause.Associations).Where("id in ?", ids).Rows()
            }
        }else{
            rHosts, err = conn.Model(&certcrawler_models.Host{}).Preload(clause.Associations).Rows()
        }

        if err != nil {
            return err
        }

        defer rHosts.Close()
        var host certcrawler_models.Host
        for rHosts.Next() {

            conn.ScanRows(rHosts, &host)
            regCount++

            ip := net.ParseIP(host.Ip)
            if ip == nil {
                log.Debugf("Invalid IP (%s)", host.Ip)
                continue
            }

            isValid, isSaas := r.CheckHostEntry(ip, host.Ptr)
            if isSaas {
                hasIgnored = true
                netcalc.AddSlice(&saasSubnetList, netcalc.NewSubnetFromIPMask(ip, 24))
                log.Debug("Host ignored: identified as SaaS address.", "ip", ip)
            }
            if isValid {
                newRegCount++
                netcalc.AddSlice(&subnetList, netcalc.NewSubnetFromIPMask(ip, r.options.MinSubnet))
            }

        }
    
        log.Infof("Processed %d hosts with %d new items", regCount, newRegCount)
    }

    for _, nmap := range r.nmapFiles {
        log.Info("Reading NMAP file", "file", nmap)
        regCount := 0
        newRegCount := 0
        nmapXML, err := r.getNmapXML(nmap)
        if err == nil {
            for _, host := range nmapXML.Hosts {
                regCount++

                ptr := ""
                for _, hostName := range host.Hostnames {
                    if strings.ToLower(hostName.Type) == "ptr" && hostName.Name != "" {
                        ptr = strings.Trim(strings.ToLower(hostName.Name), " ")
                    }
                }

                for _, address := range host.Addresses {
                    if !tools.SliceHasStr([]string{"ipv4", "ipv6"}, address.AddrType) {
                        continue
                    }

                    ip := net.ParseIP(address.Addr)
                    if ip == nil {
                        log.Debugf("Invalid IP (%s)", address.Addr)
                        continue
                    }

                    add := true
                    if len(r.options.FilterList) > 0 {
                        add = false
                        // serialize to Json and check strings
                        j, err := json.Marshal(host)
                        if err != nil {
                            add = true
                        }else{
                            jsonStr := strings.ToLower(string(j))

                            for _, f := range r.options.FilterList {
                                if strings.Contains(jsonStr, f) {
                                    add = true
                                }
                            }
                        }
                    }

                    if add {
                        isValid, isSaas := r.CheckHostEntry(ip, ptr)
                        if isSaas {
                            hasIgnored = true
                            netcalc.AddSlice(&saasSubnetList, netcalc.NewSubnetFromIPMask(ip, 24))
                            log.Debug("Host ignored: identified as SaaS address.", "ip", ip)
                        }
                        if isValid {
                            newRegCount++
                            netcalc.AddSlice(&subnetList, netcalc.NewSubnetFromIPMask(ip, r.options.MinSubnet))
                        }
                    }
                }
            }
        }
        log.Infof("Processed %d hosts with %d new items", regCount, newRegCount)
    }

    for _, txt := range r.textFiles {
        log.Info("Reading TXT file", "file", txt)
        regCount := 0
        newRegCount := 0

        file, err := os.Open(txt)
        if err != nil {
            return err
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            line := scanner.Text()
            if line == "" {
                continue
            }

            subnets, err := tools.ExtractAllSubnets(line)
            if err != nil {
                return err
            }

            if len(subnets) > 0 {
                for _, subnet := range subnets {
                    regCount++

                    add := true
                    m, _ := subnet.Mask.Size()

                    if m == 32 {
                        isValid, isSaas := r.CheckHostEntry(subnet.IP, "")
                        if isSaas {
                            hasIgnored = true
                            netcalc.AddSlice(&saasSubnetList, netcalc.NewSubnetFromIPMask(subnet.IP, 24))
                            log.Debug("Host ignored: identified as SaaS address.", "ip", subnet.IP)
                        }
                        add = isValid
                    }

                    if m > r.options.MinSubnet {
                        m = r.options.MinSubnet
                    }else if m < r.options.MaxSubnet {
                        m = r.options.MaxSubnet
                    }

                    if add {
                        for _, netIp := range saasSubnetList {
                             _, saas, err := net.ParseCIDR(fmt.Sprintf("%s/%d", netIp.Net, netIp.Mask))
                            if err != nil {
                                log.Debug("Error parsing network ip", "err", err)
                            }

                            if err == nil {
                                if !saas.Contains(subnet.IP) {
                                    hasIgnored = true
                                    add = false
                                    continue
                                }
                            }
                        }
                    }
                    if add {
                        newRegCount++
                        netcalc.AddSlice(&subnetList, netcalc.NewSubnetFromIPMask(subnet.IP, m))
                    }
                }
            }
        }

        if err := scanner.Err(); err != nil {
            return err
        }
        
        log.Infof("Processed %d hosts with %d new items", regCount, newRegCount)
    }

    saasSubnetList2 := []net.IPNet{}
    for _, saasSubnet := range saasSubnetList {
        n := fmt.Sprintf("%s/%d", saasSubnet.Net, saasSubnet.Mask)
        _, subnet, err := net.ParseCIDR(n)
        if err != nil {
            log.Debug("Error parsing network ip", "err", err)
        }
        saasSubnetList2 = append(saasSubnetList2, *subnet)
    }

    sort.Slice(subnetList, func(i, j int) bool {
        return binary.BigEndian.Uint32(subnetList[i].To4()) < binary.BigEndian.Uint32(subnetList[j].To4())
    })

    subnetList2 := []string{}
    for _, subnet := range subnetList {
        n := fmt.Sprintf("%s/%d", subnet.Net, subnet.Mask)
        if !tools.SliceHasStr(subnetList2, n) {
            subnetList2 = append(subnetList2, n)
        }
    }

    supnetList2 := []string{}

    log.Info("Calculating supernets...")
    
    netGroups := netcalc.GroupSubnets(subnetList2)
    if (r.options.NoSupernet) {
        netGroups = [][]net.IPNet{}
        for _, cidr := range subnetList2 {
            _, ipnet, err := net.ParseCIDR(cidr)
            if err != nil {
                fmt.Println("Erro CIDR:", cidr)
                continue
            }
            
            netGroups = append(netGroups, []net.IPNet{*ipnet})

        }
        
    }
    for i, group := range netGroups {
        supnet := netcalc.CalculateSupernet(group)
        n := supnet.String()
        if !tools.SliceHasStr(supnetList2, n) {
            supnetList2 = append(supnetList2, n)
            log.Infof("Supernet %04d: %s (from %d ips)", i+1, n, len(group))
        }
    }


    serviceSplitList := []([]models.Service){}
    tmpServices := []models.Service{}
    for _, svc := range r.options.Services {
        tmpServices = append(tmpServices, svc)
        if len(tmpServices) >= r.options.PortsPerScan {
            svcCopy := make([]models.Service, len(tmpServices))
            copy(svcCopy, tmpServices)
            serviceSplitList = append(serviceSplitList, svcCopy)
            tmpServices = []models.Service{}
        }
    }
    if len(tmpServices) > 0 {
        serviceSplitList = append(serviceSplitList, tmpServices)
    }
    log.Infof("Selected ports were split into %d separate scans.", len(serviceSplitList))

    if len(serviceSplitList) == 0 {
        return models.NoDataError{Message:"No services available to generate files."}
    }

    var allLabeled []tools.LabeledIP
    for _, cidr := range supnetList2 {
        ips, err := tools.ExpandCIDR(cidr)
        if err != nil {
            log.Errorf("Error expanding subnet: %s", err.Error())
            continue
        }

        log.Debugf("Subnet %s expanded in %d ip addresses", cidr, len(ips))
        for _, ip := range ips {
            add := true
            if len(r.options.ExcludeFilterList) > 0 {
                for _, f := range r.options.ExcludeFilterList {
                    if f.Contains(ip.IP) {
                        add = false
                    }
                }
            }
            if add {
                if len(saasSubnetList) > 0 {
                    for _, netIp := range saasSubnetList {
                        _, saas, err := net.ParseCIDR(fmt.Sprintf("%s/%d", netIp.Net, netIp.Mask))
                        if err != nil {
                            log.Debug("Error parsing network ip", "err", err)
                        }

                        if err == nil {
                            if saas.Contains(ip.IP) {
                                hasIgnored = true
                                add = false
                            }
                        }
                    }
                }
            }

            if add {
                allLabeled = append(allLabeled, ip)
            }
        }
    }

    if len(allLabeled) == 0 {
        return models.NoDataError{Message:"No items available to generate files."}
    }

    log.Debug("Addresses", "count", len(allLabeled))
    tools.ShuffleLabeledIPs(allLabeled)

    scanGroups := r.GroupIPsAcrossSubnets(allLabeled)

    scans := []models.ScanMap{}

    if (r.options.Append) {
        log.Info("Getting previous scan data")

        file, err := os.Open(filepath.Join(outputPath, "scan_0000_list.json"))
        if err != nil {
            log.Error("could not open file scan_0000_list.json", "err", err)
        }else{
            defer file.Close()

            fileData, err := io.ReadAll(file)
            if err != nil {
                log.Error("could not read file scan_0000_list.json", "err", err)
            }else{
                if err := json.Unmarshal(fileData, &scans); err != nil {
                    log.Error("could not unmarshal JSON file scan_0000_list.json", "err", err)
                    scans = []models.ScanMap{}
                }
            }
        }
        log.Infof("Read \033[33m%d\033[0m distinct scans.", len(scans))

    }

    idx := len(scans) + 1
    for _, group := range scanGroups {
        for _, svc := range serviceSplitList {
            filePrefix := fmt.Sprintf("scan_%04d", idx)
            newScan := models.ScanMap{
                IpFile    : filePrefix + "_ips.txt",
                PortFile  : filePrefix + "_ports.txt",
            }
            newScan.Hosts = make([]net.IP, len(group.Hosts))
            newScan.Services = make([]models.Service, len(svc))

            copy(newScan.Hosts, group.Hosts)
            copy(newScan.Services, svc)

            scans = append(scans, newScan)
            idx++
        }
    }


    j, err := json.Marshal(scans)
    if err != nil {
        return err
    }

    // Open the file in append mode, create it if it doesn't exist
    file, err := os.OpenFile(filepath.Join(outputPath, "scan_0000_list.json"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
    if err != nil {
        return err
    }
    defer file.Close()

    // Append the JSON data as a new line
    if _, err := file.Write(append(j, '\n')); err != nil {
        return err
    }

    for _, scan := range scans {
        
        ipList := filepath.Join(outputPath, scan.IpFile)
        portList := filepath.Join(outputPath, scan.PortFile)

        file1, err := os.OpenFile(ipList, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
        if err != nil {
            return err
        }
        defer file1.Close()

        for _, ip := range scan.Hosts {
            if _, err := file1.WriteString(ip.String() + "\n"); err != nil {
                return err
            }
        }

        file2, err := os.OpenFile(portList, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
        if err != nil {
            return err
        }
        defer file2.Close()

        tmpList := []string{}
        for _, svc := range scan.Services {
            tmpList = append(tmpList, svc.String())
        }

        if _, err := file2.WriteString(strings.Join(tmpList, ",")); err != nil {
            return err
        }

    }

    if hasIgnored{
        log.Warn("Some SaaS service addresses were ignored. Use the \033[33m-F\033[0m flag to include them.")
    }

    log.Infof("Generated \033[33m%d\033[0m IP groups and \033[33m%d\033[0m port groups, resulting in a total of \033[33m%d\033[0m distinct scans.", len(scanGroups), len(serviceSplitList), len(scanGroups) * len(serviceSplitList))

    return nil

}

// Group IPs across subnets with constraints
func (r *DataReader) GroupIPsAcrossSubnets(allIPs []tools.LabeledIP) []models.ScanMap {
    var result []models.ScanMap
    var current models.ScanMap
    subnetCount := make(map[string]int)

    for _, item := range allIPs {
        // Check if current group is full
        if len(current.Hosts) >= r.options.HostsPerScan {
            result = append(result, current)
            current = models.ScanMap{}
            subnetCount = make(map[string]int)
        }

        // Check if this subnet already hit its limit in current group
        if subnetCount[item.Subnet] >= r.options.SameSubnet {
            continue
        }

        current.Hosts = append(current.Hosts, item.IP)
        subnetCount[item.Subnet]++
    }

    if len(current.Hosts) > 0 {
        result = append(result, current)
    }
    return result
}

func (r *DataReader) CheckHostEntry(ip net.IP, hostNames ...interface{}) (bool, bool) { // return is_valid and is_sass
    add := false
    if len(r.options.IncludeFilterList) > 0 {
        for _, f := range r.options.IncludeFilterList {
            if f.Contains(ip) {
                add = true
            }
        }
    }else{
        add = true
    }
    if len(r.options.ExcludeFilterList) > 0 {
        for _, f := range r.options.ExcludeFilterList {
            if f.Contains(ip) {
                add = false
                log.Debug("IP denied by exclude filter", "ip", ip)
            }
        }
    }
    if !add {
        return false, false
    }

    hasSaas := false
    if !r.options.IncludeSaas {
        for _, v := range hostNames {
            if hn, ok := v.(string); ok {
                if hn != "" {
                    if ss, _, _ := enumdns_run.ContainsSaaS(hn); ss {
                       hasSaas = true
                       continue
                    }
                    if ss, _, _ := enumdns_run.ContainsCloudProduct(hn); ss {
                       hasSaas = true
                       continue
                    }
                }
            }
        }
    }

    return !hasSaas, hasSaas
}

func (r *DataReader) getNmapXML(filePath string) (*nmap.NmapRun, error) {
    xml, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    nmapXML, err := nmap.Parse(xml)
    if err != nil {
        if len(xml) < 1024 {
            return nil, err
        }

        log.Warn("XML data is broken, trying to solve that...", "err", err)

        // Check if we can solve the most common issue
        var err2 error
        newText := string(xml[len(xml)-1024:])
        if strings.Contains(newText, "<runstats") && !strings.Contains(newText, "</runstats>") {
            xml = append(xml, []byte("</runstats>")...)
        } 
        if !strings.Contains(newText, "</nmaprun>") {
            xml =  append(xml, []byte("</nmaprun>")...)
        } 
        nmapXML, err2 = nmap.Parse(xml)
        if err2 != nil {
            return nil, err //Return original error
        }
        log.Warn("Issue resolved: XML data has been successfully repaired and loaded.")
    }

    return nmapXML, nil
}

func (r *DataReader) prepareSQL(fields []string) string {
    sql := ""
    for _, f := range fields {
        for _, w := range r.options.FilterList {
            if sql != "" {
                sql += " or "
            }
            sql += " " + f + " like '%"+ w + "%' "
        }
    }
    if sql != "" {
        sql = " and (" + sql + ")"
    }
    return sql
}

func (r *DataReader) Close() {
    r.enumdnsFiles = []string{ }
}
