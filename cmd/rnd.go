package cmd

import (
	"regexp"
    "strings"
    "errors"
    "net"
    "fmt"
    "sort"
    "path/filepath"
    "strconv"
    "os"

    "github.com/helviojunior/randmap/internal/ascii"
    "github.com/helviojunior/randmap/internal/tools"
    "github.com/helviojunior/randmap/pkg/readers"
    "github.com/helviojunior/randmap/pkg/models"
    "github.com/helviojunior/randmap/pkg/log"
    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)

type PathInfo struct {
    Path string
    Type string
}

var disablePortRatio bool
var tmpProto []string
var tmpPort string
var topPorts int
var tmpExcludeFilter = []string{}
var tmpIncludeFilter = []string{}
var tmpFromPaths       []string
var conversionCmdExtensions = []string{".sqlite", ".sqlite3", ".db", ".xml", ".txt"}
var convertCmdFlags = struct {
    fromPaths       []PathInfo
    toPath          string
}{}

var reportCmd = &cobra.Command{
    Use:   "rnd",
    Short: "Randomized ip & port feed for scans",
    Long: ascii.LogoHelp(ascii.Markdown(`
# rnd

Randomized ip & port feed for scans.

A --from-path and --to-path must be specified.`)),
    Example: `
- randmap rnd --from-path ~/client_data/ --top-ports 100
- randmap rnd --from-path ~/client_data/ -p 80,443,445,3389
- randmap rnd --from-path ~/client_data/enumdns.sqlite3 --to-path ~/Desktop/ --top-ports 100
`,
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        // Annoying quirk, but because I'm overriding PersistentPreRun
        // here which overrides the parent it seems.
        // So we need to explicitly call the parent's one now.
        if err = rootCmd.PersistentPreRunE(cmd, args); err != nil {
            return err
        }

        if len(tmpFromPaths) == 0 {
            return errors.New("--from-path not set")
        }
        if convertCmdFlags.toPath == "" {
            return errors.New("--to-path not set")
        }

        if opts.MinSubnet < 8 || opts.MinSubnet > 32 {
            return errors.New("--min-cidr-mask must be a valid CIDR value between 8 and 32")
        }

        if opts.PortsPerScan < 5 {
            return errors.New("--ports-per-host must be greater or equal of 5")
        }

        re := regexp.MustCompile("[^a-zA-Z0-9@-_.]")
        for _, s1 := range tmpIncludeFilter {
            incLines := []string{}

            s1 = strings.Trim(s1, " ")
            if len(s1) > 1 {
                if s1[0:1] == "@" {

                    f1, err := resolver.ResolveFullPath(s1[1:])
                    if err != nil {
                        return errors.New(fmt.Sprintf("Invalid file path (%s): %s", s1[1:], err.Error()))
                    }
                    if !tools.FileExists(f1) {
                        return errors.New(fmt.Sprintf("Invalid file path (%s): %s", s1[1:], "File not found"))
                    }

                    readers.ReadAllLines(f1, &incLines)

                }else{
                    incLines = append(incLines, s1)
                }
                for _, s2 := range incLines {
                    subnet, err := ExtractSubnet(s2)
                    if err != nil {
                        return err
                    }
                    if subnet != nil {
                        opts.IncludeFilterList = append(opts.IncludeFilterList, *subnet)
                    }else{
                        s3 := strings.ToLower(strings.Trim(s2, " "))
                        s3 = re.ReplaceAllString(s2, "")
                        if s3 != "" {
                            opts.FilterList = append(opts.FilterList, s3)
                        }
                    }
                }
            }
        }

        // Sort subnets by IP
        sort.Slice(opts.IncludeFilterList, func(i, j int) bool {
            return tools.SubnetToUint32(opts.IncludeFilterList[i]) < tools.SubnetToUint32(opts.IncludeFilterList[j])
        })

        for _, s1 := range tmpExcludeFilter {
            incLines := []string{}

            s1 = strings.Trim(s1, " ")
            if len(s1) > 1 {
                if s1[0:1] == "@" {

                    f1, err := resolver.ResolveFullPath(s1[1:])
                    if err != nil {
                        return errors.New(fmt.Sprintf("Invalid file path (%s): %s", s1[1:], err.Error()))
                    }
                    if !tools.FileExists(f1) {
                        return errors.New(fmt.Sprintf("Invalid file path (%s): %s", s1[1:], "File not found"))
                    }

                    readers.ReadAllLines(f1, &incLines)

                }else{
                    incLines = append(incLines, s1)
                }
                for _, s2 := range incLines {
                    subnet, err := ExtractSubnet(s2)
                    if err != nil {
                        return err
                    }
                    if subnet != nil {
                        opts.ExcludeFilterList = append(opts.ExcludeFilterList, *subnet)
                    }
                }
            }
        }

        // Sort subnets by IP
        sort.Slice(opts.IncludeFilterList, func(i, j int) bool {
            return tools.SubnetToUint32(opts.IncludeFilterList[i]) < tools.SubnetToUint32(opts.IncludeFilterList[j])
        })

        sort.Slice(opts.ExcludeFilterList, func(i, j int) bool {
            return tools.SubnetToUint32(opts.ExcludeFilterList[i]) < tools.SubnetToUint32(opts.ExcludeFilterList[j])
        })

        allowTcp := false
        allowUdp := false
        if len(tmpProto) > 0 {
            for _, p := range tmpProto {
                switch strings.ToLower(p) {
                case "t", "tcp":
                    allowTcp = true
                 case "u", "udp":   
                    allowUdp = true
                default:
                    return errors.New("Invalid protocol selector. Permitted values are -sU or -sT")
                }
            }
        }else{
            allowTcp = true
            allowUdp = true
        }

        if tmpPort != "" {
            tmpList := []int{}
            re := regexp.MustCompile("(\\b[0-9]{1,5}(?:-[0-9]{1,5})?\\b)")
            matches := re.FindAllString(tmpPort, -1)
            for _, m := range matches {
                if strings.Contains(m, "-") {
                    p := strings.Split(m, "-")
                    p1, err := strconv.ParseInt(p[0], 10, 32) // base 10, 32-bit range
                    if err != nil {
                        return errors.New("Port filter conversion error: " + err.Error())
                    }
                    p2, err := strconv.ParseInt(p[1], 10, 32) // base 10, 32-bit range
                    if err != nil {
                        return errors.New("Port filter conversion error: " + err.Error())
                    }
                    for i := p1; i <= p2; i++ {
                        if !tools.SliceHasInt(tmpList, int(i)) {     
                            tmpList = append(tmpList, int(i))
                        }
                    }
                }else{
                    num, err := strconv.ParseInt(m, 10, 32) // base 10, 32-bit range
                    if err != nil {
                        return errors.New("Port filter conversion error: " + err.Error())
                    }

                    if !tools.SliceHasInt(tmpList, int(num)) {   
                        tmpList = append(tmpList, int(num))
                    }
                }       
            }
            opts.Services = models.GetServicesFromList(tmpList, allowTcp, allowUdp)

            tmpShowList := []string{}
            for _, s := range opts.Services {
                tmpShowList = append(tmpShowList, s.String())
            }

            if len(tmpShowList) > 0 {
                log.Warn("Port list: " + strings.Join(tmpShowList, ", "))
            }
        }

        if topPorts > 0 {
            opts.Services = models.GetTopServices(topPorts, allowTcp, allowUdp, !disablePortRatio)
            log.Warnf("Filtering top %d ports", topPorts)
        }

        if len(opts.Services) == 0 {
            return errors.New("You must specify either --port or --top-ports.")
        }

        models.ShuffleServices(opts.Services)

        if len(opts.IncludeFilterList) > 0 {
            fl := []string{}
            for _, n := range opts.IncludeFilterList {
                fl = append(fl, n.String())
            }
            log.Warn("IP/subnet inclusion list: " + strings.Join(fl, ", "))
        }

        if len(opts.ExcludeFilterList) > 0 {
            fl := []string{}
            for _, n := range opts.ExcludeFilterList {
                fl = append(fl, n.String())
            }
            log.Warn("IP/subnet exclusion list: " + strings.Join(fl, ", "))
        }

        if len(opts.FilterList) > 0 {
            log.Warn("Filter list: " + strings.Join(opts.FilterList, ", "))
        }

        return nil
    },
    PreRunE: func(cmd *cobra.Command, args []string) error {
        var err error
        
        for i, fp := range tmpFromPaths {
            if strings.Trim(fp, " ") == "" {
                return errors.New(fmt.Sprintf("from-path entry %d is empty", i+1))
            }

            fp1, err := resolver.ResolveFullPath(fp)
            if err != nil {
                return err
            }

            if fpt, err := tools.FileType(fp1); err != nil {
                return err
            }else{

                if fpt == "file" {

                    fromExt := strings.ToLower(filepath.Ext(fp1))

                    if !tools.SliceHasStr(conversionCmdExtensions, fromExt) {
                        return errors.New("unsupported source file type: " + fp1)
                    }
                }

                convertCmdFlags.fromPaths = append(convertCmdFlags.fromPaths, PathInfo{
                    Path   : fp1,
                    Type   : fpt,
                })
            }

        }

        convertCmdFlags.toPath, err = resolver.ResolveFullPath(convertCmdFlags.toPath)
        if err != nil {
            return err
        }

        if ft, err := tools.FileType(convertCmdFlags.toPath); err != nil {
            if !os.IsNotExist(err) {
                return err
            }
            if _, err := tools.CreateDir(convertCmdFlags.toPath); err != nil {
                return err
            }
        }else if ft != "directory" {
            return errors.New("to-path must be a directory")
        }


        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
        //var ft string
        //var err error

        log.Info("Starting process...")

        
        reader, err := readers.NewDataReader(*opts)
        if err != nil {
            log.Error("Error starting data reader", "err", err)
            os.Exit(2)
        }

        for _, fp := range convertCmdFlags.fromPaths {
            if fp.Type == "file" {
                log.Debug("Adding source file", "path", fp.Path)
                reader.AddDatabase(fp.Path)
            }else {

                log.Debug("Checking folder", "path", fp.Path)
                entries, err := os.ReadDir(fp.Path)
                if err != nil {
                    log.Error("Cannot reader path", "path", fp.Path, "err", err)
                    os.Exit(2)
                }
             
                for _, e := range entries {
                    fileFullPath := filepath.Join(fp.Path, e.Name())
                    fileRelativePath, _ := resolver.ResolveRelativePath(fp.Path, filepath.Join(fp.Path, e.Name()))
                    fileExt := strings.ToLower(filepath.Ext(e.Name()))
                    if tools.SliceHasStr(conversionCmdExtensions, fileExt) {
                        log.Debug("Adding source file", "path", fileRelativePath)
                        reader.AddDatabase(fileFullPath)
                    }else{
                        log.Debug("Ignoring file", "path", fileRelativePath)
                    }
                    
                }

            }
        }

        log.Info("Generating scan template files")
        err = reader.GenerateScanFiles(convertCmdFlags.toPath)
        if err != nil {

            log.Error("Failed to generate files")
            log.Errorf("%s", err.Error())

            if _, ok := err.(models.NoDataError); ok {
                os.Exit(5)
            }
            
            os.Exit(2)
        }
        log.Infof("Files saved at %s", convertCmdFlags.toPath)

        fmt.Printf(ascii.Markdown("# Files generated sucessuly!\n\nUse them with the following command sample \n`nmap -Pn -v -T4 -A -sTV -p $(tr '\\n' , <scan_0001_ports.txt) -iL scan_0001_ips.txt -oX nmap.xml`"))
        
    },
}

func ExtractSubnet(text string) (*net.IPNet, error) {
    netRe1 := regexp.MustCompile("\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\/(3[0-2]|[12][0-9]|[1-9])\\b")
    netRe2 := regexp.MustCompile("\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\/(255\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\b")
    ipRe := regexp.MustCompile("\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\b")

    // Check if is an CIDR Subnet (xxx.xxx.xxx.xxx/xx)
    mNet1 := netRe1.FindStringSubmatch(text)
    if len(mNet1) > 0 {
        _, subnet, err := net.ParseCIDR(mNet1[0])
        if err != nil {
            return nil, errors.New("Invalid subnet: " + err.Error())
        }
        return subnet, nil
    }

    // Check if is an Netmask Subnet (xxx.xxx.xxx.xxx/255.xxx.xxx.xxx)
    mNet2 := netRe2.FindStringSubmatch(text)
    if len(mNet2) > 0 {
        ip := net.ParseIP(mNet2[1])
        if ip == nil {
            return nil, errors.New(fmt.Sprintf("Invalid subnet ip (%s)", mNet2[0]))
        }
        mask := net.IPMask(net.ParseIP(mNet2[2]).To4())
        if mask == nil {
            return nil, errors.New(fmt.Sprintf("Invalid subnet mask (%s)", mNet2[0]))
        }
        ones, _ := mask.Size()

        cidr := fmt.Sprintf("%s/%d", ip.String(), ones)

        _, subnet, err := net.ParseCIDR(cidr)
        if err != nil {
            return nil, errors.New("Invalid subnet: " + err.Error())
        }
        return subnet, nil
    }

    // Check if is an IP addr
    mIp := ipRe.FindStringSubmatch(text)
    if len(mIp) > 0 {
        ip := net.ParseIP(mIp[0])
        if ip == nil {
            return nil, errors.New(fmt.Sprintf("Invalid ip address (%s)", mIp[0]))
        }
        _, subnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, 32))
        if err != nil {
            return nil, errors.New(fmt.Sprintf("Invalid ip address (%s): %s", mIp[0], err.Error()))
        }
        return subnet, nil
    }

    return nil, nil
}

func init() {
    rootCmd.AddCommand(reportCmd)

    reportCmd.PersistentFlags().StringSliceVar(&tmpExcludeFilter, "exclude", []string{}, "Exclude all IP or Network. You can specify multiple values by comma-separated terms or by repeating the flag. Use @filename to load from text file.")
    
    reportCmd.PersistentFlags().StringSliceVar(&tmpIncludeFilter, "include", []string{}, "Include only IP or Network. You can specify multiple values by comma-separated terms or by repeating the flag. Use @filename to load from text file.")
    
    reportCmd.PersistentFlags().StringSliceVarP(&tmpFromPaths, "from-path", "I", []string{}, "The file(s) or directory(ies) to convert from. You can specify multiple values by repeating the flag.")

    reportCmd.PersistentFlags().StringVarP(&convertCmdFlags.toPath, "to-path", "o", "./randmap_out", "The directory to store output files.")

    reportCmd.PersistentFlags().StringVarP(&tmpPort, "port", "p", "", "Only show specified ports. (Ex: -p22; -p1-65535; -p 53,111,137,21-25,80,139,8080)")
    reportCmd.PersistentFlags().IntVar(&topPorts, "top-ports", 0, "Show <number> most common ports")

    reportCmd.PersistentFlags().IntVarP(&opts.SameSubnet, "max-same-subnet", "S", 16, "Number of same-subnet hosts scanned per scan")
    reportCmd.PersistentFlags().IntVarP(&opts.HostsPerScan, "hosts-per-scan", "H", 64, "Host count per scan instance")
    reportCmd.PersistentFlags().IntVarP(&opts.PortsPerScan, "ports-per-host", "P", 128, "Number of ports scanned per host")
    reportCmd.PersistentFlags().IntVarP(&opts.MinSubnet, "min-cidr-mask", "m", 27, "Defines the minimum subnet size (CIDR) to consider when expanding target hosts. Use /32 to treat each host individually, or a broader subnet like /27 to include nearby hosts.")

    reportCmd.PersistentFlags().StringSliceVarP(&tmpProto, "scan-protocol", "s", []string{"tcp"}, "Protocol to scan (TCP or UDP). You can specify multiple values by comma-separated terms or by repeating the flag.")

    reportCmd.PersistentFlags().BoolVarP(&opts.IncludeSaas, "full", "F", false, "Include SaaS addresses to scan list")
    reportCmd.PersistentFlags().BoolVar(&disablePortRatio, "disable-port-ratio", false, "Disables sorting by port ratio when using --top-ports. Ports will be selected in linear order instead.")

    reportCmd.PersistentFlags().BoolVarP(&opts.Append, "append", "A", false, "Append to an existing list")
}
