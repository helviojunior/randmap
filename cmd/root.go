package cmd

import (
	"os"
	"fmt"
	"os/signal"
    "syscall"
    "time"
    //"runtime"

	"github.com/helviojunior/randmap/internal/ascii"
	"github.com/helviojunior/randmap/internal/tools"
	"github.com/helviojunior/randmap/pkg/log"
	"github.com/helviojunior/randmap/pkg/readers"
    resolver "github.com/helviojunior/gopathresolver"
	"github.com/spf13/cobra"
)

var tempFolder string
var workspacePath string
var opts = &readers.Options{}
var rootCmd = &cobra.Command{
	Use:   "randmap",
	Short: "randmap is a modular chart generator",
	Long:  ascii.Logo(),
	Example: `
- randmap report dot --from-path ~/client_data/ --to-file randmap.dot
- randmap report dot --from-path ~/client_data/ --to-file randmap.dot  --type certificates
- randmap report dot --from-path ~/client_data/enumdns.sqlite3 --to-file randmap.dot -F
- randmap report dot --from-path ~/client_data/nmap_file.xml --to-file randmap.dot
`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		
	    if cmd.CalledAs() != "version" && !opts.Logging.Silence {
			fmt.Println(ascii.Logo())
		}

		if opts.Logging.Silence {
			log.EnableSilence()
		}

		if opts.Logging.Debug && !opts.Logging.Silence {
			log.EnableDebug()
			log.Debug("debug logging enabled")
		}

		workspacePath, err = resolver.ResolveFullPath(".")
        if err != nil {
            return err
        }

        basePath := ""
        if opts.StoreTempInWorkspace {
            basePath = "./"
        }

        if tempFolder, err = tools.CreateDir(tools.TempFileName(basePath, "randmap_", "")); err != nil {
            log.Error("error creatting temp folder", "err", err)
            os.Exit(2)
        }

		return nil
	},
}

func Execute() {
	
	ascii.SetConsoleColors()

	c := make(chan os.Signal)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        ascii.ClearLine()
        fmt.Fprintf(os.Stderr, "\r\n")
        ascii.ClearLine()
        ascii.ShowCursor()
        log.Warn("interrupted, shutting down...                            ")
        ascii.ClearLine()
        fmt.Printf("\n")
        tools.RemoveFolder(tempFolder)
        os.Exit(2)
    }()

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SilenceErrors = true
	err := rootCmd.Execute()
	if err != nil {
		var cmd string
		c, _, cerr := rootCmd.Find(os.Args[1:])
		if cerr == nil {
			cmd = c.Name()
		}

		v := "\n"

		if cmd != "" {
			v += fmt.Sprintf("An error occured running the `%s` command\n", cmd)
		} else {
			v += "An error has occured. "
		}

		v += "The error was:\n\n" + fmt.Sprintf("```%s```", err)
		fmt.Println(ascii.Markdown(v))

		os.Exit(1)
	}

	//Time to wait the logger flush
	time.Sleep(time.Second/4)
    tools.RemoveFolder(tempFolder)
    ascii.ShowCursor()
    fmt.Printf("\n")
}

func init() {
	
	rootCmd.PersistentFlags().BoolVarP(&opts.Logging.Debug, "debug-log", "D", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&opts.Logging.Silence, "quiet", "q", false, "Silence (almost all) logging")
	rootCmd.PersistentFlags().BoolVar(&opts.StoreTempInWorkspace, "local-temp", false, "Store the temporary file in the current workspace")
        
}
