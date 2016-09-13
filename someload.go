package main

import (
	crypto "crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/montanaflynn/stats"
	"io"
	mrand "math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"
)

type (
	user struct {
		Identity        string
		Password        string
		MacAddress      string
		IpAddress       string
		DhcpFingerprint string
		DhcpVendor      string
	}

	confTmp struct {
		peap string
		tls  string
		fast string
		mab  string
	}

	rl_stats struct {
		requests   uint64
		success    uint64
		failures   uint64
		timeouts   uint64
		start_time time.Time
		times      []float64
	}

	rl_config struct {
		workers  uint64
		csv      string
		dir      string
		log      string
		MACs     uint64
		maxreq   uint64
		maxtime  uint64
		clean    bool
		conf     string
		job_type string
	}
)

var (
	macs     []string
	logfile  *os.File
	lock     = make(chan int, 1)
	reqstats rl_stats
	users    []user
	Config   rl_config
	cliArgs  []string
)

const (
	eapol_cmd      string = "eapol_test"
	acct_cmd       string = "acct_test"
	dhcp_cmd       string = "dhcp_test"
	http_cmd       string = "curl"
	radius_mab_cmd string = "radclient"
	ntlm_auth_cmd  string = "ntlm_auth"
	confSuffix            = ".rl_conf" // appended to all configfiles created
)

func main() {

	reqstats.start_time = time.Now()
	// signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		_ = <-sigs
		atExit(0)
	}()

	setConfig()
	/*

	  EAPOL_TEST flags
	  -c<conf> = configuration file
	  -a<AS IP> = IP address of the authentication server, default 127.0.0.1
	  -p<AS port> = UDP port of the authentication server, default 1812
	  -s<AS secret> = shared secret with the authentication server, default 'radius'
	  -A<client IP> = IP address of the client, default: select automatically
	  -r<count> = number of re-authentications
	  -W = wait for a control interface monitor before starting
	  -S = save configuration after authentication
	  -n = no MPPE keys expected
	  -t<timeout> = sets timeout in seconds (default: 30 s)
	  -C<Connect-Info> = RADIUS Connect-Info (default: CONNECT 11Mbps 802.11b)
	  -M<client MAC address> = Set own MAC address (Calling-Station-Id,
	                           default: 02:00:00:00:00:01)
	  -o<server cert file> = Write received server certificate
	                         chain to the specified file
	*/

	var err error

	// take care of maximum running time
	if Config.maxtime > 0 {
		go func() {
			time.Sleep(time.Duration(Config.maxtime) * time.Second)
			fmt.Fprintf(os.Stderr, "Time's up. Exiting.\n")
			atExit(0)
		}()
	}

	logfile, err = os.Create(Config.log)

	if Config.MACs > 0 {
		for i := uint64(0); i < Config.MACs; i++ {
			macs = append(macs, genMAC())
		}
	}

	confTemplate := confTmp{
		peap: `
			network={
				ssid="EXAMPLE-SSID"
				key_mgmt=WPA-EAP
				eap=PEAP
				identity="{{.Identity}}"
				anonymous_identity="{{.Identity}}"
				password="{{.Password}}"
				phase2="autheap=MSCHAPV2"

				#  Uncomment the following to perform server certificate validation.
				#	ca_cert="/root/ca.crt"
		}`,
		tls: `
		  network={
			  ssid="YOUR-SSID"
			  scan_ssid=1
			  key_mgmt=WPA-EAP
			  pairwise=CCMP TKIP
			  group=CCMP TKIP
			  eap=TLS
			  identity="{{.Identity}}"
			  ca_cert="/etc/certs/cacert.pem"
			  client_cert="/etc/certs/cert.pem"
			  private_key="/etc/certs/key.pem"
			  private_key_passwd="{{.Password}}"
   		}`,
		mab: `User-Name = "{{.MacAddress}}"
User-Password = "{{.MacAddress}}"
Calling-Station-Id = "{{.MacAddress}}"
NAS-Port = 1
Message-Authenticator = 0x00000000000000000000000000000000`,
		fast: `
			network={
				eap=FAST
				pac_file="/tmp/tmp-{{.Identity}}.pac"
				phase1="fast_provisioning=2"
				#anonymous_identity="anonymous"
				phase2="autheap=MSCHAPV2"
				identity="{{.Identity}}"
				password="{{.Password}}"
			}`,
	}

	// read usernames/passwords from csv and generate conf files
	file, err := os.Open(Config.csv)
	check(err)
	r := csv.NewReader(io.Reader(file))
	r.Comma = '|'
	records, err := r.ReadAll()
	check(err)
	file.Close()

	// create the directory
	err = os.MkdirAll(Config.dir, 0700)
	check(err)
	err = os.Chdir(Config.dir)
	check(err)

	tmpl_peap, err := template.New("eapconfig").Parse(confTemplate.peap)
	check(err)

	tmpl_mab, err := template.New("eapconfig").Parse(confTemplate.mab)
	check(err)

	tmpl_fast, err := template.New("eapconfig").Parse(confTemplate.fast)
	check(err)

	tmpl_tls, err := template.New("eapconfig").Parse(confTemplate.tls)
	check(err)

	for _, record := range records {
		nextUser := user{record[0], record[1], record[2], record[3], record[4], record[5]}
		if nextUser.DhcpFingerprint == "" {
			nextUser.DhcpFingerprint = "NULL"
		}
		if nextUser.DhcpVendor == "" {
			nextUser.DhcpVendor = "NULL"
		}
		users = append(users, nextUser)

		//args := struct {
		//	Config rl_config
		//	User   user
		//}{Config, nextUser}

		f, err := os.Create(nextUser.Identity + confSuffix)
		check(err)
		err = tmpl_peap.Execute(f, nextUser)
		check(err)
		f.Close()

		f, err = os.Create(_os_safe_mac(nextUser.MacAddress) + confSuffix)
		check(err)
		err = tmpl_mab.Execute(f, nextUser)
		check(err)
		f.Close()

		f, err = os.Create(nextUser.Identity + "-fast-" + confSuffix)
		check(err)
		err = tmpl_fast.Execute(f, nextUser)
		check(err)
		f.Close()

		f, err = os.Create(nextUser.Identity + "-tls-" + confSuffix)
		check(err)
		err = tmpl_tls.Execute(f, nextUser)
		check(err)
		f.Close()
	}

	var sem = make(chan int, Config.workers)
	for {
		sem <- 1 // add to the semaphore, will block if > than workersPtr

		if (Config.maxreq != 0) && (reqstats.requests >= Config.maxreq) {
			fmt.Fprintf(os.Stderr, "Maximum requests reached. Exiting.\n")
			atExit(0)
		}
		go execute_job(sem)
	}
}

func execute_job(sem chan int) {
	user := users[mrand.Intn(len(users))] // pick a random user

	before := time.Now()
	var cmdErr error
	switch Config.job_type {
	case "radius_eap":
		cmdErr = _eapol_test(user, cliArgs)
	case "radius_eap_fast":
		cmdErr = _radius_eap_fast(user, cliArgs)
	case "radius_eap_tls":
		cmdErr = _radius_eap_tls(user, cliArgs)
	case "radius_mab":
		cmdErr = _radius_mab(user, cliArgs)
	case "dhcp":
		cmdErr = _dhcp(user, cliArgs)
	case "acct":
		cmdErr = _acct(user, cliArgs)
	case "http":
		cmdErr = _http(user, cliArgs)
	case "ntlm_auth":
		cmdErr = _ntlm_auth(user, cliArgs)
	default:
		panic("Don't know that type...")
	}
	diff := time.Since(before).Seconds()

	var status string
	var failed bool
	if cmdErr != nil {
		fmt.Fprintln(os.Stderr, cmdErr)
		status = "failed"
		failed = true
	} else {
		failed = false
		status = "successful"
	}

	lock <- 1 //  lock the shared data structures
	reqstats.requests++
	if failed {
		reqstats.failures++
	} else {
		reqstats.success++
	}
	reqstats.times = append(reqstats.times, diff)

	result := fmt.Sprintf("[%v / %v] %v. Duration %v s\n", user.Identity, user.MacAddress, status, diff)
	io.WriteString(logfile, result)

	<-lock //  unlock the shared data

	<-sem // clear the semaphore
}

func _os_safe_mac(mac string) string {
	return strings.Replace(mac, ":", "", -1)
}

func _radius_mab(user user, cliArgs []string) error {
	cliArgs = append(cliArgs, "-f"+_os_safe_mac(user.MacAddress)+confSuffix)
	cmdErr := _run(radius_mab_cmd, cliArgs)
	return cmdErr
}

func _http(user user, cliArgs []string) error {
	// we add forwarded for to make the server believe we are another IP
	cliArgs = append(cliArgs, "-HX-Forwarded-For: "+user.IpAddress)
	cmdErr := _run(http_cmd, cliArgs)
	return cmdErr
}

func _ntlm_auth(user user, cliArgs []string) error {
	cliArgs = append(cliArgs, "--username="+user.Identity)
	cliArgs = append(cliArgs, "--password="+user.Password)
	cmdErr := _run(ntlm_auth_cmd, cliArgs)
	return cmdErr
}

func _acct(user user, cliArgs []string) error {
	//	/root/pftester/acct.pl --secret=radius --server=172.20.20.109 --mac=00:11:22:33:44:55
	cliArgs = append(cliArgs, "--mac="+user.MacAddress)
	cmdErr := _run(acct_cmd, cliArgs)
	return cmdErr
}

func _dhcp(user user, cliArgs []string) error {
	cliArgs = append(cliArgs, "--mac="+user.MacAddress)
	cliArgs = append(cliArgs, "--ip="+user.IpAddress)
	cliArgs = append(cliArgs, "--hostname=test-hostname")
	cliArgs = append(cliArgs, "--dhcp-fingerprint="+user.DhcpFingerprint)
	cliArgs = append(cliArgs, "--dhcp-vendor="+user.DhcpVendor)

	cmdErr := _run(dhcp_cmd, cliArgs)

	return cmdErr
}

func _eapol_test(user user, cliArgs []string) error {
	cliArgs = append(cliArgs, "-c"+user.Identity+confSuffix)

	cliArgs = append(cliArgs, fmt.Sprintf("-M%v", user.MacAddress))

	cmdErr := _run(eapol_cmd, cliArgs)

	return cmdErr
}

func _radius_eap_fast(user user, cliArgs []string) error {
	cliArgs = append(cliArgs, "-c"+user.Identity+"-fast-"+confSuffix)

	cliArgs = append(cliArgs, fmt.Sprintf("-M%v", user.MacAddress))

	cmdErr := _run(eapol_cmd, cliArgs)

	return cmdErr
}

func _radius_eap_tls(user user, cliArgs []string) error {
	cliArgs = append(cliArgs, "-c"+user.Identity+"-tls-"+confSuffix)

	cliArgs = append(cliArgs, fmt.Sprintf("-M%v", user.MacAddress))

	cmdErr := _run(eapol_cmd, cliArgs)

	return cmdErr
}

func _run(command string, cliArgs []string) error {
	output, cmdErr := exec.Command(command, cliArgs...).Output()
	if cmdErr != nil {
		fmt.Print(string(output[:]))
	}
	return cmdErr
}

// generate a fake MAC address
func genMAC() string {
	buf := make([]byte, 6)
	_, err := crypto.Read(buf)
	if err != nil {
		panic(err)
	}
	// Set the local bit
	buf[0] |= 2
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

func check(e error) {
	if e != nil {
		fmt.Fprintf(os.Stderr, "%v", e)
		os.Exit(1)
	}
}

func atExit(status int) {
	printStats()
	cleanUp()
	os.Exit(status)
}

func printStats() {
	fmt.Printf("Run finished\n")

	max, _ := stats.Max(reqstats.times)
	min, _ := stats.Min(reqstats.times)
	median, _ := stats.Median(reqstats.times)
	_ = "breakpoint"

	fmt.Printf("============= Statistics =======================\n")
	fmt.Printf("\n")
	fmt.Printf("%s Total running time: %v \n", Config.job_type, time.Now().Sub(reqstats.start_time))
	fmt.Printf("%s Total requests handled: %v \n", Config.job_type, reqstats.requests)
	fmt.Printf("%s Successful authentications : %v \n", Config.job_type, reqstats.success)
	fmt.Printf("%s Failed authentications : %v \n", Config.job_type, reqstats.failures)
	fmt.Printf("%s Longuest authentication: %v s\n", Config.job_type, max)
	fmt.Printf("%s Shortest authentication: %v s\n", Config.job_type, min)
	fmt.Printf("%s Median authentication time: %v s\n", Config.job_type, median)
	fmt.Printf("Type: %s Total: %v Failures: %v Median: %v", Config.job_type, reqstats.requests, reqstats.failures, median)
}

func cleanUp() {
	if Config.clean {
		d, err := os.Open(Config.dir)
		check(err)
		defer d.Close()
		names, err := d.Readdirnames(-1)
		check(err)
		for _, name := range names {
			err = os.RemoveAll(filepath.Join(Config.dir, name))
			check(err)
		}
	}
}

func setConfig() {

	confPtr := flag.String("f", "~/.radload.conf", "path to configuration file")
	workersPtr := flag.Int("w", 1, "number of workers to run concurrently (defaults to 1)")
	csvPtr := flag.String("x", "radload.csv", "path to csv file from which username and password will be read")
	dirPtr := flag.String("d", "/tmp/radload", "path to directory where to store the temporary configuration files")
	logPtr := flag.String("l", "radload.log", "path to log file")
	macsPtr := flag.Int("m", 10000, "generate a list of 'm' random MAC addresses and use them as Calling-Station-Id values (defaults to 10000)")
	countPtr := flag.Uint64("r", 0, "run a maximum of 'r' requests before exiting (defaults to infinity)")
	timePtr := flag.Int("t", 0, "run for a maximum of 't' seconds before exiting (defaults to infinity)")
	cleanPtr := flag.Bool("c", false, "Cleanup. Deletes all configuration files at exit.")
	jobTypePtr := flag.String("type", "eapol_test", "Sets the type of the job")
	flag.Parse()
	cliArgs = flag.Args()

	if *confPtr == "~/.radload.conf" {
		Config.conf = os.Getenv("HOME") + "/.radload.conf"
	} else {
		Config.conf = *confPtr
	}

	Config.workers = uint64(*workersPtr)
	Config.csv = *csvPtr
	Config.dir = *dirPtr
	Config.log = *logPtr
	Config.MACs = uint64(*macsPtr)
	Config.maxreq = *countPtr
	Config.maxtime = uint64(*timePtr)
	Config.clean = *cleanPtr
	Config.job_type = *jobTypePtr

}
