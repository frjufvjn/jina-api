package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gosnmp/gosnmp"
	"github.com/kardianos/service"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

const (
	logcontextpath = "hansolsocket"
	ctxservicename = "hansolsocket" // 신한카드 snmp 모듈 서비스명: ismonsnmpgo   SKBB 소켓 모듈 서비스명: hansolsocket
	programVersion = "v.1.0.3"      // 공백이 트림되지 않게 처리
)

var (
	logn                   = log.Println
	logf                   = log.Printf
	prn                    = fmt.Println
	prf                    = fmt.Printf
	serviceLogger          service.Logger
	listenPort             string
	logColorEnable         = false
	fileHashTargetPath     string
	fileHashTempPath       string
	fileHashInitailKeyword string
	fileHashKeywords       []string
)

type program struct{}

// Login is Binding from JSON
type Login struct {
	User     string `form:"user" json:"user" xml:"user"  binding:"required"`
	Password string `form:"password" json:"password" xml:"password" binding:"required"`
}

type FileHashConfig struct {
	TargetPath     string   `yaml:"target-path"`
	TempPath       string   `yaml:"temp-path"`
	InitialKeyword string   `yaml:"initial-keyword"`
	Keywords       []string `yaml:"keywords"`
}

// FileHashRequest is ...
type FileHashRequest struct {
	FileName string `json:"filename" binding:"required"`
	FileHash string `json:"filehash" binding:"required"`
	ApiKey   string `json:"api-key" binding:"required"`
}

// FileHashResponse is ...
type FileHashResponse struct {
	Result        string `json:"result"`
	ResultMessage string `json:"message"`
}

// SockRequest is ....
type SockRequest struct {
	Host        string `json:"host" binding:"required"`
	Port        int    `json:"port" binding:"required"`
	SendStr     string `json:"sendstr" binding:"required"`
	Type        string `json:"type" binding:"required"`
	ServiceName string `json:"servicename" binding:"required"`
}

type SockResponse struct {
	Data        string `json:"data"`
	Size        int    `json:"size"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Type        string `json:"type"`
	ServiceName string `json:"servicename"`
}

// APIRequest is Request ...
type APIRequest struct {
	DeviceID     string `json:"deviceid" binding:"required"`
	DeviceIP     string `json:"ip" binding:"required"`
	OidGroupName string `json:"oid-group-name" binding:"required"`
	UserName     string `json:"user" binding:"required"`
	AuthPass     string `json:"authpass" binding:"required"`
	PrivPass     string `json:"privpass" binding:"required"`
	Timeout      int    `json:"timeout" binding:"required"`
	Oid          string `json:"oid" binding:"required"`
	IsYesterday  bool   `json:"is-yesterday"`
}

// Output is ...
type Output struct {
	Success      bool        `json:"success"`
	DeviceID     string      `json:"deviceid"`
	DeviceIP     string      `json:"deviceip"`
	OidGroupName string      `json:"oid-group-name"`
	IsYesterday  bool        `json:"is-yesterday"`
	ElabsedTime  string      `json:"elapsedtime"`
	Res          []Responses `json:"response"`
}

// Responses is ...
type Responses struct {
	Oid   string `json:"oid"`
	Value string `json:"value"`
}

func (r *Output) setResponses(res []Responses) {
	r.Res = res
}

func (r *Output) getOutputJSON() string {
	resJSON, _ := json.Marshal(r)
	return string(resJSON)
}

func (sr *SockResponse) getSockResponse() string {
	resJSON, _ := json.Marshal(sr)
	return string(resJSON)
}

func (fhr *FileHashResponse) getFileHashResponse() []byte {
	resJSON, _ := json.Marshal(fhr)
	return []byte(string(resJSON))
}

// TCP SOCKET / SNMPv3 API 서버
// TODO: GIN SWAGGER 추가 : https://dejavuqa.tistory.com/330
func main() {

	currpath := flag.String("currpath", "H:/shcsw", "program path define")
	port := flag.String("port", "8080", "http listen port")
	logcolor := flag.Bool("color", false, "")
	flag.Parse()

	if !isFlagInputed("port") {
		prn("")
		prn("VERSION:", programVersion)
		prn("PURPOSE: Light-Weight, Low-Latency API Server (TCP Client, SNMPv3)")
		prn("PUBLISHER: frjufvjn@gmail.com")
		prn("")
		flag.Usage()
		return
	}

	if !isFlagInputed("currpath") {
		prn("")
		prn("VERSION:", programVersion)
		prn("PURPOSE: Light-Weight, Low-Latency API Server (TCP Client, SNMPv3)")
		prn("PUBLISHER: frjufvjn@gmail.com")
		prn("")
		flag.Usage()
		return
	}

	listenPort = *port
	logColorEnable = *logcolor

	createDirIfNotExist(*currpath + "/" + logcontextpath + "-logs")

	l := &lumberjack.Logger{
		Filename:   *currpath + "/" + logcontextpath + "-logs" + "/ismonsnmp.log",
		MaxSize:    10, // megabytes
		MaxBackups: 3,
		MaxAge:     28,   //days
		Compress:   true, // disabled by default
	}
	log.SetOutput(l)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)

	go func() {
		for {
			<-c
			l.Rotate()
		}
	}()

	// * For Service
	svcConfig := &service.Config{
		Name:        ctxservicename,
		DisplayName: ctxservicename,
		Description: "Hansol Inticube IS-MON's API Service",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	serviceLogger, err = s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}

	err = s.Run()
	if err != nil {
		serviceLogger.Error(err)
	}

}

// * For Service Start ----------------------------------------------------------------------------------------

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	logn("Stop Service.... service name:", s.String())
	prn("Stop Service.... service name:", s.String())
	return nil
}

func (p *program) run() {

	confFilename, _ := filepath.Abs("config.yml")
	yamlFile, err := ioutil.ReadFile(confFilename)
	var fileConfig FileHashConfig
	err = yaml.Unmarshal(yamlFile, &fileConfig)
	if err != nil {
		panic(err)
	}

	prn("TargetPath:", fileConfig.TargetPath, "TempPath:", fileConfig.TempPath, ">>", len(fileConfig.Keywords))

	fileHashTargetPath = fileConfig.TargetPath
	fileHashTempPath = fileConfig.TempPath
	fileHashInitailKeyword = fileConfig.InitialKeyword
	fileHashKeywords = fileConfig.Keywords

	for idx, keyword := range fileHashKeywords {
		fmt.Println(idx, keyword)
	}

	// #########################################################################################
	// Disable Console Color, you don't need console color when writing the logs to file.
	if !logColorEnable {
		gin.DisableConsoleColor()
	}

	// Logging to a file.
	// f, _ := os.Create("gin.log")
	// gin.DefaultWriter = io.MultiWriter(f)

	// gin.SetMode(gin.ReleaseMode)

	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	// https://gin-gonic.com/docs/examples/binding-and-validation/
	// Example for binding JSON ({"user": "manu", "password": "123"})
	// $ curl -v -X POST \
	// 	http://localhost:8080/loginJSON \
	// 	-H 'content-type: application/json' \
	// 	-d '{ "user": "manu" }'
	router.POST("/loginJSON", func(c *gin.Context) {
		var json Login
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if json.User != "manu" || json.Password != "123" {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "you are logged in"})
	})

	// https://gin-gonic.com/docs/examples/goroutines-inside-a-middleware/
	router.GET("/long_async", func(c *gin.Context) {
		// create copy to be used inside the goroutine
		cCp := c.Copy()
		go func() {
			// simulate a long task with time.Sleep(). 5 seconds
			time.Sleep(5 * time.Second)

			// note that you are using the copied context "cCp", IMPORTANT
			log.Println("Done! in path " + cCp.Request.URL.Path)

			// NOT WORKING...
			// c.JSON(http.StatusOK, gin.H{"status": "long_async response"})
		}()
	})

	router.GET("/long_sync", func(c *gin.Context) {
		// simulate a long task with time.Sleep(). 5 seconds
		time.Sleep(5 * time.Second)

		// since we are NOT using a goroutine, we do not have to copy the context
		log.Println("Done! in path " + c.Request.URL.Path)

		c.JSON(http.StatusOK, gin.H{"status": "long_sync response"})
	})

	router.POST("/file-hash", func(c *gin.Context) {
		var req FileHashRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"result":  "fail",
				"message": err.Error(),
			})
			return
		}

		timeoutSecDuration := "30s"
		maxDuration, _ := time.ParseDuration(timeoutSecDuration)
		ctx, _ := context.WithTimeout(context.Background(), maxDuration)

		start := time.Now()
		result, err := fileHashProcessithCtxWrapper(ctx, req)
		logf("duration:%v result:%s\n", time.Since(start), result)

		if err != nil {
			logn(err)
			c.JSON(http.StatusRequestTimeout, gin.H{
				"result":  "fail",
				"message": err.Error(),
			})
			return
		}

		res := &FileHashResponse{}
		res.Result = "success"
		res.ResultMessage = "no message"

		c.Data(http.StatusOK, gin.MIMEJSON, res.getFileHashResponse())
	})

	/*
	   type SockRequest struct {
	   	SendStr     string `json:"sendstr" binding:"required"`
	   	Type        string `json:"type" binding:"required"`
	   	ServiceName string `json:"servicename" binding:"required"`
	   }
	*/
	router.POST("/api-sock", func(c *gin.Context) {
		var req SockRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       err.Error(),
				"success":     false,
				"sendstr":     req.SendStr,
				"type":        req.Type,
				"servicename": req.ServiceName,
				"response":    nil,
			})
			return
		}

		reqJSON, _ := json.Marshal(req)
		logn("request trace :", string(reqJSON))
		prn("Host : ", req.Host)
		prn("Port : ", req.Port)

		timeoutSecDuration := "3s"
		maxDuration, _ := time.ParseDuration(timeoutSecDuration)
		ctx, _ := context.WithTimeout(context.Background(), maxDuration)

		start := time.Now()
		result, err := sockWithCtxWrapper(ctx, req)
		logf("duration:%v result:%s\n", time.Since(start), result)

		if err != nil {
			logn(err)
			c.JSON(http.StatusRequestTimeout, gin.H{
				"error":       err.Error(),
				"success":     false,
				"sendstr":     req.SendStr,
				"type":        req.Type,
				"servicename": req.ServiceName,
				"response":    nil,
			})
			return
		}

		sockRes := &SockResponse{}
		sockRes.Data = result
		sockRes.Host = req.Host
		sockRes.Port = req.Port
		sockRes.ServiceName = req.ServiceName
		sockRes.Type = req.Type
		sockRes.Size = len(result)

		c.JSON(http.StatusOK, sockRes.getSockResponse())
	})

	router.POST("/api-snmp", func(c *gin.Context) {
		var req APIRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":          err.Error(),
				"success":        false,
				"deviceid":       req.DeviceID,
				"deviceip":       req.DeviceIP,
				"oid-group-name": req.OidGroupName,
				"is-yesterday":   req.IsYesterday,
				"response":       nil,
			})
			return
		}

		reqJSON, _ := json.Marshal(req)
		logn("request trace :", string(reqJSON))

		timeoutSecDuration := strconv.Itoa(req.Timeout+1) + "s"
		maxDuration, _ := time.ParseDuration(timeoutSecDuration)
		ctx, _ := context.WithTimeout(context.Background(), maxDuration)

		start := time.Now()
		result, err := snmpWithCtxWrapper(ctx, req)
		logf("duration:%v result:%s\n", time.Since(start), result)

		if err != nil {
			logn(err)
			c.JSON(http.StatusRequestTimeout, gin.H{
				"error":          err.Error(),
				"success":        false,
				"deviceid":       req.DeviceID,
				"deviceip":       req.DeviceIP,
				"oid-group-name": req.OidGroupName,
				"is-yesterday":   req.IsYesterday,
				"response":       nil,
			})
			return
		}

		c.JSON(http.StatusOK, result)
	})

	router.Run(":" + listenPort) // listen and serve on 0.0.0.0:8080
}

func fileHashProcessithCtxWrapper(ctx context.Context, req FileHashRequest) (bool, error) {
	done := make(chan bool)

	go func() {
		done <- fileHashProcess(req)
	}()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case result := <-done:
		return result, nil
	}
}

// fileHashProcess(targetFilePath string, oHash string, tmpFilePrefix string)
func fileHashProcess(req FileHashRequest) bool {

	target := fileHashTargetPath + "/" + req.FileName
	oHash := req.FileHash
	tmpFilePrefix := req.FileHash

	input, err := ioutil.ReadFile(target)
	if err != nil {
		log.Fatalln(err)
		return false
	}

	lines := strings.Split(string(input), "\n")

	// Manupulate target file (multi-part uploaded file http chunk string)
	cnt := 0
	for i, line := range lines {
		if strings.Contains(line, fileHashInitailKeyword) {
			// fmt.Println(line, ", ", len(lines), ", ", i)
			lines = remove(lines, i)
			cnt++
		}

		if i > 0 && cnt > 0 {

			if (i - cnt) >= len(lines) {
				break
			}

			for _, keyword := range fileHashKeywords {
				if strings.Contains(lines[i-cnt], keyword) {
					fmt.Println(lines[i-cnt])
					lines = remove(lines, i-cnt)
				}
			}
		}
	}

	tempFileName := tmpFilePrefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(fileHashTempPath+"/"+tempFileName, []byte(output[2:len(output)-2]), 0644)
	if err != nil {
		log.Fatalln(err)
		return false
	}

	calculatedHash := fileHash(fileHashTempPath + "/" + tempFileName)

	errRemove := os.Remove(fileHashTempPath + "/" + tempFileName)
	if errRemove != nil {
		log.Fatalln(errRemove)
	}

	fmt.Printf("[%s]\n", oHash)
	fmt.Printf("[%s]\n", calculatedHash)

	return (oHash == calculatedHash)
}

func remove(slice []string, s int) []string {
	return append(slice[:s], slice[s+1:]...)
}

func fileHash(src string) string {
	f, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return BytesToString(h.Sum(nil))
}

func BytesToString(data []byte) string {
	// return string(data[:])
	return hex.EncodeToString(data)
}

func sockWithCtxWrapper(ctx context.Context, req SockRequest) (string, error) {
	done := make(chan string)

	go func() {
		done <- sockRun(req)
	}()

	select {
	case <-ctx.Done():
		return "Fail", ctx.Err()
	case result := <-done:
		return result, nil
	}
}

func sockRun(req SockRequest) string {

	strSend := req.SendStr                              // "Halo"
	servAddr := req.Host + ":" + strconv.Itoa(req.Port) // "localhost:9000"
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		logn("ResolveTCPAddr failed:", err.Error())
		// os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		logn("Dial failed:", err.Error())
		return "failed"
	}

	// if conn != nil {
	defer conn.Close()
	// }

	_, err = conn.Write([]byte(strSend))
	if err != nil {
		logn("Write to server failed:", err.Error())
		// os.Exit(1)
	}

	logn("write to server = ", strSend)

	reply := make([]byte, 1024*30)

	_, err = conn.Read(reply)
	if err != nil {
		logn("Write to server failed:", err.Error())
		// os.Exit(1)
	}

	reply = bytes.Trim(reply, "\x00")

	logn("reply from server=", string(reply))

	// conn.Close()

	return string(reply) // strings.Trim(string(reply), " ")
}

func snmpWithCtxWrapper(ctx context.Context, req APIRequest) (string, error) {
	done := make(chan string)

	go func() {
		done <- snmpWalkRun(req)
	}()

	select {
	case <-ctx.Done():
		return "Fail", ctx.Err()
	case result := <-done:
		return result, nil
	}
}

func snmpWalkRun(req APIRequest) string {

	_host := req.DeviceIP
	_oids := req.Oid
	_timeout := req.Timeout
	_user := req.UserName
	_authprotocol := "SHA"
	_authpass := req.AuthPass
	_privcypass := req.PrivPass
	_privacyprotocol := "AES"
	_version := "v3"

	timeoutSecDuration := strconv.Itoa(_timeout) + "s"
	duration, _ := time.ParseDuration(timeoutSecDuration)

	target := _host
	oidstr := _oids
	splitedOid := strings.Split(oidstr, "|")

	startTime := time.Now()

	gosnmp.Default.Target = target
	gosnmp.Default.Timeout = duration // time.Duration(*timeout * time.Second) // Timeout better suited to walking
	gosnmp.Default.Retries = 1

	if _version == "v3" {

		var authProtocol gosnmp.SnmpV3AuthProtocol
		switch _authprotocol {
		case "SHA":
			authProtocol = gosnmp.SHA
		default:
			authProtocol = gosnmp.MD5
		}

		var privacyProtocol gosnmp.SnmpV3PrivProtocol
		switch _privacyprotocol {
		case "DES":
			privacyProtocol = gosnmp.DES
		case "AES":
			privacyProtocol = gosnmp.AES
		case "AES192":
			privacyProtocol = gosnmp.AES192
		case "AES256":
			privacyProtocol = gosnmp.AES256
		default:
			privacyProtocol = gosnmp.AES
		}

		gosnmp.Default.Version = gosnmp.Version3
		gosnmp.Default.SecurityModel = gosnmp.UserSecurityModel
		gosnmp.Default.MsgFlags = gosnmp.AuthPriv
		gosnmp.Default.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 _user,
			AuthenticationProtocol:   authProtocol,
			AuthenticationPassphrase: _authpass,
			PrivacyProtocol:          privacyProtocol,
			PrivacyPassphrase:        _privcypass,
		}
	} else if _version == "v2c" {
		gosnmp.Default.Version = gosnmp.Version2c
		gosnmp.Default.Community = _user
	} else if _version == "v1" {
		gosnmp.Default.Version = gosnmp.Version1
		gosnmp.Default.Community = _user
	} else {
		log.Println("Only v3, v2c available")
		return "" // TODO
	}

	err := gosnmp.Default.Connect()
	if err != nil {
		logf("Connect err: %v\n", err)
		return "" // TODO
	}
	defer gosnmp.Default.Conn.Close()

	oid := splitedOid[0]

	output := &Output{}

	output.DeviceID = req.DeviceID
	output.DeviceIP = req.DeviceIP
	output.OidGroupName = req.OidGroupName
	output.IsYesterday = req.IsYesterday

	var res []Responses

	asyncRes := func(pdu gosnmp.SnmpPDU) error {
		// fmt.Printf("%s = ", pdu.Name)

		var value string
		switch pdu.Type {
		case gosnmp.OctetString:
			b := pdu.Value.([]byte)
			// fmt.Printf("STRING: %s\n", string(b))
			value = string(b)
		default:
			// fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
			value = strconv.Itoa(int(gosnmp.ToBigInt(pdu.Value).Int64()))
		}

		res = append(res, Responses{
			Oid:   pdu.Name,
			Value: value,
		})

		return nil
	}

	errorB := gosnmp.Default.BulkWalk(oid, asyncRes)
	if errorB != nil {
		logf("Walk Error: %v\n", errorB)
		output.Success = false
	} else {
		output.Success = true
	}

	unitElapsedTime := time.Since(startTime)
	output.ElabsedTime = unitElapsedTime.String()
	output.setResponses(res)

	return output.getOutputJSON()
}

func createDirIfNotExist(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			logn(err.Error())
			panic(err)
		}
	}
}

func isFlagInputed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
