# jina-api [![Go](https://github.com/frjufvjn/jina-api/actions/workflows/go.yml/badge.svg)](https://github.com/frjufvjn/jina-api/actions/workflows/go.yml)
## Goal
- If the feature to make is easier to implement on golang than on Java, let us make it with you.
- continue to add features.
## Features
- Golang TCP Socket Client API
- Golang SNMPv3 walk Client API
- Golang Get File Hash Checksum (from HTTP Multi-part request stream file) API
  * If the following chunk is included in the file entered through the http multipart request, a case to be deleted is found.
  ```
  --------------------------67c90ab8464a32d3
  Content-Disposition: form-data; name="file"; filename="sys-mon.7z"
  Content-Type: application/octet-stream
  ...
  --------------------------67c90ab8464a32d3--
  ```
## Build
```
$ go build

# For windows
$ GOOS=windows go build -o jina-api.exe

# For linux
$ GOOS=linux go build -o jina-api.bin
```
## Windows Service Deploy
1. Open Command Open as Administrator
2. SERVICE_MODULE_NAME variable is ./config.yml > module-name .
3. PATH variable is absolute binary (jina-api.exe)
4. COMMAND variable is...
```
COMMAND = "%PATH%/jina-api.exe -port=59090 -currpath=%PATH% -color=false"
```
5. if already installed service
```
C:> sc delete "%SERVICE_MODULE_NAME%"
```
6. service install
```
C:> sc create ismonagent Displayname= "%SERVICE_MODULE_NAME%" binpath= "%COMMAND%" type= share start= auto
```
7. service description install
```
C:> sc description ismonagent "jina api application server"
```
## Linux Service Deploy (WIP)
