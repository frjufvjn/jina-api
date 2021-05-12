# jina-api [![Go](https://github.com/frjufvjn/jina-api/actions/workflows/go.yml/badge.svg)](https://github.com/frjufvjn/jina-api/actions/workflows/go.yml)
## Features
- Golang TCP Socket Client API
- Golang SNMPv3 walk Client API
- Golang Get File Hash Checksum (from HTTP Multi-part request stream file) API
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
C:> sc delete 
```
6. service install
```
C:> sc create ismonagent Displayname= "%SERVICE_MODULE_NAME%" binpath= "%COMMAND%" type= share start= auto
```
7. service description install
```
C:> sc description ismonagent "jina api application server"
```
