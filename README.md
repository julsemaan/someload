# someload

Generate load via external scripts

## Installation

Download and install go.

Then from your go path 

`# go get github.com/julsemaan/someload`

Switch to the directory that contains the code

`# go install someload.go`

Example usage : 

```
# someload --help
# someload -t 30 -l /dev/shm/xload.log -m 10 -x /root/mock_data.csv -type http -w 4 -- 172.20.20.109/captive-portal
# someload -t 30 -l /dev/shm/xload.log -m 10 -x /root/mock_data.csv -type acct -w 5 -- --server=172.20.20.109 --secret=radius
# someload -t 30 -l /dev/shm/xload.log -m 10 -x /root/mock_data.csv -type dhcp -w 5
```
