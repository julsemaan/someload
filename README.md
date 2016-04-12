# someload

Generate load via external scripts

## Installation

Download and install go.

Then from your go path 

`# go get github.com/julsemaan/someload`

Switch to the directory that contains the code

```
# go get ../.
# go install someload.go
```

## Example usage : 

```
# someload --help
# someload -t 300 -l /dev/shm/radload.log -x mock_data.csv -type radius_eap -w 15 -- -a 10.0.0.100 -s radius -N30:s:02:02:00:00:00:02:example -N4:x:ac150284 -N87:s:10003
# someload -t 300 -l /dev/shm/xload.log -x mock_data.csv -type http -w 8 -- https://10.0.0.100/captive-portal --insecure
# someload -t 300 -l /dev/shm/radload.log -x mock_data.csv -type acct -w 15 -- --server=10.0.0.100 --secret=radius --nas-ip-address=172.21.2.132
# someload -t 300 -l /dev/shm/xload.log -x mock_data.csv -type dhcp -w 1 -- --server=10.0.0.100
```
Arguments after `--` are passed to the script that is called.

## External scripts used by type (must be in the path)

* radius_eap : eapol_test
* dhcp : dhcp_test
* acct : acct_test
* http : curl
