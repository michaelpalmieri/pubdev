Get-adcomputer wsus -properties pwdLastSet,PasswordLastSet  | sort Name | ft Name,@{Name='pwdLastSet';Expression={[DateTime]::FromFileTime($_.pwdLastSet)}},PasswordLastSet

get-adcomputer wsus -Properties *

Get-NetTCPConnection -State Listen | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Sort-Object LocalPort |ft

Get-NetTCPConnection -State Established |Select-Object -Property LocalAddress, LocalPort,@{name='RemoteHostName';expression={(Resolve-DnsName $_.RemoteAddress).NameHost}},RemoteAddress, RemotePort, State,@{name='ProcessName';expression={(Get-Process -Id $_.OwningProcess). Path}},OffloadState,CreationTime |ft

