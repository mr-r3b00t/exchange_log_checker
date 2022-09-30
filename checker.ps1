$regex=‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’
$checker = 0

$iparray =("125.212.220.48","5.180.61.17","47.242.39.92","61.244.94.85","86.48.6.69","86.48.12.64","94.140.8.48","94.140.8.113","103.9.76.208","103.9.76.211","104.244.79.6","112.118.48.186","122.155.174.188","125.212.241.134","185.220.101.182","194.150.167.88","212.119.34.11")

DO
{


$logs = Get-ChildItem -Path "C:\inetpub\logs\LogFiles\W3SVC1\*.log"

$logs

foreach($log in $logs){

$logcontent = Get-Content $log

$Matched = $logcontent |select-string  -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }

$iplist = $Matched | Sort-Object -Unique -Descending

foreach($ip in $iplist){

#Only write out if TRUE
if($iparray.contains($ip)){
write-host "WARNING BAD IP DETECTED" -ForegroundColor Red
$checker = 1
}

}

$results = $logcontent -match '.*autodiscover\.json.*\@.*Powershell.*'

if($results.count -ge 1){

$checker = 1
write-host "Exchange Exploitation Detected" -ForegroundColor Red
write-host $results -ForegroundColor Red

}
else
{
write-host "logs are clean..." -ForegroundColor Green
}

}
write-host "Sleeping for 60 seconds..." -ForegroundColor Cyan
sleep -Seconds 60


} While ($checker -eq 0)
