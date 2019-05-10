$a = "www.google.fr",'www.microsoft.com',"www.yahoo.com","www.digg.com",'www.facebook.com','www.lemonde.fr'
$MaxConcurentJobs = 1


## Scriptblock, lancé par le Start-Job
## $args[0] correspodant au 1° argument passé au paramètre -argumentlist de Start-Job
$ScriptBlock = {
    ## ici au lieu de faire un if, on fait un while test-connection et ça devrait le faire ... !
    Try {
        If ( Test-Connection -ComputerName $args[0] -Count 10 -ErrorAction Stop ) {
            $result = $True
        } Else {
            $result = $false
        }
    } Catch {
        $result = "PingFailedCheckManually"
    }
    [PSCustomObject]@{
        Name = $args[0]
        Ping = $result
    }
}


$datas = @()
$VerbosePreference = 'Continue'

foreach ( $truc in $a ) {

    while ( (get-job -State Running).count -gt $MaxConcurentJobs) {
        Write-Verbose 'Too Many job running... Waiting for job(s) to finish'
        Start-Sleep 2
    }

    Start-Job -Name $truc -ScriptBlock $ScriptBlock -ArgumentList $truc

    [Array]$CompletedJobs = Get-Job -State 'Completed' -HasMoreData $True
    If ( $CompletedJobs.count -gt 0 ) {
        Foreach ( $CompletedJob in $CompletedJobs ) {
            Write-Verbose "Displaying Data for Job: $($CompletedJob.Name)"
            $datas += Receive-Job $CompletedJob
        }
    }

}

Write-Verbose "Waiting for the lasts jobs to finish..."
get-job -state  running | Wait-Job
Get-Job -State 'Completed' -HasMoreData $True | %{$datas+=Receive-Job $_}

## waiting for last(s) job(s) to finish ...
$VerbosePreference = 'SilentlyContinue'
remove-variable CompletedJobs
Stop-Job -Name *
remove-job -Name *
