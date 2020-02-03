Invoke-ScriptAnalyzer -Recurse -Path src/ -ReportSummary

$HealthReport = Invoke-PSCodeHealth -Path src/
$Health = Test-PSCodeHealthCompliance -HealthReport $HealthReport -Summary

$Health
Test-PSCodeHealthCompliance -HealthReport $HealthReport -CustomSettingsPath .\pscodehealth-notest.json | where {$_.Result -ne 'Pass'} |Format-Table -Property *
$HealthReport
$HealthReport.FunctionHealthRecords | Format-Table
