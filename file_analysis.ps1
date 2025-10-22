# Added base date to "2024-10-14" so dates in files correspond to script
$now = Get-Date "2024-10-14"

$weekAgo = $now.AddDays(-7)


# Get all files with .conf, .rules and .log and export to files_in_network_configs.csv
Get-ChildItem -Path "network_configs" -Recurse -File |
Where-Object { $_.Extension -in ".conf", ".rules", ".log" } |
Select-Object Name,
@{Name = "Folder"; Expression = { $_.DirectoryName.Split("network_configs")[1] } },
@{Name = "Size"; Expression = { $_.Length } },
@{Name = "LastModified"; Expression = { $_.LastWriteTime } } |
Export-Csv -Path "files_in_network_configs.csv" -NoTypeInformation -Encoding UTF8

# Get files mofified in the last week
$files_last_modified = Get-ChildItem -path "network_configs" -Recurse -File | 
Where-Object { $_.LastWriteTime -gt $weekAgo } | Sort-Object -Property LastWriteTime -descending | 
Select-Object Name,
@{Name = 'Folder'; Expression = { $_.DirectoryName.Split("network_configs")[1] } },
@{Name = 'LastModified'; Expression = { $_.LastWriteTime } }

# Get all files and group by filetype
$by_file_type = Get-ChildItem -File -Path "network_configs" -Recurse | 
Group-Object -Property Extension

# Get the 5 biggest log files
$biggest_log_files = Get-ChildItem -path "network_configs"  -Recurse -File -Filter "*.log" |
Sort-Object -Property Length -Descending | Select-Object -first 5  Name, 
@{Name = "SizeMB"; Expression = { [math]::Round($_.Length / 1MB, 2) } }

# Get all unique ip adresses from .conf files
$ips = Get-ChildItem -path "network_configs"  -Recurse -File -Filter "*.conf" |
Select-String -Pattern "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" |
ForEach-Object { $_.Matches.Value } |
Sort-Object -Unique 


# Create the report
$report = @"
SECURITY AUDIT REPORT
$("=" * 40)
Genererad: $($now)

Filinformation
$("-" * 40)

Filer i network_configs som är ändrade senaste veckan:


"@

$report += "{0,-27}  {1,-30} {2,-10}  `n" -f "  Filnamn", "Undermapp", "Senast ändrad"

# Add files modified in the last week to report
foreach ($file in $files_last_modified) {
    $report += "  {0,-25}  {1,-30} {2,10}  `n" -f $file.Name, $file.Folder, $file.LastModified
}

$report += "`nAntal filer per filtyp:`n"

# Add file count by filetype
foreach ($type in $by_file_type) {
    $report += "  {0,-6}  {1,3}  `n" -f $type.Name, $type.Count
}

$report += "`nDe 5 största logfilerna: `n"
$report += $("-" * 40) + "`n"

foreach ($file in $biggest_log_files) {
    $report += "  {0,-30} {1,3} MB `n" -f $file.Name, $file.SizeMB
}

$report += "`nUnika IP-adresser som används i .conf filerna: `n"
$report += $("-" * 40) + "`n"
$report += ($ips -join "`n") + "`n"

# Export the report to security_audit.txt
$report | Out-File -FilePath  "security_audit.txt" -Encoding utf8