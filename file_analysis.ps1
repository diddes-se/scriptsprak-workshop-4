# Added base date to "2024-10-14" so dates in files correspond to script
$now = Get-Date "2024-10-14"

$weekAgo = $now.AddDays(-7)

function Find-SecurityIssues {
    [CmdletBinding()]
    param(
        [string] $Path = ".",
        [switch] $Recurse
    )

    # Pattern to search for
    $security_patterns = @(
        @{ Name = "Cleartext Password/Secret"; Pattern = "(?i)\b(?:password|secret)\s+(?!\d)\S+" },
        @{ Name = "SNMP Community (public/private)"; Pattern = "(?i)\b(snmp(-server)?\s+community)\s+(public|private)\b" },
        @{ Name = "Enable Password (Plain)"; Pattern = "(?i)\benable\s+password\b.*" }
    )

    # Get all .conf files
    $conf_files = Get-ChildItem -Path $Path -Recurse:$Recurse -File -Filter "*.conf" -ErrorAction SilentlyContinue
    if (-not $conf_files) {
        Write-Host "Inga .conf-filer hittades i $Path"
        return
    }

    $results = foreach ($file in $conf_files) {
        foreach ($pattern in $security_patterns) {
            $matches = Select-String -Path $file.FullName -Pattern $pattern.Pattern -AllMatches -ErrorAction SilentlyContinue
            foreach ($match in $matches) {
                [PSCustomObject]@{
                    File      = $file.FullName.Split($path)[1]
                    Line      = $match.LineNumber
                    IssueType = $pattern.Name
                    Text      = $match.Line
                }
            }
        }
    }

    if (-not $results) {
        Write-Host "Inga säkerhetsproblem hittades."
        return @()
    }

    # Sort results
    $results = $results | Sort-Object File, Line

    return $results
}

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
@{Name = "Folder"; Expression = { $_.DirectoryName.Split("network_configs")[1] } },
@{Name = "LastModified"; Expression = { $_.LastWriteTime } }

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

# Create a table to store data for ERROR, FAILD, DENIED
$log_errors = @()

# Get all log files
$log_files = Get-ChildItem -path "network_configs"  -Recurse -File -Filter "*.log"

# Count all ERROR, FAILD, DENIED per file
foreach ($file in $log_files) {
    $count = 0
    foreach ($pattern in $patterns) {
        $count += (Select-String -Path $file.FullName -Pattern "ERROR|FAILED|DENIED").Count
    }
    $log_errors += [PSCustomObject]@{
        File   = $file.FullName.Split("network_configs")[1]
        Counts = $count
    }
}

# Sort after most counts
$log_errors = $log_errors | Sort-Object Counts -Descending

# Get all files with .conf and export to config_inventory.csv
Get-ChildItem -Path "network_configs" -Recurse -File -include *.conf, *.rules |
Select-Object Name,
@{Name = "Folder"; Expression = { $_.DirectoryName.Split("network_configs")[1] } } |
Export-Csv -Path "config_inventory.csv" -NoTypeInformation -Encoding UTF8

# Use the function "Find-SecurityIssuses"
$security_issuses = Find-SecurityIssues -Path "network_configs" -Recurse

# Get all ERROR messages
$errors = Get-ChildItem -Path "network_configs" -Recurse -File -Filter "*.log" |
Select-String -Pattern "ERROR" -CaseSensitive -SimpleMatch |
Group-Object { $_.Line -replace "\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s*", "" } |
Sort-Object Count -Descending |
Select-Object @{Name = "Text"; Expression = { $_.Name } },
@{Name = "Counts"; Expression = { $_.Count } }

# Get all FAILED messages
$failed = Get-ChildItem -Path "network_configs" -Recurse -File -Filter "*.log" |
Select-String -Pattern "FAILED" -CaseSensitive 

# Get all .conf, .rules and .bak to compare
$config_files = Get-ChildItem -Path "network_configs" -Recurse -File -include *.conf, *.rules
$bak_files = Get-ChildItem -Path "network_configs" -Recurse -File -Filter "*.bak" 

# Filter full path to only file names
$config_names = $config_files.Name
$bak_names = $bak_files.Name

# Compare to backup files
$missing_backups = $config_names | Where-Object {
    ($_.Name + ".bak") -notin $bak_names
}

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

$report += "`nLog-filer som innehåller fel (ERROR, FAILD, DENIED): `n"
$report += $("-" * 40) + "`n"

foreach ($log in $log_errors) {
    $report += "  {0,-30} {1,2} st `n" -f $log.File, $log.Counts
}

$report += "`nSammanfattning av error meddelanden: `n"
$report += $("-" * 40) + "`n"

$report += " {0,6} {1,-40}`n" -f "Antal", "Meddelande"

foreach ($err in $errors) {
    $report += " {0,6} {1,-40} `n" -f $err.Counts, $err.Text
}

$report += "`nMisslyckade inloggningar: `n"
$report += $("-" * 40) + "`n"

$report += ($failed | ForEach-Object { "$($_.Line)`n" }) -join ""

$report += "`nKonfigurationsgranskning: `n"
$report += $("-" * 40) + "`n"

$report += "  {0,-30} {1,4} {2,-35} Meddelande `n" -f "Filnamn", "Rad", "Typ"

foreach ($issuses in $security_issuses) {
    $report += "  {0,-30} {1,4} {2,-35} {3,-40}`n" -f $issuses.File, $issuses.Line, $issuses.IssueType, $issuses.Text
}

$report += "`nKonfigurationer som skanar backup: `n"
$report += $("-" * 40) + "`n"

$report += ($missing_backups | ForEach-Object { "  $($_)`n" }) -join ""


# Export the report to security_audit.txt
$report | Out-File -FilePath  "security_audit.txt" -Encoding utf8