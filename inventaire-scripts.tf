
provider "aws" {}

locals {
  linux_get_os_cmd = "cat /etc/os-release 2>/dev/null"
  windows_get_os_cmd = ["$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption",
         "$os_version = (Get-WmiObject -Class Win32_OperatingSystem).Version",
         "$boottime = (systeminfo | Select-String \"System Boot Time\")",
         "Write-Output \"NAME=$os\"",
         "Write-Output \"VERSION_ID=$os_version\"",
         "Write-Output \"launch_time=$boottime\""]
  windows_get_pending_updates_cmd = ["$UpdateSession = New-Object -ComObject Microsoft.Update.Session",
         "$UpdateSearcher = $UpdateSession.CreateupdateSearcher()",
         "@($UpdateSearcher.Search(\"IsHidden=0 and IsInstalled=0\").Updates)| Out-String -Width 4096"]
  windows_get_installed_updates_cmd = ["$UpdateSession = New-Object -ComObject Microsoft.Update.Session",
         "$UpdateSearcher = $UpdateSession.CreateupdateSearcher()",
         "@($UpdateSearcher.Search(\"IsHidden=0 and IsInstalled=1\").Updates)| Out-String -Width 4096"]
  linux_get_uptime_cmd = "uptime -s 2>/dev/null"
  yum_get_pending_pkg_cmd = "yum --cacheonly check-update -q | grep -v \"^(Loaded plugins|security|Obsoleting|Last metadata expiration check)\""
  dnf_get_pending_pkg_cmd = "dnf --cacheonly check-update -q | grep -v \"^(Last metadata expiration check|Dependencies resolved)\""
  apt_get_pending_pkg_cmd = "apt list --upgradable | grep -v -e \"^Listing...\" | cut -d \" \" -f 1"
}

resource "aws_ssm_document" "linux_get_os" {
  name            = "LinuxGetOsCmd"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: 'Run a bash script on Linux instances'
parameters:
  commands:
    type: String
    description: 'Extract /etc/os-release content for inventory purpose'
    default: ''
mainSteps:
  - action: 'aws:runShellScript'
    name: 'runShellScript'
    inputs:
      runCommand:
        - '${local.linux_get_os_cmd}'
DOC

  tags = {
    Owner = "PLAT"
    RefreshDate = timestamp()
  }
}

resource "aws_ssm_document" "windows_get_os" {
  name            = "WindowsGetOsCmd"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: 'Run a PowerShell script on Windows instances'
parameters:
  commands:
    type: String
    description: 'Extract relevent data from Win32_OperatingSystem WmiObject.'
    default: ''
mainSteps:
  - action: 'aws:runPowerShellScript'
    name: 'runPowerShellScript'
    inputs:
      runCommand:
        - '${local.windows_get_os_cmd[0]}'
        - '${local.windows_get_os_cmd[1]}'
        - '${local.windows_get_os_cmd[2]}'
        - '${local.windows_get_os_cmd[3]}'
        - '${local.windows_get_os_cmd[4]}'
        - '${local.windows_get_os_cmd[5]}'
DOC

  tags = {
    Owner = "PLAT"
    RefreshDate = timestamp()
  }
}

resource "aws_ssm_document" "windows_get_pending_updates" {
  name            = "WindowsGetPendingUpdatesCmd"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: 'Run a PowerShell script on Windows instances'
parameters:
  commands:
    type: String
    description: 'Extract pending updates from an Update.Session object.'
    default: ''
mainSteps:
  - action: 'aws:runPowerShellScript'
    name: 'runPowerShellScript'
    inputs:
      runCommand:
        - '${local.windows_get_pending_updates_cmd[0]}'
        - '${local.windows_get_pending_updates_cmd[1]}'
        - '${local.windows_get_pending_updates_cmd[2]}'
DOC

  tags = {
    Owner = "PLAT"
    RefreshDate = timestamp()
  }
}

resource "aws_ssm_document" "windows_get_installed_updates" {
  name            = "WindowsGetInstalledUpdatesCmd"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: 'Run a PowerShell script on Windows instances'
parameters:
  commands:
    type: String
    description: 'Extract installed updates from an Update.Session object.'
    default: ''
mainSteps:
  - action: 'aws:runPowerShellScript'
    name: 'runPowerShellScript'
    inputs:
      runCommand:
        - '${local.windows_get_installed_updates_cmd[0]}'
        - '${local.windows_get_installed_updates_cmd[1]}'
        - '${local.windows_get_installed_updates_cmd[2]}'
DOC

  tags = {
    Owner = "PLAT"
    RefreshDate = timestamp()
  }
}

resource "aws_ssm_document" "linux_get_uptime" {
  name            = "LinuxGetUptimeCmd"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: 'Run a bash script on Linux instances'
parameters:
  commands:
    type: String
    description: 'Fetch instance uptime'
    default: ''
mainSteps:
  - action: 'aws:runShellScript'
    name: 'runShellScript'
    inputs:
      runCommand:
        - '${local.linux_get_uptime_cmd}'
DOC

  tags = {
    Owner = "PLAT"
    RefreshDate = timestamp()
  }
}

resource "aws_ssm_document" "yum_get_pending_pkg" {
  name            = "YumGetPendingPkg"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: 'Run a bash script on Linux instances'
parameters:
  commands:
    type: String
    description: 'Use yum to get a list of upgrade pending packages.'
    default: ''
mainSteps:
  - action: 'aws:runShellScript'
    name: 'runShellScript'
    inputs:
      runCommand:
        - '${local.yum_get_pending_pkg_cmd}'
DOC

  tags = {
    Owner = "PLAT"
    RefreshDate = timestamp()
  }
}

resource "aws_ssm_document" "dnf_get_pending_pkg" {
  name            = "DnfGetPendingPkg"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: 'Run a bash script on Linux instances'
parameters:
  commands:
    type: String
    description: 'Use dnf to get a list of upgrade pending packages.'
    default: ''
mainSteps:
  - action: 'aws:runShellScript'
    name: 'runShellScript'
    inputs:
      runCommand:
        - '${local.dnf_get_pending_pkg_cmd}'
DOC

  tags = {
    Owner = "PLAT"
    RefreshDate = timestamp()
  }
}

resource "aws_ssm_document" "apt_get_pending_pkg" {
  name            = "AptGetPendingPkg"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: 'Run a bash script on Linux instances'
parameters:
  commands:
    type: String
    description: 'Use apt to get a list of upgrade pending packages.'
    default: ''
mainSteps:
  - action: 'aws:runShellScript'
    name: 'runShellScript'
    inputs:
      runCommand:
        - '${local.apt_get_pending_pkg_cmd}'
DOC

  tags = {
    Owner = "PLAT"
    RefreshDate = timestamp()
  }
}