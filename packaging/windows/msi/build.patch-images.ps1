$ErrorActionPreference = "Stop"
# Set-PSDebug -Trace 1

function CopyFile($Path, $Destination) {
  Write-Host "Copying file from: ""$Path"", to: ""$Destination""..."
  Copy-Item -Path "$Path" -Destination "$Destination" -Force -ErrorAction SilentlyContinue
  if (-Not $?) {
    Write-Host $Error[0].ToString()
  }
}

function PatchImages($Product, $Version, $ProductName) {
  Write-Host "PatchImages called with product $Product, version $Version and product name $ProductName"
  $Repo = "seal-icons"
  $TargetResourceDir = "packaging/windows/msi/resource/images"
  # check for product or service
  Write-Host -NoNewline "Patching images for "
  if ("$ProductName" -ne "") {
    Write-Host -NoNewline "bundle $ProductName"
  } else {
    Write-Host -NoNewline "service $Product"
    # for services use platform icons
    $Product = "service"
  }
  switch ($Product) {
    {($_ -eq "plossys") -Or ($_ -eq "out-ngn")} {
      $name = "PLOSSYS_Output_Engine"
      Break
    }
    "service" {
      $name = "SEAL"
      Break
    }
    "build-pipeline-playground" {
      $name = "SEAL"
      Break
    }
    default {
      $name = "Default"
    }
  }
  Write-Host " from $Repo/$name (ignoring version $Version)."
  # if ($Version -ne "") {
  #   $branch = "--branch $Version"
  #   Write-Host "Using branch info: Version = $Version"
  # }

  # Clone images from github
  git clone $branch https://${env:GITHUB_TOKEN}@github.com/sealsystems/$Repo
  $Dir = "seal-icons/$name"
  if (-Not (Test-Path -Path $Dir)) {
    Write-Host "Image directory $Dir not found! Images are not patched. "
    return 13
  }
  Write-Host Listing of $Dir
  ls $Dir

  # Copy to target images
  Write-Host Listing of current $TargetResourceDir
  ls $TargetResourceDir

  # always copy Icon
  $File = (Get-ChildItem -Path "$Dir" *.ico).Name
  if ($File) {
    CopyFile "$Dir/$File" "$TargetResourceDir/logo.ico"
  }
  # copy logo for bundle banner
  if ("$ProductName" -ne "") {
    $File = (Get-ChildItem -Path "$Dir" *.png).Name
    if (-Not $File) {
      Write-Host "No PNG file for bundle banner found. Trying copy of icon file!"
      $File = (Get-ChildItem -Path "$Dir" *.ico).Name
    }
    if ($File) {
      CopyFile "$Dir/$File" "$TargetResourceDir/logo.png"
    }
  } else {
    # copy banner
    $File = Get-ChildItem -Path "$Path" | Where-Object {$_.Name -match '.*Banner.*\.bmp'}
    if ($File) {
      CopyFile "$Dir/$File" "$TargetResourceDir/msi-banner.bmp"
    }
    # copy dialog
    $File = Get-ChildItem -Path "$Path" | Where-Object {$_.Name -match '.*Welcome.*\.bmp'}
    if ($File) {
      CopyFile "$Dir/$File" "$TargetResourceDir/msi-welcome.bmp"
    }
  }
  Remove-Item -Recurse -Force seal-icons
  Write-Host Listing of new $TargetResourceDir
  ls $TargetResourceDir
}

# Patch images
PatchImages "$env:PACKAGE_NAME" "$env:PACKAGE_VERSION" "$env:PRODUCT_NAME"
