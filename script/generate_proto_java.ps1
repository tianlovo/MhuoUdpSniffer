<#
.SYNOPSIS
    *.proto文件转换为*.java
.DESCRIPTION
    将proto文件通过谷歌的protoc编译为java源文件
.AUTHOR
    TianluoQAQ
.LINK
    https://github.com/protocolbuffers/protobuf
#>

# 是否在编译proto前清空原有文件
$shouldEmpty = $true

# 生成路径
$generatePath = "../src/main/java"

# 设置要清空的文件夹路径
$clearPath = "$generatePath/com/tlovo/proto"


# proto原文件路径
$protoPath = "../proto"

# protoc
$protocPath = "../bin/protoc.exe"

# 根据布尔变量决定是否清空文件夹
if ($shouldEmpty) {
    # 确保文件夹存在
    if (Test-Path $clearPath) {
        # 删除文件夹下的所有文件和子文件夹
        Get-ChildItem -Path $clearPath -Force -Recurse | Remove-Item -Force -Recurse
        Write-Host "Generate folder clear success."
    } else {
        Write-Host "Generate folder not exits."
    }
} else {
    Write-Host "Skip clear generate folder."
}

Write-Host "Start generate..."
Start-Process -FilePath $protocPath -ArgumentList "--proto_path=$protoPath", "--java_out=$generatePath", "$protoPath/*.proto" -WindowStyle Hidden -Wait
Write-Host "Generate completed."
