on run
    set resourceRoot to POSIX path of (path to resource "payload")
    try
        set firstChoice to button returned of (display dialog "双击安装 Claude Guard

无需拖入应用程序文件夹。点击继续，按提示完成一次管理员授权。不会自动切换网络或开启防护。

离线恢复工具与手册已内置。应用无法打开或网络异常时，可在这里直接打开恢复工具，无需先安装。" buttons {"恢复工具", "取消", "继续"} default button "继续" cancel button "取消")
        if firstChoice is "恢复工具" then
            set recoveryRoot to POSIX path of (path to resource "Recovery")
            do shell script "/usr/bin/open " & quoted form of recoveryRoot & " " & quoted form of (recoveryRoot & "/恢复说明.md")
            return
        end if
        set processList to do shell script "/bin/ps -axo comm="
        if processList contains "ClaudeSafeLauncher.app/Contents/MacOS/ClaudeSafeLauncher" then
            display dialog "请先在旧版菜单栏选择「恢复并退出」，确认 Claude/Code 已退出、临时 IPv6 已恢复，再打开本程序。不会自动结束你的应用。" buttons {"知道了"} default button 1 with icon caution
            return
        end if
        set choice to button returned of (display dialog "Claude Guard\n\n个人测试版未经过 Apple 公证。继续表示你信任此来源，并同意仅移除本安装包解出的 Claude Guard 副本的下载隔离属性，再核验签名；不会关闭 Gatekeeper 或修改其他应用。\n\n将 App 与助手配置到此 Mac，需要一次管理员授权。不会启动代理、切换网络或开启防护。\n\n默认使用标准路径的 FLClash；其他兼容核心可手动选择其可执行文件及运行配置。恢复和移除工具可从 App 的「恢复工具」打开。" buttons {"取消", "其他核心…", "继续"} default button "继续" cancel button "取消")
        set corePath to ""
        set configPath to ""
        if choice is "其他核心…" then
            set coreFile to choose file with prompt "选择实际代理核心可执行文件（不是 App 目录）" with showing package contents
            set configFile to choose file with prompt "选择该核心的单节点 HTTP 运行配置 YAML"
            set corePath to POSIX path of coreFile
            set configPath to POSIX path of configFile
        end if
        set ownerUID to do shell script "/usr/bin/id -u"
        if (ownerUID as integer) < 501 then error "请从普通用户账户打开。"
        -- quoted form protects spaces, apostrophes and shell metacharacters in all selected paths.
        set commandText to my installationCommand(resourceRoot, ownerUID, corePath, configPath)
        with timeout of 600 seconds
            set resultText to do shell script commandText with administrator privileges
        end timeout
        display dialog "配置完成。助手当前空闲，防护未开启。\n\n接下来打开 App，按首次引导填写自己的网络信息。" buttons {"完成", "打开 Claude Guard"} default button "打开 Claude Guard"
        if button returned of result is "打开 Claude Guard" then
            try
                do shell script "/usr/bin/open /Applications/ClaudeSafeLauncher.app"
            on error openError
                display dialog "安装已完成，但 macOS 未能打开 App。请从应用程序中打开 ClaudeSafeLauncher，并检查隐私与安全性提示。无需重复安装。\n\n" & openError buttons {"知道了"} default button 1 with icon caution
            end try
        end if
    on error errorText number errorNumber
        if errorNumber is not -128 then display dialog "未完成配置（" & errorNumber & "）\n\n" & errorText & "\n\n不要继续安全启动。若网络受影响，重新打开本安装器，选择「恢复工具」。" buttons {"知道了"} default button 1 with icon stop
    end try
end run

-- Pure command construction; offline tests call this handler without running the applet.
on installationCommand(resourceRoot, ownerUID, corePath, configPath)
    set numericUID to ownerUID as integer
    if numericUID < 501 then error "普通用户 UID 无效"
    if resourceRoot does not start with "/" then error "资源路径必须是绝对路径"
    set extraArgs to ""
    if corePath is not "" or configPath is not "" then
        if corePath does not start with "/" or configPath does not start with "/" then error "核心和配置路径必须同时提供绝对路径"
        set extraArgs to " " & quoted form of corePath & " " & quoted form of configPath
    end if
    return "CLAUDE_GUARD_ALLOW_UNNOTARIZED=1 SUDO_UID=" & quoted form of (numericUID as text) & " /bin/bash " & quoted form of (resourceRoot & "/scripts/install.sh") & extraArgs
end installationCommand
