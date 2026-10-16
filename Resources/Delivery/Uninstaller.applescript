on run
    set resourceRoot to POSIX path of (path to resource "payload")
    try
        set processList to do shell script "/bin/ps -axo comm="
        if processList contains "ClaudeSafeLauncher.app/Contents/MacOS/ClaudeSafeLauncher" then
            display dialog "请先在启动器菜单栏选择「恢复并退出」，确认 OFF 与临时 IPv6 已恢复。" buttons {"知道了"} default button 1 with icon caution
            return
        end if
        display dialog "移除 Claude Guard 及其管理员助手？\n\n同时清空当前用户的节点设置和首次引导记录。请先记下网关、端口、预期出口和自定义核心路径，重装后需要重新填写。\n\n请先确认防护 OFF、Claude/Code 已退出、临时 IPv6 已恢复。若仍有恢复事务，工具会拒绝移除并保留记录。" buttons {"取消", "移除"} default button "取消" cancel button "取消" with icon caution
        set ownerUID to do shell script "/usr/bin/id -u"
        if (ownerUID as integer) < 501 then error "请以普通用户打开移除工具。"
        with timeout of 120 seconds
            do shell script "SUDO_UID=" & quoted form of ownerUID & " /bin/bash " & quoted form of (resourceRoot & "/scripts/uninstall.sh") with administrator privileges
        end timeout
        display dialog "Claude Guard、助手及当前用户节点/引导设置已移除并核验。" buttons {"完成"} default button 1
    on error errorText number errorNumber
        if errorNumber is not -128 then display dialog "移除未完成（" & errorNumber & "）\n\n" & errorText & "\n\n保留恢复记录，必要时使用映像中的离线恢复工具。" buttons {"知道了"} default button 1 with icon stop
    end try
end run
