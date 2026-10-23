import SwiftUI
import AppKit
import GuardRuntime
import GuardUIModel

final class WindowLifecycle:NSObject,NSApplicationDelegate {
    weak var model:AppModel?
    func applicationShouldTerminateAfterLastWindowClosed(_ sender:NSApplication)->Bool {false}
    func applicationShouldTerminate(_ sender:NSApplication)->NSApplication.TerminateReply {
        guard let model else{return .terminateCancel}
        guard let task=model.request(.shutdown) else{return .terminateCancel}
        Task {await task.value
            let restored=model.readyToQuit
            sender.reply(toApplicationShouldTerminate:restored)
            if !restored {sender.activate(ignoringOtherApps:true)}
        }
        return .terminateLater
    }
}
@main struct GuardApplication:App {
    @NSApplicationDelegateAdaptor(WindowLifecycle.self) private var lifecycle
    @StateObject private var model:AppModel
    init() {
        #if DEBUG
        if CommandLine.arguments.count>=3,CommandLine.arguments[1]=="--render-preview" {
            let sample=AppModel(autoPoll:false,preferences:nil)
            sample.state.message="离线界面预览 · 未连接助手，未运行网络检测"
            sample.state.processInventoryComplete=true
            let scenario=CommandLine.arguments.count>3 ? CommandLine.arguments[3]:"empty"
            sample.testingIP=scenario=="loading"
            if scenario=="armed" {sample.state.phase="armed";sample.state.verified=true;sample.state.claude=true;sample.state.blockedPackets=128}

            if scenario=="success" || scenario=="error" {
                let error=scenario=="error" ? "HTTPS IPv4 检测失败或超时；离线预览长文本":""
                let object:[String:Any] = ["expected":sample.settings.expectedEgress,"startedAt":0,"samples":["ipify","webshare"].map{["service":$0,"ip":error.isEmpty ? sample.settings.expectedEgress:"","error":error,"measuredAt":0] as [String:Any]}]
                sample.ipCheck=try? JSONDecoder().decode(IPCheck.self,from:JSONSerialization.data(withJSONObject:object))
                sample.ipStale=false
                if scenario=="error" {sample.failure=String(repeating:"离线模拟错误详情；",count:30);sample.state.report=String(repeating:"[离线预览] 长日志验证内部滚动\n",count:40)}
            }
            _model=StateObject(wrappedValue:sample)
            let path=CommandLine.arguments[2]
            DispatchQueue.main.async {
                let host=NSHostingView(rootView:scenario=="welcome" ? AnyView(WelcomeView(model:sample,configure:{})):AnyView(LauncherView(model:sample,preview:true,previewPage:scenario)))
                let window=NSWindow(contentRect:NSRect(x:0,y:0,width:1100,height:660),styleMask:[.titled,.resizable],backing:.buffered,defer:false)
                window.contentView=host;window.orderFront(nil);host.layoutSubtreeIfNeeded();window.display()
                DispatchQueue.main.asyncAfter(deadline:.now()+0.5){
                    if let bitmap=host.bitmapImageRepForCachingDisplay(in:host.bounds) {
                        host.cacheDisplay(in:host.bounds,to:bitmap)
                        if let data=bitmap.representation(using:.png,properties:[:]){try? data.write(to:URL(fileURLWithPath:path))}
                    };exit(0)
                }
            }
            return
        }
        #endif
        _model=StateObject(wrappedValue:AppModel())
    }
    var body:some Scene {
        Window("Claude 安全启动器",id:"main") {
            LauncherView(model:model,preview:CommandLine.arguments.contains("--render-preview"))
                .task{lifecycle.model=model}
        }
            .defaultSize(width:1100,height:700)
        MenuBarExtra { GuardMenu(model:model) } label: { MenuStatus(model:model) }
        Window("出口 IP 检测",id:"ip-test") { IPPanel(model:model).padding(28).frame(minWidth:560,minHeight:310) }
    }
}
private struct MenuStatus:View {
    @ObservedObject var model:AppModel
    @Environment(\.openWindow) private var openWindow
    var body:some View {
        Label("Claude · \(model.menuStatus)",systemImage:model.state.verified ? "checkmark.shield.fill":"shield.lefthalf.filled")
            .onChange(of:model.interruptionAlert?.id){_,id in if id != nil {openWindow(id:"main");NSApp.activate(ignoringOtherApps:true)}}
            .onChange(of:model.egressWarningAlert?.id){_,id in if id != nil {openWindow(id:"main");NSApp.activate(ignoringOtherApps:true)}}
            .onChange(of:model.registrationAlert){_,visible in if visible {openWindow(id:"main");NSApp.activate(ignoringOtherApps:true)}}
    }
}
private struct GuardMenu:View {
    @ObservedObject var model:AppModel
    @Environment(\.openWindow) private var openWindow
    var body:some View {
        Text("Claude Guard · \(model.menuStatus)")
        Text(model.guidance.title)
        Divider()
        Button("打开主窗口"){openWindow(id:"main");NSApp.activate(ignoringOtherApps:true)}
        Button("关闭防护"){model.request(.stop)}
        Divider()
        Text("关闭窗口继续防护；退出会关闭 Claude 并恢复")
        Button("恢复并退出启动器"){NSApp.terminate(nil)}.keyboardShortcut("q")
    }
}
private struct WelcomeView:View {
    @ObservedObject var model:AppModel
    var configure:()->Void
    @State private var step=0
    private let titles=["欢迎使用 Claude Guard","先准备你的网络","填写并核对端点","关闭窗口与退出的区别"]
    private let descriptions=[
        "启动器先验证代理出口与防护，再启动 Claude。IP 匹配只是其中一项检查。当前仍是本机测试版，首次通过图形程序完成管理员授权。",
        "由你手动启动已登记的兼容代理核心、选择 HTTP 节点并开启 TUN。启动器不会切换代理。若主页面提醒存在 IPv6 默认路由，先退出 Claude/Code，再点击临时关闭 IPv6。",
        "下一步进入网络设置，先选择并登记当前使用的单节点 HTTP 配置。成功后填入候选网关；你需要核对服务商提供的网关、端口和预期出口。内置 IP 检测只能辅助填写预期出口，不能推断网关或端口。",
        "关闭主窗口后，菜单栏与防护继续运行。菜单栏的「恢复并退出」会先结束受保护的 Claude/Code、恢复本工具设置再退出；恢复失败会留在应用中。配置会记住，防护不会自动开启。"
    ]
    var body:some View {
        VStack(alignment:.leading,spacing:24) {
            HStack{Image(systemName:["checkmark.shield","network","slider.horizontal.3","menubar.rectangle"][step]).font(.system(size:44)).foregroundStyle(.blue);Spacer();Text("\(step+1) / 4").foregroundStyle(.secondary)}
            Text(titles[step]).font(.largeTitle.bold())
            HStack(spacing:16){Label("准备网络",systemImage:"network");Image(systemName:"chevron.right");Label("验证防护",systemImage:"shield");Image(systemName:"chevron.right");Label("启动 Claude",systemImage:"play.fill")}.font(.caption)
            Text(descriptions[step]).font(.title3).multilineTextAlignment(.leading).frame(height:150,alignment:.topLeading)
            HStack{Button("上一步"){step-=1}.disabled(step==0);Spacer();Button(step==3 ? "前往网络设置":"下一步"){if step==3 {model.completeOnboarding();configure()} else{step+=1}}.buttonStyle(.borderedProminent)}
        }.padding(32).frame(width:620).background(Color(nsColor:.windowBackgroundColor)).interactiveDismissDisabled()
    }
}
private enum Page:String,CaseIterable,Identifiable {
    case overview="总览",network="网络设置",diagnostics="诊断与恢复",about="软件声明"
    var id:String{rawValue}
    var icon:String{switch self{case .overview:"shield.lefthalf.filled";case .network:"network";case .diagnostics:"waveform.path.ecg";case .about:"info.circle"}}
}
private struct GlassSurface:ViewModifier {
    func body(content:Content)->some View {
        if #available(macOS 26.0,*) {content.glassEffect(.regular,in:.rect(cornerRadius:22))}
        else {content.background(.regularMaterial,in:RoundedRectangle(cornerRadius:22))}
    }
}
private struct GlassAction:ViewModifier {
    var primary=false
    @ViewBuilder func body(content:Content)->some View {
        if #available(macOS 26.0,*) {
            if primary {content.buttonStyle(.glassProminent).controlSize(.large)}
            else {content.buttonStyle(.glass).controlSize(.large)}
        } else {
            if primary {content.buttonStyle(.borderedProminent).controlSize(.large)}
            else {content.buttonStyle(.bordered).controlSize(.large)}
        }
    }
}
private struct LauncherView:View {
    @ObservedObject var model:AppModel
    var preview=false
    var previewPage:String?
    @State private var page:Page? = .overview
    @State private var showWelcome=false
    @State private var showEndpointHelp=false
    @Environment(\.openWindow) private var openWindow
    private var canStart:Bool {model.confirmation && !model.state.fingerprint.isEmpty && model.state.processInventoryComplete && model.state.phase=="off" && !model.busy && !model.needsIPv6Off}
    var body:some View {
        NavigationSplitView {
            VStack(alignment:.leading,spacing:24) {
                Label("Claude Guard",systemImage:"shield.lefthalf.filled").font(.title3.bold()).padding(.top,22)
                List(Page.allCases,selection:$page){item in Label(item.rawValue,systemImage:item.icon).tag(item)}.listStyle(.sidebar)
                VStack(alignment:.leading,spacing:6){Text("本机测试版").font(.caption.bold());Text(BuildIdentity.buildID).font(.caption.monospaced());Text("PF 防护 · 有限进程观测").font(.caption2)}.foregroundStyle(.secondary).padding(.bottom,18)
            }.padding(.horizontal,12).navigationSplitViewColumnWidth(min:190,ideal:205,max:230)
        } detail: {
            Group {
                if page == .overview || page == nil {
                    overview.padding(20).frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)
                } else {
                    ScrollView {
                        VStack(alignment:.leading,spacing:22) {
                            Text((page ?? .overview).rawValue).font(.largeTitle.bold())
                            if page == .network {network} else if page == .about {about} else {diagnostics}
                            if !model.failure.isEmpty {notice(model.failure,icon:"exclamationmark.triangle.fill",color:.red)}
                            if !model.state.processWarning.isEmpty {notice(model.state.processWarning,icon:"info.circle",color:.orange)}
                        }.padding(24).frame(maxWidth:1300,alignment:.leading)
                    }
                }
            }.background(Color(nsColor:.windowBackgroundColor).gradient)
            .toolbar {
                ToolbarItem {Button{model.testIP();openWindow(id:"ip-test")}label:{Label("IP 检测",systemImage:"globe")}.disabled(model.busy)}
                ToolbarItem {Button{model.export()}label:{Label("导出反馈",systemImage:"square.and.arrow.up")}}
            }
        }.frame(minWidth:1100,minHeight:660)
        .task {if preview {if previewPage=="about" {page = .about};if previewPage=="network" {page = .network}};if !preview {showWelcome = !model.onboardingComplete;model.poll();model.testIP()}}
        .sheet(isPresented:$showWelcome){WelcomeView(model:model){showWelcome=false;page = .network}}
        .onChange(of:model.state.phase){_,_ in model.ipStale=true}
        .onChange(of:model.interruptionAlert?.id){_,id in if id != nil && !preview {showWelcome=false;NSApp.activate(ignoringOtherApps:true)}}
        .onChange(of:model.egressWarningAlert?.id){_,id in if id != nil && !preview {showWelcome=false;NSApp.activate(ignoringOtherApps:true)}}
        .onChange(of:model.registrationAlert){_,visible in if visible && !preview {showWelcome=false;NSApp.activate(ignoringOtherApps:true)}}
        .alert(model.registrationAlert ? "Claude 已更新，需要重新登记":model.interruptionAlert != nil ? "启动器自动停止提醒":"出口暂时无法核验",isPresented:Binding(get:{model.registrationAlert || model.interruptionAlert != nil || model.egressWarningAlert != nil},set:{if !$0 {model.acknowledgeVisibleAlert()}})) {
            if model.registrationAlert {
                Button("验证并重新登记 Claude"){model.registrationAlert=false;model.request(.refreshClaudeRegistration)}
                    .disabled(model.busy || model.state.phase != "off")
            }
            Button("查看诊断"){page = .diagnostics;model.acknowledgeVisibleAlert()}
            Button("知道了",role:.cancel){model.acknowledgeVisibleAlert()}
        } message: {
            if model.registrationAlert {
                Text("Claude 的构建与原登记不一致，通常由自动更新引起，并不表示 IP 泄漏。\n\n请先退出 Claude 和 Claude Code，确认防护 OFF。点击后将核验 Anthropic 官方签名并更新登记，无需重新安装防护器；不会更改网络设置或自动启动 Claude。\n\n" + (model.state.phase != "off" ? "当前尚未 OFF，请先完成关闭或恢复。\n":"") + (model.failure.contains("Claude registration") ? String(model.failure.prefix(350)):""))
            } else if let event=model.interruptionAlert {
                Text("\(event.exitConfirmed ? "启动器已主动关闭 Claude。":event.requestedClaudeStop ? "启动器已请求关闭 Claude，但尚未确认全部退出。":"启动器已结束防护验证。")\n\(Guidance.reason(event.reason).title)\n\(Guidance.reason(event.reason).action)\n时间：\(event.timestamp)\n原始原因：\(String(event.reason.prefix(400)))")
            } else if let event=model.egressWarningAlert {
                Text("两次出口检测均未取得可用结果。Claude 未关闭，PF 与本地防护检查继续运行。当前公网出口尚未确认，不代表检测到 IP 泄漏。\n请检查代理连通性；程序每 5 分钟重测，恢复后自动清除提醒。检测到不同公网 IP 仍会立即关闭 Claude。\n时间：\(event.timestamp)")
            }
        }
    }
    private var overview:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack(spacing:12) {
                Image(systemName:model.bannerTone == .protected ? "checkmark.shield.fill":model.bannerTone == .blocked ? "exclamationmark.shield.fill":"shield.lefthalf.filled").font(.system(size:30)).foregroundStyle(bannerColor)
                VStack(alignment:.leading,spacing:3) {
                    Text(model.bannerTitle).font(.system(size:20,weight:.bold)).lineLimit(1).help(model.bannerTitle)
                    Text(model.bannerTone == .protected ? "出口与防护验证通过 · Claude：\(model.state.claudeKnown == false ? "待确认" : (model.state.claude ? "运行中":"未运行"))":model.guidance.action).font(.caption).foregroundStyle(.secondary).lineLimit(1).help(model.guidance.action)
                }
                Spacer(minLength:4)
                Text("已阻断数据包 \(model.blockCountText) 次")
                    .font(.system(size:20,weight:.semibold,design:.rounded)).monospacedDigit()
                    .lineLimit(1).minimumScaleFactor(0.7).frame(width:250,alignment:.trailing)
                    .padding(.horizontal,12).padding(.vertical,10)
                    .background(bannerColor.opacity(0.08),in:RoundedRectangle(cornerRadius:12)).help(model.blockCountHelp)
                Text(model.state.phase.uppercased()).font(.subheadline.bold().monospaced()).foregroundStyle(bannerColor)
            }.padding(.horizontal,16).padding(.vertical,10).frame(maxWidth:.infinity,alignment:.leading)
             .background(bannerColor.opacity(0.12),in:RoundedRectangle(cornerRadius:18)).modifier(GlassSurface())
            HStack(spacing:12) {
                action("安全启动 Claude",icon:"play.fill",primary:true){model.request(.start)}.disabled(!canStart)
                action("仅验证防护",icon:"checkmark.shield"){model.request(.verify)}.disabled(!canStart)
                action("关闭防护",icon:"stop.fill"){model.request(.stop)}
            }
            HStack(spacing:10) {
                action("重新检测配置",icon:"arrow.clockwise"){model.confirmation=false;model.request(.inspect)}.disabled(model.busy || model.state.phase != "off")
                action("检测 IP",icon:"globe"){model.testIP()}.disabled(model.busy || model.testingIP)
                action("离线自检",icon:"stethoscope"){model.request(.selfTest)}.disabled(model.busy || model.state.phase != "off")
                action("网络设置",icon:"slider.horizontal.3"){page = .network}
                action("恢复工具",icon:"lifepreserver"){openRecovery()}
            }
            HStack(spacing:10) {
                endpointButton
                Text("网关：\(model.state.gateway.isEmpty ? "先检测配置，再核对服务商端点":model.state.gateway)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength:0)
            }
            HStack(alignment:.top,spacing:12) {
                VStack(alignment:.leading,spacing:12) {
                    IPPanel(model:model)
                    ipv6Panel.frame(height:160)
                }.frame(maxWidth:.infinity)
                outputPanel.frame(maxWidth:.infinity).frame(height:382)
            }
            HStack {
                Text("配置：\(model.state.fingerprint.isEmpty ? "未读取":String(model.state.fingerprint.prefix(16)))").font(.caption.monospaced()).foregroundStyle(.secondary)
                Spacer()

            }
            Text("代理 / TUN 由你手动准备。IP 匹配不等于防泄漏验证。关闭窗口继续后台防护；退出会结束 Claude 并恢复原设置。").font(.caption).foregroundStyle(.secondary)
        }
    }
    private func action(_ title:String,icon:String,primary:Bool=false,run:@escaping ()->Void)->some View {
        Button(action:run){Label(title,systemImage:icon).font(.system(size:14,weight:.semibold)).frame(maxWidth:.infinity,minHeight:28).padding(.vertical,3)}.modifier(GlassAction(primary:primary))
    }
    private var outputPanel:some View {
        VStack(alignment:.leading,spacing:10) {
            HStack{Label("执行与诊断",systemImage:"terminal").font(.headline);Spacer();if model.busy{ProgressView().controlSize(.small)};Text(model.busy ? "处理中":"就绪").font(.caption).foregroundStyle(.secondary)}
            VStack(alignment:.leading,spacing:4) {
                Text(model.guidance.category).font(.caption.bold()).foregroundStyle(model.guidance.severe ? Color.red:.blue)
                Text(model.guidance.title).font(.system(size:15,weight:.bold)).lineLimit(1).help(model.guidance.title)
                Text(model.guidance.action).font(.caption).lineLimit(2).help(model.guidance.action)
            }.frame(maxWidth:.infinity,minHeight:74,maxHeight:74,alignment:.topLeading)
             .padding(10).background((model.guidance.severe ? Color.red:Color.blue).opacity(0.08),in:RoundedRectangle(cornerRadius:12))
            ScrollViewReader{reader in
                GeometryReader { geometry in
                ScrollView(.vertical) {
                    VStack(alignment:.leading,spacing:8) {
                        Text("当前阶段："+model.state.message).foregroundStyle(.secondary)
                        Text(model.state.report.isEmpty ? "尚无执行记录。\n点击上方指令后，助手会输出实际执行阶段。":model.state.report)
                        if !model.failure.isEmpty {Text("错误：\(model.failure)").foregroundStyle(.red)}
                        if !model.state.lastRisk.isEmpty {Text("最近事件：\(model.state.lastRisk)").foregroundStyle(.orange)}
                        if !model.state.processWarning.isEmpty {Text(model.state.processWarning).foregroundStyle(.orange)}
                        Color.clear.frame(height:1).id("tail")
                    }.font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                     .multilineTextAlignment(.leading)
                     .frame(width:max(0,geometry.size.width-20),alignment:.topLeading)
                     .fixedSize(horizontal:false,vertical:true)
                     .frame(minHeight:max(0,geometry.size.height-20),alignment:.topLeading).padding(10)
                }.frame(maxWidth:.infinity,maxHeight:.infinity).background(Color.primary.opacity(0.035),in:RoundedRectangle(cornerRadius:12))
                 .onChange(of:model.state.report){_,_ in reader.scrollTo("tail",anchor:.bottom)}
                }
            }
            HStack{Text("实际阶段 · 完整信息可在框内滚动").font(.caption2).foregroundStyle(.secondary);Spacer();Button("复制记录"){NSPasteboard.general.clearContents();NSPasteboard.general.setString([model.state.report,model.failure,model.state.lastRisk,model.state.processWarning].filter{!$0.isEmpty}.joined(separator:"\n"),forType:.string)}}
        }.padding(16).background(.regularMaterial,in:RoundedRectangle(cornerRadius:18))
    }
    private var ipv6Panel:some View {
        VStack(alignment:.leading,spacing:6) {
            HStack{Label("临时 IPv6",systemImage:"arrow.triangle.2.circlepath").font(.headline);Spacer()}
            HStack {
                Text(model.ipv6ReadinessText).font(.caption.weight(.semibold)).foregroundStyle(model.needsIPv6Off ? Color.red:.secondary).lineLimit(1).help(model.ipv6ReadinessText+"；"+model.state.ipv6Override)
                Spacer(minLength:4);Button{model.refreshIPv6()}label:{Image(systemName:"arrow.clockwise")}.help("只读刷新 IPv6 状态")
            }
            HStack(spacing:8) {
                action(model.needsIPv6Off ? "需关闭":"关闭",icon:"network.slash",primary:model.needsIPv6Off){model.request(.ipv6Off)}.tint(model.needsIPv6Off ? Color.red:.accentColor)
                action("启用",icon:"network"){model.request(.ipv6Automatic)}
                action("恢复",icon:"arrow.uturn.backward"){model.request(.ipv6Restore)}
            }.disabled(!canChangeIPv6)
            Text("仅 OFF 且 Claude/Code 已退出时可改；关闭防护时保留；退出启动器后恢复原设置。启用使用 Automatic。")
                .font(.caption2).foregroundStyle(.secondary).lineLimit(2).fixedSize(horizontal:false,vertical:true)
        }.padding(16).frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)
         .background(.background.opacity(0.7),in:RoundedRectangle(cornerRadius:18))
    }
    private var canChangeIPv6:Bool {!model.busy && model.state.phase=="off" && !model.state.claude && model.state.processInventoryComplete}
    private var network:some View {
        VStack(alignment:.leading,spacing:22) {
            HStack{Text("修改即保存；每次启动仍重新验证，不自动开启防护。").font(.caption).foregroundStyle(.secondary);Spacer();Button("使用引导"){showWelcome=true}.disabled(model.busy || model.state.phase != "off")}
            card("已登记代理配置",icon:"doc.text") {
                Text(model.state.configurationPath.flatMap{$0.isEmpty ? nil:$0} ?? "尚未登记：请选择当前使用的配置")
                    .font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)
                Text("不要选旧订阅或仅为通过检查导出的文件。配置登记只提供候选节点，实际 Core/网关/TUN/出口仍须验证。")
                    .font(.caption).foregroundStyle(.secondary)
                Button("选择并登记配置…"){model.chooseProxyConfiguration()}.buttonStyle(.borderedProminent)
                    .disabled(model.busy || model.state.phase != "off")
            }
            card("代理端点",icon:"server.rack") {
                Text("首次使用不预填地址。网关 / 端口来自代理服务商；公网 IP 检测只能辅助填写预期出口。").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Text("如何填写端点？").font(.caption)
                    Button{showEndpointHelp=true}label:{Image(systemName:"questionmark.circle")}.buttonStyle(.plain)
                        .popover(isPresented:$showEndpointHelp){Text("① 网关 IP 和端口：查看服务商控制面板或代理软件当前节点。需明确支持的数字 IPv4 HTTP endpoint，不能把域名自行替换为 IP。\n\n② 预期出口：先手动准备代理，再运行内置 IP 检测；点击「检测并填入出口 IP」，两个服务一致时自动填写。这不会填写网关或端口，也不证明已受到保护。\n\n③ 端口无法通过出口检测推断；0 表示尚未填写。网关与出口即使相同，也要分别确认。\n\n④ 兼容范围：安装时登记的核心 + 单节点 HTTP 的 Mihomo 配置。其他格式 / VPN 未支持，出口一致也不会绕过验证。").font(.callout).padding(20).frame(width:380)}
                    Spacer()
                }
                HStack{TextField("Gateway IPv4",text:$model.settings.gateway);TextField("端口",value:$model.settings.port,format:.number.grouping(.never)).frame(width:95);TextField("接口",text:$model.settings.physical).frame(width:70)}
                LabeledContent("预期出口 IPv4"){TextField("IPv4",text:$model.settings.expectedEgress).frame(maxWidth:250)}
                HStack {
                    Button(model.testingIP ? "正在检测…":"检测并填入出口 IP"){model.testIP(fillEgress:true)}.buttonStyle(.borderedProminent).disabled(model.testingIP || model.busy || model.state.phase != "off")
                    Button("重新检测配置"){model.confirmation=false;model.request(.inspect)}.disabled(model.busy)
                }
                Text("候选网关：\(model.state.gateway)\n指纹：\(model.state.fingerprint)").font(.caption.monospaced()).textSelection(.enabled)
                endpointButton
            }.disabled(model.state.phase != "off" || model.busy)
            ipv6Panel
        }
    }
    private var endpointButton:some View {
        Button {model.confirmation.toggle()} label: {
            Label(model.confirmation ? "端点已确认":"确认代理端点",systemImage:model.confirmation ? "checkmark.seal.fill":"checkmark.seal")
                .font(.system(size:13,weight:.semibold)).padding(.vertical,3)
        }.buttonStyle(.borderedProminent).tint(model.confirmation ? .green:.accentColor)
         .disabled(model.busy || model.state.phase != "off" || model.state.fingerprint.isEmpty)
         .help("核对服务商数字网关、端口、预期出口后确认。配置修改后需要重新确认；再次点击可撤销。")
    }
    private func openRecovery() {
        guard let folder=Bundle.main.url(forResource:"Recovery",withExtension:nil) else{model.failure="恢复资源缺失，请重新打开 DMG 使用内置恢复工具";return}
        NSWorkspace.shared.open(folder)
        NSWorkspace.shared.open(folder.appendingPathComponent("恢复说明.md"))
    }
    private var bannerColor:Color {switch model.bannerTone {case .protected:.green;case .waiting:.yellow;case .blocked:.red}}
    private var about:some View {
        VStack(alignment:.leading,spacing:22) {
            card("Claude Guard",icon:"shield.lefthalf.filled") {
                Text("为 Claude Desktop 与本机 Claude Code 提供可验证的临时网络防护。").font(.title3)
                row("版本",BuildIdentity.buildID+" · 测试版")
                row("作者","colorful · @colorful-tju")
                Link("GitHub 个人主页",destination:URL(string:"https://github.com/colorful-tju")!)
                Text("项目仓库尚未发布。此应用不是 Anthropic、Apple 或代理软件的官方产品，与上述机构无隶属关系。").font(.caption).foregroundStyle(.secondary)
            }
            card("源码与许可",icon:"doc.text") {
                Text("源码可见 · 仅限非商业使用 · 禁止二次开发").font(.headline)
                Text("允许阅读、审计、按原样构建与个人非商业使用。未经作者另行书面授权，不允许商业使用、修改程序或制作衍生版本。用户填写自己的运行配置不属于二次开发。完整条款以随附 LICENSE 为准。")
                Text("这些限制不符合 OSI 开源定义，因此本项目不标为标准开源软件。").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("阅读许可"){openDocument("LICENSE",extension:nil)}
                    Button("使用说明"){openDocument("README",extension:"md")}
                    Button("技术与功能文档"){openDocument("技术与功能详解",extension:"md")}
                    Button("第三方与隐私说明"){openDocument("NOTICE",extension:"md")}
                }
            }
            card("能力与边界",icon:"checklist") {
                Text("PF 出口限制是防护边界；进程观测仅为辅助。支持登记的兼容 TCP/TUN 核心与单节点 HTTP 配置，不等于支持任意 VPN。无法验证时会拒绝启动或结束受保护应用。")
                Text("没有遥测、账号登录或自动上传日志。IP 测试访问 ipify 与 Webshare；反馈报告仍可能包含网络地址，请脱敏后再分享。未承诺绝对匿名、零漏洞或平台账号安全。")
            }
        }
    }
    private func openDocument(_ name:String,extension ext:String?) {
        if let url=Bundle.main.url(forResource:name,withExtension:ext){NSWorkspace.shared.open(url)}
    }
    private var diagnostics:some View {
        VStack(alignment:.leading,spacing:22) {
            card("运行证据",icon:"checklist") {
                row("UDP / PF",model.state.udp);row("IPv6 路径",model.state.ipv6);row("进程观测",model.state.monitor)
                row("采集完整性",model.state.processInventoryComplete ? "完整":"未确认")
                row("助手版本",model.state.daemonBuildID);row("探针版本",model.state.workerBuildID)
                row("最近刷新",model.state.refreshedAt)
            }
            if let event=model.state.interruption {
                card("自动停止原因",icon:"exclamationmark.shield") {
                    Text(event.exitConfirmed ? "启动器已关闭 Claude":event.requestedClaudeStop ? "已请求关闭；退出尚未确认":"已结束防护验证").font(.headline).foregroundStyle(.red)
                    Text(Guidance.reason(event.reason).title+"\n"+Guidance.reason(event.reason).action)
                    Text(event.timestamp+"\n"+event.reason).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            card("最近事件",icon:"clock") {Text(model.state.lastRisk.isEmpty ? "暂无记录":model.state.lastRisk).textSelection(.enabled).font(.callout);Text("Claude 自行退出属于正常生命周期事件，不等于网络泄漏。").font(.caption).foregroundStyle(.secondary)}
            card("恢复与反馈",icon:"lifepreserver") {
                Button("打开恢复工具与手册"){openRecovery()}.buttonStyle(.borderedProminent)
                Text("出现恢复受阻时，先点击「关闭防护」。若仍无法联网，在终端执行独立恢复；不要删除恢复记录。").font(.callout)
                HStack{Button("关闭防护"){model.request(.stop)};Button("导出反馈报告"){model.export()};Button("查看测试与恢复手册"){if let url=Bundle.main.url(forResource:"新版界面与IPv6验证",withExtension:"md"){NSWorkspace.shared.open(url)}}}
                Text(model.state.report).font(.caption.monospaced()).textSelection(.enabled).frame(maxHeight:220,alignment:.topLeading).clipped()
            }
        }
    }
    private func notice(_ text:String,icon:String,color:Color)->some View {Label(text,systemImage:icon).font(.callout).foregroundStyle(color).textSelection(.enabled)}
    private func row(_ title:String,_ value:String)->some View {LabeledContent(title){Text(value.isEmpty ? "—":value).multilineTextAlignment(.trailing).textSelection(.enabled)}.font(.callout)}
    private func card<Content:View>(_ title:String,icon:String,@ViewBuilder content:()->Content)->some View {
        VStack(alignment:.leading,spacing:14){Label(title,systemImage:icon).font(.headline);content()}.padding(20).frame(maxWidth:.infinity,alignment:.leading).background(.background.opacity(0.7),in:RoundedRectangle(cornerRadius:18))
    }
}
private struct IPPanel:View {
    @ObservedObject var model:AppModel
    private var verdict:String {
        if model.testingIP {return "正在通过两个 HTTPS 服务检测…"}
        guard let result=model.ipCheck else{return "尚未检测"}
        if model.ipStale || result.expected != model.settings.expectedEgress {return "网络或设置已改变，请重新检测"}
        return result.matches ? "两个来源均匹配预期出口":"未匹配 / 检测未完成"
    }
    var body:some View {
        VStack(alignment:.leading,spacing:8) {
            HStack{Label("公网 IPv4",systemImage:"globe").font(.headline);Spacer();if model.testingIP{ProgressView().controlSize(.small)};Button("重新检测"){model.testIP()}.disabled(model.testingIP || model.busy)}.frame(height:24)
            Text(verdict).font(.callout.bold()).lineLimit(1).help(verdict)
                .foregroundStyle(!model.testingIP && !model.ipStale && model.ipCheck?.expected==model.settings.expectedEgress && model.ipCheck?.matches==true ? Color.green:Color.secondary)
                .frame(height:20,alignment:.leading)
            ForEach(["ipify","webshare"],id:\.self){service in
                let sample=model.ipCheck?.samples.first{$0.service==service}
                let value=model.testingIP ? "检测中…":sample.map{$0.ip.isEmpty ? $0.error:$0.ip} ?? "—"
                HStack(spacing:8) {
                    Text(service=="ipify" ? "ipify":"Webshare").font(.caption).foregroundStyle(.secondary).frame(width:62,alignment:.leading)
                    Text(value).font(.system(size:13,design:.monospaced)).lineLimit(1).help(value).textSelection(.enabled)
                    Spacer(minLength:0)
                    if let sample {Text(sample.measuredAt,style:.time).font(.caption2).foregroundStyle(.secondary)}
                }.frame(height:24)
            }
            Text("预期：\(model.settings.expectedEgress)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Text("当前路由 / TUN · 仅检测 IPv4，不代表防泄漏验证")
                .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                .help("绕过系统代理设置，使用当前系统路由 / TUN。不在线查询地理位置；检测失败不改变安全模式。ARMED 由守护进程独立验证。")
        }.padding(16).frame(maxWidth:.infinity).frame(height:210,alignment:.topLeading)
         .background(.background.opacity(0.7),in:RoundedRectangle(cornerRadius:18))
    }
}
