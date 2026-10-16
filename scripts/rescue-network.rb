#!/usr/bin/ruby
# Administrator-operated escape hatch, deliberately separate from verified OFF.
# Fixed commands only. Never loads rules, flushes states, releases guessed
# tokens, deletes recovery assets, restarts the helper, or changes DNS/routes.
require 'open3'

mode = ARGV.fetch(0, '')
abort '用法：rescue-network.rb --force-own 或 --last-resort' unless ARGV.length == 1 && ['--force-own', '--last-resort'].include?(mode)
abort '需要 Mac 管理员权限；请运行 emergency-recover.sh 的对应参数。' unless Process.euid == 0
$stdout.sync = true
root = '/Library/Application Support/ClaudeSafeLauncher'
label = 'local.claudesafelauncher.guard'
anchor = 'com.apple/000.local.claudesafelauncher'
leaf = '000.local.claudesafelauncher'
last_resort = mode == '--last-resort'
lock = nil
class BusyRecoveryLock < StandardError; end

def run_fixed(path, arguments, timeout = 5)
  env = {'PATH'=>'/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL'=>'C', 'LANG'=>'C'}
  input, output, errors, waiter = Open3.popen3(env, path, *arguments, unsetenv_others:true, pgroup:true)
  input.close
  readers = [output, errors].map {|io| Thread.new {io.read} }
  unless waiter.join(timeout) && readers.all? {|reader| reader.join(0.5) }
    begin Process.kill('KILL', -waiter.pid); rescue Errno::ESRCH; end
    raise "命令超时：#{File.basename(path)}；未宣称恢复成功"
  end
  out, err = readers.map(&:value)
  raise '命令输出超限' if out.bytesize > 2*1024*1024 || err.bytesize > 1024*1024
  [waiter.value.exitstatus, out, err]
ensure
  [input, output, errors].compact.each {|io| io.close unless io.closed? }
  readers&.each {|reader| reader.kill if reader.alive? }
end

def display(arguments)
  status, out, err = run_fixed('/sbin/pfctl', arguments)
  benign = ['No ALTQ support in kernel', 'ALTQ related functions disabled']
  raise "PF 读取失败或包含错误诊断（exit=#{status}）：#{err.lines.first(4).join.strip}" unless status == 0 && err.lines.all? {|row| row.strip.empty? || benign.include?(row.strip) } && !out.lines.any? {|row| row.lstrip.start_with?('pfctl:') }
  out
end

def names(text, parent = '')
  result = text.lines.map(&:strip).reject(&:empty?).map {|name| parent.empty? ? name : name.delete_prefix(parent+'/') }
  raise 'PF 目录未知或歧义' unless result.uniq == result && result.all? {|name| name.match?(/\A[A-Za-z0-9_.-]+\z/) && !['.', '..'].include?(name) }
  result
end

def own_filter(anchor, leaf)
  return '' unless names(display(['-s', 'Anchors'])).include?('com.apple')
  return '' unless names(display(['-a', 'com.apple', '-s', 'Anchors']), 'com.apple').include?(leaf)
  display(['-a', anchor, '-sr'])
end

begin
  puts '强制恢复会结束本工具的安全防护。请勿在恢复期间运行 Claude。'
  puts '最后兜底将临时停用整个 PF，包括其他软件使用的 PF 防护。' if last_resort
  puts '1/4 停止本工具 launchd 助手；不会自动重新启动。'
  run_fixed('/bin/launchctl', ['bootout', 'system/'+label])
  loaded, out, err = run_fixed('/bin/launchctl', ['print', 'system/'+label])
  missing = "Bad request.\nCould not find service \"#{label}\" in domain for system"
  raise '助手仍加载或 launchd 状态无法核验；未修改 PF' unless loaded == 113 && out.strip.empty? && err.strip == missing

  # Lock the same transaction file after bootout. Do not repair unknown modes
  # or follow links, and never read the journal just to guess a release token.
  begin
    if File.exist?(root) || File.symlink?(root)
      info = File.lstat(root)
      trusted = info.directory? && !info.symlink? && info.uid == Process.euid && (info.mode & 0022) == 0
      raise '事务目录不可信' unless trusted
      lock = File.open(root+'/daemon.lock', File::RDWR|File::CREAT|File::NOFOLLOW, 0600)
      info = lock.stat
      raise '事务锁不是普通文件' unless info.file?
      raise BusyRecoveryLock, '其他恢复进程持有事务锁；未修改 PF' unless lock.flock(File::LOCK_EX|File::LOCK_NB)
      raise '事务锁归属不可信' unless info.uid == Process.euid && (info.mode & 0022) == 0
    end
  rescue BusyRecoveryLock
    raise
  rescue => error
    raise unless last_resort
    # If a regular file was locked successfully, retain that lock even when
    # owner/mode validation failed. Never bypass an actual busy transaction.
    if lock && !lock.stat.file?
      lock.close; lock = nil
    end
    puts "事务元数据无法核验：#{error}；保留资产，仅执行明确选择的应急 PF 操作。"
  end

  puts '2/4 尝试结束当前用户的已知 Claude/Helper；不是完整按进程身份验收。'
  uid = ENV['SUDO_UID']
  raise '请从普通用户终端通过 sudo 运行，无法确定用户 UID' unless uid && uid.match?(/\A[0-9]+\z/) && uid.to_i >= 501
  pattern = 'Claude( Helper( .*)?)?'
  %w[TERM KILL].each do |signal|
    status, = run_fixed('/usr/bin/pkill', ['-'+signal, '-u', uid, '-x', pattern])
    raise '无法发送 Claude 结束请求' unless [0,1].include?(status)
    sleep 0.15
  end
  present, = run_fixed('/usr/bin/pgrep', ['-a', '-u', uid, '-x', pattern])
  raise '已知 Claude（可能含恢复命令的祖先进程）仍在或无法读取；请先退出 Claude，从系统 Terminal/Finder 运行。未解除 PF' unless present == 1

  puts '3/4 只清除本工具 anchor 的 filter；保留 Apple/其他规则、state、token 和事务日志。'
  begin
    unless own_filter(anchor, leaf).strip.empty?
      status, out, err = run_fixed('/sbin/pfctl', ['-a', anchor, '-F', 'rules'])
      raise "自身规则清理命令失败：#{status}" unless status == 0
      raise '自身 filter 仍存在' unless own_filter(anchor, leaf).strip.empty?
    end
    puts 'ONLY_OWN_FILTER_CLEARED（不是 OFF 验收；未探测互联网）'
  rescue => error
    raise unless last_resort
    puts "自身规则读取/清理失败：#{error}；尝试固定自身 anchor 清理，再执行明确选择的全局 PF 兜底。"
    # Explicit administrator override only: try removing the fixed owned
    # filter even if its display is unavailable, so another PF user enabling
    # PF later is less likely to reactivate our stale block. Never claim this
    # succeeded without a successful subsequent read; global status is separate.
    begin
      status, = run_fixed('/sbin/pfctl', ['-a', anchor, '-F', 'rules'])
      puts "自身清理尝试退出码=#{status}（读取不可用，未确认清理成功）"
    rescue => cleanup_error
      puts "自身清理尝试失败：#{cleanup_error}；继续明确选择的全局 PF 停用。"
    end
  end

  if last_resort
    puts '4/4 停用全局 PF，随后读取内核状态确认；不清空 state 或加载主规则。'
    run_fixed('/sbin/pfctl', ['-d'])
    raise '未能确认 PF 已停用；不能宣称恢复成功' unless display(['-s', 'info']).match?(/\AStatus: Disabled\b/)
    puts 'PF_DISABLED_VERIFIED：PF 阻断已停用。尚未验证互联网；请手动测试当前网络。'
  else
    puts '4/4 自身 filter 已移除；PF 启用引用与恢复资产保留。若仍断网，可明确选择 --last-resort。'
  end
  puts '临时 IPv6 备份同样保留；如使用过临时开关，请按新版手册执行独立 --restore-ipv6 恢复。'
  puts '助手保持停止；不要继续安全启动。由后续正常恢复/卸载处理保留资产。'
rescue => error
  warn "恢复受阻：#{error}"
  exit 2
ensure
  lock&.close
end
