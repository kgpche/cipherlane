/* cipherlane · 控制面板 —— 打开主页 / 停止服务 / 关于 / 检查更新 */
'use strict'

const $ = (s) => document.querySelector(s)
const token = location.hash.slice(1) // 停机令牌：仅本页持有，浏览器规范保证不过网
const show = (msg, cls) => {
  const el = $('#result')
  el.textContent = msg
  el.className = 'result' + (cls ? ' ' + cls : '')
}

function fmtUptime(ms) {
  const s = Math.floor(ms / 1000)
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
  return h ? `${h} 时 ${m} 分` : m ? `${m} 分 ${s % 60} 秒` : `${s} 秒`
}

async function refresh() {
  try {
    const j = await (await fetch('/api/version')).json()
    $('#ver').textContent = 'v' + j.version
    $('#rooms').textContent = j.rooms
    $('#uptime').textContent = fmtUptime(Date.now() - j.startedAt)
    $('#dot').classList.add('on')
  } catch {
    $('#dot').classList.remove('on')
    $('#uptime').textContent = '已停止'
  }
}

$('#open').onclick = () => window.open('/', '_blank')

$('#about').onclick = () => { $('#about-box').hidden = !$('#about-box').hidden }

$('#stop').onclick = async () => {
  if (!token) return show('⚠️ 本会话未携带停机令牌（请从应用列表或启动器打开面板）', 'warn')
  if (!confirm('确定退出密道？服务将停止，传输中的任务会中断。')) return
  try {
    const r = await fetch('/api/shutdown', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    })
    if (r.ok) {
      show('✅ 已退出。可从应用列表重新开启 cipherlane。', 'ok')
      $('#dot').classList.remove('on')
    } else show('❌ 停止失败：' + r.status + '（令牌无效或非本机）', 'err')
  } catch (e) { show('❌ ' + e.message, 'err') }
}

$('#update').onclick = async () => {
  show('⟳ 正在检查更新…', 'dim')
  try {
    const j = await (await fetch('/api/update')).json()
    if (!j.source) return show('ℹ️ 当前 v' + j.current + '。' + (j.message || '未配置更新源'), 'dim')
    if (j.error) return show('⚠️ 更新源不可达：' + j.error, 'warn')
    if (j.newer) show(`🟢 有新版本：v${j.current} → v${j.latest}（更新源：${j.source}）`, 'ok')
    else show(`✅ 已是最新：v${j.current}（更新源报告 v${j.latest}）`, 'ok')
  } catch (e) { show('❌ ' + e.message, 'err') }
}

refresh()
setInterval(refresh, 2000)
