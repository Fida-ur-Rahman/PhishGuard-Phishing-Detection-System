// DATA
// ═══════════════════════════════════════
var SCANS = [
  { id:'S-001', url:'http://paypa1-secure.com/login/verify', risk:'high', score:97, cat:'Credential Theft', time:'2 min ago', analyst:'Engine', domain:'paypa1-secure.com', ip:'185.220.101.12', reg:'NameCheap', created:'3 days ago', ssl:false, signals:['Homograph typosquatting: "paypa1" mimics PayPal','Domain registered only 3 days ago','No valid SSL certificate','Redirect chain of 2 hops detected','Login/verify keyword cluster','Known malicious IP range'] },
  { id:'S-002', url:'https://g00gle-verify.net/auth/confirm', risk:'high', score:94, cat:'Brand Impersonation', time:'5 min ago', analyst:'Engine', domain:'g00gle-verify.net', ip:'91.134.22.87', reg:'GoDaddy', created:'1 day ago', ssl:true, signals:['Homograph: "g00gle" spoofs Google','Domain age: 1 day only','Phishing keyword cluster: verify+auth+confirm','Known bad IP network block'] },
  { id:'S-003', url:'http://amazon-prize.win/claim-reward', risk:'high', score:91, cat:'Lottery Scam', time:'11 min ago', analyst:'Engine', domain:'amazon-prize.win', ip:'45.142.212.100', reg:'PDR Ltd', created:'5 days ago', ssl:false, signals:['High-risk TLD ".win" heavily used in scams','Brand name + prize/claim pattern matches lottery scam','No SSL on data-collection page','3 redirect hops detected','IP flagged in multiple threat feeds'] },
  { id:'S-004', url:'https://netfl1x-update.info/billing/card', risk:'high', score:89, cat:'Credential Theft', time:'18 min ago', analyst:'J. Smith', domain:'netfl1x-update.info', ip:'77.34.53.90', reg:'NameSilo', created:'8 days ago', ssl:true, signals:['Homograph: "netfl1x" spoofs Netflix','Financial keywords: billing + card','Domain only 8 days old','.info TLD over-represented in phishing','Free CA certificate (not EV)'] },
  { id:'S-005', url:'http://secure-bankofamerica-login.xyz', risk:'high', score:96, cat:'Banking Phish', time:'24 min ago', analyst:'Engine', domain:'secure-bankofamerica-login.xyz', ip:'95.216.44.21', reg:'Namecheap', created:'2 days ago', ssl:false, signals:['Full bank brand embedded in domain name','High-risk TLD ".xyz"','No HTTPS on banking login page','Matches known phishing kit signature v2.3','Domain age: 2 days'] },
  { id:'S-006', url:'https://bit.ly/3xR7aB9', risk:'medium', score:62, cat:'URL Shortener', time:'31 min ago', analyst:'Engine', domain:'bit.ly', ip:'67.199.248.11', reg:'GoDaddy', created:'2014', ssl:true, signals:['URL shortener obfuscates true destination','Target domain has low reputation score','Cannot inspect page content without redirect follow'] },
  { id:'S-007', url:'http://dropbox-shared-file.com/doc.pdf', risk:'medium', score:58, cat:'Malware Delivery', time:'44 min ago', analyst:'M. Chen', domain:'dropbox-shared-file.com', ip:'104.21.33.72', reg:'Cloudflare', created:'12 days ago', ssl:false, signals:['Brand compound domain (Dropbox impersonation)','PDF used as phishing lure','No SSL on file delivery page','Domain age under 2 weeks'] },
  { id:'S-008', url:'https://support-microsft.com/fix-now', risk:'medium', score:71, cat:'Tech Support Scam', time:'1 hr ago', analyst:'Engine', domain:'support-microsft.com', ip:'23.106.56.14', reg:'PDR Ltd', created:'6 days ago', ssl:true, signals:['Typosquatting: "microsft" vs "microsoft"','Tech support scam URL pattern','Urgency keyword: fix-now','Domain age: 6 days'] },
  { id:'S-009', url:'https://github.com/torvalds/linux', risk:'clean', score:2, cat:'Legitimate', time:'1 hr ago', analyst:'Engine', domain:'github.com', ip:'140.82.112.4', reg:'MarkMonitor', created:'2008', ssl:true, signals:['Established high-trust domain (github.com)','Valid EV certificate issued to GitHub Inc.','No phishing indicators detected','IP is part of GitHub CDN infrastructure'] },
  { id:'S-010', url:'https://stackoverflow.com/q/12345678', risk:'low', score:8, cat:'Low Risk', time:'2 hr ago', analyst:'Engine', domain:'stackoverflow.com', ip:'151.101.65.69', reg:'MarkMonitor', created:'2008', ssl:true, signals:['Well-known developer community site','Valid SSL certificate','No suspicious patterns found'] },
  { id:'S-011', url:'https://apple-id-verify.cc/account/login', risk:'high', score:93, cat:'Brand Impersonation', time:'2 hr ago', analyst:'Engine', domain:'apple-id-verify.cc', ip:'31.220.56.214', reg:'PDR Ltd', created:'4 days ago', ssl:true, signals:['Apple brand impersonation pattern','.cc TLD high phishing frequency','Login page at suspicious domain','Domain age: 4 days','Multiple redirect hops'] },
  { id:'S-012', url:'https://docs.google.com/spreadsheets/d/1xyz', risk:'low', score:12, cat:'Low Risk', time:'2 hr ago', analyst:'A. Patel', domain:'docs.google.com', ip:'142.250.185.78', reg:'MarkMonitor', created:'2006', ssl:true, signals:['Legitimate Google-owned subdomain','Valid Google Trust Services certificate','Known safe platform'] },
  { id:'S-013', url:'http://chase-alert-message.com/secure/login', risk:'high', score:95, cat:'Banking Phish', time:'3 hr ago', analyst:'Engine', domain:'chase-alert-message.com', ip:'37.120.222.161', reg:'Namecheap', created:'1 day ago', ssl:false, signals:['Chase bank brand embedded in domain','Multiple phishing keywords: alert+secure+login','No HTTPS on login page','Domain registered 1 day ago','IP flagged as Tier-1 threat'] },
  { id:'S-014', url:'https://login.microsoftonline.com', risk:'clean', score:1, cat:'Legitimate', time:'3 hr ago', analyst:'Engine', domain:'login.microsoftonline.com', ip:'20.190.144.242', reg:'MarkMonitor', created:'2012', ssl:true, signals:['Official Microsoft Azure AD endpoint','EV certificate issued to Microsoft Corporation','Well-known legitimate authentication portal'] },
  { id:'S-015', url:'http://fedex-package-track.info/claim/parcel', risk:'medium', score:55, cat:'Delivery Scam', time:'4 hr ago', analyst:'Engine', domain:'fedex-package-track.info', ip:'194.165.16.39', reg:'PDR Ltd', created:'9 days ago', ssl:false, signals:['FedEx brand impersonation','.info TLD high-risk','No SSL on form page','Delivery scam keyword pattern'] },
];
 
var ALERTS_DATA = [
  { type:'critical', icon:'🔴', title:'Mass Phishing Campaign Detected', desc:'A coordinated campaign targeting PayPal users has been identified. 47 unique domains were registered in the last 6 hours, all impersonating PayPal login pages with valid SSL certificates to appear legitimate.', tags:['47 domains','PayPal brand','SSL abuse','Active now'], time:'3 min ago' },
  { type:'critical', icon:'🚨', title:'Zero-Day Phishing Kit Identified', desc:'A new phishing kit bypassing 2FA via real-time OTP relay has been uploaded to threat feeds. It targets Microsoft 365 and Google Workspace using adversary-in-the-middle (AiTM) technique.', tags:['AiTM attack','Microsoft 365','Google Workspace','2FA bypass'], time:'18 min ago' },
  { type:'warning', icon:'⚠️', title:'Spike in Banking Credential Scans', desc:'Scan volume targeting banking keywords increased 340% in the past hour. Predominantly targeting Bank of America, Chase, and Wells Fargo impersonation pages hosted on bulletproof hosting.', tags:['Banking sector','+340% spike','BoA / Chase','Wells Fargo'], time:'34 min ago' },
  { type:'warning', icon:'⚠️', title:'Threat Feed Signature Update Available', desc:'PhishTank and OpenPhish feeds have 1,842 new signatures available. Manual approval required before deployment to the production rules engine. Review changes in Threat Intel.', tags:['1,842 signatures','PhishTank','OpenPhish','Pending review'], time:'1 hr ago' },
  { type:'info', icon:'💡', title:'ML Model Retrain Complete — Ready to Deploy', desc:'The heuristic detection model completed retraining with 2.4M labelled samples. Accuracy improved from 98.8% to 99.2% on the validation set. False-positive rate reduced by 18%.', tags:['99.2% accuracy','2.4M samples','FP −18%','Awaiting deploy'], time:'2 hr ago' },
];
 
var BAR = [ {d:'Mon',p:38,s:15},{d:'Tue',p:52,s:22},{d:'Wed',p:44,s:18},{d:'Thu',p:61,s:28},{d:'Fri',p:78,s:35},{d:'Sat',p:31,s:12},{d:'Sun',p:43,s:20} ];
var BRANDS  = [['PayPal',82],['Microsoft',74],['Apple',68],['Amazon',61],['Google',55],['Chase Bank',48],['Netflix',39]];
var VECTORS = [['Email Phishing',88],['SMS Smishing',61],['Social Media',44],['Malvertising',38],['Voice Vishing',22]];
var TLDS    = [['.com',42],['.xyz',18],['.net',12],['.info',10],['.cc',8],['.win',6],['.io',4]];
var IOCS    = [['45.142.212.100','IP — C2 Server'],['paypa1-secure.com','Domain — Phishing'],['94.130.52.81','IP — Phishing host'],['g00gle-verify.net','Domain — Impersonation'],['185.220.101.45','IP — Tor exit node']];
 
// ═══════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════
function navigate(pageId) {
  // hide all pages
  document.querySelectorAll('.page').forEach(function(p){ p.classList.remove('active'); });
  var target = document.getElementById('page-' + pageId);
  if (target) target.classList.add('active');
 
  // update nav tabs
  document.querySelectorAll('#nav .ntab[data-page]').forEach(function(b){
    b.classList.toggle('active', b.dataset.page === pageId);
  });
 
  // update sidebar
  document.querySelectorAll('#sidebar .slink[data-page]').forEach(function(b){
    b.classList.toggle('active', b.dataset.page === pageId);
  });
}
 
// attach all nav buttons (top + sidebar) once
document.querySelectorAll('[data-page]').forEach(function(btn){
  btn.addEventListener('click', function(){ navigate(this.dataset.page); });
});
 
// ═══════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════
function rb(risk) {
  var map = { high:'rb rb-high ⛔ High Risk', medium:'rb rb-medium ⚠️ Medium', low:'rb rb-low 🔵 Low', clean:'rb rb-clean ✅ Clean' };
  var parts = (map[risk] || map.clean).split(' ');
  var cls = parts.shift() + ' ' + parts.shift();
  return '<span class="' + cls + '">' + parts.join(' ') + '</span>';
}
 
function scoreColor(s) {
  if (s >= 75) return 'var(--red)';
  if (s >= 45) return 'var(--orange)';
  if (s >= 20) return 'var(--blue)';
  return 'var(--green)';
}
 
function parseURL(raw) {
  try {
    var url = (raw.indexOf('http') === 0) ? raw : 'https://' + raw;
    var u = new URL(url);
    return { protocol: u.protocol.replace(':','').toUpperCase(), host: u.hostname, path: u.pathname || '/', params: u.search || '—' };
  } catch(e) {
    var host = raw.replace(/https?:\/\//,'').split('/')[0];
    return { protocol: raw.indexOf('https') === 0 ? 'HTTPS' : 'HTTP', host: host || raw, path:'/', params:'—' };
  }
}
 
function toast(msg, color) {
  var t = document.getElementById('toast');
  t.style.color = color === 'red' ? 'var(--red)' : 'var(--green)';
  t.textContent = (color === 'red' ? '🚫 ' : '✓ ') + msg;
  t.classList.add('on');
  clearTimeout(t._timer);
  t._timer = setTimeout(function(){ t.classList.remove('on'); }, 2500);
}
 
// ═══════════════════════════════════════
// DASHBOARD TABLE
// ═══════════════════════════════════════
var dashQuery = '';
 
function renderDashTable(data) {
  var rows = data.slice(0, 10);
  var html = '';
  if (!rows.length) {
    html = '<tr><td colspan="6" style="text-align:center;color:var(--dim);padding:24px">No results found</td></tr>';
  } else {
    rows.forEach(function(d){
      html += '<tr onclick="openModal(\'' + d.id + '\')">' +
        '<td class="url-cell" title="' + d.url + '">' + d.url + '</td>' +
        '<td>' + rb(d.risk) + '</td>' +
        '<td><span style="font-family:var(--mono);font-size:12px;font-weight:600;color:' + scoreColor(d.score) + '">' + d.score + '/100</span></td>' +
        '<td>' + d.cat + '</td>' +
        '<td style="font-size:11px;color:var(--dim)">' + d.time + '</td>' +
        '<td><button class="btn" onclick="event.stopPropagation();toast(\'Blocked: \'+\'' + d.domain + '\',\'red\')">Block</button></td>' +
        '</tr>';
    });
  }
  document.getElementById('dash-tbody').innerHTML = html;
}
 
function dashFilter(q) {
  dashQuery = q.toLowerCase();
  var filtered = SCANS.filter(function(d){
    return d.url.toLowerCase().indexOf(dashQuery) !== -1 || d.cat.toLowerCase().indexOf(dashQuery) !== -1;
  });
  renderDashTable(filtered);
}
 
// ═══════════════════════════════════════
// HISTORY TABLE
// ═══════════════════════════════════════
var histRisk = 'all';
var histQ    = '';
 
function getHistRows() {
  var data = histRisk === 'all' ? SCANS : SCANS.filter(function(d){ return d.risk === histRisk; });
  if (histQ) data = data.filter(function(d){ return d.url.toLowerCase().indexOf(histQ) !== -1; });
  return data;
}
 
function renderHistTable() {
  var data = getHistRows();
  document.getElementById('hist-count').textContent = '(' + data.length + ' records)';
  var html = '';
  if (!data.length) {
    html = '<tr><td colspan="9" style="text-align:center;color:var(--dim);padding:24px">No records match filter</td></tr>';
  } else {
    data.forEach(function(d, i){
      html += '<tr onclick="openModal(\'' + d.id + '\')">' +
        '<td style="font-family:var(--mono);font-size:10.5px;color:var(--dim)">' + d.id + '</td>' +
        '<td class="url-cell" title="' + d.url + '">' + d.url + '</td>' +
        '<td>' + rb(d.risk) + '</td>' +
        '<td><span style="font-family:var(--mono);font-size:12px;font-weight:600;color:' + scoreColor(d.score) + '">' + d.score + '</span></td>' +
        '<td style="font-size:11.5px">' + d.signals.length + ' signals</td>' +
        '<td>' + d.cat + '</td>' +
        '<td style="font-size:11.5px">' + d.analyst + '</td>' +
        '<td style="font-size:11px;color:var(--dim)">' + d.time + '</td>' +
        '<td><button class="btn btn-green" onclick="event.stopPropagation();openModal(\'' + d.id + '\')">Details</button></td>' +
        '</tr>';
    });
  }
  document.getElementById('hist-tbody').innerHTML = html;
}
 
function setHistFilter(f, btn) {
  histRisk = f;
  document.querySelectorAll('#hist-pills .pill').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  renderHistTable();
}
 
function histFilter2(q) {
  histQ = q.toLowerCase();
  renderHistTable();
}
 
// ═══════════════════════════════════════
// MODAL
// ═══════════════════════════════════════
function openModal(id) {
  var d = null;
  SCANS.forEach(function(s){ if(s.id === id) d = s; });
  if (!d) return;
 
  var p = parseURL(d.url);
  var c = d.risk === 'high' ? 'var(--red)' : d.risk === 'medium' ? 'var(--orange)' : d.risk === 'clean' ? 'var(--green)' : 'var(--blue)';
 
  var html = '';
 
  // URL box
  html += '<div class="modal-url"><div class="modal-url-label">Scanned URL</div><div class="modal-url-val">' + d.url + '</div></div>';
 
  // Score row
  html += '<div style="display:flex;align-items:center;gap:14px">' +
    '<div style="flex:1">' +
    '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">' + rb(d.risk) +
    '<span style="font-size:22px;font-weight:700;font-family:var(--mono);color:' + c + '">' + d.score +
    '<span style="font-size:13px;color:var(--dim)">/100</span></span></div>' +
    '<div style="height:5px;background:var(--border2);border-radius:3px;overflow:hidden">' +
    '<div style="height:100%;width:' + d.score + '%;background:' + c + ';border-radius:3px;transition:width .8s"></div></div></div></div>';
 
  // URL breakdown
  html += '<div class="modal-url-label" style="margin-bottom:8px">URL Breakdown</div><div class="modal-grid">' +
    '<div class="mg-item"><div class="mg-label">Protocol</div><div class="mg-val" style="color:' + (p.protocol==='HTTPS'?'var(--green)':'var(--red)') + '">' + p.protocol + ' ' + (p.protocol==='HTTPS'?'✓':'✗') + '</div></div>' +
    '<div class="mg-item"><div class="mg-label">Host / Domain</div><div class="mg-val">' + p.host + '</div></div>' +
    '<div class="mg-item"><div class="mg-label">Path</div><div class="mg-val">' + p.path + '</div></div>' +
    '<div class="mg-item"><div class="mg-label">Parameters</div><div class="mg-val">' + p.params + '</div></div>' +
    '</div>';
 
  // Domain info
  html += '<div class="modal-url-label" style="margin-bottom:8px">Domain Information</div><div class="modal-grid">' +
    '<div class="mg-item"><div class="mg-label">Domain</div><div class="mg-val">' + d.domain + '</div></div>' +
    '<div class="mg-item"><div class="mg-label">IP Address</div><div class="mg-val">' + d.ip + '</div></div>' +
    '<div class="mg-item"><div class="mg-label">Registrar</div><div class="mg-val">' + d.reg + '</div></div>' +
    '<div class="mg-item"><div class="mg-label">Domain Created</div><div class="mg-val">' + d.created + '</div></div>' +
    '<div class="mg-item"><div class="mg-label">SSL Certificate</div><div class="mg-val" style="color:' + (d.ssl?'var(--green)':'var(--red)') + '">' + (d.ssl ? '✓ Valid' : '✗ Missing / Invalid') + '</div></div>' +
    '<div class="mg-item"><div class="mg-label">Category</div><div class="mg-val">' + d.cat + '</div></div>' +
    '</div>';
 
  // Detection signals
  html += '<div class="modal-url-label" style="margin-bottom:8px">Detection Signals (' + d.signals.length + ')</div><div class="modal-signals">';
  d.signals.forEach(function(s){
    html += '<div class="modal-signal"><span class="ms-dot">●</span><span class="ms-text">' + s + '</span></div>';
  });
  html += '</div>';
 
  // Actions
  html += '<div class="modal-actions">' +
    '<button class="rp-btn rp-btn-danger" onclick="toast(\'Blocked: ' + d.domain + '\',\'red\');closeModal()">🚫 Block URL</button>' +
    '<button class="rp-btn rp-btn-neutral" onclick="toast(\'Reported to PhishTank feed\')">↗ Report to Feed</button>' +
    '<button class="rp-btn rp-btn-safe" onclick="toast(\'Marked as safe\');closeModal()">✓ Mark Safe</button>' +
    '<button class="rp-btn rp-btn-neutral" style="margin-left:auto" onclick="closeModal()">Close</button>' +
    '</div>';
 
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('overlay').classList.add('on');
}
 
function closeModal() {
  document.getElementById('overlay').classList.remove('on');
}
 
// ═══════════════════════════════════════
// BAR CHART
// ═══════════════════════════════════════
function renderBars() {
  var max = 0;
  BAR.forEach(function(b){ if(b.p+b.s > max) max = b.p+b.s; });
  var barsHtml = '';
  var labelsHtml = '';
  BAR.forEach(function(b){
    var ph = Math.round((b.p / max) * 100);
    var sh = Math.round((b.s / max) * 100);
    barsHtml += '<div class="bar-group" title="' + b.d + ': ' + b.p + ' phishing, ' + b.s + ' suspicious">' +
      '<div class="bar" style="height:' + ph + '%;background:var(--red)"></div>' +
      '<div class="bar" style="height:' + sh + '%;background:var(--orange)"></div>' +
      '</div>';
    labelsHtml += '<div class="bar-lbl">' + b.d + '</div>';
  });
  document.getElementById('bar-chart').innerHTML = barsHtml;
  document.getElementById('bar-labels').innerHTML = labelsHtml;
}
 
// ═══════════════════════════════════════
// ALERTS
// ═══════════════════════════════════════
var alerts = ALERTS_DATA.slice();
 
function renderAlerts() {
  var el = document.getElementById('alert-list');
  if (!alerts.length) {
    el.innerHTML = '<div style="text-align:center;padding:48px;color:var(--dim)">✓ No active alerts</div>';
    updateAlertBadge(0);
    return;
  }
  updateAlertBadge(alerts.length);
  var html = '';
  alerts.forEach(function(a, i){
    html += '<div class="alert alert-' + a.type + '" id="al-' + i + '">' +
      '<div class="alert-icon">' + a.icon + '</div>' +
      '<div class="alert-body">' +
        '<div class="alert-title">' + a.title + '</div>' +
        '<div class="alert-desc">' + a.desc + '</div>' +
        '<div class="alert-tags">' + a.tags.map(function(t){ return '<span class="alert-tag">' + t + '</span>'; }).join('') + '</div>' +
      '</div>' +
      '<div class="alert-right">' +
        '<div class="alert-time">' + a.time + '</div>' +
        '<button class="alert-dismiss" onclick="event.stopPropagation();dismissAlert(' + i + ')">Dismiss</button>' +
      '</div>' +
    '</div>';
  });
  el.innerHTML = html;
}
 
function dismissAlert(i) {
  var el = document.getElementById('al-' + i);
  if (!el) return;
  el.style.cssText += 'opacity:0;transform:translateX(20px);transition:opacity .3s,transform .3s;';
  setTimeout(function(){
    alerts.splice(i, 1);
    renderAlerts();
  }, 320);
}
 
function updateAlertBadge(n) {
  ['alert-badge','sidebar-badge'].forEach(function(id){
    var el = document.getElementById(id);
    if (el) { el.textContent = n; el.style.display = n > 0 ? '' : 'none'; }
  });
}
 
// ═══════════════════════════════════════
// THREAT INTEL
// ═══════════════════════════════════════
function renderIntel() {
  function barRows(data, color) {
    return data.map(function(row){
      return '<div class="intel-row"><div class="intel-name">' + row[0] + '</div>' +
        '<div class="intel-bar"><div class="intel-fill" style="width:' + row[1] + '%;background:' + color + '"></div></div>' +
        '<div class="intel-val">' + row[1] + '%</div></div>';
    }).join('');
  }
  document.getElementById('brand-list').innerHTML  = barRows(BRANDS,  'var(--red)');
  document.getElementById('vector-list').innerHTML = barRows(VECTORS, 'var(--orange)');
  document.getElementById('tld-list').innerHTML    = barRows(TLDS,    'var(--purple)');
  document.getElementById('ioc-list').innerHTML = IOCS.map(function(row){
    return '<div class="ioc-row"><div><div class="ioc-val">' + row[0] + '</div><div class="ioc-lbl">' + row[1] + '</div></div><span class="ioc-badge">ACTIVE</span></div>';
  }).join('');
}
 
// ═══════════════════════════════════════
// SCANNER ENGINE
// ═══════════════════════════════════════
var STEPS = [
  'Resolving DNS records…','Checking WHOIS registration…',
  'Validating SSL certificate…','Querying PhishTank database…',
  'Running ML heuristics…','Analysing URL structure…',
  'Cross-referencing threat intelligence…','Computing final risk score…'
];
 
function doScan() {
  var raw = document.getElementById('url-inp').value.trim();
  if (!raw) { toast('Please enter a URL to scan', 'red'); return; }
 
  document.getElementById('result-wrap').style.display = 'none';
  document.getElementById('result-wrap').innerHTML = '';
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('scan-anim').classList.add('on');
 
  var fill = document.getElementById('scan-prog-fill');
  var stepEl = document.getElementById('scan-step');
  fill.style.width = '0%';
 
  var step = 0;
  var total = STEPS.length;
 
  var iv = setInterval(function(){
    if (step < total) {
      stepEl.textContent = STEPS[step];
      fill.style.width = Math.round(((step + 1) / total) * 100) + '%';
      step++;
    }
  }, 350);
 
  setTimeout(function(){
    clearInterval(iv);
    fill.style.width = '100%';
    setTimeout(function(){
      document.getElementById('scan-anim').classList.remove('on');
      document.getElementById('scan-btn').disabled = false;
      showResult(raw);
    }, 300);
  }, total * 350 + 250);
}
 
function analyse(raw) {
  var u = raw.toLowerCase();
  var p = parseURL(raw);
  var host = p.host.toLowerCase();
 
  // known safe domains
  var safeDomains = ['github.com','stackoverflow.com','google.com','microsoft.com','apple.com','amazon.com','facebook.com','twitter.com','youtube.com','linkedin.com','reddit.com','cloudflare.com','mozilla.org','docs.google.com','login.microsoftonline.com'];
  var isSafe = false;
  safeDomains.forEach(function(d){ if(host === d || host.endsWith('.' + d)) isSafe = true; });
 
  if (isSafe) {
    return {
      score: Math.floor(Math.random() * 7) + 1,
      risk: 'safe',
      signals: [
        { type:'safe', name:'Established Trusted Domain', desc:'This domain has a long-standing verified track record with no phishing history.' },
        { type:'safe', name:'Valid HTTPS Certificate', desc:'SSL/TLS certificate issued by a trusted Certificate Authority (CA).' },
        { type:'safe', name:'No Phishing Patterns Detected', desc:'URL structure, keyword analysis, and domain age show no suspicious signals.' },
        { type:'safe', name:'Reputable IP Infrastructure', desc:'IP address belongs to a well-known, trusted hosting provider.' }
      ],
      parsed: p
    };
  }
 
  var score = 0;
  var signals = [];
 
  // Homograph check (numbers replacing letters in brand names)
  var homographBrands = ['paypa1','g00g','g0ogle','amaz0n','netfl1x','micros0ft','app1e','ch4se'];
  var hasHomograph = false;
  homographBrands.forEach(function(h){ if(host.indexOf(h) !== -1) hasHomograph = true; });
  if (hasHomograph) {
    score += 32;
    signals.push({ type:'danger', name:'Homograph Attack Detected', desc:'The domain uses digits or lookalike characters to impersonate a well-known brand (e.g. "0" for "o", "1" for "l").' });
  }
 
  // Brand impersonation (known brands on unofficial domains)
  var brands = ['paypal','google','amazon','netflix','apple','microsoft','chase','bankofamerica','wellsfargo','fedex','dropbox','instagram','facebook','twitter'];
  var hasBrand = false;
  brands.forEach(function(b){
    if (u.indexOf(b) !== -1 && !isSafe) hasBrand = true;
  });
  if (hasBrand && !hasHomograph) {
    score += 22;
    signals.push({ type:'danger', name:'Brand Impersonation', desc:'URL contains a well-known brand name hosted on an unofficial or unrelated domain.' });
  }
 
  // Phishing keywords
  var phishWords = ['login','verify','confirm','secure','update','billing','account','credential','auth','claim','prize','reward','alert','fix','suspend','unlock','validate'];
  var kwCount = 0;
  phishWords.forEach(function(w){ if(u.indexOf(w) !== -1) kwCount++; });
  if (kwCount >= 3) {
    score += 18;
    signals.push({ type:'danger', name:'High Phishing Keyword Density (' + kwCount + ' keywords)', desc:'Multiple phishing-associated keywords detected in the URL path and domain name.' });
  } else if (kwCount >= 1) {
    score += 9;
    signals.push({ type:'warn', name:'Suspicious Keywords (' + kwCount + ' found)', desc:'URL contains keywords commonly associated with phishing pages.' });
  }
 
  // High-risk TLD
  var badTLDs = ['.xyz','.win','.cc','.info','.tk','.ml','.ga','.cf','.gq','.pw','.top','.site','.online','.click','.work'];
  var hasBadTLD = false;
  badTLDs.forEach(function(t){ if(host.endsWith(t)) hasBadTLD = true; });
  if (hasBadTLD) {
    score += 18;
    var tld = host.split('.').pop();
    signals.push({ type:'danger', name:'High-Risk Top-Level Domain', desc:'The ".' + tld + '" TLD is significantly over-represented in phishing campaigns and malicious sites.' });
  }
 
  // No HTTPS
  if (raw.toLowerCase().indexOf('https') !== 0) {
    score += 14;
    signals.push({ type:'danger', name:'Missing HTTPS (Plain HTTP)', desc:'Page is served over unencrypted HTTP. Any credentials or data submitted would be sent in plain text.' });
  }
 
  // URL shortener
  var shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','short.io','rb.gy'];
  var isShortener = false;
  shorteners.forEach(function(s){ if(host === s || host.endsWith('.' + s)) isShortener = true; });
  if (isShortener) {
    score += 20;
    signals.push({ type:'warn', name:'URL Shortener Detected', desc:'The true destination is obfuscated by a shortening service. The actual landing page cannot be verified without following redirects.' });
  }
 
  // No signals at all — low risk
  if (signals.length === 0) {
    score = Math.floor(Math.random() * 20) + 5;
    signals.push({ type:'safe', name:'No Critical Indicators Found', desc:'URL structure does not closely match known phishing patterns.' });
    signals.push({ type:'safe', name:'Domain Appears Legitimate', desc:'No brand impersonation, typosquatting, or high-risk TLD detected.' });
  }
 
  // Cap and jitter
  score = Math.min(98, Math.max(4, score + Math.floor(Math.random() * 7) - 2));
  var risk = score >= 75 ? 'danger' : score >= 45 ? 'warn' : 'safe';
 
  return { score: score, risk: risk, signals: signals, parsed: p };
}
 
function showResult(raw) {
  var r = analyse(raw);
  var p = r.parsed;
 
  var riskClass  = { danger:'rp-danger', warn:'rp-warn', safe:'rp-safe' }[r.risk];
  var icon       = { danger:'🚨', warn:'⚠️', safe:'🛡️' }[r.risk];
  var verdict    = { danger:'Phishing Detected — Block Immediately', warn:'Suspicious URL — Proceed with Caution', safe:'No Threats Detected' }[r.risk];
  var subtext    = { danger:'This URL matches multiple phishing indicators. Do not visit or share this link.', warn:'This URL has suspicious traits. Verify the source before proceeding.', safe:'This URL appears safe based on current detection signals.' }[r.risk];
  var fillColor  = { danger:'var(--red)', warn:'var(--orange)', safe:'var(--green)' }[r.risk];
  var actionBtn  = '';
  if (r.risk === 'danger') actionBtn = '<button class="rp-btn rp-btn-danger" onclick="toast(\'URL blocked and reported\',\'red\')">🚫 Block URL</button>';
  else if (r.risk === 'warn') actionBtn = '<button class="rp-btn rp-btn-warn" onclick="toast(\'Flagged for manual review\',\'red\')">⚠️ Flag for Review</button>';
  else actionBtn = '<button class="rp-btn rp-btn-safe" onclick="toast(\'URL whitelisted\')">✓ Mark as Safe</button>';
 
  // Group signals
  var dangerSigs = [], warnSigs = [], safeSigs = [];
  r.signals.forEach(function(s){ if(s.type==='danger') dangerSigs.push(s); else if(s.type==='warn') warnSigs.push(s); else safeSigs.push(s); });
 
  function renderSigs(arr) {
    return arr.map(function(s){
      return '<div class="ind"><div class="ind-icon">' + (s.type==='danger'?'⛔':s.type==='warn'?'⚠️':'✅') + '</div><div><div class="ind-name">' + s.name + '</div><div class="ind-desc">' + s.desc + '</div></div></div>';
    }).join('');
  }
 
  var sigsHtml = '';
  if (dangerSigs.length) sigsHtml += '<div class="rp-section">🔴 Critical Signals (' + dangerSigs.length + ')</div><div class="ind-grid">' + renderSigs(dangerSigs) + '</div>';
  if (warnSigs.length)   sigsHtml += '<div class="rp-section" style="margin-top:12px">⚠️ Warning Signals (' + warnSigs.length + ')</div><div class="ind-grid">' + renderSigs(warnSigs) + '</div>';
  if (safeSigs.length)   sigsHtml += '<div class="rp-section" style="margin-top:12px">✅ Passing Checks (' + safeSigs.length + ')</div><div class="ind-grid">' + renderSigs(safeSigs) + '</div>';
 
  var html = '<div class="rp ' + riskClass + '">' +
    // header
    '<div class="rp-header">' +
    '<div class="rp-top">' +
    '<div class="rp-icon">' + icon + '</div>' +
    '<div><div class="rp-verdict">' + verdict + '</div><div class="rp-sub">' + subtext + '</div></div>' +
    '</div>' +
    '<div class="rp-meta">' +
    '<div class="rp-meta-item"><div class="rp-meta-label">Risk Score</div><div class="rp-meta-val" style="color:' + fillColor + '">' + r.score + '/100</div></div>' +
    '<div class="rp-meta-item"><div class="rp-meta-label">Host</div><div class="rp-meta-val">' + p.host + '</div></div>' +
    '<div class="rp-meta-item"><div class="rp-meta-label">Protocol</div><div class="rp-meta-val" style="color:' + (p.protocol==='HTTPS'?'var(--green)':'var(--red)') + '">' + p.protocol + '</div></div>' +
    '<div class="rp-meta-item"><div class="rp-meta-label">Scanned At</div><div class="rp-meta-val">' + new Date().toLocaleTimeString() + '</div></div>' +
    '</div>' +
    '<div class="score-bar"><div class="score-fill" id="sfill" style="background:' + fillColor + ';width:0%"></div></div>' +
    '</div>' +
    // body
    '<div class="rp-body">' +
    sigsHtml +
    '<div class="url-breakdown" style="margin-top:14px">' +
    '<div class="ub-title">URL Breakdown</div>' +
    '<div class="ub-grid">' +
    '<div class="ub-item"><label>Full URL</label><span style="color:var(--blue)">' + raw + '</span></div>' +
    '<div class="ub-item"><label>Path</label><span>' + p.path + '</span></div>' +
    '<div class="ub-item"><label>Host</label><span>' + p.host + '</span></div>' +
    '<div class="ub-item"><label>Parameters</label><span>' + p.params + '</span></div>' +
    '</div></div>' +
    '<div class="rp-actions" style="margin-top:14px">' +
    actionBtn +
    '<button class="rp-btn rp-btn-neutral" onclick="toast(\'Reported to PhishTank\')">↗ Report to Feed</button>' +
    '<button class="rp-btn rp-btn-neutral" onclick="copyReport(\'' + encodeURIComponent(raw) + '\',' + r.score + ')">📋 Copy Report</button>' +
    '</div></div></div>';
 
  var wrap = document.getElementById('result-wrap');
  wrap.innerHTML = html;
  wrap.style.display = 'block';
 
  // animate score bar
  requestAnimationFrame(function(){
    requestAnimationFrame(function(){
      var el = document.getElementById('sfill');
      if (el) el.style.width = r.score + '%';
    });
  });
 
  // Add to scan history
  var newId = 'S-' + String(SCANS.length + 1).padStart(3, '0');
  SCANS.unshift({
    id: newId, url: raw,
    risk: { danger:'high', warn:'medium', safe:'clean' }[r.risk],
    score: r.score, cat: 'Manual Scan', time: 'just now',
    analyst: 'You', domain: p.host, ip: '—', reg: '—', created: '—',
    ssl: p.protocol === 'HTTPS',
    signals: r.signals.map(function(s){ return s.name; })
  });
  renderDashTable(SCANS);
  renderHistTable();
}
 
function copyReport(encodedUrl, score) {
  var url = decodeURIComponent(encodedUrl);
  var txt = 'PhishGuard Scan Report\n========================\nURL: ' + url + '\nRisk Score: ' + score + '/100\nScanned: ' + new Date().toLocaleString() + '\n';
  navigator.clipboard.writeText(txt).then(function(){ toast('Report copied to clipboard'); }).catch(function(){ toast('Copy not supported', 'red'); });
}
 
// ═══════════════════════════════════════
// KEYBOARD SHORTCUTS
// ═══════════════════════════════════════
document.getElementById('url-inp').addEventListener('keydown', function(e){
  if (e.key === 'Enter') doScan();
});
document.addEventListener('keydown', function(e){
  if (e.key === 'Escape') closeModal();
});
 
// Filter pills (non-history) generic toggle
document.querySelectorAll('#page-dashboard .pills .pill, #page-alerts .pills .pill, #page-scanner .pills .pill').forEach(function(b){
  b.addEventListener('click', function(){
    this.closest('.pills').querySelectorAll('.pill').forEach(function(x){ x.classList.remove('active'); });
    this.classList.add('active');
  });
});
 
// ═══════════════════════════════════════
// INIT
// ═══════════════════════════════════════
renderDashTable(SCANS);
renderHistTable();
renderBars();
renderAlerts();
renderIntel();
