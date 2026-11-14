/**
 * =============================================================================
 *  Mihomo (Clash.Meta) 完整配置覆写脚本  ·  for Sub-Store
 * =============================================================================
 *
 * 【用法】
 *  1. Sub-Store → 新建「文件 / 组合订阅」，把你的机场订阅（单条订阅）添加进去；
 *  2. 在该文件的「脚本操作」里新建 JavaScript 脚本，粘贴本文件全部内容；
 *  3. 该文件的输出格式选 Mihomo / Clash（不要选 URI、Base64、Surge 等格式）；
 *  4. 用生成的文件链接导入 mihomo 内核或 Clash Verge Rev / Meta for Android 等客户端。
 *  ※ 请挂在「文件 / 组合订阅」的脚本操作上；单条订阅的脚本入口期望「返回节点数组」，
 *    而本脚本返回的是完整配置对象，挂错位置会生成失败。
 *
 * 【做了什么】
 *  - 保留订阅原有 proxies，过滤广告假节点、处理重名节点；
 *  - 生成完整策略组（节点选择 / 自动测速 / 故障转移 / 分流组 / 广告拦截 / 漏网之鱼）；
 *  - 生成完整 DNS(fake-ip) / sniffer / 基础配置 / 可选 TUN；
 *  - 生成分流规则：局域网 → 广告 → AI / 电报 / 流媒体 / 微软 / GitHub → 国内直连 → 境外代理 → MATCH；
 *  - 可选：引用 ACL4SSR 远程规则集增强分流；可选：按地区自动分组。
 *
 * 【参数（$arguments）】
 *  Sub-Store 用「脚本链接 # 后面」传参，脚本内通过全局变量 $arguments 读取（注意是 # 不是 ?）：
 *    https://.../mihomo-override.js#allowregion=true&enableLoadBalance=1&enableFallbackGroup=false
 *  无值参数等价于 true（#allowregion）；布尔支持 true/false、1/0、yes/no、on/off。
 *  也支持 JSON 对象或 "a=1&b=2" 字符串形式的 $arguments，以及 $options / main 的 context 参数。
 *
 *  常用参数（别名 → 实际变量）：
 *    allowregion              → enableRegionGroups   按地区自动分组
 *    enableFallbackGroup      → 同名（别名 allowfallback）故障转移组
 *    enableLoadBalance        → 同名（别名 allowbalance / loadbalance）负载均衡组
 *    tun → tunEnable，remoterules → useRemoteRuleSets
 *  实际上 CFG 里所有标量项都能用同名参数覆盖（大小写不敏感），例如：
 *    #mixedPort=7891&dnsMode=redir-host&testUrl=https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204
 *  数组项用 | 分隔：#extraDirectDomains=a.com|b.com
 *
 * 【兼容性】
 *  - 入口为 main(config, context) → return config（Sub-Store 文件/组合订阅的标准脚本接口）；
 *  - 全脚本使用 ES5 语法，不依赖 $utils / fetch / 箭头函数 / 可选链，
 *    以兼容 Sub-Store 在浏览器端与 Node 端不同的 JS 沙箱；
 *  - 若传入的是节点数组，会自动包装成 { proxies: [...] }；
 *  - 若传入的是 YAML 字符串，会尝试用 Sub-Store 的 $utils.yaml 解析。
 *
 * 【怎么改】优先用参数；也可直接改下面 CFG 里的默认值（参数优先级更高）。
 * =============================================================================
 */

// -----------------------------------------------------------------------------
// 1. 用户配置区
// -----------------------------------------------------------------------------
var CFG = {
  // ---------- 基础设置 ----------
  mode: 'rule',                  // rule / global / direct
  mixedPort: 7890,
  redirPort: 0,                  // 0 = 不开启；配合 iptables REDIRECT 时填 7892
  tproxyPort: 0,                 // 0 = 不开启；配合 TPROXY 时填 7893
  allowLan: false,
  logLevel: 'info',              // silent / error / warning / info / debug
  ipv6: false,                   // 无 IPv6 环境建议关掉，避免解析异常
  unifiedDelay: true,
  tcpConcurrent: true,
  geodataMode: true,             // GEOSITE / GEOIP 规则依赖它，务必保持 true
  geoAutoUpdate: true,
  geoUpdateInterval: 24,         // 小时
  externalController: '',        // 例：'127.0.0.1:9090'，纯内核 + 面板时填；留空则不输出
  secret: '',                    // API 密钥，仅在 externalController 有值时生效
  externalUI: '',                // 例：'./ui/metacubexd'，留空则不输出
  debug: true,                   // 在 Sub-Store 日志里打印一行统计

  // ---------- DNS ----------
  dnsEnable: true,
  dnsMode: 'fake-ip',            // 'fake-ip' / 'redir-host' / 'off'（off = 不覆写 dns 段）
  fakeIpRange: '198.18.0.1/16',
  domesticDns: [
    'https://doh.pub/dns-query',
    'https://dns.alidns.com/dns-query',
    '223.5.5.5'
  ],
  fallbackDns: [                 // 境外 DNS，配合 fallback-filter 使用
    'tls://8.8.4.4',
    'tls://1.1.1.1',
    'https://dns.google/dns-query'
  ],
  defaultNameserver: ['223.5.5.5', '119.29.29.29'], // 只放纯 IP，用于解析 DoH 域名
  proxyServerNameserver: ['https://doh.pub/dns-query', '223.5.5.5'], // 解析节点域名
  directNameserver: ['system'],  // DIRECT 出口用系统 DNS，国内解析更准
  respectRules: false,           // 与 preferH3 不要同时开
  preferH3: false,

  // ---------- 域名嗅探 ----------
  snifferEnable: true,
  snifferOverrideDestination: false, // true 可缓解部分「域名不匹配」，但可能影响少数应用

  // ---------- TUN ----------
  // 用 Clash Verge Rev / Meta for Android 等客户端时保持 false（由客户端接管 TUN）；
  // 直接用 mihomo 纯内核启动时改成 true。
  tunEnable: false,
  tunStack: 'mips',              // mips(官方推荐) / mixed / gvisor / system
  tunMtu: 9000,
  tunStrictRoute: true,
  tunAutoRedirect: true,         // 仅 Linux 生效

  // ---------- 节点处理 ----------
  filterAds: true,               // 过滤机场下发的「公告 / 剩余流量」类假节点
  excludeNameRegex: '官网|官方|到期|过期|剩余流量|已用流量|重置时间|订阅地址|套餐|公告|客服|注意事项|免责|教程|网址|关注微信|https?://|www\\.',
  dedupe: true,                  // 节点重名会导致内核加载失败，自动加序号
  excludeTypes: ['direct', 'reject', 'relay', 'selector', 'urltest', 'fallback', 'loadbalance'],

  // ---------- 健康检查 ----------
  // Cloudflare 官方连通性检测端点：HTTPS、返回 204、无响应体，测速轻量且不易被劫持
  testUrl: 'https://cp.cloudflare.com/generate_204',
  testStatus: 204,               // expected-status；若换用 cdn-cgi/trace(200) 请改成 200 或 '*'
  testInterval: 300,
  testTolerance: 50,

  // ---------- 可选功能 ----------
  enableFallbackGroup: true,     // 故障转移组
  enableLoadBalance: false,      // 负载均衡组
  enableRegionGroups: false,     // 按节点名里的地区关键字自动分组
  useRemoteRuleSets: false,      // 打开后引用 ACL4SSR 远程规则集（需要能访问 GitHub）
  ruleSetInterval: 86400,        // 规则集更新周期（秒）
  ruleSetDownloadProxy: 'PROXY', // 'PROXY' = 走主代理组下载规则集；'DIRECT' = 直连下载

  // ---------- 策略组名称（改名只改这里，规则会自动跟着变） ----------
  groups: {
    proxy: '🚀 节点选择',
    auto: '♻️ 自动选择',
    fallback: '🔯 故障转移',
    balance: '⚖️ 负载均衡',
    overseas: '🌍 国外网站',
    media: '🎬 流媒体',
    ai: '🤖 AI 服务',
    telegram: '📲 电报消息',
    microsoft: '🪟 微软服务',
    github: '🐙 GitHub',
    apple: '🍎 苹果服务',
    cn: '🇨🇳 国内网站',
    ads: '🛑 广告拦截',
    direct: '🎯 全球直连',
    final: '🐟 漏网之鱼'
  },

  // ---------- 自定义规则（会放在所有内置规则之前，优先级最高） ----------
  // 写法与 config.yaml 的 rules 完全一致，最后一行不要写 MATCH。
  extraRules: [
    // 'DOMAIN-SUFFIX,example.com,DIRECT',
    // 'IP-CIDR,10.10.10.0/24,DIRECT,no-resolve',
  ],
  extraDirectDomains: [],        // 例：['my-nas.example.com']
  extraProxyDomains: [],         // 例：['some-blocked-site.com']
  extraRejectDomains: [],        // 例：['ads.example.com']

  // ---------- GEOSITE 兜底类别 ----------
  // 若你的 geosite.dat 不含某个类别，内核会报「can't find geosite」，删掉对应项即可。
  useGeosite: true,
  geositeAds: ['category-ads-all'],
  geositeCn: ['cn', 'private'],
  geositeOverseas: ['geolocation-!cn'],
  geositeTelegram: ['telegram'],
  geositeAi: ['openai'],
  // 只保留各版本 geosite.dat 必然存在的类别；需要更多可自行加 spotify / disney / hulu 等
  geositeMedia: ['netflix', 'youtube'],
  geositeApple: ['apple'],
  // 微软 / GitHub 默认只用域名规则；确认你的 geosite.dat 含这两个类别时可填 ['microsoft'] / ['github']
  geositeMicrosoft: [],
  geositeGithub: [],

  // ---------- 微软 / GitHub 分流组 ----------
  // 组类型：'select'(手动选择的分流组) / 'url-test'(自动测速选节点) / 'fallback' / 'load-balance'
  // 换成 url-test 等类型时，组内放全部真实节点并使用上面的健康检查地址。
  microsoftGroupType: 'select',
  githubGroupType: 'select',
  microsoftDirectFirst: true,    // 微软服务默认直连（OneDrive / Office 可手动切代理）
  githubDirectFirst: false,      // GitHub 默认走代理
  microsoftDomains: [
    'microsoft.com', 'microsoftonline.com', 'office.com', 'office.net', 'office365.com',
    'outlook.com', 'live.com', 'live.net', 'hotmail.com', 'msn.com',
    'bing.com', 'bing.net', 'azure.com', 'azure.net', 'azureedge.net',
    'windows.com', 'windows.net', 'windowsupdate.com', 'msftconnecttest.com', 'msftncsi.com',
    'msauth.net', 'msftauth.net', 'onedrive.com', '1drv.ms', 'sharepoint.com',
    'svc.ms', 'sfx.ms', 'msecnd.net', 'xbox.com', 'xboxlive.com',
    'skype.com', 'visualstudio.com', 'vsassets.io', 'vscode.dev'
  ],
  githubDomains: [
    'github.com', 'githubusercontent.com', 'github.io', 'githubassets.com',
    'githubapp.com', 'github.blog', 'githubstatus.com', 'githubcopilot.com',
    'github.dev', 'github.net', 'ghcr.io', 'git.io'
  ]
};

// 按地区自动分组时的关键字（enableRegionGroups = true 时生效）
var REGIONS = [
  { name: '🇭🇰 香港节点', keys: ['香港', 'HK', 'HongKong', 'Hong Kong', '🇭🇰'] },
  { name: '🇹🇼 台湾节点', keys: ['台湾', 'TW', 'Taiwan', 'Taipei', '🇹🇼'] },
  { name: '🇸🇬 新加坡节点', keys: ['新加坡', 'SG', 'Singapore', '狮城', '🇸🇬'] },
  { name: '🇯🇵 日本节点', keys: ['日本', 'JP', 'Japan', 'Tokyo', '东京', '🇯🇵'] },
  { name: '🇺🇸 美国节点', keys: ['美国', 'US', 'USA', 'United States', 'Los Angeles', '硅谷', '🇺🇸'] },
  { name: '🇬🇧 英国节点', keys: ['英国', 'UK', 'GB', 'London', '伦敦', '🇬🇧'] },
  { name: '🇰🇷 韩国节点', keys: ['韩国', 'KR', 'Korea', '首尔', '🇰🇷'] },
  { name: '🇩🇪 德国节点', keys: ['德国', 'DE', 'Germany', '法兰克福', '🇩🇪'] }
];

// ACL4SSR 规则集（确认存在的官方路径）
var ACL_BASE = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/';

// -----------------------------------------------------------------------------
// 2. 工具函数（ES5）
// -----------------------------------------------------------------------------
function log(msg) {
  if (CFG.debug && typeof console !== 'undefined' && console && console.log) {
    try { console.log('[mihomo-override] ' + msg); } catch (e) {}
  }
}

function isArray(a) {
  return Object.prototype.toString.call(a) === '[object Array]';
}

function merge(dst, src) {
  if (!src) return dst;
  for (var k in src) {
    if (Object.prototype.hasOwnProperty.call(src, k)) dst[k] = src[k];
  }
  return dst;
}

function copyArray(a) {
  return isArray(a) ? a.slice(0) : [];
}

function domainRules(list, policy, prefix) {
  var out = [];
  if (!isArray(list)) return out;
  for (var i = 0; i < list.length; i++) {
    out.push(prefix + ',' + list[i] + ',' + policy);
  }
  return out;
}

function geositeRules(list, policy) {
  return domainRules(list, policy, 'GEOSITE');
}

// 把 Sub-Store 可能传入的各种形态统一成配置对象
function normalize(config) {
  if (isArray(config)) return { proxies: config };
  if (typeof config === 'string') {
    var parser = null;
    var parserThis = null;
    try {
      if (typeof $utils !== 'undefined' && $utils && $utils.yaml) {
        if (typeof $utils.yaml.parse === 'function') { parser = $utils.yaml.parse; parserThis = $utils.yaml; }
        else if (typeof $utils.yaml.load === 'function') { parser = $utils.yaml.load; parserThis = $utils.yaml; }
      }
      if (!parser && typeof YAML !== 'undefined' && YAML && typeof YAML.parse === 'function') {
        parser = YAML.parse; parserThis = YAML;
      }
    } catch (e) {}
    if (parser) {
      var obj = parser.call(parserThis, config);
      if (obj && typeof obj === 'object') return obj;
    }
    throw new Error('[mihomo-override] 收到的是文本而非配置对象；请把脚本添加到「文件/组合订阅」的脚本操作中，并确认输出格式为 Mihomo/Clash。');
  }
  if (!config || typeof config !== 'object') return {};
  return config;
}

// -----------------------------------------------------------------------------
// 2.1 参数系统：Sub-Store 的 $arguments（脚本链接 # 参数）→ 覆盖 CFG
// -----------------------------------------------------------------------------
// 短别名（键一律小写）；未列出的参数按 CFG 同名键匹配，大小写不敏感
var PARAM_ALIAS = {
  'allowregion': 'enableRegionGroups',
  'region': 'enableRegionGroups',
  'allowfallback': 'enableFallbackGroup',
  'allowbalance': 'enableLoadBalance',
  'loadbalance': 'enableLoadBalance',
  'tun': 'tunEnable',
  'remoterules': 'useRemoteRuleSets'
};

var CFG_DEFAULTS = null;

function cloneCfgValue(v) {
  return isArray(v) ? v.slice(0) : v;
}

function snapshotCfg() {
  if (CFG_DEFAULTS) return;
  CFG_DEFAULTS = {};
  for (var k in CFG) {
    if (Object.prototype.hasOwnProperty.call(CFG, k)) CFG_DEFAULTS[k] = cloneCfgValue(CFG[k]);
  }
}

function resetCfg() {
  snapshotCfg();
  for (var k in CFG_DEFAULTS) {
    if (Object.prototype.hasOwnProperty.call(CFG_DEFAULTS, k)) CFG[k] = cloneCfgValue(CFG_DEFAULTS[k]);
  }
}

function parseQuery(text) {
  var out = {};
  var s = String(text).replace(/^[?#&]+/, '');
  var parts = s.split('&');
  for (var i = 0; i < parts.length; i++) {
    if (!parts[i]) continue;
    var eq = parts[i].indexOf('=');
    var key, val;
    if (eq < 0) {
      key = parts[i];
      val = true;                       // #allowregion 等价于 true
    } else {
      key = parts[i].slice(0, eq);
      var raw = parts[i].slice(eq + 1).replace(/\+/g, ' ');
      try { val = decodeURIComponent(raw); } catch (e) { val = raw; }
    }
    key = String(key).replace(/^\s+|\s+$/g, '');
    if (typeof val === 'string') val = val.replace(/^\s+|\s+$/g, '');
    if (key) out[key] = val;
  }
  return out;
}

function toArgObject(value) {
  if (!value) return {};
  if (typeof value === 'string') {
    var s = value.replace(/^\s+|\s+$/g, '');
    if (s.charAt(0) === '{') {
      try {
        var obj = JSON.parse(s);
        return obj && typeof obj === 'object' ? obj : {};
      } catch (e) { return {}; }
    }
    return parseQuery(s);
  }
  if (typeof value === 'object') return value;
  return {};
}

// 用 typeof 保护未注入的全局变量，避免在某些沙箱里直接引用报 ReferenceError
function readGlobal(name) {
  try {
    if (name === '$arguments' && typeof $arguments !== 'undefined') return $arguments;
    if (name === '$options' && typeof $options !== 'undefined') return $options;
  } catch (e) {}
  return null;
}

function castValue(raw, old) {
  if (typeof raw === 'boolean') return raw;
  var s = String(raw);
  var low = s.toLowerCase();
  if (typeof old === 'boolean') {
    return low === 'true' || low === '1' || low === 'yes' || low === 'on' || low === '';
  }
  if (typeof old === 'number') {
    if (/^\d+$/.test(s)) return parseInt(s, 10);
    if (s === '*' || /^[\d\/\-]+$/.test(s)) return s; // expected-status 支持 200/302 等
    return old;
  }
  if (isArray(old)) return s === '' ? [] : s.split('|');
  return s;
}

function applyArguments(context) {
  resetCfg(); // 同一沙箱多次执行时，避免上一次的参数残留

  var args = {};
  merge(args, toArgObject(readGlobal('$options')));
  if (context && typeof context === 'object') {
    merge(args, toArgObject(context.$arguments || context.args || context.query || context.params || context));
  }
  merge(args, toArgObject(readGlobal('$arguments'))); // 脚本链接 # 参数，优先级最高

  var keyMap = {};
  for (var k in CFG) {
    if (Object.prototype.hasOwnProperty.call(CFG, k)) keyMap[k.toLowerCase()] = k;
  }

  var applied = [];
  var ignored = [];
  for (var name in args) {
    if (!Object.prototype.hasOwnProperty.call(args, name)) continue;
    var raw = args[name];
    var low = String(name).toLowerCase();
    var target = PARAM_ALIAS[low] || keyMap[low];
    if (!target || !Object.prototype.hasOwnProperty.call(CFG, target) ||
        (raw && typeof raw === 'object') ||
        (CFG[target] && typeof CFG[target] === 'object' && !isArray(CFG[target]))) {
      ignored.push(name);
      continue;
    }
    CFG[target] = castValue(raw, CFG[target]);
    applied.push(name + ' -> ' + target + '=' + CFG[target]);
  }
  if (applied.length) log('应用参数: ' + applied.join(', '));
  if (ignored.length) log('忽略 ' + ignored.length + ' 个无关参数: ' + ignored.slice(0, 5).join(', '));
  return applied;
}

// -----------------------------------------------------------------------------
// 3. 各部分配置生成
// -----------------------------------------------------------------------------
function applyGeneral(config) {
  config['mode'] = CFG.mode;
  config['mixed-port'] = CFG.mixedPort;
  config['allow-lan'] = CFG.allowLan;
  config['log-level'] = CFG.logLevel;
  config['ipv6'] = CFG.ipv6;
  config['unified-delay'] = CFG.unifiedDelay;
  config['tcp-concurrent'] = CFG.tcpConcurrent;
  config['geodata-mode'] = CFG.geodataMode;
  config['geo-auto-update'] = CFG.geoAutoUpdate;
  config['geo-update-interval'] = CFG.geoUpdateInterval;
  config['profile'] = { 'store-selected': true, 'store-fake-ip': CFG.dnsMode === 'fake-ip' };

  // 订阅常带的 http/socks 端口会和 mixed-port 抢同一个端口，直接清掉
  delete config['port'];
  delete config['socks-port'];
  // redir / tproxy 端口与 mixed-port 不冲突，按需开启或保留订阅原有值
  if (CFG.redirPort) config['redir-port'] = CFG.redirPort;
  else if (!config['redir-port']) delete config['redir-port'];
  if (CFG.tproxyPort) config['tproxy-port'] = CFG.tproxyPort;
  else if (!config['tproxy-port']) delete config['tproxy-port'];

  if (CFG.externalController) {
    config['external-controller'] = CFG.externalController;
    if (CFG.secret) config['secret'] = CFG.secret;
    if (CFG.externalUI) config['external-ui'] = CFG.externalUI;
  } else {
    delete config['external-controller'];
    delete config['secret'];
    delete config['external-ui'];
  }
}

function buildDns() {
  var dns = {
    'enable': true,
    'ipv6': CFG.ipv6,
    'enhanced-mode': CFG.dnsMode,
    'prefer-h3': CFG.preferH3,
    'respect-rules': CFG.respectRules,
    'use-hosts': true,
    'use-system-hosts': true,
    'cache-algorithm': 'arc',
    'default-nameserver': copyArray(CFG.defaultNameserver),
    'nameserver': copyArray(CFG.domesticDns),
    'proxy-server-nameserver': copyArray(CFG.proxyServerNameserver),
    'direct-nameserver': copyArray(CFG.directNameserver),
    'fallback': copyArray(CFG.fallbackDns),
    'fallback-filter': {
      'geoip': true,
      'geoip-code': 'CN',
      'ipcidr': ['240.0.0.0/4', '0.0.0.0/32', '127.0.0.1/32', '100.64.0.0/10']
    }
  };

  if (CFG.dnsMode === 'fake-ip') {
    dns['fake-ip-range'] = CFG.fakeIpRange;
    dns['fake-ip-filter'] = [
      '*.lan', '*.local', 'localhost', '+.arpa',
      '+.msftconnecttest.com', '+.msftncsi.com', 'dns.msftncsi.com',
      '+.pool.ntp.org', '+.ntp.org', '+.router', '+.mi.com'
    ];
  }
  return dns;
}

function buildSniffer() {
  return {
    'enable': true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,
    'override-destination': CFG.snifferOverrideDestination,
    'sniff': {
      'TLS': { 'ports': [443, 8443] },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443] }
    },
    'skip-domain': ['Mijia Cloud', '+.msftconnecttest.com']
  };
}

function buildTun() {
  return {
    'enable': true,
    'stack': CFG.tunStack,
    'auto-route': true,
    'auto-redirect': CFG.tunAutoRedirect,
    'auto-detect-interface': true,
    'dns-hijack': ['any:53', 'tcp://any:53'],
    'strict-route': CFG.tunStrictRoute,
    'mtu': CFG.tunMtu,
    'route-exclude-address': [
      '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '169.254.0.0/16', 'fc00::/7'
    ]
  };
}

// 过滤假节点 + 去重
function cleanProxies(proxies) {
  var adRe = CFG.filterAds && CFG.excludeNameRegex ? new RegExp(CFG.excludeNameRegex, 'i') : null;
  var out = [];
  for (var i = 0; i < proxies.length; i++) {
    var p = proxies[i];
    if (!p || typeof p !== 'object' || !p.name) continue;
    if (CFG.excludeTypes.indexOf(String(p.type || '').toLowerCase()) !== -1) continue;
    if (adRe && adRe.test(p.name)) continue;
    out.push(p);
  }
  if (CFG.dedupe) {
    var seen = {};
    for (var j = 0; j < out.length; j++) {
      var name = String(out[j].name);
      if (seen[name]) {
        var n = 2;
        while (seen[name + ' ' + n]) n++;
        out[j].name = name + ' ' + n;
        seen[name + ' ' + n] = true;
      } else {
        seen[name] = true;
      }
    }
  }
  return out;
}

// 两位字母的地区代码用词边界匹配，避免 "AUSTRALIA" 被误判成 "US"
function matchRegion(name, key) {
  var n = String(name).toUpperCase();
  var k = String(key).toUpperCase();
  if (/^[A-Z]{2}$/.test(k)) {
    return new RegExp('(^|[^A-Z])' + k + '([^A-Z]|$)').test(n);
  }
  return n.indexOf(k) !== -1;
}

function makeGroup(type, name, proxies, providerNames, extra) {
  var g = { 'name': name, 'type': type, 'proxies': proxies };
  if (providerNames.length) g['use'] = providerNames; // 订阅用 proxy-providers 时也能引用
  if (extra) merge(g, extra);
  return g;
}

function buildRegionGroups(names, providerNames) {
  var groups = [];
  var used = {};
  for (var i = 0; i < REGIONS.length; i++) {
    var members = [];
    for (var j = 0; j < names.length; j++) {
      if (used[names[j]]) continue; // 一个节点只进一个地区组
      for (var k = 0; k < REGIONS[i].keys.length; k++) {
        var key = REGIONS[i].keys[k];
        if (matchRegion(names[j], key)) {
          members.push(names[j]);
          used[names[j]] = true;
          break;
        }
      }
    }
    if (members.length) {
      members.push('DIRECT');
      groups.push(makeGroup('select', REGIONS[i].name, members, providerNames));
    }
  }
  return groups;
}

function buildGroups(names, providerNames) {
  var G = CFG.groups;
  var groups = [];
  var regionGroups = CFG.enableRegionGroups ? buildRegionGroups(names, providerNames) : [];
  var regionNames = [];
  for (var i = 0; i < regionGroups.length; i++) regionNames.push(regionGroups[i].name);

  var health = {
    'url': CFG.testUrl,
    'interval': CFG.testInterval,
    'tolerance': CFG.testTolerance,
    'expected-status': CFG.testStatus
  };

  // 自动测速 / 故障转移 / 负载均衡：只放真实节点
  var autoMembers = copyArray(names);
  groups.push(makeGroup('url-test', G.auto, autoMembers, providerNames, health));
  if (CFG.enableFallbackGroup) {
    groups.push(makeGroup('fallback', G.fallback, copyArray(names), providerNames, {
      'url': CFG.testUrl,
      'interval': CFG.testInterval,
      'expected-status': CFG.testStatus
    }));
  }
  if (CFG.enableLoadBalance) {
    groups.push(makeGroup('load-balance', G.balance, copyArray(names), providerNames, {
      'url': CFG.testUrl,
      'interval': CFG.testInterval,
      'expected-status': CFG.testStatus,
      'strategy': 'consistent-hashing'
    }));
  }

  // 主选择组
  var mainMembers = [G.auto];
  if (CFG.enableFallbackGroup) mainMembers.push(G.fallback);
  if (CFG.enableLoadBalance) mainMembers.push(G.balance);
  mainMembers = mainMembers.concat(regionNames, copyArray(names), ['DIRECT']);
  groups.push(makeGroup('select', G.proxy, mainMembers, providerNames));

  // 地区组（放在主组之后，避免引用尚未定义的组）
  groups = groups.concat(regionGroups);

  // 分流组：引用主组，界面清爽；想直接选节点可在 includeAllProxies 处加 names
  function sub(name, extraMembers, directFirst) {
    var m = [G.proxy, G.auto].concat(extraMembers || []);
    if (CFG.enableFallbackGroup) m.splice(2, 0, G.fallback);
    if (directFirst) m = ['DIRECT'].concat(m); // 苹果 / 国内服务默认直连
    groups.push(makeGroup('select', name, m, providerNames));
  }
  // 微软 / GitHub 组默认是 select 分流组；把类型改成 url-test / fallback / load-balance
  // 即可变成「按健康检查自动选节点」的测试组，组内放全部真实节点。
  function serviceGroup(name, type, directFirst) {
    if (type === 'url-test' || type === 'fallback' || type === 'load-balance') {
      var extra = {
        'url': CFG.testUrl,
        'interval': CFG.testInterval,
        'expected-status': CFG.testStatus
      };
      if (type === 'url-test') extra['tolerance'] = CFG.testTolerance;
      if (type === 'load-balance') extra['strategy'] = 'consistent-hashing';
      groups.push(makeGroup(type, name, copyArray(names), providerNames, extra));
    } else {
      sub(name, [G.overseas, 'DIRECT'], directFirst);
    }
  }

  sub(G.overseas, ['DIRECT']);
  sub(G.media, [G.overseas, 'DIRECT']);
  sub(G.ai, [G.overseas, 'DIRECT']);
  sub(G.telegram, [G.overseas, 'DIRECT']);
  serviceGroup(G.microsoft, CFG.microsoftGroupType, CFG.microsoftDirectFirst);
  serviceGroup(G.github, CFG.githubGroupType, CFG.githubDirectFirst);
  sub(G.apple, [G.overseas], true);
  sub(G.cn, [G.overseas], true);
  groups.push(makeGroup('select', G.ads, ['REJECT', 'DIRECT', G.proxy], providerNames));
  groups.push(makeGroup('select', G.direct, ['DIRECT', G.proxy], providerNames));
  sub(G.final, ['DIRECT']);

  return groups;
}

function buildRuleProviders() {
  var G = CFG.groups;
  var proxy = CFG.ruleSetDownloadProxy === 'DIRECT' ? 'DIRECT' : G.proxy;
  var defs = {
    'unban': 'UnBan.yaml',
    'lan': 'LocalAreaNetwork.yaml',
    'ads': 'BanAD.yaml',
    'apple': 'Apple.yaml',
    'cn-domain': 'ChinaDomain.yaml',
    'cn-ip': 'ChinaIp.yaml',
    'media': 'ProxyMedia.yaml',
    'gfw': 'ProxyGFWlist.yaml'
  };
  var providers = {};
  for (var key in defs) {
    if (!Object.prototype.hasOwnProperty.call(defs, key)) continue;
    providers[key] = {
      'type': 'http',
      'url': ACL_BASE + defs[key],
      'behavior': 'classical',
      'format': 'yaml',
      'interval': CFG.ruleSetInterval,
      'proxy': proxy
    };
  }
  return providers;
}

function buildRules() {
  var G = CFG.groups;
  var r = [];

  // 0. 用户自定义规则（优先级最高）
  r = r.concat(copyArray(CFG.extraRules));
  r = r.concat(domainRules(CFG.extraDirectDomains, 'DIRECT', 'DOMAIN-SUFFIX'));
  r = r.concat(domainRules(CFG.extraProxyDomains, G.proxy, 'DOMAIN-SUFFIX'));
  r = r.concat(domainRules(CFG.extraRejectDomains, G.ads, 'DOMAIN-SUFFIX'));

  // 1. 放行 / 局域网直连
  if (CFG.useRemoteRuleSets) {
    r.push('RULE-SET,unban,DIRECT');
    r.push('RULE-SET,lan,DIRECT');
  }
  r.push('DOMAIN-SUFFIX,lan,DIRECT');
  r.push('DOMAIN-SUFFIX,local,DIRECT');
  r.push('DOMAIN-SUFFIX,localhost,DIRECT');
  r.push('IP-CIDR,127.0.0.0/8,DIRECT,no-resolve');
  r.push('IP-CIDR,192.168.0.0/16,DIRECT,no-resolve');
  r.push('IP-CIDR,10.0.0.0/8,DIRECT,no-resolve');
  r.push('IP-CIDR,172.16.0.0/12,DIRECT,no-resolve');
  r.push('IP-CIDR,100.64.0.0/10,DIRECT,no-resolve');
  r.push('IP-CIDR,224.0.0.0/4,DIRECT,no-resolve');
  r.push('IP-CIDR6,::1/128,DIRECT,no-resolve');
  r.push('IP-CIDR6,fc00::/7,DIRECT,no-resolve');

  // 2. 广告拦截
  if (CFG.useRemoteRuleSets) r.push('RULE-SET,ads,' + G.ads);
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeAds, G.ads));

  // 3. 需要优先分流的特定服务（放在国内直连 / 大范围规则之前）
  var aiDomains = [
    'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com',
    'anthropic.com', 'claude.ai', 'claude.com', 'perplexity.ai',
    'poe.com', 'midjourney.com', 'x.ai', 'grok.com', 'huggingface.co'
  ];
  r = r.concat(domainRules(aiDomains, G.ai, 'DOMAIN-SUFFIX'));
  r.push('DOMAIN-SUFFIX,gemini.google.com,' + G.ai);
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeAi, G.ai));

  var tgIps = [
    '91.108.4.0/22', '91.108.8.0/22', '91.108.12.0/22', '91.108.16.0/22',
    '91.108.56.0/22', '109.239.140.0/24', '149.154.160.0/20', '95.161.64.0/20'
  ];
  r = r.concat(domainRules(tgIps, G.telegram, 'IP-CIDR'));
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeTelegram, G.telegram));

  if (CFG.useRemoteRuleSets) r.push('RULE-SET,media,' + G.media);
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeMedia, G.media));

  if (CFG.useRemoteRuleSets) r.push('RULE-SET,apple,' + G.apple);
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeApple, G.apple));

  // 微软 / GitHub 分流（必须排在国内直连与 geolocation-!cn 兜底之前）
  r = r.concat(domainRules(CFG.microsoftDomains, G.microsoft, 'DOMAIN-SUFFIX'));
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeMicrosoft, G.microsoft));
  r = r.concat(domainRules(CFG.githubDomains, G.github, 'DOMAIN-SUFFIX'));
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeGithub, G.github));

  // 4. 国内直连
  if (CFG.useRemoteRuleSets) {
    r.push('RULE-SET,cn-domain,DIRECT');
    r.push('RULE-SET,cn-ip,DIRECT');
  }
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeCn, G.cn));

  // 5. 境外走代理；GFW 列表放在兜底 geolocation-!cn 之前
  if (CFG.useRemoteRuleSets) r.push('RULE-SET,gfw,' + G.overseas);
  if (CFG.useGeosite) r = r.concat(geositeRules(CFG.geositeOverseas, G.overseas));

  // 6. 纯 IP 流量
  r.push('GEOIP,private,DIRECT,no-resolve');
  r.push('GEOIP,CN,DIRECT,no-resolve');

  // 7. 兜底（务必保持在最后一行）
  r.push('MATCH,' + G.final);
  return r;
}

// -----------------------------------------------------------------------------
// 4. 入口：Sub-Store 调用 main(config)，必须返回配置对象
// -----------------------------------------------------------------------------
function main(config, context) {
  applyArguments(context); // 每次执行都重新解析 $arguments，参数优先于 CFG 默认值
  var c = normalize(config);

  // 节点处理
  var proxies = cleanProxies(isArray(c.proxies) ? c.proxies : []);
  c.proxies = proxies;
  var names = [];
  for (var i = 0; i < proxies.length; i++) names.push(proxies[i].name);

  var providerObj = c['proxy-providers'];
  var providerNames = providerObj && typeof providerObj === 'object' ? Object.keys(providerObj) : [];

  // 基础配置
  applyGeneral(c);
  if (CFG.dnsEnable && CFG.dnsMode !== 'off') c.dns = buildDns();
  else delete c.dns;

  if (CFG.snifferEnable) c.sniffer = buildSniffer();
  else delete c.sniffer;

  if (CFG.tunEnable) c.tun = buildTun();
  else delete c.tun;

  // 没有任何可用节点时，不动订阅原有的策略组和规则，避免生成坏配置
  if (names.length === 0 && providerNames.length === 0) {
    log('未发现可用节点，仅覆写基础/DNS/嗅探配置，保留原有 proxy-groups 与 rules');
    return c;
  }

  c['proxy-groups'] = buildGroups(names, providerNames);

  if (CFG.useRemoteRuleSets) c['rule-providers'] = buildRuleProviders();
  else delete c['rule-providers'];

  c.rules = buildRules();

  log('nodes=' + names.length +
      ' providers=' + providerNames.length +
      ' groups=' + c['proxy-groups'].length +
      ' rules=' + c.rules.length +
      ' dns=' + CFG.dnsMode +
      ' tun=' + CFG.tunEnable +
      ' region=' + CFG.enableRegionGroups +
      ' fallback=' + CFG.enableFallbackGroup +
      ' balance=' + CFG.enableLoadBalance +
      ' test=' + CFG.testUrl);
  return c;
}
