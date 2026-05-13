// LIDO Briefing Cloudflare Worker
// 處理 LIDO 登入、Session 管理、API Proxy

const LIDO_BASE = 'https://sjx.lido.aero';
const LIDO_LOGIN_URL = `${LIDO_BASE}/lido/las/login.jsp`;
const LIDO_DWR_URL = `${LIDO_BASE}/lido/las/dwr/call/plaincall/LoginBean.login.dwr`;
const LIDO_API_BASE = `${LIDO_BASE}/lido/lcb/ui`;

// 允許的 CORS 來源
const ALLOWED_ORIGINS = [
  'https://karsten77114.github.io',
  'http://localhost',
  'http://127.0.0.1'
];

function corsHeaders(origin) {
  // file:// 頁面送出的 origin 是字串 "null"，直接允許（個人工具，安全無虞）
  if (!origin || origin === 'null') {
    return {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    };
  }
  const allowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o));
  return {
    'Access-Control-Allow-Origin': allowed ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function generateUUID() {
  let t, n;
  for (n = t = ''; t++ < 36; n += 51*t&52 ? (15^t ? 8^Math.random()*(20^t ? 16 : 4) : 4).toString(16) : '-');
  return n;
}

// 從 Set-Cookie header 解析特定 cookie 值
function parseCookieValue(setCookieHeaders, cookieName) {
  if (!setCookieHeaders) return null;
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const h of headers) {
    const match = h.match(new RegExp(`${cookieName}=([^;]+)`));
    if (match) return match[1];
  }
  return null;
}

// Step 1: 取得初始 LIDO session cookie
async function getLidoSession() {
  const resp = await fetch(
    `${LIDO_LOGIN_URL}?DESMON_RESULT_PAGE=https%3A%2F%2Fsjx.lido.aero%2Flido%2Fshell%2F%23lcb&DESMON_LANG=en`,
    { redirect: 'follow' }
  );

  // 從 Set-Cookie 取 lido_las
  const setCookie = resp.headers.get('set-cookie') || '';
  const lidoLas = parseCookieValue([setCookie], 'lido_las');
  const serverid = parseCookieValue([setCookie], 'las_serverid') || 'docker1';

  if (!lidoLas) throw new Error('Failed to get lido_las session cookie');
  return { lidoLas, serverid };
}

// 解碼 lido_csrf cookie（base64 JSON），取出 csrf_id 和 uid
function decodeLidoCsrf(lidoCsrf) {
  try {
    const decoded = JSON.parse(atob(lidoCsrf));
    return { csrfId: decoded.csrf_id || lidoCsrf, uid: decoded.uid || null, env: decoded.env || null };
  } catch(e) {
    return { csrfId: lidoCsrf, uid: null, env: null };
  }
}

// 解碼 JWT payload（base64url → JSON）
function decodeJwtPayload(jwt) {
  if (!jwt) return null;
  try {
    const parts = jwt.split('.');
    if (parts.length < 2) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    return JSON.parse(atob(padded));
  } catch(e) {
    return null;
  }
}

// Step 2: DWR 登入
async function dwrLogin(userId, password, lidoLas, serverid) {
  const scriptSessionId = generateUUID().replace(/-/g, '').toUpperCase().substring(0, 16) +
    '/' + generateUUID().replace(/-/g, '').toUpperCase().substring(0, 16);

  const dwrBody = [
    'callCount=1',
    'page=%2Flido%2Flas%2Flogin.jsp%3FDESMON_RESULT_PAGE%3Dhttps%253A%252F%252Fsjx.lido.aero%252Flido%252Fshell%252F%2523lcb%26DESMON_LANG%3Den',
    `httpSessionId=${lidoLas}`,
    `scriptSessionId=${encodeURIComponent(scriptSessionId)}`,
    'instanceId=0',
    'batchId=0',
    'c0-scriptName=LoginBean',
    'c0-methodName=login',
    'c0-id=0',
    `c0-param0=string:${userId}`,
    `c0-param1=string:${password}`,
    'c0-param2=string:',
    'c0-param3=string:LIDO',
    'c0-param4=string:en',
  ].join('\n');

  const resp = await fetch(LIDO_DWR_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Cookie': `lido_las=${lidoLas}; las_serverid=${serverid}`,
    },
    body: dwrBody,
  });

  const text = await resp.text();

  // 檢查登入失敗：只有 errorCode 不是 null 才算失敗
  const errorCodeMatch = text.match(/errorCode:([^,}\s]+)/);
  const errorCode = errorCodeMatch ? errorCodeMatch[1].trim() : null;
  if (errorCode && errorCode !== 'null') {
    const errMatch = text.match(/errorMessage2:"([^"]+)"/) ||
                     text.match(/errorMessage1:"([^"]+)"/) ||
                     text.match(/warningMessage:"([^"]+)"/);
    throw new Error(errMatch ? errMatch[1] : `LIDO error: ${errorCode}`);
  }

  // 從 response 取 cookies（login 成功時設 lido_auth + lido_csrf）
  const setCookie = resp.headers.get('set-cookie') || '';
  const lidoCsrf  = parseCookieValue([setCookie], 'lido_csrf');
  const lidoAuth  = parseCookieValue([setCookie], 'lido_auth');
  const newLidoLas = parseCookieValue([setCookie], 'lido_las') || lidoLas;

  if (!lidoCsrf) throw new Error('Login succeeded but no lido_csrf cookie returned');

  // 解碼 csrf cookie 取 csrfId + uid
  const { csrfId, uid, env } = decodeLidoCsrf(lidoCsrf);

  // 解碼 JWT 取 businessId
  const jwtPayload = decodeJwtPayload(lidoAuth);
  const businessId = jwtPayload?.businessId || jwtPayload?.business_id ||
    jwtPayload?.customerId || jwtPayload?.customer_id ||
    jwtPayload?.organizationId || jwtPayload?.org ||
    uid || userId;

  return { lidoCsrf, csrfId, uid: uid || userId, businessId, env, lidoAuth, lidoLas: newLidoLas, serverid, jwtPayload };
}

// 建立 LIDO API request headers
// businessId 依呼叫類型傳入：主 briefing = "GetBriefing"，文件 = "GetDoc{TYPE}"
function buildLidoHeaders(session, businessId) {
  const { lidoCsrf, lidoLas, serverid, lidoAuth } = session;
  const cookieParts = [`lido_las=${lidoLas}`, `lido_csrf=${lidoCsrf}`, `las_serverid=${serverid}`];
  if (lidoAuth) cookieParts.push(`lido_auth=${lidoAuth}`);
  return {
    'Cookie': cookieParts.join('; '),
    'X-lido-csrf': lidoCsrf,          // 完整 base64 cookie（Angular 確認）
    'X-lido-auth': 'LAS',             // 固定 LAS
    'X-lido-businessId': businessId || 'GetBriefing',
    'X-lido-clientId': 'lido-lcb-ui',
    'X-lido-applicationId': 'lido-lcb',
    'X-lido-customerId': 'LSY',
    'X-lido-authkey': '',             // 空字串（Angular 確認）
    'X-lido-operatingAirline': '',    // 空字串（Angular 確認）
    'X-lido-traceId': generateUUID(),
    'X-lido-timeStamp': new Date().toISOString(),
    'Accept': 'application/vnd.lsy.lido.lcb.v1.hal+json',
    'Accept-Language': 'en',
  };
}

// 組合 leg ID：JX.850.28Apr2026.TPE.CTS.
function buildLegId(flightNum, dateStr, dep, dest) {
  // dateStr 格式: YYYYMMDD → DDMmmYYYY
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const d = new Date(dateStr.substring(0,4), parseInt(dateStr.substring(4,6))-1, parseInt(dateStr.substring(6,8)));
  const dd = String(d.getDate()).padStart(2,'0');
  const mmm = months[d.getMonth()];
  const yyyy = d.getFullYear();
  return `JX.${flightNum}.${dd}${mmm}${yyyy}.${dep}.${dest}.`;
}

// 取得飛行清單（用 /flightlist 端點 + flightNumber 搜尋 legId）
// 回傳：{ legId, dep, dest } 或 null
async function fetchFlightList(flightNum, dateStr, session) {
  // YYYYMMDD → YYYY-MM-DD
  const datePart = `${dateStr.slice(0,4)}-${dateStr.slice(4,6)}-${dateStr.slice(6,8)}`;
  const startDT = `${datePart}T00:00:00.000Z`;
  const endDT   = `${datePart}T23:59:59.000Z`;
  const url = `${LIDO_API_BASE}/flightlist?startDateTime=${startDT}&endDateTime=${endDT}`;

  const headers = buildLidoHeaders(session, 'GetFlightList');
  const resp = await fetch(url, { headers });
  if (!resp.ok) return null;

  const data = await resp.json();
  // 回傳值是陣列（或類陣列物件）
  const flights = Array.isArray(data) ? data : Object.values(data);

  // 完全匹配班號
  const matches = flights.filter(f => f.flightNumber === String(flightNum));
  if (matches.length === 0) return null;

  // 若有多個（同班號不同航段），回傳全部讓呼叫者選擇
  return matches.map(f => ({
    legId: f.legId,
    dep: f.departureAirport,
    dest: f.destinationAirport,
    std: f.std,
    flightNumber: f.flightNumber,
  }));
}

// 取得 Briefing 資料
async function fetchBriefingData(legId, headers) {
  const resp = await fetch(`${LIDO_API_BASE}/${legId}/briefing`, { headers });
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Briefing fetch failed: ${resp.status} - ${errText.substring(0, 200)}`);
  }
  return resp.json();
}

// 從 LIDO briefing JSON 解析結構化資料
// 回傳: { leg, files: {OFP, ATS, NOTAM, ...}, times, fuel, weight, aircraft, route }
function parseBriefingJson(data) {
  const pkg = data?.briefingPackages?.[0];
  if (!pkg) return null;
  const leg = pkg.leg?.[0] || {};

  // 時刻（Unix ms → UTC 字串）
  const toUTC = ms => ms ? new Date(ms).toISOString().replace('T',' ').replace('.000Z','Z') : null;
  const toHHMM = ms => ms ? new Date(ms).toISOString().slice(11,16) + 'Z' : null;

  // 從 categories 找各類文件的 fileId（透過 _links.self.href 解析）
  // fileIds: { OFP: "uuid", UAD: "uuid-of-first-doc", ... }  (first doc per category, for text docs)
  // allDocs: { UAD: [{fileId, label, index}, ...], ... }  (ALL docs per category, for charts)
  const fileIds = {};
  const allDocs = {};
  for (const cat of pkg.categories || []) {
    const docs = cat.documents || [];
    if (!docs.length) continue;
    allDocs[cat.name] = [];
    for (let i = 0; i < docs.length; i++) {
      const doc = docs[i];
      const href = doc._links?.self?.href || '';
      const m = href.match(/briefing\/([^/]+)\/docs/);
      if (!m) continue;
      const fileId = m[1];
      const label = doc.label || doc.name || doc.title || doc.description || String(i);
      const flightLevel = doc.metadata?.find(m => m.key === 'flightLevel')?.value || null;
      const fileName = doc.fileName || '';
      allDocs[cat.name].push({ fileId, label, flightLevel, fileName, index: i });
      if (i === 0) fileIds[cat.name] = fileId;  // keep first for text doc lookups
    }
  }

  // Extract structured alternate airports from leg object (LIDO may provide these directly)
  const legAirports = [];
  for (const key of ['alternateAirports','enrouteAlternates','weatherAirports','alternates','airports']) {
    const arr = leg[key];
    if (Array.isArray(arr)) {
      for (const a of arr) {
        const icao = typeof a === 'string' ? a : (a?.icao || a?.airportCode || a?.airport);
        if (icao && /^[A-Z]{3,4}$/.test(icao)) legAirports.push(icao);
      }
    }
  }

  return {
    legId: leg.legidentifier || leg.legId,
    flightNumber: leg.flightNumber,
    dep: leg.departureAirport,
    dest: leg.destinationAirport,
    ofpNumber: leg.ofpNumber,
    aircraft: leg.aircraftDetails,
    std: toHHMM(leg.scheduledDepartureTime),
    sta: toHHMM(leg.scheduledTimeOfArrival),
    etd: toHHMM(leg.estimatedDepartureTime),
    eta: toHHMM(leg.estimatedTimeOfArrival),
    dateOfOperation: leg.dateOfOperation,
    flightRoute: leg.flightRoute,
    fuel: leg.fuel,
    weight: leg.weight,
    fileIds,  // { OFP: "uuid", ATS: "uuid", ... }  first doc per category
    allDocs,  // { UAD: [{fileId, label, index}, ...], ... }  ALL docs per category
    legAirports,
    legKeys: Object.keys(leg),
  };
}

// 取得特定文件（OFP、ATS 等）
async function fetchDocument(legId, fileId, headers, asText = false) {
  const acceptHdr = asText ? 'text/plain, */*' : 'application/vnd.lsy.lido.lcb.v1.hal+json';
  const resp = await fetch(`${LIDO_API_BASE}/${legId}/briefing/${fileId}/docs`, {
    headers: { ...headers, Accept: acceptHdr }
  });
  if (!resp.ok) return null;
  return asText ? resp.text() : resp.json();
}

// 解析 OFP 文字
function parseOFP(txt) {
  if (!txt) return {};
  const r = {};
  let m;

  m = txt.match(/(?:SJX|JX)\s*(\d{3,4})/); if (m) r.flightNum = m[1];
  m = txt.match(/\b(\d{2}(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\d{4})\b/i); if (m) r.date = m[1].toUpperCase();
  m = txt.match(/\b(B-?\d{5}|HL\d{4}|JA\d{4})\b/); if (m) r.reg = m[1];

  // 起降機場
  m = txt.match(/FROM\s+(\w{3,4})\s+TO\s+(\w{3,4})/i);
  if (m) { r.dep = m[1]; r.dest = m[2]; }

  // 時間
  m = txt.match(/STD\s+(\d{4})L\s+(\d{4})Z/); if (m) { r.stdLocal = m[1]; r.stdUtc = m[2]+'Z'; }
  m = txt.match(/STA\s+(\d{4})L\s+(\d{4})Z/); if (m) { r.staLocal = m[1]; r.staUtc = m[2]+'Z'; }
  m = txt.match(/ETE\s+(\d+)\.(\d+)/); if (m) r.ete = m[1]+':'+m[2];

  // 飛行距離、Wind、Cost Index
  m = txt.match(/BOF\s+\w+\s+(\d+)\s+[\d.]+\s+(\d+)NM.*?W\/C\s+([PM])(\d+)/s);
  if (m) { r.tripFuel = +m[1]; r.dist = +m[2]; r.wc = (m[3]==='P'?'+':'-')+m[4]; }
  m = txt.match(/CRZ\s+CI(\d+)/i); if (m) r.ci = +m[1];

  // 備降（主 ALTN + 燃油）
  m = txt.match(/ALTN\s+(\w+)\s+(\d+)/); if (m) { r.altnApt = m[1]; r.altnFuel = +m[2]; }

  // 所有天氣機場：ALTN（多個）+ EDTO/ETP 備降場 + ERA（Enroute Alternates）
  // NOTE: Do NOT parse ICAO/IATA pairs from OFP — too many false positives (OPR/SJX, TEMP/ISA, WIND/xxx)
  //       ICAO/IATA pairs are parsed from the LIDO Weather Service text document instead.
  const wxSet = new Set();
  // Standard alternates
  for (const [, a] of txt.matchAll(/\bALTN\d*\s+([A-Z]{3,4})\b/g)) wxSet.add(a);
  // EDTO / ETP alternates
  for (const [, a] of txt.matchAll(/\bEDTO\s+(?:ALT|ALTN)\s+([A-Z]{3,4})\b/g)) wxSet.add(a);
  for (const [, a] of txt.matchAll(/\bETP\s+\d+.*?\bALT\s+([A-Z]{3,4})\b/g)) wxSet.add(a);
  // Takeoff alternates
  for (const [, a] of txt.matchAll(/\bTKOFF\s+ALTN\s+([A-Z]{3,4})\b/g)) wxSet.add(a);
  // ERA (Enroute Alternates) — LIDO formats: "ERA RJFF", "ERA1 RJFF", "ERA1-RJFF"
  for (const [, a] of txt.matchAll(/\bERA\d*[-\s]+([A-Z]{3,4})\b/g)) wxSet.add(a);
  // "ENRTE ALT RJFF" / "ENROUTE ALT RJFF" / "ENROUTE ALTERNATE RJFF"
  for (const [, a] of txt.matchAll(/\bENR(?:OUE?TE?)?\s+ALT(?:ERN(?:ATE)?)?\s+([A-Z]{3,4})\b/gi)) wxSet.add(a.toUpperCase());
  // Remove generic tokens that aren't airport codes
  ['DEST','ALTN','HOLD','FUEL','TIME','FROM','CONT','TAXI','TKOF','TKOFF','EDTO'].forEach(x => wxSet.delete(x));
  r.wxAirports = [...wxSet].filter(a => /^[A-Z]{3,4}$/.test(a));

  // 燃油明細（LIDO OFP 標準格式，含 0 值）
  const fuelLine = label => { const x = txt.match(new RegExp(label + '\\s+(\\d+)')); return x ? +x[1] : undefined; };
  r.destHoldFuel = fuelLine('DEST\\s+HOLD');
  r.finalFuel    = fuelLine('FINAL\\s+RES');
  r.wxxFuel      = fuelLine('ADD\\s+WXX');
  r.opnFuel      = fuelLine('ADD\\s+OPN');
  r.atcFuel      = fuelLine('ADD\\s+ATC');
  r.devFuel      = fuelLine('ADD\\s+DEV');
  r.critFuel     = fuelLine('CRIT\\s+FUEL');
  r.extraFuel    = fuelLine('EXTRA');
  r.tankerFuel   = fuelLine('TANKER(?:ING)?');
  m = txt.match(/^CONT\s+(\d+)/m);    if (m) r.contFuel  = +m[1];
  m = txt.match(/^TAKEOFF\s+(\d+)/m); if (m) r.toFuel    = +m[1];
  m = txt.match(/^TAXI\s+(\d+)/m);    if (m) r.taxiFuel  = +m[1];

  // 重量
  m = txt.match(/ZFW\s+([\d.]+)\s*\/\s*([\d.]+)/); if (m) { r.zfwLim = +m[1]; r.zfwPln = +m[2]; }
  m = txt.match(/TOW\s+([\d.]+)\s*\/\s*([\d.]+)/); if (m) { r.towLim = +m[1]; r.towPln = +m[2]; }
  m = txt.match(/LDW\s+([\d.]+)\s*\/\s*([\d.]+)/); if (m) { r.ldwLim = +m[1]; r.ldwPln = +m[2]; }

  return r;
}

// 解析 ATS clearance route
function parseATSRoute(txt) {
  if (!txt) return null;
  // ATS 格式通常是：DEP/SID ROUTE DEST/STAR
  const lines = txt.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  return lines.join(' ');
}

// 主 Handler
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin') || '';
  const headers = corsHeaders(origin);

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers });
  }

  try {
    // POST /auth/login — 使用者登入
    if (url.pathname === '/auth/login' && request.method === 'POST') {
      const body = await request.json();
      const userId = body.userId || env.LIDO_USER_ID;
      const password = body.password || env.LIDO_PASSWORD;

      if (!userId || !password) {
        return new Response(JSON.stringify({ error: 'Missing credentials' }), {
          status: 400, headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }

      const { lidoLas, serverid } = await getLidoSession();
      const session = await dwrLogin(userId, password, lidoLas, serverid);

      // Stateless: encode session as base64 token (no KV needed)
      const sessionToken = btoa(JSON.stringify({ ...session, ts: Date.now() }));

      return new Response(JSON.stringify({
        success: true,
        sessionToken,
        userId,
        debug: {
          csrfId: session.csrfId,
          uid: session.uid,
          businessId: session.businessId,
          jwtPayload: session.jwtPayload,
        }
      }), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // GET /api/briefing?flight=850&date=20260428&sessionToken=...
    if (url.pathname === '/api/briefing') {
      const flightNum = url.searchParams.get('flight');
      const dateStr = url.searchParams.get('date');
      const sessionToken = url.searchParams.get('sessionToken');
      const dep = url.searchParams.get('dep') || 'TPE';
      const dest = url.searchParams.get('dest') || '';
      const directLegId = url.searchParams.get('legId') || '';   // pre-resolved legId from flight table

      if (!flightNum || !dateStr) {
        return new Response(JSON.stringify({ error: 'Missing flight or date' }), {
          status: 400, headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }

      // Stateless: decode session from base64 token
      let session;
      if (sessionToken) {
        try {
          session = JSON.parse(atob(sessionToken));
        } catch(e) {
          session = null;
        }
      }

      if (!session) {
        return new Response(JSON.stringify({ error: 'Not authenticated. Please login first.' }), {
          status: 401, headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }

      // 統一日期格式：YYYYMMDD 或 YYYY-MM-DD → YYYYMMDD
      const normDate = dateStr.replace(/-/g, '');

      const briefingHeaders = buildLidoHeaders(session, 'GetBriefing');

      // 組合 legId
      let legId = null;
      let resolvedDep = dep, resolvedDest = dest;

      if (directLegId) {
        // 直接使用前端傳來的 legId（來自班表，避免 ICAO/IATA 混淆）
        legId = directLegId;
      } else if (dep && dest) {
        // dep/dest 都有 → 直接組合
        legId = buildLegId(flightNum, normDate, dep, dest);
      } else {
        // 用飛行清單搜尋
        const matches = await fetchFlightList(flightNum, normDate, session);
        if (!matches || matches.length === 0) {
          return new Response(JSON.stringify({ error: `JX${flightNum} 在 ${normDate} 查無班表，請確認班號與日期` }), {
            status: 404, headers: { ...headers, 'Content-Type': 'application/json' }
          });
        }
        // 若有多個航段且有提示的 dep/dest，嘗試匹配
        let chosen = matches[0];
        if (dep) chosen = matches.find(m => m.dep?.startsWith(dep) || m.dep === dep) || chosen;
        if (dest) chosen = matches.find(m => m.dest?.startsWith(dest) || m.dest === dest) || chosen;
        legId = chosen.legId;
        resolvedDep = chosen.dep;
        resolvedDest = chosen.dest;
      }

      if (!legId) {
        return new Response(JSON.stringify({ error: `JX${flightNum} 在 ${normDate} 查無班表` }), {
          status: 404, headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }

      // 取得 briefing JSON（包含所有結構化資料）
      const briefingData = await fetchBriefingData(legId, briefingHeaders);
      const parsed = parseBriefingJson(briefingData);

      if (!parsed) {
        return new Response(JSON.stringify({ error: 'Failed to parse briefing response', legId }), {
          status: 500, headers: { ...headers, 'Content-Type': 'application/json' }
        });
      }

      // 取 OFP / ATS / APLI 文字
      // APLI = Airport List — 包含所有天氣所需機場（格式：ICAO4+IATA3+空格+[Y/N]+日期）
      // 例：WMKKKUL     Y13MAY2026... / RCKHKHH     N13MAY2026...
      const ofpFileId  = parsed.fileIds?.OFP;
      const atsFileId  = parsed.fileIds?.ATS;
      const apliFileId = parsed.fileIds?.APLI;

      const [ofpText, atsText, apliText] = await Promise.all([
        ofpFileId  ? fetchDocument(legId, ofpFileId,  buildLidoHeaders(session, 'GetDocOFP'),  true) : Promise.resolve(null),
        atsFileId  ? fetchDocument(legId, atsFileId,  buildLidoHeaders(session, 'GetDocATS'),  true) : Promise.resolve(null),
        apliFileId ? fetchDocument(legId, apliFileId, buildLidoHeaders(session, 'GetDocAPLI'), true) : Promise.resolve(null),
      ]);

      // 只做補充解析（STD local time 等 OFP 文字獨有的資訊）
      const ofpExtra = parseOFP(ofpText);

      // Parse APLI airport list.
      // APLI format: ...ICAO(4)IATA(3)     [Y/N]13MAY2026...<info></info>...
      // Y = has SA/FT data in this briefing; N = forecast only (enroute/suitable)
      // Only extract entries with the 4+3+space+[YN] pattern — avoids FIR/SIGMET codes after
      function parseApliAirports(txt) {
        if (!txt) return [];
        const set = new Set();
        // Match: 4-letter ICAO + 3-letter IATA + whitespace + Y or N
        for (const [, icao] of txt.matchAll(/([A-Z]{4})[A-Z]{3}\s+[YN]/g)) {
          set.add(icao);
        }
        return [...set];
      }

      const apliAirports = parseApliAirports(apliText);

      // Merge all airport sources
      const allWxAirports = [...new Set([
        ...(ofpExtra.wxAirports || []),
        ...apliAirports,
      ])];

      // 組合回傳資料
      const result = {
        legId,
        flightNumber: `JX${parsed.flightNumber || flightNum}`,
        date: normDate,
        dep: parsed.dep,
        dest: parsed.dest,
        ofpNumber: parsed.ofpNumber,
        aircraft: parsed.aircraft,
        times: {
          std: parsed.std,
          sta: parsed.sta,
          etd: parsed.etd,
          eta: parsed.eta,
          stdLocal: ofpExtra.stdLocal,
          staLocal: ofpExtra.staLocal,
          ete: ofpExtra.ete,
        },
        fuel: parsed.fuel,
        weight: parsed.weight,
        flightRoute: parsed.flightRoute,
        atsRoute: atsText ? parseATSRoute(atsText) : parsed.flightRoute,
        availableDocs: Object.keys(parsed.fileIds),
        // OFP 文字解析補充
        ofp: { ...ofpExtra, flight: flightNum, dep: parsed.dep, dest: parsed.dest },
        wxAirports: allWxAirports,
        raw: {
          ofpPreview:  ofpText  ? ofpText.substring(0, 800)  : null,
          apliPreview: apliText ? apliText.substring(0, 800) : null,
        }
      };

      return new Response(JSON.stringify(result), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // GET /flights?sessionToken=...&date=YYYYMMDD — 返回當日所有航班清單（供前端班表顯示）
    if (url.pathname === '/flights' && request.method === 'GET') {
      const sessionToken = url.searchParams.get('sessionToken');
      const dateStr = url.searchParams.get('date') || new Date().toISOString().slice(0,10).replace(/-/g,'');
      if (!sessionToken) return new Response(JSON.stringify({ error: 'missing sessionToken' }), { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } });
      let session;
      try { session = JSON.parse(atob(sessionToken)); } catch(e) {
        return new Response(JSON.stringify({ error: 'bad token' }), { status: 401, headers: { ...headers, 'Content-Type': 'application/json' } });
      }
      const normDate = dateStr.replace(/-/g, '');
      const datePart = `${normDate.slice(0,4)}-${normDate.slice(4,6)}-${normDate.slice(6,8)}`;
      const listUrl = `${LIDO_API_BASE}/flightlist?startDateTime=${datePart}T00:00:00.000Z&endDateTime=${datePart}T23:59:59.000Z`;
      try {
        const listResp = await fetch(listUrl, { headers: buildLidoHeaders(session, 'GetFlightList') });
        if (listResp.status === 401) {
          return new Response(JSON.stringify({ error: 'session_expired' }), { status: 401, headers: { ...headers, 'Content-Type': 'application/json' } });
        }
        if (!listResp.ok) {
          return new Response(JSON.stringify({ error: `LIDO ${listResp.status}` }), { status: 502, headers: { ...headers, 'Content-Type': 'application/json' } });
        }
        const listData = await listResp.json();
        const raw = Array.isArray(listData) ? listData : Object.values(listData);
        const flights = raw
          .filter(f => f.flightNumber || f.legId)   // skip empty/error rows
          .map(f => ({
            legId:  f.legId,
            flight: f.flightNumber,
            dep:    f.departureAirport,
            dest:   f.destinationAirport,
            std:    f.std,
            sta:    f.sta,
            status: f.briefingStatus,
          }))
          .sort((a, b) => (a.std || '').localeCompare(b.std || ''));
        return new Response(JSON.stringify(flights), { headers: { ...headers, 'Content-Type': 'application/json' } });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { ...headers, 'Content-Type': 'application/json' } });
      }
    }

    // GET /debug/flightlist?sessionToken=...&flight=...&date=... — 查看飛行清單
    if (url.pathname === '/debug/flightlist') {
      const sessionToken = url.searchParams.get('sessionToken');
      const flightNum = url.searchParams.get('flight');
      const dateStr = url.searchParams.get('date') || new Date().toISOString().slice(0,10).replace(/-/g,'');
      if (!sessionToken) return new Response('missing sessionToken', { status: 400, headers });
      let session;
      try { session = JSON.parse(atob(sessionToken)); } catch(e) { return new Response('bad token', { status: 400, headers }); }

      const normDate = dateStr.replace(/-/g, '');
      const datePart = `${normDate.slice(0,4)}-${normDate.slice(4,6)}-${normDate.slice(6,8)}`;
      const listUrl = `${LIDO_API_BASE}/flightlist?startDateTime=${datePart}T00:00:00.000Z&endDateTime=${datePart}T23:59:59.000Z`;
      const listHdrs = buildLidoHeaders(session, 'GetFlightList');
      const listResp = await fetch(listUrl, { headers: listHdrs });
      const listData = await listResp.json();
      const flights = Array.isArray(listData) ? listData : Object.values(listData);
      const matching = flightNum ? flights.filter(f => f.flightNumber === String(flightNum)) : flights.slice(0, 5);
      return new Response(JSON.stringify({
        status: listResp.status,
        total: flights.length,
        matching: matching.map(f => ({ legId: f.legId, flightNumber: f.flightNumber, dep: f.departureAirport, dest: f.destinationAirport, std: f.std, briefingStatus: f.briefingStatus })),
      }), { headers: { ...headers, 'Content-Type': 'application/json' } });
    }

    // GET /debug/login?userId=...&password=... — 回傳原始 DWR 回應供除錯
    if (url.pathname === '/debug/login') {
      const userId = url.searchParams.get('userId');
      const password = url.searchParams.get('password');
      if (!userId || !password) {
        return new Response('missing userId or password', { status: 400, headers });
      }
      const { lidoLas, serverid } = await getLidoSession();
      const scriptSessionId = generateUUID().replace(/-/g,'').toUpperCase().substring(0,16) +
        '/' + generateUUID().replace(/-/g,'').toUpperCase().substring(0,16);
      const dwrBody = [
        'callCount=1',
        'page=%2Flido%2Flas%2Flogin.jsp%3FDESMON_RESULT_PAGE%3Dhttps%253A%252F%252Fsjx.lido.aero%252Flido%252Fshell%252F%2523lcb%26DESMON_LANG%3Den',
        `httpSessionId=${lidoLas}`,
        `scriptSessionId=${encodeURIComponent(scriptSessionId)}`,
        'instanceId=0','batchId=0','c0-scriptName=LoginBean','c0-methodName=login','c0-id=0',
        `c0-param0=string:${userId}`,`c0-param1=string:${password}`,
        'c0-param2=string:','c0-param3=string:LIDO','c0-param4=string:en',
      ].join('\n');
      const dwrResp = await fetch('https://sjx.lido.aero/lido/las/dwr/call/plaincall/LoginBean.login.dwr', {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain', 'Cookie': `lido_las=${lidoLas}; las_serverid=${serverid}` },
        body: dwrBody,
      });
      const rawText = await dwrResp.text();
      const setCookie = dwrResp.headers.get('set-cookie') || '';
      return new Response(JSON.stringify({
        httpStatus: dwrResp.status,
        setCookie,
        rawDwr: rawText,
        lidoLas, serverid,
      }), { headers: { ...headers, 'Content-Type': 'application/json' } });
    }

    // GET /debug/briefing?sessionToken=...&legId=...
    if (url.pathname === '/debug/briefing') {
      const sessionToken = url.searchParams.get('sessionToken');
      const legId = url.searchParams.get('legId');
      if (!sessionToken || !legId) return new Response('missing params', { status: 400, headers });
      let session;
      try { session = JSON.parse(atob(sessionToken)); } catch(e) { return new Response('bad token', { status: 400, headers }); }

      // 若舊 session 沒有 csrfId/uid，重新解碼
      if (!session.csrfId && session.lidoCsrf) {
        const decoded = decodeLidoCsrf(session.lidoCsrf);
        session.csrfId = decoded.csrfId;
        session.uid = session.uid || decoded.uid;
      }
      if (!session.jwtPayload && session.lidoAuth) {
        session.jwtPayload = decodeJwtPayload(session.lidoAuth);
        session.businessId = session.businessId ||
          session.jwtPayload?.businessId || session.jwtPayload?.business_id ||
          session.jwtPayload?.customerId || session.uid;
      }

      const apiHeaders = buildLidoHeaders(session, 'GetBriefing');
      const testUrl = `https://sjx.lido.aero/lido/lcb/ui/${legId}/briefing`;

      const result = await fetch(testUrl, { headers: apiHeaders })
        .then(async r => ({ status: r.status, body: (await r.text()).substring(0, 500) }));

      return new Response(JSON.stringify({
        sessionDebug: {
          csrfId: session.csrfId,
          uid: session.uid,
          businessId: session.businessId,
          jwtPayload: session.jwtPayload,
          csrfRaw: session.lidoCsrf ? session.lidoCsrf.substring(0, 30) + '...' : null,
          authPrefix: session.lidoAuth ? session.lidoAuth.substring(0, 20) + '...' : null,
        },
        headersSent: {
          'X-lido-csrf': apiHeaders['X-lido-csrf'],
          'X-lido-auth': apiHeaders['X-lido-auth'],
          'X-lido-userId': apiHeaders['X-lido-userId'],
          'X-lido-businessId': apiHeaders['X-lido-businessId'],
          'X-lido-customerId': apiHeaders['X-lido-customerId'],
        },
        result,
      }), { headers: { ...headers, 'Content-Type': 'application/json' } });
    }

    // GET /charts?sessionToken=...&flight=XXX&date=YYYYMMDD
    // 回傳所有圖表 metadata（category → [{fileId, label}]）
    if (url.pathname === '/charts' && request.method === 'GET') {
      const sessionToken = url.searchParams.get('sessionToken');
      const flightNum    = url.searchParams.get('flight');
      const dateStr      = url.searchParams.get('date');
      if (!sessionToken || !flightNum || !dateStr) {
        return new Response(JSON.stringify({ error: 'missing params' }), { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } });
      }
      let session;
      try { session = JSON.parse(atob(sessionToken)); } catch(e) {
        return new Response(JSON.stringify({ error: 'bad token' }), { status: 401, headers: { ...headers, 'Content-Type': 'application/json' } });
      }
      if (!session.csrfId && session.lidoCsrf) {
        const d2 = decodeLidoCsrf(session.lidoCsrf);
        session.csrfId = d2.csrfId; session.uid = session.uid || d2.uid;
      }
      if (!session.jwtPayload && session.lidoAuth) {
        session.jwtPayload = decodeJwtPayload(session.lidoAuth);
        session.businessId = session.businessId || session.jwtPayload?.businessId || session.jwtPayload?.business_id || session.uid;
      }

      const normDate = dateStr.replace(/-/g,'');
      const dep = url.searchParams.get('dep') || '';
      const dest = url.searchParams.get('dest') || '';
      const legId = url.searchParams.get('legId') ||
        `JX.${flightNum}.${normDate.slice(0,4)}${['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][+normDate.slice(4,6)]}${normDate.slice(6,8)}.${dep}.${dest}.`;

      const briefingData = await fetchBriefingData(legId, buildLidoHeaders(session, 'GetBriefing'));
      const parsed = parseBriefingJson(briefingData);
      if (!parsed) return new Response(JSON.stringify({ error: 'no briefing' }), { status: 500, headers: { ...headers, 'Content-Type': 'application/json' } });

      // FL labels are now read directly from doc.fileName/doc.flightLevel in allDocs (no UADXML needed)

      // Chart categories and their display groups (CREWINFO/DISP/RAIM excluded — handled elsewhere)
      const CHART_GROUPS = [
        { group: 'UAD MAPS',          cats: ['UAD'] },
        { group: 'SIGWX WITH ROUTE',  cats: ['SIGWXROUTE'] },
        { group: 'OFFICIAL VAA/TCA',  cats: ['APTDXML','ASPDXML'] },
        { group: 'SIGNIFICANT WX',    cats: ['WXSIGWX'] },
        { group: 'VERTICAL PROFILE',  cats: ['VERTPROF'] },
      ];

      const uadDocs = parsed.allDocs?.UAD || [];
      const result = [];
      for (const { group, cats } of CHART_GROUPS) {
        const files = [];
        for (const cat of cats) {
          const docs = parsed.allDocs?.[cat] || [];
          for (const doc of docs) {
            let label;
            if (cat === 'UAD') {
              // Use fileName as primary source (most reliable)
              if (/MERGE/i.test(doc.fileName)) {
                label = 'MERGE';
              } else if (doc.flightLevel) {
                label = `FL${doc.flightLevel}`;
              } else {
                const fnMatch = doc.fileName.match(/FL(\d+)/i);
                label = fnMatch ? `FL${fnMatch[1]}` : `Chart ${doc.index + 1}`;
              }
            } else {
              label = (doc.label || '').trim();
              if (!label || label === String(doc.index)) {
                label = docs.length > 1 ? `${cat} ${doc.index + 1}` : cat;
              }
            }
            files.push({ cat, fileId: doc.fileId, label, index: doc.index });
          }
          // Sort UAD by FL ascending, MERGE last
          if (cat === 'UAD') {
            files.sort((a, b) => {
              if (a.label === 'MERGE') return 1;
              if (b.label === 'MERGE') return -1;
              return parseInt(a.label.replace('FL','')) - parseInt(b.label.replace('FL',''));
            });
          }
        }
        if (files.length) result.push({ group, files });
      }

      return new Response(JSON.stringify({ legId: parsed.legId, charts: result }), {
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // GET /chart?sessionToken=...&legId=...&cat=UAD&fileId=...
    // 代理 LIDO 圖片，回傳原始 binary（PNG / PDF）
    if (url.pathname === '/chart' && request.method === 'GET') {
      const sessionToken = url.searchParams.get('sessionToken');
      const legId        = url.searchParams.get('legId');
      const fileId       = url.searchParams.get('fileId');
      const cat          = url.searchParams.get('cat') || 'UAD';
      if (!sessionToken || !legId || !fileId) {
        return new Response('missing params', { status: 400, headers });
      }
      let session;
      try { session = JSON.parse(atob(sessionToken)); } catch(e) {
        return new Response('bad token', { status: 401, headers });
      }
      if (!session.csrfId && session.lidoCsrf) {
        const d2 = decodeLidoCsrf(session.lidoCsrf);
        session.csrfId = d2.csrfId; session.uid = session.uid || d2.uid;
      }
      if (!session.jwtPayload && session.lidoAuth) {
        session.jwtPayload = decodeJwtPayload(session.lidoAuth);
        session.businessId = session.businessId || session.jwtPayload?.businessId || session.jwtPayload?.business_id || session.uid;
      }

      const imgHeaders = buildLidoHeaders(session, `GetDoc${cat}`);
      const resp = await fetch(`${LIDO_API_BASE}/${legId}/briefing/${fileId}/docs`, {
        headers: { ...imgHeaders, Accept: 'image/*, application/pdf, text/plain, */*' }
      });
      if (!resp.ok) return new Response(`LIDO error ${resp.status}`, { status: resp.status, headers });

      const buf = await resp.arrayBuffer();
      const contentType = resp.headers.get('content-type') || 'application/octet-stream';
      return new Response(buf, {
        headers: {
          ...headers,
          'Content-Type': contentType,
          'Cache-Control': 'private, max-age=3600',
        }
      });
    }

    return new Response(JSON.stringify({ error: 'Not found', routes: ['/auth/login', '/api/briefing'] }), {
      status: 404, headers: { ...headers, 'Content-Type': 'application/json' }
    });

  } catch (err) {
    console.error('Worker error:', err);
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500, headers: { ...headers, 'Content-Type': 'application/json' }
    });
  }
}

export default {
  fetch: handleRequest,
};
