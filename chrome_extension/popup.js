"use strict";

var DASHBOARD_URL = "http://127.0.0.1:5000/extension/";

// ════════════════════════════════════════════════════════════════════════════
// GAUGE GEOMETRY — u- prefix for URL gauge, e- prefix for email gauge
// ════════════════════════════════════════════════════════════════════════════

var CX = 130, CY = 138, R = 100, ARC_START = 210, ARC_SPAN = 240;

function deg2rad(d) { return d * Math.PI / 180; }

function scoreToXY(score, radius) {
  var ang = deg2rad(ARC_START - (score / 100) * ARC_SPAN);
  return { x: CX + radius * Math.cos(ang), y: CY - radius * Math.sin(ang) };
}

function arcPath(sA, sB, radius) {
  var p1 = scoreToXY(sA, radius), p2 = scoreToXY(sB, radius);
  var span = (sB - sA) / 100 * ARC_SPAN;
  return ["M",p1.x,p1.y,"A",radius,radius,0,span>180?1:0,1,p2.x,p2.y].join(" ");
}

function buildGauge(prefix) {
  function el(name) { return document.getElementById(prefix + name); }
  el("trackSafe")  .setAttribute("d", arcPath(0,  35,  R));
  el("trackWarn")  .setAttribute("d", arcPath(35, 70,  R));
  el("trackDanger").setAttribute("d", arcPath(70, 100, R));
  var gT = el("ticks"), gL = el("tickLabels");
  [0, 25, 50, 75, 100].forEach(function (v) {
    var o=scoreToXY(v,R+4), i=scoreToXY(v,R-10), lp=scoreToXY(v,R-23);
    var ln=document.createElementNS("http://www.w3.org/2000/svg","line");
    ln.setAttribute("x1",o.x); ln.setAttribute("y1",o.y);
    ln.setAttribute("x2",i.x); ln.setAttribute("y2",i.y);
    gT.appendChild(ln);
    var tx=document.createElementNS("http://www.w3.org/2000/svg","text");
    tx.setAttribute("x",lp.x); tx.setAttribute("y",lp.y);
    tx.textContent=String(v);
    gL.appendChild(tx);
  });
  drawAt(prefix, 0);
}

var _gs = { "u-":{cur:0,tgt:0,raf:null}, "e-":{cur:0,tgt:0,raf:null} };

function setScore(prefix, s) {
  var st=_gs[prefix];
  st.tgt=Math.max(0,Math.min(100,s));
  if (!st.raf) { animTick(prefix); }
}

function animTick(prefix) {
  var st=_gs[prefix], diff=st.tgt-st.cur;
  if (Math.abs(diff)<0.2) { st.cur=st.tgt; drawAt(prefix,st.cur); st.raf=null; return; }
  st.cur+=diff*0.11;
  drawAt(prefix,st.cur);
  st.raf=requestAnimationFrame(function(){ animTick(prefix); });
}

function drawAt(prefix, score) {
  function el(name) { return document.getElementById(prefix+name); }
  var arc=el("arcProgress");
  if (!arc) { return; }
  if (score<0.3) { arc.setAttribute("d",""); }
  else {
    arc.setAttribute("d", arcPath(0,score,R));
    arc.setAttribute("stroke", score>=70?"#ff3d3d":score>=35?"#ffab00":"#00e676");
  }
  var tip=scoreToXY(score,R-10), tail=scoreToXY(score,-16);
  var nd=el("needle"), tl=el("needleTail");
  if (!nd||!tl) { return; }
  nd.setAttribute("x1",CX); nd.setAttribute("y1",CY);
  nd.setAttribute("x2",tip.x); nd.setAttribute("y2",tip.y);
  tl.setAttribute("x1",CX); tl.setAttribute("y1",CY);
  tl.setAttribute("x2",tail.x); tl.setAttribute("y2",tail.y);
}


// ════════════════════════════════════════════════════════════════════════════
// DOM REFS
// ════════════════════════════════════════════════════════════════════════════

var pgStatusDot    = document.getElementById("pgStatusDot");
var pgStatusText   = document.getElementById("pgStatusText");
var pgScore        = document.getElementById("pgScore");
var pgVerdict      = document.getElementById("pgVerdict");
var pgUrl          = document.getElementById("pgUrl");
var pgSummary      = document.getElementById("pgSummary");
var pgActionIcon   = document.getElementById("pgActionIcon");
var pgAction       = document.getElementById("pgAction");
var pgScanBtn      = document.getElementById("pgScanBtn");
var pgResetBtn     = document.getElementById("pgResetBtn");
var pgDashBtn      = document.getElementById("pgDashBtn");
var autoScanToggle = document.getElementById("autoScanToggle");
var toggleLbl      = document.getElementById("toggleLbl");
var scanOverlay    = document.getElementById("scanOverlay");
var scanLog        = document.getElementById("scanLog");
var scanProgFill   = document.getElementById("scanProgFill");
var overlayTitle   = document.getElementById("overlayTitle");
var tabUrl         = document.getElementById("tabUrl");
var tabEmail       = document.getElementById("tabEmail");
var urlPanel       = document.getElementById("urlPanel");
var emailPanel     = document.getElementById("emailPanel");
var gmailBadge     = document.getElementById("gmailBadge");
var noEmailNotice  = document.getElementById("noEmailNotice");
var noEmailText    = document.getElementById("noEmailText");
var emailContent   = document.getElementById("emailContent");
var eScore         = document.getElementById("eScore");
var eVerdict       = document.getElementById("eVerdict");
var eSender        = document.getElementById("eSender");
var eSubject       = document.getElementById("eSubject");
var eSummary       = document.getElementById("eSummary");
var eActionIcon    = document.getElementById("eActionIcon");
var eAction        = document.getElementById("eAction");
var pgEmailScanBtn  = document.getElementById("pgEmailScanBtn");
var pgEmailResetBtn = document.getElementById("pgEmailResetBtn");
var pgEmailDashBtn  = document.getElementById("pgEmailDashBtn");

var ACTION_CFG = {
  ALLOW:      { icon:"✔", text:"SAFE TO VISIT",                color:"#00e676" },
  WARN:       { icon:"⚠", text:"REVIEW BEFORE PROCEEDING",    color:"#ffab00" },
  QUARANTINE: { icon:"⛔", text:"DO NOT INTERACT — QUARANTINE", color:"#ff3d3d" },
  BLOCK:      { icon:"✖", text:"BLOCKED — KNOWN MALICIOUS",   color:"#ff3d3d" },
};


// ════════════════════════════════════════════════════════════════════════════
// MODE SWITCHER — JS only, no inline onclick (Manifest V3 CSP)
// ════════════════════════════════════════════════════════════════════════════

var _currentMode = "url";

function switchMode(mode) {
  _currentMode = mode;
  tabUrl.classList.toggle("active",   mode==="url");
  tabEmail.classList.toggle("active", mode==="email");
  urlPanel.style.display   = mode==="url"   ? "block" : "none";
  emailPanel.style.display = mode==="email" ? "block" : "none";
  if (mode==="email") { detectGmail(); }
}

tabUrl.addEventListener("click",   function(){ switchMode("url");   });
tabEmail.addEventListener("click", function(){ switchMode("email"); });


// ════════════════════════════════════════════════════════════════════════════
// SCANNING OVERLAY
// ════════════════════════════════════════════════════════════════════════════

var _logTimer   = null;
var _scanActive = false;

var URL_LOG_LINES = [
  "RESOLVING DNS...","FETCHING SSL CERTIFICATE...","CHECKING DOMAIN AGE...",
  "RUNNING URL CLASSIFIER...","SCANNING FOR REDIRECTS...",
  "QUERYING THREAT FEEDS...","RUNNING ML MODELS...",
  "COMPUTING RISK SCORE...","FINALIZING REPORT...",
];
var EMAIL_LOG_LINES = [
  "PARSING EMAIL HEADERS...","CHECKING SPF / DKIM / DMARC...",
  "EXTRACTING URLS...","RUNNING DISTILBERT CLASSIFIER...",
  "SCORING ANOMALIES...","COMPUTING RISK SCORE...","FINALIZING REPORT...",
];

function showOverlay(label, url) {
  _scanActive = true;
  scanLog.innerHTML = '<div class="log-line">INITIALIZING MODULES...</div>';
  scanProgFill.style.transition = "none";
  scanProgFill.style.width      = "0%";
  scanProgFill.style.background = "";
  scanProgFill.style.boxShadow  = "";
  scanProgFill.classList.remove("indeterminate");
  void scanProgFill.offsetWidth;
  scanProgFill.classList.add("indeterminate");
  overlayTitle.textContent = label || "SCANNING TARGET";
  if (url) {
    try { overlayTitle.textContent = "SCANNING · "+new URL(url).hostname.toUpperCase(); } catch(e){}
  }
  scanOverlay.classList.add("active");
  setScanBtnsDisabled(true);
  var lines = _currentMode==="email" ? EMAIL_LOG_LINES : URL_LOG_LINES;
  var idx=0;
  clearInterval(_logTimer);
  _logTimer = setInterval(function(){
    if (idx>=lines.length) { clearInterval(_logTimer); return; }
    var div=document.createElement("div");
    div.className="log-line"; div.textContent=lines[idx++];
    while (scanLog.children.length>=3) { scanLog.removeChild(scanLog.firstChild); }
    scanLog.appendChild(div);
  }, 800);
}

function hideOverlay(success) {
  _scanActive = false;
  clearInterval(_logTimer); _logTimer=null;
  scanProgFill.classList.remove("indeterminate");
  scanProgFill.style.transition = "width .3s ease";
  scanProgFill.style.width      = "100%";
  if (success) {
    scanProgFill.style.background="#00e676";
    scanProgFill.style.boxShadow ="0 0 8px #00e676";
    _appendLog("SCAN COMPLETE ✔","#00e676");
  } else {
    scanProgFill.style.background="#ff3d3d";
    scanProgFill.style.boxShadow ="0 0 8px #ff3d3d";
    _appendLog("SCAN FAILED — CHECK BACKEND","#ff3d3d");
  }
  setTimeout(function(){
    scanOverlay.classList.remove("active");
    setScanBtnsDisabled(false);
  }, 900);
}

function setScanBtnsDisabled(d) {
  pgScanBtn.disabled=pgResetBtn.disabled=pgEmailScanBtn.disabled=pgEmailResetBtn.disabled=d;
  pgScanBtn.textContent      = d ? "⏳ SCANNING..." : "⬡ Scan";
  pgEmailScanBtn.textContent = d ? "⏳ SCANNING..." : "✉ Scan Email";
}

function _appendLog(text, color) {
  var div=document.createElement("div");
  div.className="log-line"; div.style.color=color||""; div.textContent=text;
  while (scanLog.children.length>=3) { scanLog.removeChild(scanLog.firstChild); }
  scanLog.appendChild(div);
}


// ════════════════════════════════════════════════════════════════════════════
// RENDER RESULTS
// ════════════════════════════════════════════════════════════════════════════

function renderUrlResult(result) {
  var score=Number(result.risk_score)||0;
  var label=(result.label||"SAFE").toUpperCase();
  setScore("u-",score);
  var col=score>=70?"#ff3d3d":score>=35?"#ffab00":"#00e676";
  pgScore.textContent=Math.round(score); pgScore.style.color=col;
  var vc={SAFE:"v-safe",SUSPICIOUS:"v-suspicious",MALICIOUS:"v-malicious"}[label]||"v-unknown";
  pgVerdict.textContent=label; pgVerdict.className="verdict-pill "+vc;
  pgUrl.textContent=result.url||"—";
  pgSummary.textContent=result.threat_summary||result.explanation||"No threat detail available.";
  var act=(result.action||result.recommended_action||"ALLOW").toUpperCase();
  var acfg=ACTION_CFG[act]||ACTION_CFG.ALLOW;
  pgActionIcon.textContent=acfg.icon; pgAction.textContent=acfg.text; pgAction.style.color=acfg.color;
}

function renderEmailResult(result) {
  var score=Number(result.risk_score)||0;
  var label=(result.label||"SAFE").toUpperCase();
  setScore("e-",score);
  var col=score>=70?"#ff3d3d":score>=35?"#ffab00":"#00e676";
  eScore.textContent=Math.round(score); eScore.style.color=col;
  var vc={SAFE:"v-safe",SUSPICIOUS:"v-suspicious",MALICIOUS:"v-malicious"}[label]||"v-unknown";
  eVerdict.textContent=label; eVerdict.className="verdict-pill "+vc;
  if (result.sender)  { eSender.textContent=result.sender;  }
  if (result.subject) { eSubject.textContent=result.subject; }
  eSummary.textContent=result.threat_summary||result.explanation||"No threat detail available.";
  var act=(result.action||result.recommended_action||"ALLOW").toUpperCase();
  var acfg=ACTION_CFG[act]||ACTION_CFG.ALLOW;
  eActionIcon.textContent=acfg.icon; eAction.textContent=acfg.text; eAction.style.color=acfg.color;
}


// ════════════════════════════════════════════════════════════════════════════
// RESET
// ════════════════════════════════════════════════════════════════════════════

function doUrlReset() {
  if (_scanActive) { return; }
  setScore("u-",0);
  pgScore.textContent="—"; pgScore.style.color="var(--muted)";
  pgVerdict.textContent="NO SCAN"; pgVerdict.className="verdict-pill v-unknown";
  pgUrl.textContent="awaiting scan target...";
  pgSummary.textContent="Click SCAN to begin threat assessment.";
  pgActionIcon.textContent="◈"; pgAction.textContent="—"; pgAction.style.color="var(--muted)";
  chrome.storage.local.remove(["lastScan","scanInFlight"]);
  pgResetBtn.classList.add("confirming");
  pgResetBtn.addEventListener("animationend", function h(){
    pgResetBtn.classList.remove("confirming");
    pgResetBtn.removeEventListener("animationend",h);
  });
}

function doEmailReset() {
  if (_scanActive) { return; }
  setScore("e-",0);
  eScore.textContent="—"; eScore.style.color="var(--muted)";
  eVerdict.textContent="NOT SCANNED"; eVerdict.className="verdict-pill v-unknown";
  eSummary.textContent="Click SCAN EMAIL to analyse this message.";
  eActionIcon.textContent="◈"; eAction.textContent="—"; eAction.style.color="var(--muted)";
  chrome.storage.local.remove("lastEmailScan");
  pgEmailResetBtn.classList.add("confirming");
  pgEmailResetBtn.addEventListener("animationend", function h(){
    pgEmailResetBtn.classList.remove("confirming");
    pgEmailResetBtn.removeEventListener("animationend",h);
  });
}


// ════════════════════════════════════════════════════════════════════════════
// GMAIL DETECTION
// ════════════════════════════════════════════════════════════════════════════

var _gmailEmailData = null;

function detectGmail() {
  chrome.tabs.query({ active:true, currentWindow:true }, function(tabs){
    if (!tabs||!tabs[0]) { return; }
    var url=tabs[0].url||"";
    var isGmail=url.includes("mail.google.com");
    gmailBadge.style.display=isGmail?"inline-block":"none";
    if (!isGmail) {
      noEmailNotice.style.display="block"; emailContent.style.display="none";
      _gmailEmailData=null;
      noEmailText.innerHTML="OPEN A GMAIL EMAIL THREAD<br>TO ENABLE EMAIL SCANNING";
      return;
    }
    chrome.tabs.sendMessage(tabs[0].id,{type:"GET_EMAIL_CONTENT"},function(resp){
      if (chrome.runtime.lastError||!resp||!resp.found) {
        noEmailNotice.style.display="block"; emailContent.style.display="none";
        _gmailEmailData=null;
        if (resp&&resp.reason==="no_thread_open") {
          noEmailText.innerHTML="OPEN A GMAIL EMAIL THREAD<br>TO ENABLE EMAIL SCANNING";
        } else if (resp&&resp.reason==="content_not_found") {
          noEmailText.innerHTML="EMAIL CONTENT NOT DETECTED<br>WAIT FOR PAGE TO FULLY LOAD";
        }
        return;
      }
      _gmailEmailData=resp;
      noEmailNotice.style.display="none"; emailContent.style.display="block";
      eSender.textContent =resp.sender ||"—";
      eSubject.textContent=resp.subject||"—";
      chrome.storage.local.get(["lastEmailScan"],function(data){
        if (data&&data.lastEmailScan) { renderEmailResult(data.lastEmailScan); }
      });
    });
  });
}


// ════════════════════════════════════════════════════════════════════════════
// AUTO-SCAN TOGGLE
// ════════════════════════════════════════════════════════════════════════════

function applyToggleUI(enabled) {
  autoScanToggle.checked=enabled;
  toggleLbl.textContent =enabled?"ON":"OFF";
  toggleLbl.style.color =enabled?"#00e676":"var(--muted)";
}

chrome.storage.local.get(["autoScanEnabled"],function(data){
  applyToggleUI(data.autoScanEnabled===true);
});

autoScanToggle.addEventListener("change",function(){
  var enabled=autoScanToggle.checked;
  applyToggleUI(enabled);
  chrome.storage.local.set({autoScanEnabled:enabled});
  chrome.runtime.sendMessage({type:"SET_AUTO_SCAN",enabled:enabled});
});


// ════════════════════════════════════════════════════════════════════════════
// BACKEND STATUS
// ════════════════════════════════════════════════════════════════════════════

function checkBackend() {
  chrome.runtime.sendMessage({type:"PING_BACKEND"},function(resp){
    if (resp&&resp.online) {
      pgStatusDot.className   ="s-dot online";
      pgStatusText.textContent="BACKEND ONLINE  ·  MAHORAGA SENTINEL ACTIVE";
    } else {
      pgStatusDot.className   ="s-dot offline";
      pgStatusText.textContent="BACKEND OFFLINE  ·  START :8001";
    }
  });
}


// ════════════════════════════════════════════════════════════════════════════
// URL SCAN
//
// THE CORE FIX:
// All previous approaches had a race condition — the scan result was written
// to storage BEFORE the popup's listener was registered, so the event fired
// into the void and the overlay spun forever.
//
// The new approach:
//   1. Record scan start time (_scanStartedAt)
//   2. Clear old lastScan from storage
//   3. Show overlay
//   4. Send SCAN_CURRENT_TAB to background
//   5. Poll storage every 300ms for up to 30 seconds
//      (polling is safe here because the popup IS open and JS IS running)
//   6. The moment lastScan.ts > _scanStartedAt, render and stop
//
// Why polling instead of onChanged:
//   onChanged only fires for FUTURE writes. If the scan completes before
//   the listener is registered (which happens consistently because the
//   background fetch is faster than popup JS startup), the event is missed.
//   Polling has no such race condition — it always catches whatever is
//   in storage at the time of each check.
// ════════════════════════════════════════════════════════════════════════════

var _scanStartedAt = 0;
var _pollTimer     = null;

function startPolling() {
  clearInterval(_pollTimer);
  var attempts = 0;
  var maxAttempts = 60;   // 60 × 300ms = 18 seconds max

  _pollTimer = setInterval(function(){
    attempts++;

    chrome.storage.local.get(["lastScan"], function(data){
      if (data && data.lastScan) {
        var result = data.lastScan;
        var resultTs = Number(result.ts) || 0;

        // Accept any result written after we started this scan
        if (resultTs >= _scanStartedAt) {
          clearInterval(_pollTimer); _pollTimer=null;
          chrome.storage.local.remove("scanInFlight");
          if (result.failed) {
            hideOverlay(false);
          } else {
            hideOverlay(true);
            renderUrlResult(result);
          }
          return;
        }
      }

      if (attempts >= maxAttempts) {
        clearInterval(_pollTimer); _pollTimer=null;
        chrome.storage.local.remove("scanInFlight");
        hideOverlay(false);
      }
    });
  }, 300);
}

pgScanBtn.addEventListener("click", function(){
  chrome.tabs.query({active:true,currentWindow:true},function(tabs){
    var url=(tabs&&tabs[0]&&tabs[0].url)||"";
    if (!url.startsWith("http")) {
      pgStatusText.textContent="CANNOT SCAN THIS PAGE TYPE";
      return;
    }

    // Record exactly when THIS scan started
    _scanStartedAt = Date.now();

    // Wipe old result so poll doesn't pick up stale data
    chrome.storage.local.remove(["lastScan","scanInFlight"], function(){
      showOverlay(null, url);

      chrome.runtime.sendMessage({type:"SCAN_CURRENT_TAB"},function(resp){
        if (!resp||!resp.ok) {
          clearInterval(_pollTimer); _pollTimer=null;
          hideOverlay(false);
          return;
        }
        // Background confirmed scan started — poll storage for result
        startPolling();
      });
    });
  });
});


// ════════════════════════════════════════════════════════════════════════════
// EMAIL SCAN BUTTON
// ════════════════════════════════════════════════════════════════════════════

pgEmailScanBtn.addEventListener("click",function(){
  if (!_gmailEmailData||!_gmailEmailData.raw_email) {
    eSummary.textContent="No email content found. Open a Gmail thread first.";
    return;
  }
  showOverlay("SCANNING EMAIL");
  chrome.runtime.sendMessage({
    type:     "SCAN_EMAIL_CONTENT",
    raw_email: _gmailEmailData.raw_email,
  },function(resp){
    if (!resp||!resp.ok) {
      hideOverlay(false);
      eSummary.textContent=resp&&resp.error?("Error: "+resp.error):"Scan failed.";
      return;
    }
    hideOverlay(true);
    renderEmailResult(resp.result);
  });
});


// ════════════════════════════════════════════════════════════════════════════
// RESET + DASH BUTTONS
// ════════════════════════════════════════════════════════════════════════════

pgResetBtn.addEventListener("click",      doUrlReset);
pgEmailResetBtn.addEventListener("click", doEmailReset);
pgDashBtn.addEventListener("click",       function(){ chrome.tabs.create({url:DASHBOARD_URL}); });
pgEmailDashBtn.addEventListener("click",  function(){ chrome.tabs.create({url:DASHBOARD_URL}); });


// ════════════════════════════════════════════════════════════════════════════
// INIT — runs every time popup opens
// ════════════════════════════════════════════════════════════════════════════

buildGauge("u-");
buildGauge("e-");

checkBackend();
detectGmail();

// On popup open: check if a result is already waiting in storage.
// This handles the popup-was-closed-during-scan case.
chrome.storage.local.get(["lastScan","scanInFlight"],function(data){
  var flight = data.scanInFlight;
  var result = data.lastScan;

  if (result && !flight) {
    // Normal — just show last result
    renderUrlResult(result);
    return;
  }

  if (result && flight) {
    var rTs = Number(result.ts)||0;
    var fTs = Number(flight.startedAt)||0;
    if (rTs >= fTs) {
      // Result arrived for the in-flight scan — render immediately
      chrome.storage.local.remove("scanInFlight");
      renderUrlResult(result);
      return;
    }
    // Result is older than the in-flight scan — scan still running
    // Show overlay and poll
    _scanStartedAt = fTs;
    showOverlay(null, flight.url||"");
    startPolling();
    return;
  }

  if (flight && !result) {
    // Scan in flight, no result yet — show overlay and poll
    _scanStartedAt = Number(flight.startedAt)||0;
    showOverlay(null, flight.url||"");
    startPolling();
  }
});

setInterval(checkBackend, 30000);