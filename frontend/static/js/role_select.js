/* ═══════════════════════════════════════
   MAHORAGA SENTINEL — role_select.js
   Link in HTML just before </body>:
   <script src="role_select.js"></script>
═══════════════════════════════════════ */
 
/* ─────────────────────────────────────
   SECTION 1 · COSMIC BACKGROUND
   Draws animated stars, nebulae,
   shooting stars and aurora on <canvas id="cosmos">
───────────────────────────────────────*/
(function(){
  const canvas = document.getElementById('cosmos');
  const ctx = canvas.getContext('2d');
  let W, H, stars, nebulae, shooters;
 
  function resize(){
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    initScene();
  }
 
  function rand(a, b){ return a + Math.random() * (b - a); }
  function randInt(a, b){ return Math.floor(rand(a, b)); }
 
  function initScene(){
    stars = Array.from({length: 280}, () => ({
      x: rand(0, W),
      y: rand(0, H),
      r: rand(0.3, 2),
      alpha: rand(0.2, 1),
      twinkleSpeed: rand(0.005, 0.025),
      twinklePhase: rand(0, Math.PI * 2),
      color: Math.random() > 0.85
        ? (Math.random() > 0.5 ? '#d4b4fe' : '#f0c0ff')
        : '#ede9ff'
    }));
 
    nebulae = Array.from({length: 5}, () => ({
      x: rand(0, W),
      y: rand(0, H),
      rx: rand(80, 220),
      ry: rand(50, 140),
      hue: [270, 290, 310, 250, 200][randInt(0,5)],
      alpha: rand(0.025, 0.07),
      drift: rand(-0.04, 0.04)
    }));
 
    shooters = [];
  }
 
  function spawnShooter(){
    if(shooters.length > 4) return;
    const side = Math.random() > 0.5;
    shooters.push({
      x:  side ? rand(0, W * 0.6) : rand(W * 0.2, W),
      y:  rand(0, H * 0.5),
      vx: rand(4, 9) * (side ? 1 : -1),
      vy: rand(1.5, 4),
      len: rand(60, 160),
      life: 1,
      decay: rand(0.018, 0.04),
      color: Math.random() > 0.5 ? '#d4a8ff' : '#f0a0ff'
    });
  }
 
  let t = 0;
  function draw(){
    ctx.clearRect(0, 0, W, H);
 
    nebulae.forEach(n => {
      n.x += n.drift;
      if(n.x > W + 250) n.x = -250;
      if(n.x < -250)    n.x = W + 250;
      const g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, Math.max(n.rx, n.ry));
      g.addColorStop(0,   `hsla(${n.hue},80%,60%,${n.alpha})`);
      g.addColorStop(0.5, `hsla(${n.hue},70%,50%,${n.alpha * 0.5})`);
      g.addColorStop(1,   `hsla(${n.hue},60%,40%,0)`);
      ctx.save();
      ctx.scale(1, n.ry / n.rx);
      ctx.beginPath();
      ctx.arc(n.x, n.y * (n.rx / n.ry), n.rx, 0, Math.PI * 2);
      ctx.fillStyle = g;
      ctx.fill();
      ctx.restore();
    });
 
    stars.forEach(s => {
      const flicker = Math.sin(t * s.twinkleSpeed + s.twinklePhase) * 0.35 + 0.65;
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r * flicker, 0, Math.PI * 2);
      ctx.globalAlpha = s.alpha * flicker;
      ctx.fillStyle = s.color;
      ctx.fill();
      ctx.globalAlpha = 1;
    });
 
    if(t % 1 === 0){
      ctx.save();
      ctx.globalAlpha = 0.12;
      [[W*0.15, H*0.25], [W*0.8, H*0.7], [W*0.5, H*0.45]].forEach(([cx,cy]) => {
        const g = ctx.createRadialGradient(cx,cy,2,cx,cy,30);
        g.addColorStop(0, '#ffffff');
        g.addColorStop(1, 'transparent');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(cx, cy, 30, 0, Math.PI*2);
        ctx.fill();
      });
      ctx.restore();
    }
 
    if(Math.random() < 0.008) spawnShooter();
    shooters = shooters.filter(s => s.life > 0);
    shooters.forEach(s => {
      ctx.save();
      ctx.strokeStyle = s.color;
      ctx.globalAlpha = s.life * 0.8;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(s.x - s.vx * s.len/10, s.y - s.vy * s.len/10);
      ctx.lineTo(s.x, s.y);
      ctx.stroke();
      ctx.restore();
      s.x += s.vx;
      s.y += s.vy;
      s.life -= s.decay;
    });
 
    const auroraY = H * 0.82;
    for(let i = 0; i < 3; i++){
      const phase = t * 0.002 + i * 1.4;
      const a = ctx.createLinearGradient(0, auroraY - 80, 0, auroraY + 40);
      const hue = 270 + Math.sin(phase) * 40;
      a.addColorStop(0,   `hsla(${hue},90%,60%,0)`);
      a.addColorStop(0.5, `hsla(${hue},80%,55%,0.04)`);
      a.addColorStop(1,   `hsla(${hue},70%,45%,0)`);
      ctx.fillStyle = a;
      ctx.fillRect(0, auroraY - 80, W, 120);
    }
 
    t++;
    requestAnimationFrame(draw);
  }
 
  window.addEventListener('resize', resize);
  resize();
  draw();
})();
 
 
/* ─────────────────────────────────────
   SECTION 2 · CARD PARTICLE BURST
   Fires coloured sparks on card hover
───────────────────────────────────────*/
const cardParticleColors = {
  'card-admin':   ['#e040fb','#d580ff','#f0a0ff','#c000e0'],
  'card-analyst': ['#a855f7','#c084fc','#d8b4fe','#8b30e0'],
  'card-viewer':  ['#7cffd4','#a8ffee','#ccfff5','#44eebb']
};
 
document.querySelectorAll('.role-card').forEach(card => {
  const container = card.querySelector('.particles');
  let particles = [];
  let animating  = false;
  const colors   = cardParticleColors[card.id] || ['#ffffff'];
 
  function burst(){
    if(animating) return;
    animating = true;
    for(let i = 0; i < 16; i++){
      const p = document.createElement('span');
      const angle  = (i / 16) * Math.PI * 2 + Math.random() * 0.4;
      const dist   = 40 + Math.random() * 80;
      const size   = 2 + Math.random() * 3;
      const color  = colors[Math.floor(Math.random() * colors.length)];
      const startX = 50 + (Math.random() - 0.5) * 30;
      const startY = 50 + (Math.random() - 0.5) * 30;
      p.style.cssText = `
        left:${startX}%;top:${startY}%;
        width:${size}px;height:${size}px;
        background:${color};
        border-radius:50%;
        position:absolute;
        pointer-events:none;
        box-shadow:0 0 ${size*3}px ${color};
        transition: transform 0.7s cubic-bezier(.2,0,.8,1), opacity 0.7s ease;
        opacity:0.9;
      `;
      container.appendChild(p);
      particles.push(p);
      const tx = Math.cos(angle) * dist;
      const ty = Math.sin(angle) * dist;
      requestAnimationFrame(() => {
        p.style.transform = `translate(${tx}px,${ty}px) scale(0)`;
        p.style.opacity   = '0';
      });
    }
    setTimeout(() => {
      particles.forEach(p => p.remove());
      particles = [];
      animating = false;
    }, 750);
  }
 
  card.addEventListener('mouseenter', burst);
});
 
 
/* ─────────────────────────────────────
   SECTION 3 · ROLE SELECTION
   Handles card clicks and "Enter" button
───────────────────────────────────────*/
const cards      = document.querySelectorAll('.role-card');
const enterBtn   = document.getElementById('enterBtn');
const roleInput  = document.getElementById('roleInput');
const adminModal = document.getElementById('adminModal');
 
const roleColors = {
  admin:   '#e040fb',
  analyst: '#a855f7',
  viewer:  '#7cffd4'
};
 
let selectedRole = null;
 
cards.forEach(card => {
  card.addEventListener('click', () => {
    const role = card.dataset.role;
    if(role === 'admin'){
      adminModal.classList.add('open');
      document.getElementById('adminUser').focus();
      return;
    }
    selectRole(card, role);
  });
});
 
function selectRole(card, role){
  cards.forEach(c => {
    c.classList.remove('selected');
    const chk = c.querySelector('.card-check');
    chk.textContent       = '';
    chk.style.background  = '';
    chk.style.borderColor = '';
    chk.style.boxShadow   = '';
  });
  card.classList.add('selected');
  selectedRole  = role;
  roleInput.value = role;
  const chk = card.querySelector('.card-check');
  const col = roleColors[role];
  chk.textContent       = '✓';
  chk.style.background  = col;
  chk.style.borderColor = col;
  chk.style.boxShadow   = `0 0 14px ${col}`;
  enterBtn.disabled = false;
  enterBtn.classList.add('active');
}
 
document.getElementById('roleForm').addEventListener('submit', e => {
  if(!selectedRole) e.preventDefault();
});
 
 
/* ─────────────────────────────────────
   SECTION 4 · ADMIN LOGIN MODAL
 
   ╔══════════════════════════════════╗
   ║  HOW THE LOGIN WORKS             ║
   ║                                  ║
   ║  Credentials are checked here    ║
   ║  in JavaScript — no server call. ║
   ║                                  ║
   ║  Default:  admin / admin123      ║
   ║                                  ║
   ║  To change them, edit the        ║
   ║  ADMIN_USER and ADMIN_PASS       ║
   ║  constants below.                ║
   ╚══════════════════════════════════╝
───────────────────────────────────────*/
 
/* ── ✏️  CHANGE CREDENTIALS HERE ── */
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';
/* ──────────────────────────────── */
 
const adminLoginForm = document.getElementById('adminLoginForm');
const cancelBtn      = document.getElementById('cancelBtn');
const modalBackdrop  = document.getElementById('modalBackdrop');
const loginBtn       = document.getElementById('loginBtn');
const modalError     = document.getElementById('modalError');
const pwToggle       = document.getElementById('pwToggle');
const adminPass      = document.getElementById('adminPass');
 
function closeModal(){
  adminModal.classList.remove('open');
  modalError.classList.remove('show');
}
 
cancelBtn.addEventListener('click', closeModal);
modalBackdrop.addEventListener('click', closeModal);
document.addEventListener('keydown', e => { if(e.key === 'Escape') closeModal(); });
 
pwToggle.addEventListener('click', () => {
  adminPass.type = adminPass.type === 'password' ? 'text' : 'password';
  pwToggle.textContent = adminPass.type === 'password' ? '👁' : '🙈';
});
 
adminLoginForm.addEventListener('submit', e => {
  e.preventDefault();
  const user = document.getElementById('adminUser').value.trim();
  const pass = adminPass.value;
 
  if(!user || !pass){
    showError('Please enter both username and password.');
    return;
  }
 
  loginBtn.disabled  = true;
  loginBtn.innerHTML = '<span class="btn-spinner"></span>Verifying...';
 
  setTimeout(() => {
    loginBtn.disabled  = false;
    loginBtn.innerHTML = 'LOGIN';
 
    if(user === ADMIN_USER && pass === ADMIN_PASS){
      /* ── ✅ Credentials matched ── */
      loginBtn.classList.add('success');
      loginBtn.textContent = '✓ GRANTED';
 
      /* Store in hidden form fields so the form POST carries them */
      document.getElementById('usernameInput').value = user;
      document.getElementById('passwordInput').value = pass;
 
      setTimeout(() => {
        closeModal();
        selectRole(document.getElementById('card-admin'), 'admin');
        loginBtn.classList.remove('success');
        loginBtn.textContent = 'LOGIN';
      }, 800);
 
    } else {
      /* ── ❌ Wrong credentials ── */
      showError('Invalid credentials. Access denied.');
    }
  }, 900);   /* simulated verification delay */
});
 
function showError(msg){
  document.getElementById('errorText').textContent = msg;
  modalError.classList.remove('show');
  void modalError.offsetWidth;   /* force reflow to restart CSS animation */
  modalError.classList.add('show');
}