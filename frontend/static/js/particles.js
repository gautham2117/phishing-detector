/**
 * particles.js — MAHORAGA Sentinel background particle system
 * Canvas-based floating dots with connection lines.
 * Purple palette to blend with the midnight purple theme.
 * Mouse proximity gently repels nearby particles.
 */

(function () {
  "use strict";

  var canvas  = document.getElementById("bgCanvas");
  if (!canvas) { return; }
  var ctx     = canvas.getContext("2d");

  // ── Config ──────────────────────────────────────────────────────────────
  var CFG = {
    count:        65,
    minR:         1.2,
    maxR:         2.8,
    minSpeed:     0.12,
    maxSpeed:     0.38,
    connectDist:  130,
    mouseRepel:   110,
    mouseForce:   0.025,
    dotOpacity:   0.55,
    lineOpacity:  0.18,
    // Purple palette matching --blue: #7c6af7
    colors: [
      "124,106,247",   // --blue (violet)
      "91, 71, 204",   // deeper purple
      "160,140,255",   // lighter violet
      "180,120,255",   // lavender
    ],
  };

  var W = 0, H = 0;
  var mouse = { x: -9999, y: -9999 };
  var particles = [];
  var raf = null;

  // ── Particle factory ────────────────────────────────────────────────────
  function makeParticle(x, y) {
    var angle = Math.random() * Math.PI * 2;
    var speed = CFG.minSpeed + Math.random() * (CFG.maxSpeed - CFG.minSpeed);
    return {
      x:    x  !== undefined ? x  : Math.random() * W,
      y:    y  !== undefined ? y  : Math.random() * H,
      vx:   Math.cos(angle) * speed,
      vy:   Math.sin(angle) * speed,
      r:    CFG.minR + Math.random() * (CFG.maxR - CFG.minR),
      col:  CFG.colors[Math.floor(Math.random() * CFG.colors.length)],
      op:   0.3 + Math.random() * 0.25,
    };
  }

  // ── Init / resize ────────────────────────────────────────────────────────
  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function init() {
    resize();
    particles = [];
    for (var i = 0; i < CFG.count; i++) {
      particles.push(makeParticle());
    }
  }

  // ── Update ───────────────────────────────────────────────────────────────
  function update() {
    for (var i = 0; i < particles.length; i++) {
      var p = particles[i];

      // Mouse repulsion
      var dx = p.x - mouse.x;
      var dy = p.y - mouse.y;
      var dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < CFG.mouseRepel && dist > 0) {
        var force = (CFG.mouseRepel - dist) / CFG.mouseRepel;
        p.vx += (dx / dist) * force * CFG.mouseForce * 6;
        p.vy += (dy / dist) * force * CFG.mouseForce * 6;
      }

      // Dampen velocity gently
      p.vx *= 0.992;
      p.vy *= 0.992;

      // Maintain minimum speed
      var spd = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
      if (spd < CFG.minSpeed) {
        p.vx = (p.vx / spd) * CFG.minSpeed;
        p.vy = (p.vy / spd) * CFG.minSpeed;
      }

      p.x += p.vx;
      p.y += p.vy;

      // Wrap around edges
      if (p.x < -10)     { p.x = W + 10; }
      if (p.x > W + 10)  { p.x = -10;    }
      if (p.y < -10)     { p.y = H + 10; }
      if (p.y > H + 10)  { p.y = -10;    }
    }
  }

  // ── Draw ─────────────────────────────────────────────────────────────────
  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Connection lines
    for (var i = 0; i < particles.length; i++) {
      for (var j = i + 1; j < particles.length; j++) {
        var a = particles[i];
        var b = particles[j];
        var dx = a.x - b.x;
        var dy = a.y - b.y;
        var d  = Math.sqrt(dx * dx + dy * dy);
        if (d < CFG.connectDist) {
          var alpha = (1 - d / CFG.connectDist) * CFG.lineOpacity;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = "rgba(" + a.col + "," + alpha.toFixed(3) + ")";
          ctx.lineWidth   = 0.6;
          ctx.stroke();
        }
      }
    }

    // Dots
    for (var i = 0; i < particles.length; i++) {
      var p = particles[i];
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(" + p.col + "," + (p.op * CFG.dotOpacity).toFixed(3) + ")";
      ctx.fill();

      // Tiny glow ring on larger dots
      if (p.r > 2.2) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r + 2, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(" + p.col + ",0.06)";
        ctx.fill();
      }
    }
  }

  // ── Loop ─────────────────────────────────────────────────────────────────
  function loop() {
    update();
    draw();
    raf = requestAnimationFrame(loop);
  }

  // ── Events ───────────────────────────────────────────────────────────────
  window.addEventListener("resize", function () {
    resize();
  }, { passive: true });

  window.addEventListener("mousemove", function (e) {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  }, { passive: true });

  window.addEventListener("mouseleave", function () {
    mouse.x = -9999;
    mouse.y = -9999;
  });

  // ── Start ─────────────────────────────────────────────────────────────────
  init();
  loop();

})();