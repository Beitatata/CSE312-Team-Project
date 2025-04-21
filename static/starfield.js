// starfield.js
// Renders a twinkling starfield background into the <canvas id="stars-canvas">

const starsCanvas = document.getElementById('stars-canvas');
const starsCtx    = starsCanvas.getContext('2d');

// Keep the canvas sized to its CSS-rendered dimensions
function resizeStars() {
  starsCanvas.width  = starsCanvas.clientWidth;
  starsCanvas.height = starsCanvas.clientHeight;
}
window.addEventListener('resize', resizeStars);
resizeStars();

// Create an array of 100 randomly positioned stars
const stars = Array.from({ length: 100 }, () => ({
  x: Math.random() * starsCanvas.width,
  y: Math.random() * starsCanvas.height,
  radius: Math.random() * 2 + 0.5,
  opacity: Math.random() * 0.8 + 0.2
}));

// Draw loop
function drawStars() {
  starsCtx.clearRect(0, 0, starsCanvas.width, starsCanvas.height);
  for (let s of stars) {
    starsCtx.beginPath();
    starsCtx.arc(s.x, s.y, s.radius, 0, Math.PI * 2);
    starsCtx.fillStyle = `rgba(255,255,255,${s.opacity})`;
    starsCtx.fill();
  }
  requestAnimationFrame(drawStars);
}
drawStars();
