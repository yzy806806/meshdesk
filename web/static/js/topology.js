/*
 * MeshDesk 3D Topology Visualization
 * ───────────────────────────────────────────────────────────
 * Features:
 *   - Three.js scene with force-directed 3D layout for nodes
 *   - Animated particles flowing along proxy circuit paths (edges)
 *   - SSE real-time updates from /api/topology/events
 *   - Mock-data fallback when no real mesh nodes exist
 *   - OrbitControls for pan/zoom/rotate
 *   - Node hover labels with role, CPU, mem, hostname
 *   - Color-coded nodes by role (entry=blue, relay=orange, exit=green, dashboard=purple)
 *   - Edge thickness/opacity modulated by latency (lower latency = brighter)
 *   - Performance-adaptive: reduces particle count on low FPS
 *
 * Depends: three.min.js (r128), OrbitControls.js
 */
(function() {
  'use strict';

  // ═══════════════════════════════════════════════════════════════
  //  Configuration
  // ═══════════════════════════════════════════════════════════════

  var CONFIG = {
    // Force-directed layout parameters — tuned so nodes spread across
    // the whole viewport instead of clustering in the center.
    layout: {
      repulsion: 4500,      // Coulomb repulsion constant
      springLength: 420,    // Rest length of springs (edges) — wide spacing
      springStrength: 0.02, // Hooke's spring constant (weak → nodes roam)
      damping: 0.85,        // Velocity damping per tick
      centerGravity: 0.0002, // Gravity pulling nodes to center (weak)
      maxVelocity: 14,      // Max velocity per tick
      ticks: 500,           // Total layout ticks before settling
    },
    // Node visual parameters
    node: {
      radius: 14,
      segments: 24,
      maxNodes: 200,       // Safety cap
    },
    // Edge/line parameters
    edge: {
      maxEdges: 500,
      baseOpacity: 0.85,
      lowLatencyOpacity: 1.0,
      glowOpacity: 0.25,
    },
    // Node label parameters
    label: {
      fontSize: 28,
      yOffset: 34,         // Above the node
      color: '#e6edf3',
      haloColor: '#000000',
    },
    // Particle animation along edges
    particles: {
      perEdge: 8,           // Particles per active edge
      size: 2.2,
      speed: 0.45,          // 0..1 per tick along the edge
      color: 0x79c0ff,      // brighter blue
      maxTotal: 2000,       // Total particle cap
    },
    // Background stars
    stars: {
      count: 600,
      size: 1.6,
      spread: 1200,
      color: 0x9db9e8,
    },
    // SSE reconnection
    sse: {
      reconnectDelay: 1000,
      maxReconnectDelay: 10000,
    },
    // Camera
    camera: {
      fov: 60,
      near: 0.1,
      far: 5000,
      initialZ: 900,
    },
    // Mock data (used when API returns empty and ?mock=1 not set)
    mockMode: null, // Will be auto-detected
  };

  // Role → color mapping (using CSS variable palette)
  var ROLE_COLORS = {
    'entry':              0x58a6ff,  // --md-primary (blue)
    'entry+relay':        0xd29922,  // --md-warning (orange)
    'relay':              0xd29922,
    'exit':               0x3fb950,  // --md-success (green)
    'entry+exit':         0x3fb950,
    'relay+exit':         0x3fb950,
    'entry+relay+exit':   0x3fb950,
    'dashboard':          0xbc8cff,  // purple-ish
    'node':               0x8b949e,  // --md-text-secondary (gray)
  };

  function roleColor(role) {
    if (role && ROLE_COLORS[role] !== undefined) return ROLE_COLORS[role];
    return 0x8b949e;
  }

  // hashString returns a stable 0..1 hash of a string (for seeding
  // deterministic pseudo-random node positions).
  function hashString(str) {
    var h = 2166136261;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return ((h >>> 0) % 100000) / 100000;
  }

  // ═══════════════════════════════════════════════════════════════
  //  Three.js Scene Setup
  // ═══════════════════════════════════════════════════════════════

  var scene, camera, renderer, controls;
  var raycaster, mouse;
  var container;
  var nodeGroup, edgeGroup, particleGroup, labelGroup;
  var hoveredObject = null;
  var tooltipVisible = false;      // Tracks tooltip visibility for fade transitions
  var statusHideTimer = null;      // Timer for delayed status hide

  // Data state
  var nodes = [];        // [{id, role, x, y, z, cpu, mem, hostname, status, mesh, velocity, ...}]
  var edges = [];        // [{source, target, latency, bandwidth, line, particles: []}]
  var nodeMap = {};      // id → node object
  var layoutTicks = 0;
  var animationId = null;
  var fpsHistory = [];
  var lastFrameTime = 0;

  function initScene() {
    container = document.getElementById('topology-3d-canvas');
    if (!container) {
      console.error('[Topology] Container #topology-3d-canvas not found');
      return;
    }

    var w = container.clientWidth || 800;
    var h = container.clientHeight || 600;

    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0d1117);  // --md-bg
    scene.fog = new THREE.Fog(0x0d1117, 1200, 3000);

    // Radial gradient background via a large sphere with shader-less trick:
    // use a big BackSide sphere with a canvas gradient texture.
    var bgCanvas = document.createElement('canvas');
    bgCanvas.width = 512;
    bgCanvas.height = 512;
    var bgCtx = bgCanvas.getContext('2d');
    var bgGrad = bgCtx.createRadialGradient(256, 256, 60, 256, 256, 360);
    bgGrad.addColorStop(0, '#1a2436');
    bgGrad.addColorStop(0.5, '#0f1522');
    bgGrad.addColorStop(1, '#0d1117');
    bgCtx.fillStyle = bgGrad;
    bgCtx.fillRect(0, 0, 512, 512);
    var bgTex = new THREE.CanvasTexture(bgCanvas);
    var bgGeo = new THREE.SphereGeometry(3400, 24, 24);
    var bgMat = new THREE.MeshBasicMaterial({ map: bgTex, side: THREE.BackSide, fog: false });
    var bgSphere = new THREE.Mesh(bgGeo, bgMat);
    scene.add(bgSphere);

    // Starfield
    var starGeo = new THREE.BufferGeometry();
    var starPos = new Float32Array(CONFIG.stars.count * 3);
    for (var i = 0; i < CONFIG.stars.count; i++) {
      starPos[i * 3] = (Math.random() - 0.5) * CONFIG.stars.spread;
      starPos[i * 3 + 1] = (Math.random() - 0.5) * CONFIG.stars.spread;
      starPos[i * 3 + 2] = (Math.random() - 0.5) * CONFIG.stars.spread;
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    var starMat = new THREE.PointsMaterial({
      color: CONFIG.stars.color,
      size: CONFIG.stars.size,
      transparent: true,
      opacity: 0.7,
      sizeAttenuation: true,
      fog: false,
    });
    var stars = new THREE.Points(starGeo, starMat);
    scene.add(stars);

    camera = new THREE.PerspectiveCamera(CONFIG.camera.fov, w / h, CONFIG.camera.near, CONFIG.camera.far);
    camera.position.set(0, 0, CONFIG.camera.initialZ);

    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(w, h);
    container.appendChild(renderer.domElement);

    // OrbitControls
    if (typeof THREE.OrbitControls !== 'undefined') {
      controls = new THREE.OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.08;
      controls.rotateSpeed = 0.6;
      controls.zoomSpeed = 0.8;
      controls.panSpeed = 0.6;
      controls.minDistance = 50;
      controls.maxDistance = 2000;
    }

    // Lights
    var ambient = new THREE.AmbientLight(0x404040, 0.6);
    scene.add(ambient);

    var dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
    dirLight.position.set(100, 200, 150);
    scene.add(dirLight);

    var dirLight2 = new THREE.DirectionalLight(0x58a6ff, 0.3);
    dirLight2.position.set(-100, -100, -100);
    scene.add(dirLight2);

    // Groups
    nodeGroup = new THREE.Group();
    edgeGroup = new THREE.Group();
    particleGroup = new THREE.Group();
    labelGroup = new THREE.Group();
    scene.add(edgeGroup);  // edges first (behind nodes)
    scene.add(particleGroup);
    scene.add(nodeGroup);
    scene.add(labelGroup);

    // Grid for spatial reference — finer and slightly brighter
    var gridHelper = new THREE.GridHelper(1200, 30, 0x2d333d, 0x1c2230);
    gridHelper.position.y = -220;
    scene.add(gridHelper);

    // Raycaster for hover
    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    renderer.domElement.addEventListener('mousemove', onMouseMove);
    window.addEventListener('resize', onResize);

    // Start animation loop
    animate();
  }

  // ═══════════════════════════════════════════════════════════════
  //  Node Creation
  // ═══════════════════════════════════════════════════════════════

  function createNode(data) {
    var color = roleColor(data.role);
    var radius = data.status === 'offline' ? CONFIG.node.radius * 0.7 : CONFIG.node.radius;

    // Core sphere — gradient-ish look via higher emissive + fresnel feel
    var geo = new THREE.SphereGeometry(radius, CONFIG.node.segments, CONFIG.node.segments);
    var mat = new THREE.MeshPhongMaterial({
      color: color,
      emissive: color,
      emissiveIntensity: 0.55,
      shininess: 90,
      specular: 0xffffff,
      transparent: data.status === 'offline',
      opacity: data.status === 'offline' ? 0.4 : 1.0,
    });
    var mesh = new THREE.Mesh(geo, mat);

    // Wireframe overlay: color by ZONE (same zone = same ring color,
    // so zone grouping is visible at a glance).
    var zoneRingColor = zoneColor(data.zone);
    var wireGeo = new THREE.SphereGeometry(radius * 1.18, 16, 16);
    var wireMat = new THREE.MeshBasicMaterial({
      color: zoneRingColor,
      wireframe: true,
      transparent: true,
      opacity: 0.5,
    });
    var wireframe = new THREE.Mesh(wireGeo, wireMat);
    mesh.add(wireframe);

    // Glow sprite for online nodes
    if (data.status !== 'offline') {
      var glowTex = createGlowTexture(color);
      var glowMat = new THREE.SpriteMaterial({
        map: glowTex,
        blending: THREE.AdditiveBlending,
        transparent: true,
        opacity: 0.8,
        depthWrite: false,
      });
      var glow = new THREE.Sprite(glowMat);
      glow.scale.set(radius * 6, radius * 6, 1);
      mesh.add(glow);
    }

    // Position from API data
    mesh.position.set(data.x || 0, data.y || 0, data.z || 0);

    // Always-visible hostname label (+ zone tag when known)
    var labelText = data.hostname || data.id.substring(0, 8);
    if (data.zone) labelText += ' [' + data.zone + ']';
    var label = createLabel(labelText);

    var node = {
      id: data.id,
      role: data.role || 'node',
      zone: data.zone || '',
      hostname: data.hostname || '',
      cpu: data.cpu || 0,
      mem: data.mem || 0,
      status: data.status || 'online',
      mesh: mesh,
      label: label,
      wireframe: wireframe,
      velocity: new THREE.Vector3(0, 0, 0),
      // Store initial position for layout
      initialPos: new THREE.Vector3(data.x || 0, data.y || 0, data.z || 0),
    };

    nodeGroup.add(mesh);
    labelGroup.add(label);
    return node;
  }

  // zoneColor maps a zone tag to a distinct ring color (stable hash).
  var ZONE_PALETTE = [
    0x3fb950, 0xd29922, 0xa371f7, 0x79c0ff, 0xf85149,
    0x56d4dd, 0xffa657, 0xbc8cff, 0x7ee787, 0xff7b72
  ];
  function zoneColor(zone) {
    if (!zone) return 0x30363d;
    var h = 0;
    for (var i = 0; i < zone.length; i++) h = (h * 31 + zone.charCodeAt(i)) >>> 0;
    return ZONE_PALETTE[h % ZONE_PALETTE.length];
  }

  // createLabel builds a canvas-text sprite that always shows the
  // node's hostname above it.
  function createLabel(text) {
    var canvas = document.createElement('canvas');
    var ctx = canvas.getContext('2d');
    var fs = CONFIG.label.fontSize;
    canvas.width = 512;
    canvas.height = 128;
    ctx.font = '600 ' + fs + 'px "JetBrains Mono", Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    // Halo
    ctx.shadowColor = CONFIG.label.haloColor;
    ctx.shadowBlur = 12;
    ctx.fillStyle = CONFIG.label.color;
    ctx.fillText(text, 256, 64);
    var tex = new THREE.CanvasTexture(canvas);
    var mat = new THREE.SpriteMaterial({
      map: tex,
      transparent: true,
      depthTest: false,
      sizeAttenuation: true,
    });
    var sprite = new THREE.Sprite(mat);
    sprite.scale.set(180, 45, 1);
    return sprite;
  }

  function createGlowTexture(color) {
    var canvas = document.createElement('canvas');
    canvas.width = 64;
    canvas.height = 64;
    var ctx = canvas.getContext('2d');
    var gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    var hex = '#' + color.toString(16).padStart(6, '0');
    gradient.addColorStop(0, hex);
    gradient.addColorStop(0.3, hex + 'cc');
    gradient.addColorStop(1, hex + '00');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 64, 64);
    var tex = new THREE.Texture(canvas);
    tex.needsUpdate = true;
    return tex;
  }

  function updateNodeMesh(node, data) {
    node.cpu = data.cpu || 0;
    node.mem = data.mem || 0;
    node.hostname = data.hostname || node.hostname;
    var newStatus = data.status || node.status;
    if (newStatus !== node.status) {
      node.status = newStatus;
      var color = roleColor(node.role);
      node.mesh.material.color.setHex(color);
      node.mesh.material.emissive.setHex(color);
      node.mesh.material.opacity = newStatus === 'offline' ? 0.4 : 1.0;
      node.mesh.material.transparent = newStatus === 'offline';
    }
    // Pulsate based on CPU load
    var pulse = 1.0 + (node.cpu / 100) * 0.15 * Math.sin(Date.now() * 0.003);
    node.mesh.scale.setScalar(pulse);
  }

  // ═══════════════════════════════════════════════════════════════
  //  Edge Creation + Particle Animation
  // ═══════════════════════════════════════════════════════════════

  function createEdge(edgeData) {
    var src = nodeMap[edgeData.source];
    var dst = nodeMap[edgeData.target];
    if (!src || !dst) return null;

    var lat = edgeData.latency_ms;
    // Normalize latency to opacity: lower latency = more visible
    var opacity = CONFIG.edge.baseOpacity;
    if (lat >= 0 && lat < 200) {
      opacity = CONFIG.edge.baseOpacity + (1 - lat / 200) * (CONFIG.edge.lowLatencyOpacity - CONFIG.edge.baseOpacity);
    }

    // Transport → color: reality (TLS) = green, udp p2p = blue,
    // 0x4d = amber, relay = grey. Cross-zone edges (Reality) stand out.
    var transportColors = {
      reality: 0x3fb950,
      udp:     0x79c0ff,
      '0x4d':  0xd29922,
      relay:   0x8b949e,
      '':      0x79c0ff
    };
    var lineColor = transportColors[edgeData.transport] || 0x79c0ff;

    var geometry = new THREE.BufferGeometry();
    var positions = new Float32Array([
      src.mesh.position.x, src.mesh.position.y, src.mesh.position.z,
      dst.mesh.position.x, dst.mesh.position.y, dst.mesh.position.z,
    ]);
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    // Bright core line
    var material = new THREE.LineBasicMaterial({
      color: lineColor,
      transparent: true,
      opacity: opacity,
      linewidth: 1,
    });

    var line = new THREE.Line(geometry, material);
    edgeGroup.add(line);

    // Soft glow line (same geometry, wider feel via additive blending)
    var glowGeo = new THREE.BufferGeometry();
    var glowPos = new Float32Array(positions);
    glowGeo.setAttribute('position', new THREE.BufferAttribute(glowPos, 3));
    var glowMat = new THREE.LineBasicMaterial({
      color: lineColor,
      transparent: true,
      opacity: CONFIG.edge.glowOpacity,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    var glowLine = new THREE.Line(glowGeo, glowMat);
    edgeGroup.add(glowLine);

    var edge = {
      source: edgeData.source,
      target: edgeData.target,
      latency: lat,
      bandwidth: edgeData.bandwidth_mbps || -1,
      transport: edgeData.transport || '',
      line: line,
      glowLine: glowLine,
      srcNode: src,
      dstNode: dst,
      particles: [],
    };

    // Create flowing particles for this edge (circuit animation)
    var particleCount = CONFIG.particles.perEdge;
    if (lat >= 0 && lat > 100) particleCount = Math.max(1, particleCount - 2); // fewer particles for high latency

    for (var i = 0; i < particleCount; i++) {
      edge.particles.push(createParticle(edge, i / particleCount));
    }

    return edge;
  }

  function createParticle(edge, initialProgress) {
    if (particleGroup.children.length >= CONFIG.particles.maxTotal) return null;

    var geo = new THREE.SphereGeometry(CONFIG.particles.size, 6, 6);
    var mat = new THREE.MeshBasicMaterial({
      color: CONFIG.particles.color,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
    });
    var mesh = new THREE.Mesh(geo, mat);
    particleGroup.add(mesh);

    return {
      mesh: mesh,
      progress: initialProgress,
      edge: edge,
    };
  }

  function updateEdgePositions() {
    edges.forEach(function(edge) {
      if (!edge.line) return;
      var src = edge.srcNode.mesh.position;
      var dst = edge.dstNode.mesh.position;
      var pos = edge.line.geometry.attributes.position;
      pos.array[0] = src.x; pos.array[1] = src.y; pos.array[2] = src.z;
      pos.array[3] = dst.x; pos.array[4] = dst.y; pos.array[5] = dst.z;
      pos.needsUpdate = true;
      if (edge.glowLine) {
        var gpos = edge.glowLine.geometry.attributes.position;
        gpos.array[0] = src.x; gpos.array[1] = src.y; gpos.array[2] = src.z;
        gpos.array[3] = dst.x; gpos.array[4] = dst.y; gpos.array[5] = dst.z;
        gpos.needsUpdate = true;
      }
    });
  }

  function updateParticles() {
    edges.forEach(function(edge) {
      edge.particles.forEach(function(p) {
        if (!p || !p.mesh) return;

        // Advance along edge
        p.progress += CONFIG.particles.speed * 0.016; // ~60fps assumption
        if (p.progress >= 1.0) p.progress = 0.0;

        var src = edge.srcNode.mesh.position;
        var dst = edge.dstNode.mesh.position;
        p.mesh.position.lerpVectors(src, dst, p.progress);

        // Fade in/out near endpoints
        var fade = 1.0;
        if (p.progress < 0.1) fade = p.progress / 0.1;
        else if (p.progress > 0.9) fade = (1.0 - p.progress) / 0.1;
        p.mesh.material.opacity = 0.9 * fade;
      });
    });
  }

  // ═══════════════════════════════════════════════════════════════
  //  Force-Directed Layout
  // ═══════════════════════════════════════════════════════════════

  function applyForceLayout() {
    if (layoutTicks >= CONFIG.layout.ticks) return;
    if (nodes.length === 0) return;

    var L = CONFIG.layout;

    // Repulsion (Coulomb): all node pairs push apart
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var a = nodes[i].mesh.position;
        var b = nodes[j].mesh.position;
        var dx = a.x - b.x;
        var dy = a.y - b.y;
        var dz = a.z - b.z;
        var distSq = dx * dx + dy * dy + dz * dz;
        if (distSq < 1) distSq = 1; // avoid division by zero
        var dist = Math.sqrt(distSq);
        var force = L.repulsion / distSq;
        var fx = (dx / dist) * force;
        var fy = (dy / dist) * force;
        var fz = (dz / dist) * force;
        nodes[i].velocity.x += fx;
        nodes[i].velocity.y += fy;
        nodes[i].velocity.z += fz;
        nodes[j].velocity.x -= fx;
        nodes[j].velocity.y -= fy;
        nodes[j].velocity.z -= fz;
      }
    }

    // Attraction (Hooke): connected nodes pull together
    edges.forEach(function(edge) {
      var a = edge.srcNode.mesh.position;
      var b = edge.dstNode.mesh.position;
      var dx = b.x - a.x;
      var dy = b.y - a.y;
      var dz = b.z - a.z;
      var dist = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1;
      var force = L.springStrength * (dist - L.springLength);
      var fx = (dx / dist) * force;
      var fy = (dy / dist) * force;
      var fz = (dz / dist) * force;
      edge.srcNode.velocity.x += fx;
      edge.srcNode.velocity.y += fy;
      edge.srcNode.velocity.z += fz;
      edge.dstNode.velocity.x -= fx;
      edge.dstNode.velocity.y -= fy;
      edge.dstNode.velocity.z -= fz;
    });

    // Center gravity + damping + apply velocity
    nodes.forEach(function(node) {
      node.velocity.x -= node.mesh.position.x * L.centerGravity;
      node.velocity.y -= node.mesh.position.y * L.centerGravity;
      node.velocity.z -= node.mesh.position.z * L.centerGravity;

      // Damping
      node.velocity.multiplyScalar(L.damping);

      // Clamp velocity
      var speed = node.velocity.length();
      if (speed > L.maxVelocity) {
        node.velocity.multiplyScalar(L.maxVelocity / speed);
      }

      // Apply
      node.mesh.position.add(node.velocity);

      // Keep the hostname label above the node
      if (node.label) {
        node.label.position.set(
          node.mesh.position.x,
          node.mesh.position.y + CONFIG.node.radius + CONFIG.label.yOffset,
          node.mesh.position.z
        );
      }

      // Update glow sprite scale based on CPU
      var pulse = 1.0 + (node.cpu / 100) * 0.15;
      node.mesh.scale.setScalar(pulse);
    });

    // Update edge geometry after nodes move
    updateEdgePositions();

    layoutTicks++;
    if (layoutTicks >= CONFIG.layout.ticks) {
      console.log('[Topology] Force-directed layout settled after ' + layoutTicks + ' ticks');
    }
  }

  // ═══════════════════════════════════════════════════════════════
  //  Data Loading: REST + SSE
  // ═══════════════════════════════════════════════════════════════

  function loadData() {
    // First, fetch the REST snapshot
    var url = '/api/topology';
    // Auto-detect mock mode: if the page has ?mock=1, use it
    var params = new URLSearchParams(window.location.search);
    if (params.get('mock') === '1') url += '?mock=1';

    fetch(url)
      .then(function(res) { return res.json(); })
      .then(function(data) {
        if (!data.nodes || data.nodes.length === 0) {
          console.log('[Topology] No real mesh data, falling back to mock mode');
          CONFIG.mockMode = true;
          loadMockData();
          return;
        }
        CONFIG.mockMode = false;
        applyTopologySnapshot(data);
        connectSSE();
        updateStats();
      })
      .catch(function(err) {
        console.error('[Topology] Failed to load topology data:', err);
        showStatus('error', 'Failed to load topology data. Using mock data for demonstration.');
        CONFIG.mockMode = true;
        loadMockData();
      });
  }

  function applyTopologySnapshot(snapshot) {
    // Clear existing
    clearScene();

    // Create nodes
    snapshot.nodes.forEach(function(n) {
      if (nodes.length >= CONFIG.node.maxNodes) return;
      var node = createNode(n);
      nodes.push(node);
      nodeMap[n.id] = node;
    });

    // Scatter nodes at random initial positions so the force layout
    // spreads them across the whole viewport instead of starting from
    // the origin (where the API may report x/y/z = 0).
    var spread = CONFIG.layout.springLength * Math.sqrt(nodes.length) * 1.2;
    nodes.forEach(function(node) {
      var seed = hashString(node.id);
      var theta = seed * Math.PI * 2;
      var phi = (seed * 7.13) % Math.PI; // pseudo-random but stable per node
      var r = spread * (0.35 + ((seed * 3.7) % 1) * 0.65);
      node.mesh.position.set(
        r * Math.sin(phi) * Math.cos(theta),
        r * Math.cos(phi) * 0.7,
        r * Math.sin(phi) * Math.sin(theta)
      );
      node.initialPos.copy(node.mesh.position);
    });

    // Create edges
    if (snapshot.edges) {
      snapshot.edges.forEach(function(e) {
        if (edges.length >= CONFIG.edge.maxEdges) return;
        var edge = createEdge(e);
        if (edge) edges.push(edge);
      });
    }

    // Reset layout
    layoutTicks = 0;
    updateStats();
  }

  function applyNodeUpdate(nodeData) {
    var node = nodeMap[nodeData.id];
    if (node) {
      updateNodeMesh(node, nodeData);
    }
  }

  function applyNodeOnline(data) {
    // Refresh full snapshot when a new node appears
    fetch('/api/topology' + (CONFIG.mockMode ? '?mock=1' : ''))
      .then(function(res) { return res.json(); })
      .then(function(snapshot) { applyTopologySnapshot(snapshot); })
      .catch(function() {});
    showStatus('info', 'Node online: ' + (data.hostname || data.id.substring(0, 8)));
  }

  function applyNodeOffline(data) {
    var node = nodeMap[data.id];
    if (node) {
      node.status = 'offline';
      node.mesh.material.transparent = true;
      node.mesh.material.opacity = 0.4;
    }
    showStatus('warn', 'Node offline: ' + (data.hostname || data.id.substring(0, 8)));
  }

  function applyEdgeUpdate(edgeData) {
    // Update existing edge or create new
    var existing = edges.find(function(e) {
      return (e.source === edgeData.source && e.target === edgeData.target) ||
             (e.source === edgeData.target && e.target === edgeData.source);
    });
    if (existing) {
      existing.latency = edgeData.latency_ms;
      existing.bandwidth = edgeData.bandwidth_mbps;
      // Update opacity
      var lat = edgeData.latency_ms;
      var opacity = CONFIG.edge.baseOpacity;
      if (lat >= 0 && lat < 200) {
        opacity = CONFIG.edge.baseOpacity + (1 - lat / 200) * (CONFIG.edge.lowLatencyOpacity - CONFIG.edge.baseOpacity);
      }
      existing.line.material.opacity = opacity;
    } else {
      var edge = createEdge(edgeData);
      if (edge) edges.push(edge);
    }
  }

  // ═══════════════════════════════════════════════════════════════
  //  SSE Connection
  // ═══════════════════════════════════════════════════════════════

  var eventSource = null;
  var sseReconnectDelay = CONFIG.sse.reconnectDelay;

  function connectSSE() {
    if (eventSource) eventSource.close();

    var url = '/api/topology/events';
    if (CONFIG.mockMode) url += '?mock=1';

    eventSource = new EventSource(url);

    eventSource.addEventListener('topology', function(e) {
      sseReconnectDelay = CONFIG.sse.reconnectDelay;
      try {
        applyTopologySnapshot(JSON.parse(e.data));
      } catch (err) {
        console.error('[Topology] SSE topology parse error:', err);
      }
    });

    eventSource.addEventListener('node_update', function(e) {
      try {
        applyNodeUpdate(JSON.parse(e.data));
        updateStats();
      } catch (err) {
        console.error('[Topology] SSE node_update parse error:', err);
      }
    });

    eventSource.addEventListener('node_online', function(e) {
      try {
        applyNodeOnline(JSON.parse(e.data));
      } catch (err) {
        console.error('[Topology] SSE node_online parse error:', err);
      }
    });

    eventSource.addEventListener('node_offline', function(e) {
      try {
        applyNodeOffline(JSON.parse(e.data));
      } catch (err) {
        console.error('[Topology] SSE node_offline parse error:', err);
      }
    });

    eventSource.addEventListener('edge_update', function(e) {
      try {
        applyEdgeUpdate(JSON.parse(e.data));
      } catch (err) {
        console.error('[Topology] SSE edge_update parse error:', err);
      }
    });

    eventSource.addEventListener('open', function() {
      console.log('[Topology] SSE connected');
      showStatus('ok', 'Live updates connected');
    });

    eventSource.onerror = function() {
      console.warn('[Topology] SSE disconnected, reconnecting in ' + sseReconnectDelay + 'ms');
      eventSource.close();
      showStatus('warn', 'Live updates disconnected, reconnecting...');
      setTimeout(function() {
        connectSSE();
        sseReconnectDelay = Math.min(sseReconnectDelay * 1.5, CONFIG.sse.maxReconnectDelay);
      }, sseReconnectDelay);
    };
  }

  // ═══════════════════════════════════════════════════════════════
  //  Mock Data Fallback
  // ═══════════════════════════════════════════════════════════════

  function loadMockData() {
    // Generate deterministic mock data if the backend has no real nodes.
    // This allows frontend development without a running mesh.

    function shortHex(seed) {
      var chars = '0123456789abcdef';
      var s = '';
      var h = 0;
      for (var i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
      for (var i = 0; i < 32; i++) {
        h = (h * 1103515245 + 12345) >>> 0;
        s += chars[h % 16];
      }
      return s;
    }

    function hashPos(id, scale) {
      scale = scale || 300;
      var h = 0;
      for (var i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
      var x = ((h & 0xFF) / 255) * scale * 2 - scale;
      var y = (((h >> 8) & 0xFF) / 255) * scale * 2 - scale;
      var z = (((h >> 16) & 0xFF) / 255) * scale * 2 - scale;
      return { x: x, y: y, z: z };
    }

    var mockNodes = [
      { id: shortHex('entry-us-east'),    role: 'entry',              hostname: 'us-east-entry',    cpu: 23.7, mem: 62.1, status: 'online' },
      { id: shortHex('relay-eu-central'),  role: 'entry+relay',        hostname: 'eu-central-relay', cpu: 45.2, mem: 71.8, status: 'online' },
      { id: shortHex('exit-asia-south'),   role: 'exit',               hostname: 'asia-south-exit',  cpu: 12.3, mem: 38.5, status: 'online' },
      { id: shortHex('dashboard-local'),   role: 'dashboard',          hostname: 'local-dashboard',  cpu: 5.1,  mem: 28.0, status: 'online' },
      { id: shortHex('relay-2-saopaulo'),  role: 'relay',              hostname: 'saopaulo-relay',   cpu: 67.8, mem: 55.2, status: 'online' },
      { id: shortHex('exit-2-tokyo'),      role: 'exit',               hostname: 'tokyo-exit',       cpu: 8.9,  mem: 22.3, status: 'online' },
      { id: shortHex('offline-relay'),     role: 'relay',              hostname: 'offline-relay',    cpu: 0,    mem: 0,    status: 'offline' },
    ];

    // Add positions
    mockNodes.forEach(function(n) {
      var pos = hashPos(n.id);
      n.x = pos.x; n.y = pos.y; n.z = pos.z;
    });

    var mockEdges = [
      { source: mockNodes[0].id, target: mockNodes[1].id, latency_ms: 12.5,  bandwidth_mbps: 940 },
      { source: mockNodes[1].id, target: mockNodes[2].id, latency_ms: 89.3,  bandwidth_mbps: 500 },
      { source: mockNodes[0].id, target: mockNodes[2].id, latency_ms: 156.7, bandwidth_mbps: 250 },
      { source: mockNodes[3].id, target: mockNodes[0].id, latency_ms: 2.1,   bandwidth_mbps: 1000 },
      { source: mockNodes[3].id, target: mockNodes[1].id, latency_ms: 24.8,  bandwidth_mbps: 940 },
      { source: mockNodes[1].id, target: mockNodes[4].id, latency_ms: 134.2, bandwidth_mbps: 800 },
      { source: mockNodes[4].id, target: mockNodes[5].id, latency_ms: 210.5, bandwidth_mbps: 400 },
      { source: mockNodes[2].id, target: mockNodes[5].id, latency_ms: 45.1,  bandwidth_mbps: 950 },
    ];

    // Also try fetching mock data from the backend if the mock package is available
    fetch('/api/topology?mock=1')
      .then(function(res) { return res.json(); })
      .then(function(data) {
        if (data.nodes && data.nodes.length > 0) {
          // Backend mock data is available — use it
          applyTopologySnapshot(data);
          connectSSE();
          updateStats();
          showStatus('ok', 'Mock data mode (backend mock topology)');
        } else {
          // Use client-side mock data
          applyTopologySnapshot({ nodes: mockNodes, edges: mockEdges });
          showStatus('ok', 'Mock data mode (client-side fallback)');
          // Simulate SSE with periodic updates
          startMockSSE();
        }
      })
      .catch(function() {
        // Use client-side mock data
        applyTopologySnapshot({ nodes: mockNodes, edges: mockEdges });
        showStatus('ok', 'Mock data mode (client-side fallback)');
        startMockSSE();
      });
  }

  function startMockSSE() {
    // Simulate periodic metric updates for demo purposes
    setInterval(function() {
      nodes.forEach(function(node) {
        if (node.status === 'offline') return;
        node.cpu = Math.max(0, Math.min(100, node.cpu + (Math.random() - 0.5) * 10));
        node.mem = Math.max(0, Math.min(100, node.mem + (Math.random() - 0.5) * 5));
      });
      updateStats();
    }, 3000);
  }

  // ═══════════════════════════════════════════════════════════════
  //  Hover / Tooltip
  // ═══════════════════════════════════════════════════════════════

  function onMouseMove(event) {
    if (!renderer || !raycaster) return;

    var rect = renderer.domElement.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    var meshes = nodes.map(function(n) { return n.mesh; });
    var intersects = raycaster.intersectObjects(meshes);

    var tooltip = document.getElementById('topology-tooltip');
    if (!tooltip) return;

    if (intersects.length > 0) {
      var hit = intersects[0].object;

      // Edge hover: show transport / latency / bandwidth.
      var hitEdge = edges.find(function(e) { return e.line === hit || e.glowLine === hit; });
      if (hitEdge) {
        var tLabel = { reality: 'Reality TLS', udp: 'UDP p2p', '0x4d': '0x4D direct', relay: 'Relay' }[hitEdge.transport] || 'Unknown';
        tooltip.style.left = (event.clientX - rect.left + 15) + 'px';
        tooltip.style.top = (event.clientY - rect.top + 15) + 'px';
        tooltip.innerHTML =
          '<div class="tt-hostname">Link</div>' +
          '<div class="tt-row"><span>Transport</span><strong>' + tLabel + '</strong></div>' +
          '<div class="tt-row"><span>Ping</span><strong>' + (hitEdge.latency >= 0 ? hitEdge.latency.toFixed(1) + ' ms' : 'n/a') + '</strong></div>' +
          '<div class="tt-row"><span>Bandwidth</span><strong>' + (hitEdge.bandwidth > 0 ? hitEdge.bandwidth.toFixed(1) + ' Mbps' : 'n/a') + '</strong></div>';
        if (!tooltipVisible) {
          tooltipVisible = true;
          tooltip.style.display = 'block';
          MeshAnim.fadeIn(tooltip);
        }
        renderer.domElement.style.cursor = 'pointer';
        return;
      }

      var node = nodes.find(function(n) { return n.mesh === hit; });
      if (node) {
        tooltip.style.left = (event.clientX - rect.left + 15) + 'px';
        tooltip.style.top = (event.clientY - rect.top + 15) + 'px';
        tooltip.innerHTML =
          '<div class="tt-hostname">' + (node.hostname || node.id.substring(0, 8)) + '</div>' +
          (node.zone ? '<div class="tt-row"><span>Zone</span><strong>' + node.zone + '</strong></div>' : '') +
          '<div class="tt-row"><span>Role</span><strong>' + node.role + '</strong></div>' +
          '<div class="tt-row"><span>Status</span><strong class="tt-status-' + node.status + '">' + node.status + '</strong></div>' +
          '<div class="tt-row"><span>CPU</span><strong>' + node.cpu.toFixed(1) + '%</strong></div>' +
          '<div class="tt-row"><span>Mem</span><strong>' + node.mem.toFixed(1) + '%</strong></div>' +
          '<div class="tt-row tt-id"><span>ID</span><code>' + node.id.substring(0, 12) + '…</code></div>';

        if (!tooltipVisible) {
          tooltipVisible = true;
          tooltip.style.display = 'block';
          MeshAnim.fadeIn(tooltip);
        }

        if (hoveredObject !== node.mesh) {
          if (hoveredObject) hoveredObject.material.emissiveIntensity = 0.3;
          hoveredObject = node.mesh;
          hoveredObject.material.emissiveIntensity = 0.6;
        }
        renderer.domElement.style.cursor = 'pointer';
      }
    } else {
      if (tooltipVisible) {
        tooltipVisible = false;
        MeshAnim.fadeOut(tooltip).then(function() {
          tooltip.style.display = 'none';
        });
      }
      if (hoveredObject) {
        hoveredObject.material.emissiveIntensity = 0.3;
        hoveredObject = null;
      }
      renderer.domElement.style.cursor = 'grab';
    }
  }

  // ═══════════════════════════════════════════════════════════════
  //  Scene Management
  // ═══════════════════════════════════════════════════════════════

  function clearScene() {
    // Remove all node meshes
    while (nodeGroup.children.length > 0) {
      var mesh = nodeGroup.children[0];
      if (mesh.geometry) mesh.geometry.dispose();
      if (mesh.material) mesh.material.dispose();
      nodeGroup.remove(mesh);
    }
    // Remove all labels
    while (labelGroup.children.length > 0) {
      var lbl = labelGroup.children[0];
      if (lbl.material) lbl.material.dispose();
      labelGroup.remove(lbl);
    }
    // Remove all edges
    while (edgeGroup.children.length > 0) {
      var line = edgeGroup.children[0];
      if (line.geometry) line.geometry.dispose();
      if (line.material) line.material.dispose();
      edgeGroup.remove(line);
    }
    // Remove all particles
    while (particleGroup.children.length > 0) {
      var p = particleGroup.children[0];
      if (p.geometry) p.geometry.dispose();
      if (p.material) p.material.dispose();
      particleGroup.remove(p);
    }
    nodes = [];
    edges = [];
    nodeMap = {};
  }

  function updateStats() {
    var el = document.getElementById('topology-node-count');
    if (el) el.textContent = nodes.length;

    var el2 = document.getElementById('topology-edge-count');
    if (el2) el2.textContent = edges.length;

    var el3 = document.getElementById('topology-online-count');
    if (el3) {
      var online = nodes.filter(function(n) { return n.status === 'online'; }).length;
      el3.textContent = online;
    }
  }

  function showStatus(level, msg) {
    var el = document.getElementById('topology-status');
    if (!el) return;
    el.textContent = msg;
    el.className = 'topology-status status-' + level;
    el.style.opacity = '';
    el.style.display = 'block';
    // Fade in the status banner
    MeshAnim.fadeIn(el);
    // Cancel any pending hide from a previous call
    if (statusHideTimer) {
      clearTimeout(statusHideTimer);
      statusHideTimer = null;
    }
    // Schedule fade-out for non-warn messages
    if (level !== 'warn') {
      statusHideTimer = setTimeout(function() {
        MeshAnim.fadeOut(el).then(function() {
          el.style.display = 'none';
          statusHideTimer = null;
        });
      }, 5000);
    }
  }

  // ═══════════════════════════════════════════════════════════════
  //  Animation Loop
  // ═══════════════════════════════════════════════════════════════

  function animate() {
    animationId = requestAnimationFrame(animate);

    var now = performance.now();
    var delta = now - lastFrameTime;
    lastFrameTime = now;

    // FPS tracking for performance adaptation
    if (delta > 0) {
      fpsHistory.push(1000 / delta);
      if (fpsHistory.length > 30) fpsHistory.shift();
    }

    // Apply force-directed layout
    applyForceLayout();

    // Update particle positions
    updateParticles();

    // Update controls
    if (controls) controls.update();

    // Render
    renderer.render(scene, camera);

    // Performance adaptation: if FPS drops below 30, reduce particles
    if (fpsHistory.length >= 30) {
      var avgFps = fpsHistory.reduce(function(a, b) { return a + b; }, 0) / fpsHistory.length;
      if (avgFps < 30 && CONFIG.particles.perEdge > 2) {
        CONFIG.particles.perEdge = Math.max(1, CONFIG.particles.perEdge - 1);
        console.log('[Topology] Low FPS (' + avgFps.toFixed(0) + '), reducing particles to ' + CONFIG.particles.perEdge + '/edge');
      }
    }
  }

  function onResize() {
    if (!container || !renderer || !camera) return;
    var w = container.clientWidth || 800;
    var h = container.clientHeight || 600;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h);
  }

  // ═══════════════════════════════════════════════════════════════
  //  Public API
  // ═══════════════════════════════════════════════════════════════

  window.MeshDeskTopology = {
    init: function() {
      // Staggered entrance for page sections
      MeshAnim.staggeredAppear(
        '.topology-header, .topology-toolbar, .topology-canvas-wrapper, .topology-legend',
        80
      );
      initScene();
      if (scene) loadData();
    },
    refresh: function() {
      loadData();
    },
    toggleMock: function() {
      CONFIG.mockMode = !CONFIG.mockMode;
      if (CONFIG.mockMode) {
        loadMockData();
      } else {
        loadData();
      }
    },
    reset: function() {
      clearScene();
      loadData();
    },
  };

  // Auto-init on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      window.MeshDeskTopology.init();
    });
  } else {
    window.MeshDeskTopology.init();
  }

})();
