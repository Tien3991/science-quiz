'use strict';
/* Science Quiz: an offline-capable quiz app for young children.
   All quiz content is AES-GCM encrypted on the server; the family password derives the key on the
   device (PBKDF2), and the key is kept on the device so the password is needed only once.
   Progress for each player is stored in IndexedDB on the device. */
(() => {
  const VERSION = '6da2f54feb';
  const QUIZ_SIZE = 5;
  const PRACTICE_SIZE = 10;
  const CONTENT_CACHE = 'sq-content';
  const app = document.getElementById('app');
  const toastEl = document.getElementById('toast');
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---------------------------------------------------------------- DOM helpers
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const c of kids.flat(Infinity)) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  function mount(...nodes) { app.replaceChildren(...nodes); window.scrollTo(0, 0); }
  function toast(msg, ms = 2600) {
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toast.t);
    toast.t = setTimeout(() => toastEl.classList.remove('show'), ms);
  }
  function shuffle(a) {
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }
  const pick = a => a[Math.floor(Math.random() * a.length)];
  const fmtDate = t => new Date(t).toLocaleDateString(undefined, {month: 'short', day: 'numeric'});
  function starsEl(n, cls = '') {
    return h('span', {class: 'stars ' + cls, role: 'img', 'aria-label': `${n} of 3 stars`},
      [0, 1, 2].map(i => h('span', {class: i < n ? 'on' : 'off'}, '★')));
  }
  function loading(text = '') {
    mount(h('div', {class: 'center'}, h('div', {class: 'spinner'}), h('p', {class: 'muted'}, text)));
  }
  function errorCard(text, retry) {
    mount(h('div', {class: 'card unlock'}, h('div', {class: 'logo'}, '😕'), h('h1', null, 'Oops'),
      h('p', null, text), retry && h('button', {class: 'btn primary big', onclick: retry}, 'Try again')));
  }

  // ---------------------------------------------------------------- storage (IndexedDB key/value)
  const store = (() => {
    let dbp = null;
    function open() {
      if (!dbp) {
        dbp = new Promise((res, rej) => {
          const r = indexedDB.open('science-quiz', 1);
          r.onupgradeneeded = () => r.result.createObjectStore('kv');
          r.onsuccess = () => res(r.result);
          r.onerror = () => rej(r.error);
        });
      }
      return dbp;
    }
    async function run(mode, fn) {
      const db = await open();
      return new Promise((res, rej) => {
        const t = db.transaction('kv', mode);
        const req = fn(t.objectStore('kv'));
        t.oncomplete = () => res(req ? req.result : undefined);
        t.onerror = t.onabort = () => rej(t.error);
      });
    }
    const ls = k => 'sq:' + k;
    return {
      async get(k) {
        try { return await run('readonly', s => s.get(k)); } catch (e) {
          try { const v = localStorage.getItem(ls(k)); return v ? JSON.parse(v) : undefined; } catch (e2) { return undefined; }
        }
      },
      async set(k, v) {
        try { await run('readwrite', s => s.put(v, k)); } catch (e) {
          try { localStorage.setItem(ls(k), JSON.stringify(v)); } catch (e2) { /* storage unavailable */ }
        }
      },
      async del(k) {
        try { await run('readwrite', s => s.delete(k)); } catch (e) { /* ignore */ }
        try { localStorage.removeItem(ls(k)); } catch (e) { /* ignore */ }
      },
    };
  })();

  // ---------------------------------------------------------------- crypto & encrypted files
  let CONFIG = null;
  let KEY = null;
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const normPw = pw => pw.trim().toLowerCase().replace(/\s+/g, ' ');

  async function loadConfig() {
    const r = await fetch('config.json', {cache: 'no-cache'});
    if (!r.ok) throw new Error('config ' + r.status);
    CONFIG = await r.json();
  }
  async function deriveKey(pw, extractable) {
    const base = await crypto.subtle.importKey('raw', enc.encode(normPw(pw)), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      {name: 'PBKDF2', salt: unb64(CONFIG.salt), iterations: CONFIG.iter, hash: 'SHA-256'},
      base, {name: 'AES-GCM', length: 256}, extractable, ['decrypt']);
  }
  async function decryptBuf(buf, key = KEY) {
    const u = new Uint8Array(buf);
    return crypto.subtle.decrypt({name: 'AES-GCM', iv: u.subarray(0, 12)}, key, u.subarray(12));
  }
  async function checkKey(key) {
    try { return dec.decode(await decryptBuf(unb64(CONFIG.check), key)) === 'science-quiz-ok'; } catch (e) { return false; }
  }
  async function saveKey(key, pw) {
    try {
      await store.set('key:' + CONFIG.kid, key);
      const back = await store.get('key:' + CONFIG.kid);
      if (back && back.type === 'secret' && await checkKey(back)) return;
    } catch (e) { /* fall through */ }
    try {
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', await deriveKey(pw, true)));
      localStorage.setItem('sq:rawkey:' + CONFIG.kid, btoa(String.fromCharCode(...raw)));
    } catch (e) { /* the key just won't be remembered */ }
  }
  async function loadSavedKey() {
    try {
      const k = await store.get('key:' + CONFIG.kid);
      if (k && k.type === 'secret' && await checkKey(k)) return k;
    } catch (e) { /* ignore */ }
    try {
      const raw = localStorage.getItem('sq:rawkey:' + CONFIG.kid);
      if (raw) {
        const k = await crypto.subtle.importKey('raw', unb64(raw), {name: 'AES-GCM'}, false, ['decrypt']);
        if (await checkKey(k)) return k;
      }
    } catch (e) { /* ignore */ }
    return null;
  }
  async function forgetKey() {
    await store.del('key:' + CONFIG.kid);
    try { localStorage.removeItem('sq:rawkey:' + CONFIG.kid); } catch (e) { /* ignore */ }
    KEY = null;
  }
  const fileURL = name => new URL('c/' + name + '.bin', location.href).href;
  async function getFile(name) {
    const r = await fetch(fileURL(name));
    if (!r.ok) throw new Error('file ' + r.status);
    return decryptBuf(await r.arrayBuffer());
  }
  async function getJSON(name) { return JSON.parse(dec.decode(await getFile(name))); }

  const media = new Map();   // name -> Promise<objectURL>
  const ready = new Map();   // name -> objectURL (already decrypted)
  function mediaURL(name, mime) {
    let p = media.get(name);
    if (!p) {
      p = getFile(name).then(buf => {
        const u = URL.createObjectURL(new Blob([buf], {type: mime}));
        ready.set(name, u);
        return u;
      });
      p.catch(() => media.delete(name));
      media.set(name, p);
    }
    return p;
  }
  function prefetchItem(q) {
    if (!q) return;
    if (q.a) mediaURL(q.a, 'audio/mpeg').catch(() => {});
    if (q.qi) mediaURL(q.qi, 'image/webp').catch(() => {});
    for (const o of q.o) if (o.i) mediaURL(o.i, 'image/webp').catch(() => {});
  }
  function freeMedia() {
    for (const u of ready.values()) URL.revokeObjectURL(u);
    ready.clear();
    media.clear();
  }

  // ---------------------------------------------------------------- sound: question audio, read-aloud, effects
  const player = new Audio();
  player.preload = 'auto';
  let actx = null;
  function silentWav() {
    const sr = 8000, n = 160, b = new ArrayBuffer(44 + n * 2), v = new DataView(b);
    const w = (o, s) => [...s].forEach((c, i) => v.setUint8(o + i, c.charCodeAt(0)));
    w(0, 'RIFF'); v.setUint32(4, 36 + n * 2, true); w(8, 'WAVE'); w(12, 'fmt ');
    v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
    v.setUint32(24, sr, true); v.setUint32(28, sr * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true);
    w(36, 'data'); v.setUint32(40, n * 2, true);
    return URL.createObjectURL(new Blob([b], {type: 'audio/wav'}));
  }
  function unlockSound() {
    // iOS only lets a page play sound after a tap; play silence once inside the first tap.
    try { player.src = silentWav(); const p = player.play(); if (p) p.catch(() => {}); } catch (e) { /* ignore */ }
    try {
      const C = window.AudioContext || window.webkitAudioContext;
      if (C && !actx) actx = new C();
      if (actx && actx.state === 'suspended') actx.resume();
    } catch (e) { /* ignore */ }
    try { if ('speechSynthesis' in window) speechSynthesis.getVoices(); } catch (e) { /* ignore */ }
  }
  function stopSound() {
    try { player.pause(); } catch (e) { /* ignore */ }
    try { if ('speechSynthesis' in window) speechSynthesis.cancel(); } catch (e) { /* ignore */ }
  }
  function playURL(u, btn) {
    stopSound();
    player.src = u;
    if (btn) {
      btn.classList.add('playing');
      player.onended = player.onpause = () => btn.classList.remove('playing');
    }
    const p = player.play();
    if (p) p.catch(() => btn && btn.classList.remove('playing'));
  }
  function playClip(name, btn) {
    const u = ready.get(name);
    if (u) return playURL(u, btn);   // already decrypted: play right inside the tap
    mediaURL(name, 'audio/mpeg').then(url => playURL(url, btn)).catch(() => {});
  }
  function voice() {
    const vs = 'speechSynthesis' in window ? speechSynthesis.getVoices() : [];
    return vs.find(v => /^en[-_]US/i.test(v.lang) && /Samantha|Ava|Allison|Susan|Nicky|Karen/i.test(v.name)) ||
           vs.find(v => /^en[-_]US/i.test(v.lang)) || vs.find(v => /^en/i.test(v.lang)) || null;
  }
  function speak(text, btn) {
    if (!('speechSynthesis' in window) || !text) return;
    stopSound();
    const u = new SpeechSynthesisUtterance(text);
    u.lang = 'en-US';
    u.rate = 0.88;
    u.pitch = 1.05;
    const v = voice();
    if (v) u.voice = v;
    if (btn) {
      btn.classList.add('playing');
      u.onend = u.onerror = () => btn.classList.remove('playing');
    }
    speechSynthesis.speak(u);
  }
  function chime(good) {
    if (!actx || !S.settings.sfx) return;
    try {
      const t = actx.currentTime;
      const notes = good ? [660, 880, 1320] : [330, 247];
      notes.forEach((f, i) => {
        const o = actx.createOscillator();
        const g = actx.createGain();
        o.type = good ? 'triangle' : 'sine';
        o.frequency.value = f;
        const s = t + i * 0.1;
        g.gain.setValueAtTime(0.0001, s);
        g.gain.exponentialRampToValueAtTime(good ? 0.22 : 0.18, s + 0.02);
        g.gain.exponentialRampToValueAtTime(0.0001, s + 0.28);
        o.connect(g).connect(actx.destination);
        o.start(s);
        o.stop(s + 0.32);
      });
    } catch (e) { /* ignore */ }
  }

  // ---------------------------------------------------------------- state, players, progress
  const S = {
    index: null, grades: {}, lessonMap: {}, profiles: [], profile: null, progress: null,
    settings: {sfx: true, autoRead: true},
  };
  const AVATARS = ['🦊', '🐼', '🐯', '🐸', '🦄', '🐙', '🦁', '🐨', '🐵', '🐧', '🐢', '🦖', '🐝', '🐳', '🦉', '🐰'];
  const GRADE_STYLE = {K: {emoji: '🌱'}, 1: {emoji: '🌍'}, 2: {emoji: '🚀'}};
  const PRAISE = ['Great job!', 'You got it!', 'Super!', 'Awesome!', 'Yes! Well done!', 'Nice work!', 'Fantastic!'];
  const TRY = ['Good try!', 'Almost!', 'Nice try!'];

  async function loadProfiles() {
    S.profiles = (await store.get('profiles')) || [];
    const last = await store.get('lastProfile');
    if (last && S.profiles.some(p => p.id === last)) await selectProfile(last);
  }
  async function saveProfiles() { await store.set('profiles', S.profiles); }
  async function selectProfile(id) {
    S.profile = S.profiles.find(p => p.id === id) || null;
    S.progress = S.profile ? ((await store.get('progress:' + id)) || {lessons: {}, questions: {}, last: null}) : null;
    if (S.profile) await store.set('lastProfile', id);
  }
  async function saveProgress() { if (S.profile) await store.set('progress:' + S.profile.id, S.progress); }

  async function loadGrade(gid) {
    if (!S.grades[gid]) {
      const g = S.index.grades.find(x => x.id === gid);
      if (!g) throw new Error('no grade ' + gid);
      const data = await getJSON(g.file);
      const list = [];
      for (const u of data.u) for (const l of u.l) { l.unit = u.t; l.grade = gid; list.push(l); S.lessonMap[l.id] = l; }
      data.list = list;
      S.grades[gid] = data;
    }
    return S.grades[gid];
  }
  function lessonStars(lid) { const r = S.progress.lessons[lid]; return r ? r.s : 0; }
  function gradeStats(gid) {
    const g = S.index.grades.find(x => x.id === gid);
    let played = 0, starsWon = 0, perfect = 0;
    for (const [lid, r] of Object.entries(S.progress.lessons)) {
      if (!lid.startsWith(gid + '-')) continue;
      if (r.s > 0) played++;
      if (r.s === 3) perfect++;
      starsWon += r.s;
    }
    return {total: g.lessons, played, perfect, starsWon};
  }

  // ---------------------------------------------------------------- routing
  function go(hash) { if (location.hash === hash) route(); else location.hash = hash; }
  window.addEventListener('hashchange', () => route());
  async function route() {
    stopSound();
    if (!KEY) return renderUnlock();
    const [view, a, b] = location.hash.replace(/^#\/?/, '').split('/').map(decodeURIComponent);
    if (view === 'parent') return renderParentGate();
    if (!S.profile) return renderProfiles();
    try {
      if (view === 'grade' && a) return await renderGrade(a);
      if (view === 'lesson' && a && b) return await renderLessonIntro(a, b);
      if (view === 'practice' && a) return await startPractice(a);
      if (view === 'profiles') return renderProfiles();
      return renderHome();
    } catch (e) {
      console.error(e);
      errorCard('Something did not load. If this device is offline, connect to the internet and try again.', () => route());
    }
  }

  // ---------------------------------------------------------------- unlock
  function renderUnlock() {
    const input = h('input', {class: 'field', type: 'password', placeholder: 'Family password', autocomplete: 'current-password',
      autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', 'aria-label': 'Family password'});
    const btn = h('button', {class: 'btn primary big', type: 'submit'}, 'Open');
    const msg = h('p', {class: 'msg', role: 'alert'});
    const form = h('form', {class: 'card unlock', onsubmit: async e => {
      e.preventDefault();
      const pw = input.value;
      if (!pw.trim()) return;
      btn.disabled = true;
      btn.textContent = 'Opening…';
      msg.textContent = '';
      try {
        const key = await deriveKey(pw, false);
        if (await checkKey(key)) {
          KEY = key;
          await saveKey(key, pw);
          await afterUnlock();
          return;
        }
        msg.textContent = 'That password is not right. Please try again.';
      } catch (err) {
        msg.textContent = 'Could not check the password on this device.';
      }
      btn.disabled = false;
      btn.textContent = 'Open';
      input.select();
    }},
    h('div', {class: 'logo'}, '🔬'), h('h1', null, 'Science Quiz'),
    h('p', null, 'A grown-up types the family password once. After that, this device remembers it.'),
    input, btn, msg);
    mount(form);
    setTimeout(() => input.focus(), 60);
  }

  // ---------------------------------------------------------------- players
  function renderProfiles() {
    const list = h('div', {class: 'profiles'},
      S.profiles.map(p => h('button', {class: 'profile', onclick: async () => { await selectProfile(p.id); go('#/home'); }},
        h('span', {class: 'av'}, p.avatar), p.name)),
      h('button', {class: 'profile add', onclick: () => renderAddProfile()}, h('span', {class: 'av'}, '＋'), 'Add player'));
    mount(
      h('div', {class: 'topbar'}, h('div', {class: 'title'}, ''), h('button', {class: 'iconbtn', 'aria-label': 'Grown-ups', onclick: () => go('#/parent')}, '⚙️')),
      h('div', {class: 'center'}, h('div', {class: 'hero-emoji'}, '🔬'), h('h1', null, S.profiles.length ? 'Who is playing?' : 'Welcome!'),
        !S.profiles.length && h('p', {class: 'muted', style: 'margin-top:8px;font-size:19px'}, 'Add a player to start.')),
      list);
  }
  function renderAddProfile(edit) {
    let avatar = edit ? edit.avatar : pick(AVATARS);
    const name = h('input', {class: 'field', maxlength: '20', placeholder: 'Name', value: edit ? edit.name : '', 'aria-label': 'Player name', autocomplete: 'off'});
    const grid = h('div', {class: 'avatars'}, AVATARS.map(a => h('button', {type: 'button', class: a === avatar ? 'sel' : '', 'aria-label': 'Avatar ' + a, onclick: e => {
      avatar = a;
      grid.querySelectorAll('button').forEach(b => b.classList.toggle('sel', b === e.currentTarget));
    }}, a)));
    const form = h('form', {class: 'card', style: 'max-width:620px;margin:4vh auto 0', onsubmit: async e => {
      e.preventDefault();
      const n = name.value.trim();
      if (!n) { name.focus(); return; }
      if (edit) { edit.name = n; edit.avatar = avatar; await saveProfiles(); return go('#/parent'); }
      const p = {id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), name: n, avatar};
      S.profiles.push(p);
      await saveProfiles();
      await selectProfile(p.id);
      go('#/home');
    }},
    h('h1', null, edit ? 'Edit player' : 'New player'),
    h('p', {class: 'muted', style: 'margin:6px 0 16px'}, 'Type a name and pick a picture.'),
    name, grid,
    h('div', {class: 'row'}, h('button', {type: 'button', class: 'btn', onclick: () => edit ? go('#/parent') : renderProfiles()}, 'Cancel'),
      h('div', {class: 'spacer'}), h('button', {type: 'submit', class: 'btn go big'}, 'Save')));
    mount(form);
    setTimeout(() => name.focus(), 60);
  }

  // ---------------------------------------------------------------- home
  function isIOS() { return /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1); }
  function isStandalone() { return navigator.standalone === true || matchMedia('(display-mode: standalone)').matches; }
  function whoButton() {
    return h('button', {class: 'who', onclick: () => go('#/profiles'), 'aria-label': 'Change player'},
      h('span', {class: 'av'}, S.profile.avatar), S.profile.name);
  }
  async function renderHome() {
    const top = h('div', {class: 'topbar'}, whoButton(), h('div', {class: 'spacer'}),
      h('button', {class: 'iconbtn', 'aria-label': 'Grown-ups', onclick: () => go('#/parent')}, '⚙️'));
    const parts = [top, h('h1', {class: 'greet'}, `Hi, ${S.profile.name}! 👋`)];
    if (isIOS() && !isStandalone() && !(await store.get('hideInstall'))) {
      const b = h('div', {class: 'banner'}, h('span', {style: 'font-size:30px'}, '📲'),
        h('div', null, h('b', null, 'Install the app: '), 'tap the Share button, then ', h('b', null, 'Add to Home Screen'),
          '. Play from the new icon. Progress is saved inside the installed app.'),
        h('button', {class: 'x', 'aria-label': 'Hide', onclick: async () => { b.remove(); await store.set('hideInstall', true); }}, '✕'));
      parts.push(b);
    }
    const last = S.progress.last;
    if (last && S.index.grades.some(g => g.id === last.g)) {
      parts.push(h('button', {class: 'continue', onclick: () => go(`#/lesson/${last.g}/${last.l}`)},
        h('span', {class: 'big'}, '▶️'),
        h('div', null, 'Keep going', h('small', null, `${last.gt} · Lesson ${last.n}: ${last.t}`))));
    }
    parts.push(h('div', {class: 'grades'}, S.index.grades.map(g => {
      const st = gradeStats(g.id);
      const pct = st.total ? Math.round(100 * st.played / st.total) : 0;
      return h('button', {class: 'grade g-' + g.id, onclick: () => go('#/grade/' + g.id)},
        h('div', {class: 'emoji'}, (GRADE_STYLE[g.id] || {}).emoji || '⭐'),
        h('div', {class: 'name'}, g.title),
        h('div', {class: 'sub'}, `${st.played} of ${st.total} lessons done · ⭐ ${st.starsWon}`),
        h('div', {class: 'bar'}, h('i', {style: `width:${pct}%`})));
    })));
    mount(...parts);
  }

  // ---------------------------------------------------------------- grade
  function practicePool(grade) {
    const out = [];
    for (const l of grade.list) {
      for (const q of l.q) { const s = S.progress.questions[q.id]; if (s && s.lw) out.push(q); }
      for (const q of l.b || []) { const s = S.progress.questions[q.id]; if (s && s.lw) out.push(Object.assign({bonus: true}, q)); }
    }
    return out;
  }
  async function renderGrade(gid) {
    loading('Opening…');
    const g = await loadGrade(gid);
    const mistakes = practicePool(g).length;
    const parts = [h('div', {class: 'topbar'},
      h('button', {class: 'iconbtn', 'aria-label': 'Home', onclick: () => go('#/home')}, '🏠'),
      h('div', {class: 'title'}, g.title), whoButton())];
    if (mistakes) {
      parts.push(h('button', {class: 'continue', style: 'background:#f59e0b;box-shadow:0 5px 0 #b45309', onclick: () => go('#/practice/' + gid)},
        h('span', {class: 'big'}, '🎯'), h('div', null, 'Practice my mistakes', h('small', null, `${mistakes} question${mistakes === 1 ? '' : 's'} to try again`))));
    }
    for (const u of g.u) {
      const done = u.l.filter(l => lessonStars(l.id) > 0).length;
      parts.push(h('section', {class: 'unit'},
        h('div', {class: 'unit-head'}, h('h2', null, u.t), h('span', {class: 'count'}, `${done} / ${u.l.length} done`)),
        h('div', {class: 'tiles'}, u.l.map(l => {
          const s = lessonStars(l.id);
          return h('button', {class: 'tile' + (s === 3 ? ' perfect' : s > 0 ? ' done' : '') + (l.d ? ' drill' : ''), onclick: () => go(`#/lesson/${gid}/${l.id}`)},
            h('span', {class: 'num'}, (l.d ? 'Drill · ' : 'Lesson ') + l.n), h('span', {class: 't'}, l.t), starsEl(s));
        }))));
    }
    mount(...parts);
  }

  // ---------------------------------------------------------------- quiz engine
  function questionPriority(q) {
    const s = S.progress.questions[q.id];
    if (!s) return Math.random() * 0.5;           // never seen
    if (s.lw) return 0.25 + Math.random() * 0.5;   // last answer was wrong
    return 1 + Math.random();                       // already right
  }
  function buildLessonQuiz(lesson) {
    const pool = lesson.q.slice().sort((a, b) => questionPriority(a) - questionPriority(b));
    const items = shuffle(pool.slice(0, Math.min(QUIZ_SIZE, pool.length)));
    for (const b of lesson.b || []) items.push(Object.assign({bonus: true}, b));
    return {kind: 'lesson', lesson, items, i: 0, results: []};
  }
  async function renderLessonIntro(gid, lid) {
    loading('Opening…');
    const g = await loadGrade(gid);
    const lesson = S.lessonMap[lid];
    if (!lesson) return go('#/grade/' + gid);
    const quiz = buildLessonQuiz(lesson);
    prefetchItem(quiz.items[0]);
    prefetchItem(quiz.items[1]);
    const rec = S.progress.lessons[lid];
    mount(
      h('div', {class: 'topbar'}, h('button', {class: 'iconbtn', 'aria-label': 'Back to lessons', onclick: () => go('#/grade/' + gid)}, '⬅️'),
        h('div', {class: 'title'}, g.title), whoButton()),
      h('div', {class: 'card intro'},
        h('span', {class: 'tag'}, `${lesson.unit} · ${lesson.d ? 'Drill' : 'Lesson'} ${lesson.n}`),
        h('h1', null, lesson.t),
        lesson.ob && h('p', {class: 'obj'}, lesson.ob),
        h('p', {class: 'meta'}, `${quiz.items.length} questions`, rec ? ' · Best: ' : '', rec ? starsEl(rec.s) : ''),
        h('button', {class: 'btn go big', onclick: () => { unlockSound(); startQuiz(quiz); }}, rec ? 'Play again ▶' : 'Start ▶')));
  }
  async function startPractice(gid) {
    loading('Opening…');
    const g = await loadGrade(gid);
    const pool = shuffle(practicePool(g)).slice(0, PRACTICE_SIZE);
    if (!pool.length) { toast('No mistakes to practice. Great job!'); return go('#/grade/' + gid); }
    const quiz = {kind: 'practice', grade: g, items: pool, i: 0, results: []};
    prefetchItem(pool[0]);
    prefetchItem(pool[1]);
    mount(
      h('div', {class: 'topbar'}, h('button', {class: 'iconbtn', 'aria-label': 'Back', onclick: () => go('#/grade/' + gid)}, '⬅️'),
        h('div', {class: 'title'}, g.title), whoButton()),
      h('div', {class: 'card intro'}, h('div', {class: 'hero-emoji'}, '🎯'), h('h1', null, 'Practice my mistakes'),
        h('p', {class: 'meta'}, `${pool.length} question${pool.length === 1 ? '' : 's'} to try again`),
        h('button', {class: 'btn go big', onclick: () => { unlockSound(); startQuiz(quiz); }}, 'Start ▶')));
  }
  function startQuiz(quiz) {
    renderQuestion(quiz);
    readQuestion(quiz.items[0], document.querySelector('.speak'), true);
  }
  function optionSentence(q) {
    // read the choices aloud only when every choice has a name (some pictures are unnamed on purpose)
    if (q.o.some(o => !o.l)) return '';
    const labels = q.o.map(o => o.l);
    if (labels.length < 2) return '';
    return ' Is it ' + labels.slice(0, -1).join(', ') + ', or ' + labels[labels.length - 1] + '?';
  }
  function readQuestion(q, btn, auto) {
    if (auto && !S.settings.autoRead) return;
    if (q.a) playClip(q.a, btn);
    else speak(q.t + (q.bonus ? optionSentence(q) : ''), btn);
  }
  function renderQuestion(quiz) {
    const q = quiz.items[quiz.i];
    prefetchItem(quiz.items[quiz.i + 1]);
    const dots = h('div', {class: 'dots', 'aria-label': `Question ${quiz.i + 1} of ${quiz.items.length}`},
      quiz.items.map((_, j) => h('i', {class: j < quiz.i ? (quiz.results[j] ? 'ok' : 'no') : j === quiz.i ? 'cur' : ''})));
    const speakBtn = h('button', {class: 'speak', 'aria-label': 'Hear the question', onclick: e => readQuestion(q, e.currentTarget)}, '🔊');
    const n = q.o.length;
    const showLetters = !q.o.some(o => o.i) && n > 1;
    const buttons = q.o.map((o, j) => {
      const b = h('button', {class: 'opt' + (o.i ? '' : ' textonly'), 'aria-label': o.l || `Choice ${j + 1}`, onclick: () => answer(quiz, j, buttons, feedback)},
        showLetters && h('span', {class: 'letter'}, 'ABCD'[j]));
      if (o.i) {
        const img = h('img', {alt: o.l || '', draggable: 'false'});
        b.append(img);
        mediaURL(o.i, 'image/webp').then(u => { img.src = u; }).catch(() => { img.replaceWith(h('div', {class: 'ph'}, o.l || '?')); });
        if (q.bonus && o.l) b.append(h('span', {class: 'lbl', style: 'font-size:20px'}, o.l));
      } else {
        b.append(h('span', {class: 'lbl'}, o.l));
      }
      return b;
    });
    const qimg = q.qi ? h('img', {class: 'qimg', alt: ''}) : null;
    if (qimg) mediaURL(q.qi, 'image/webp').then(u => { qimg.src = u; }).catch(() => qimg.remove());
    const feedback = h('div', {class: 'feedback', 'aria-live': 'polite'});
    mount(
      h('div', {class: 'qtop'},
        h('button', {class: 'iconbtn', 'aria-label': 'Stop quiz', onclick: () => {
          if (quiz.kind === 'lesson') go(`#/lesson/${quiz.lesson.grade}/${quiz.lesson.id}`); else go('#/grade/' + quiz.grade.id);
        }}, '✕'),
        dots, h('div', {style: 'width:56px'})),
      h('div', {class: 'card'},
        q.bonus && h('span', {class: 'badge bonus'}, '⭐ Bonus question'),
        h('div', {class: 'qcard'}, h('div', {class: 'qt'}, q.t || 'Listen, then choose.'), speakBtn),
        qimg),
      h('div', {class: 'opts n' + Math.min(Math.max(n, 2), 4)}, buttons),
      feedback);
  }
  function answer(quiz, j, buttons, feedback) {
    if (quiz.locked) return;
    quiz.locked = true;
    const q = quiz.items[quiz.i];
    const ok = j === q.k;
    stopSound();
    chime(ok);
    quiz.results.push(ok);
    const st = S.progress.questions[q.id] || {r: 0, w: 0};
    if (ok) st.r++; else st.w++;
    st.lw = !ok;
    st.t = Date.now();
    S.progress.questions[q.id] = st;
    saveProgress();
    buttons.forEach((b, i) => {
      b.disabled = true;
      if (i === q.k) { b.classList.add('right'); b.append(h('span', {class: 'mark'}, '✅')); }
      else if (i === j) { b.classList.add('wrong'); b.append(h('span', {class: 'mark'}, '❌')); }
      else b.classList.add('dim');
    });
    const last = quiz.i === quiz.items.length - 1;
    const next = h('button', {class: 'btn primary big', onclick: () => {
      quiz.locked = false;
      if (last) return renderResults(quiz);
      quiz.i++;
      renderQuestion(quiz);
      readQuestion(quiz.items[quiz.i], document.querySelector('.speak'), true);
    }}, last ? 'Finish 🏁' : 'Next ▶');
    feedback.replaceChildren(...[
      h('div', {class: 'say ' + (ok ? 'ok' : 'no')}, ok ? pick(PRAISE) : `${pick(TRY)} The green one is right.`),
      next,
      !ok && q.w ? h('div', {class: 'why'}, q.w) : null].filter(Boolean));
    if (ok && S.settings.sfx && 'speechSynthesis' in window && S.settings.autoRead) {
      // a short spoken cheer for pre-readers
      setTimeout(() => { if (quiz.locked) speak(feedback.querySelector('.say').textContent); }, 350);
    }
    next.scrollIntoView({behavior: 'smooth', block: 'nearest'});
  }
  function confetti() {
    const box = h('div', {class: 'confetti'});
    const bits = ['🎉', '⭐', '✨', '🎊', '🌟', '💫'];
    for (let i = 0; i < 36; i++) {
      box.append(h('i', {style: `left:${Math.random() * 100}%;animation-duration:${2.2 + Math.random() * 2}s;animation-delay:${Math.random() * 0.8}s`}, pick(bits)));
    }
    document.body.append(box);
    setTimeout(() => box.remove(), 5200);
  }
  async function renderResults(quiz) {
    stopSound();
    const right = quiz.results.filter(Boolean).length;
    const total = quiz.results.length;
    const ratio = total ? right / total : 0;
    const stars = ratio >= 0.9 ? 3 : ratio >= 0.7 ? 2 : ratio >= 0.5 ? 1 : 0;
    let nextLesson = null;
    if (quiz.kind === 'lesson') {
      const l = quiz.lesson;
      const rec = S.progress.lessons[l.id] || {b: 0, s: 0, p: 0};
      rec.b = Math.max(rec.b, ratio);
      rec.s = Math.max(rec.s, stars);
      rec.p++;
      rec.t = Date.now();
      S.progress.lessons[l.id] = rec;
      const list = S.grades[l.grade].list;
      nextLesson = list[list.indexOf(l) + 1] || null;
      const target = stars > 0 && nextLesson ? nextLesson : l;
      S.progress.last = {g: l.grade, l: target.id, n: target.n, t: target.t, gt: S.grades[l.grade].title};
      await saveProgress();
    }
    const emoji = stars === 3 ? '🏆' : stars === 2 ? '🎉' : stars === 1 ? '👍' : '💪';
    const title = stars === 3 ? 'Amazing!' : stars === 2 ? 'Great work!' : stars === 1 ? 'Good job!' : 'Keep practicing!';
    const gid = quiz.kind === 'lesson' ? quiz.lesson.grade : quiz.grade.id;
    mount(h('div', {class: 'card result'},
      h('div', {class: 'hero-emoji'}, emoji),
      h('h1', null, title),
      h('p', {style: 'font-size:22px;font-weight:800;color:#334155'}, `You got ${right} of ${total} right.`),
      starsEl(stars, 'huge'),
      h('div', {class: 'actions'},
        nextLesson && stars > 0 && h('button', {class: 'btn go big', onclick: () => go(`#/lesson/${gid}/${nextLesson.id}`)}, 'Next lesson ▶'),
        h('button', {class: 'btn primary big', onclick: () => {
          unlockSound();
          const again = quiz.kind === 'lesson' ? buildLessonQuiz(quiz.lesson) : {kind: 'practice', grade: quiz.grade, items: shuffle(practicePool(quiz.grade)).slice(0, PRACTICE_SIZE), i: 0, results: []};
          if (!again.items.length) { toast('No mistakes left. Great job!'); return go('#/grade/' + gid); }
          startQuiz(again);
        }}, '🔁 Play again'),
        h('button', {class: 'btn big', onclick: () => go('#/grade/' + gid)}, 'All lessons'))));
    if (stars === 3) confetti();
    if (S.settings.autoRead) speak(`${title} You got ${right} of ${total} right.`);
  }

  // ---------------------------------------------------------------- grown-ups corner
  function renderParentGate() {
    const a = 3 + Math.floor(Math.random() * 7), b = 3 + Math.floor(Math.random() * 7);
    const input = h('input', {class: 'field', inputmode: 'numeric', pattern: '[0-9]*', placeholder: 'Answer', 'aria-label': 'Answer', autocomplete: 'off'});
    const msg = h('p', {class: 'msg'});
    mount(
      h('div', {class: 'topbar'}, h('button', {class: 'iconbtn', 'aria-label': 'Back', onclick: () => history.length > 1 ? history.back() : go('#/home')}, '⬅️'), h('div', {class: 'title'}, 'Grown-ups')),
      h('form', {class: 'card unlock', onsubmit: e => {
        e.preventDefault();
        if (parseInt(input.value, 10) === a * b) renderParent(S.profile ? S.profile.id : (S.profiles[0] || {}).id);
        else { msg.textContent = 'Not quite. This part is for grown-ups.'; input.select(); }
      }}, h('div', {class: 'logo'}, '🔒'), h('h1', null, 'Grown-ups only'), h('p', null, `What is ${a} × ${b}?`), input,
      h('button', {class: 'btn primary big', type: 'submit'}, 'Continue'), msg));
    setTimeout(() => input.focus(), 60);
  }
  async function contentFilesForGrade(gid) {
    const g = await loadGrade(gid);
    const files = new Set([S.index.grades.find(x => x.id === gid).file]);
    for (const l of g.list) for (const q of [...l.q, ...(l.b || [])]) {
      if (q.a) files.add(q.a);
      if (q.qi) files.add(q.qi);
      for (const o of q.o) if (o.i) files.add(o.i);
    }
    return [...files];
  }
  async function saveGradeOffline(gid, onProgress) {
    const list = await contentFilesForGrade(gid);
    const cache = await caches.open(CONTENT_CACHE);
    let i = 0, done = 0, failed = 0;
    await Promise.all(Array.from({length: 6}, async () => {
      while (i < list.length) {
        const url = fileURL(list[i++]);
        try {
          if (!(await cache.match(url))) {
            const r = await fetch(url, {cache: 'no-store'});
            if (r.ok) await cache.put(url, r); else failed++;
          }
        } catch (e) { failed++; }
        done++;
        if (done % 10 === 0 || done === list.length) onProgress(done, list.length);
      }
    }));
    if (!failed) await store.set('offline:' + gid, {t: Date.now(), n: list.length, v: CONFIG.index});
    return {total: list.length, failed};
  }
  async function renderParent(pid) {
    loading('Loading…');
    const who = S.profiles.find(p => p.id === pid) || null;
    const prog = who ? ((who.id === (S.profile && S.profile.id) ? S.progress : await store.get('progress:' + who.id)) || {lessons: {}, questions: {}}) : null;
    const sections = [];
    sections.push(h('div', {class: 'topbar'}, h('button', {class: 'iconbtn', 'aria-label': 'Home', onclick: () => go('#/home')}, '🏠'), h('div', {class: 'title'}, 'Grown-ups corner')));

    // players
    sections.push(h('h2', null, 'Players'));
    sections.push(h('div', {class: 'card'},
      S.profiles.length ? h('div', {class: 'chips'}, S.profiles.map(p => h('button', {class: 'chip' + (who && p.id === who.id ? ' sel' : ''), onclick: () => renderParent(p.id)}, `${p.avatar} ${p.name}`))) : h('p', {class: 'muted'}, 'No players yet.'),
      who && h('div', {class: 'row'},
        h('button', {class: 'btn small', onclick: () => renderAddProfile(who)}, '✏️ Rename'),
        h('button', {class: 'btn small warn', onclick: async () => {
          if (!confirm(`Delete ${who.name} and all of ${who.name}'s progress on this device?`)) return;
          S.profiles = S.profiles.filter(p => p.id !== who.id);
          await saveProfiles();
          await store.del('progress:' + who.id);
          if (S.profile && S.profile.id === who.id) { S.profile = null; S.progress = null; await store.del('lastProfile'); }
          renderParent((S.profiles[0] || {}).id);
        }}, '🗑 Delete player'),
        h('button', {class: 'btn small', onclick: () => renderAddProfile()}, '＋ Add player'))));

    // progress
    if (who && prog) {
      sections.push(h('h2', null, `${who.avatar} ${who.name}'s progress`));
      for (const gi of S.index.grades) {
        const g = await loadGrade(gi.id);
        const rows = g.list.filter(l => prog.lessons[l.id]);
        const done = rows.filter(l => prog.lessons[l.id].s > 0).length;
        const weak = rows.filter(l => prog.lessons[l.id].b < 0.7);
        const card = h('div', {class: 'card'},
          h('div', {class: 'row'}, h('b', {style: 'font-size:20px'}, gi.title), h('div', {class: 'spacer'}), h('span', {class: 'muted'}, `${done} of ${gi.lessons} lessons done`)),
          h('div', {class: 'progress-line'}, h('div', {class: 'bar dark'}, h('i', {style: `width:${Math.round(100 * done / gi.lessons)}%`})), `${Math.round(100 * done / gi.lessons)}%`));
        if (rows.length) {
          const show = rows.slice().sort((a, b) => (prog.lessons[b.id].t || 0) - (prog.lessons[a.id].t || 0)).slice(0, 12);
          card.append(h('p', {style: 'margin:14px 0 6px;font-weight:800'}, 'Recently played'),
            h('table', {class: 'table'}, h('tr', null, h('th', null, 'Lesson'), h('th', null, 'Best'), h('th', null, 'Plays'), h('th', null, 'Last')),
              show.map(l => { const r = prog.lessons[l.id]; return h('tr', null, h('td', null, `${l.n}. ${l.t}`), h('td', {class: 'n'}, `${Math.round(r.b * 100)}%`), h('td', {class: 'n'}, r.p), h('td', {class: 'n'}, r.t ? fmtDate(r.t) : '')); })));
          if (weak.length) card.append(h('p', {style: 'margin:14px 0 4px;font-weight:800;color:#b45309'}, `Needs practice (${weak.length})`),
            h('p', {class: 'muted'}, weak.slice(0, 15).map(l => `${l.n}. ${l.t}`).join(' · ')));
        }
        sections.push(card);
      }
    }

    // offline
    sections.push(h('h2', null, 'Offline'));
    const offCard = h('div', {class: 'card'}, h('p', {class: 'muted', style: 'margin-bottom:12px'}, 'Save a grade on this device so it works without the internet. Each grade is a few dozen MB.'));
    for (const gi of S.index.grades) {
      const flag = await store.get('offline:' + gi.id);
      const status = h('span', {class: 'muted'}, flag && flag.v === CONFIG.index ? `Saved ✓ (${fmtDate(flag.t)})` : 'Not saved');
      const line = h('div', {class: 'progress-line', style: 'display:none'}, h('div', {class: 'bar dark'}, h('i', {style: 'width:0%'})), h('span', null, '0%'));
      const btn = h('button', {class: 'btn small primary', onclick: async () => {
        btn.disabled = true;
        line.style.display = 'flex';
        try {
          const r = await saveGradeOffline(gi.id, (d, t) => { line.querySelector('i').style.width = `${Math.round(100 * d / t)}%`; line.lastChild.textContent = `${d} / ${t}`; });
          status.textContent = r.failed ? `${r.failed} files failed; try again` : `Saved ✓ (${fmtDate(Date.now())})`;
        } catch (e) { status.textContent = 'Could not save; check the internet connection'; }
        btn.disabled = false;
      }}, '⬇️ Save');
      offCard.append(h('div', {style: 'padding:8px 0;border-bottom:1px solid #e2e8f0'}, h('div', {class: 'row'}, h('b', null, gi.title), status, h('div', {class: 'spacer'}), btn), line));
    }
    const usage = h('p', {class: 'muted', style: 'margin-top:12px'});
    if (navigator.storage && navigator.storage.estimate) navigator.storage.estimate().then(e => { usage.textContent = `Storage used on this device: ${(e.usage / 1048576).toFixed(0)} MB`; }).catch(() => {});
    offCard.append(usage, h('div', {class: 'row', style: 'margin-top:10px'}, h('button', {class: 'btn small warn', onclick: async () => {
      if (!confirm('Remove the saved offline files? Progress is kept.')) return;
      await caches.delete(CONTENT_CACHE);
      for (const gi of S.index.grades) await store.del('offline:' + gi.id);
      toast('Offline files removed');
      renderParent(pid);
    }}, 'Remove offline files')));
    sections.push(offCard);

    // backup
    sections.push(h('h2', null, 'Backup'));
    const fileIn = h('input', {type: 'file', accept: 'application/json,.json', style: 'display:none', onchange: async e => {
      const f = e.target.files[0];
      if (!f) return;
      try {
        const data = JSON.parse(await f.text());
        if (data.app !== 'science-quiz' || !Array.isArray(data.profiles)) throw new Error('bad file');
        if (!confirm(`Restore ${data.profiles.length} player(s) from this backup? Players with the same name are replaced.`)) return;
        for (const p of data.profiles) {
          const existing = S.profiles.find(x => x.id === p.id);
          if (existing) Object.assign(existing, {name: p.name, avatar: p.avatar}); else S.profiles.push({id: p.id, name: p.name, avatar: p.avatar});
          await store.set('progress:' + p.id, p.progress || {lessons: {}, questions: {}});
        }
        await saveProfiles();
        if (S.profile) await selectProfile(S.profile.id);
        toast('Backup restored');
        renderParent(pid);
      } catch (err) { toast('That file is not a Science Quiz backup'); }
    }});
    sections.push(h('div', {class: 'card'},
      h('p', {class: 'muted', style: 'margin-bottom:12px'}, 'Progress lives on this device only. Save a backup file now and then, or to move progress to another device.'),
      h('div', {class: 'row'},
        h('button', {class: 'btn small primary', onclick: async () => {
          const profiles = [];
          for (const p of S.profiles) profiles.push(Object.assign({}, p, {progress: (await store.get('progress:' + p.id)) || {}}));
          const blob = new Blob([JSON.stringify({app: 'science-quiz', saved: new Date().toISOString(), profiles}, null, 1)], {type: 'application/json'});
          const name = `science-quiz-backup-${new Date().toISOString().slice(0, 10)}.json`;
          const file = new File([blob], name, {type: 'application/json'});
          if (navigator.canShare && navigator.canShare({files: [file]})) {
            try { await navigator.share({files: [file], title: 'Science Quiz backup'}); return; } catch (e) { if (e && e.name === 'AbortError') return; }
          }
          const a = h('a', {href: URL.createObjectURL(blob), download: name});
          document.body.append(a); a.click(); a.remove();
        }}, '💾 Save backup'),
        h('button', {class: 'btn small', onclick: () => fileIn.click()}, '📂 Restore backup'), fileIn)));

    // settings
    sections.push(h('h2', null, 'Settings'));
    const tog = (key, label) => h('label', {class: 'toggle'}, h('input', {type: 'checkbox', checked: S.settings[key] ? true : null, onchange: async e => { S.settings[key] = e.target.checked; await store.set('settings', S.settings); }}), label);
    sections.push(h('div', {class: 'card'},
      tog('autoRead', 'Read each question aloud automatically'),
      tog('sfx', 'Sound effects and spoken cheers'),
      h('div', {class: 'row', style: 'margin-top:12px'},
        h('button', {class: 'btn small warn', onclick: async () => {
          if (!confirm('Lock the app on this device? The family password will be needed again. Progress is kept.')) return;
          await forgetKey();
          freeMedia();
          S.grades = {};
          S.lessonMap = {};
          go('#/home');
        }}, '🔒 Lock this device')),
      h('p', {class: 'muted', style: 'margin-top:12px;font-size:14px'}, `Version ${VERSION}`)));
    mount(h('div', {class: 'parent'}, sections));
  }

  // ---------------------------------------------------------------- start up
  async function afterUnlock() {
    loading('Opening…');
    try { if (navigator.storage && navigator.storage.persist) navigator.storage.persist(); } catch (e) { /* ignore */ }
    S.settings = Object.assign({sfx: true, autoRead: true}, (await store.get('settings')) || {});
    try {
      S.index = await getJSON(CONFIG.index);
    } catch (e) {
      return errorCard('Could not open the quiz. Connect to the internet and try again.', () => afterUnlock());
    }
    await loadProfiles();
    route();
  }
  async function boot() {
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
    document.addEventListener('pointerdown', unlockSound, {once: true, capture: true});
    loading('');
    try {
      await loadConfig();
    } catch (e) {
      return errorCard('Could not load the quiz. Connect to the internet and try again.', () => boot());
    }
    if (!(window.crypto && crypto.subtle)) return errorCard('This browser cannot open the quiz. Please update the device and use Safari or Chrome.');
    KEY = await loadSavedKey();
    if (KEY) await afterUnlock(); else renderUnlock();
  }
  boot();
})();
