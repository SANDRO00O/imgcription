// assets/upload.js
// Client-side E2E: تشفير metadata+file معاً، توليد token آمن، ثم إرسال البيانات المشفّرة إلى الخادم.

const form = document.getElementById('uploadForm');
const fileInput = document.getElementById('file');
const status = document.getElementById('status');
const btnReset = document.getElementById('btnReset');
const tokenBox = document.getElementById('tokenBox');
const tokenVal = document.getElementById('tokenVal');

function b64(arrayBuffer){
  return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}
function fromB64(b64str){
  const binary = atob(b64str);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKey(password, salt, iterations = 200000){
  const pwUtf8 = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', pwUtf8, 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt: salt,
    iterations: iterations,
    hash: 'SHA-256'
  }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return key;
}

function genToken(len = 24){
  const arr = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  status.style.color = '';
  status.textContent = 'جاري التحضير...';
  tokenBox.classList.add('hidden');
  tokenVal.textContent = '';

  const displayName = document.getElementById('displayName').value.trim();
  const password = document.getElementById('password').value;
  const file = fileInput.files[0];
  if (!file) { status.textContent = 'اختر ملف صورة.'; return; }
  if (password.length < 8) { status.textContent = 'اختر كلمة مرور أقوى (نوصي 12+ حرف).'; return; }

  try {
    // قراءة الملف كـ ArrayBuffer
    const fileBuf = await file.arrayBuffer();

    // metadata JSON
    const meta = { original_filename: file.name, mime: file.type || 'application/octet-stream', displayName: displayName || null };
    const metaJson = new TextEncoder().encode(JSON.stringify(meta));

    // تحضير حزمة بيانات: [4 bytes metaLen][metaJson][fileBytes]
    const metaLenBuf = new Uint32Array([metaJson.byteLength]).buffer; // little-endian by default
    const totalLen = 4 + metaJson.byteLength + fileBuf.byteLength;
    const combined = new Uint8Array(totalLen);
    combined.set(new Uint8Array(metaLenBuf), 0);
    combined.set(new Uint8Array(metaJson), 4);
    combined.set(new Uint8Array(fileBuf), 4 + metaJson.byteLength);

    // توليد salt و iv
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // اشتقاق المفتاح
    status.textContent = 'اشتقاق المفتاح...';
    const key = await deriveKey(password, salt);

    // تشفير (AES-GCM)
    status.textContent = 'جاري التشفير...';
    const cipherBuffer = await crypto.subtle.encrypt({name:'AES-GCM', iv: iv}, key, combined.buffer);

    // توليد token آمن للمستخدم
    const token = genToken(24);

    // إرسال الـ payload
    const payload = {
      token: token,
      ciphertext: b64(cipherBuffer),
      iv: b64(iv.buffer),
      salt: b64(salt.buffer),
      size: cipherBuffer.byteLength
    };

    status.textContent = 'رفع البيانات إلى الخادم...';
    const resp = await fetch('api/upload.php', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify(payload)
    });
    const resJson = await resp.json();
    if (resJson.success) {
      status.style.color = '#b7ffb2';
      status.textContent = 'تم الرفع بأمان! احفظ الـ token لاسترجاع الصورة لاحقًا.';
      tokenVal.textContent = token;
      tokenBox.classList.remove('hidden');
      form.reset();
    } else {
      status.style.color = '#ffb2b2';
      status.textContent = 'فشل: ' + (resJson.message || 'خطأ غير معروف');
    }
  } catch (err) {
    console.error(err);
    status.style.color = '#ffb2b2';
    status.textContent = 'حدث خطأ أثناء التشفير أو الرفع.';
  }
});

btnReset.addEventListener('click', () => {
  form.reset();
  status.textContent = '';
  tokenBox.classList.add('hidden');
  tokenVal.textContent = '';
});