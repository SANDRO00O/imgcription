// assets/fetch.js
const form = document.getElementById('fetchForm');
const status = document.getElementById('status');
const preview = document.getElementById('preview');
const imgOut = document.getElementById('imgOut');
const downloadLink = document.getElementById('downloadLink');

let currentObjectUrl = null;

function b64(arrayBuffer){
  // تحذير: لا تستخدم هذه الدالة على بايتات كبيرة جداً بسبب القيود على spread operator
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
  const baseKey = await crypto.subtle.importKey('raw', pwUtf8, {name:'PBKDF2'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt: salt,
    iterations: iterations,
    hash: 'SHA-256'
  }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return key;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  status.style.color = '';
  status.textContent = 'جاري الطلب...';
  // أخفي المعاينة الآن
  preview.classList.add('hidden');
  // إذا كان هناك object URL سابق، نلغي ربطه حتى لا يتسرب الذاكرة
  if (currentObjectUrl) {
    try { URL.revokeObjectURL(currentObjectUrl); } catch (err) {}
    currentObjectUrl = null;
  }
  imgOut.src = '';
  downloadLink.href = '';
  downloadLink.removeAttribute('download');

  const token = document.getElementById('token').value.trim();
  const password = document.getElementById('password').value;
  if (!token || !password) { status.textContent = 'املأ الحقول'; return; }

  try {
    const resp = await fetch('api/get.php', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify({token})
    });

    if (!resp.ok) {
      status.style.color = '#ffb2b2';
      status.textContent = `خطأ من الخادم: ${resp.status} ${resp.statusText}`;
      return;
    }

    const resJson = await resp.json();
    if (!resJson.success) {
      status.style.color = '#ffb2b2';
      status.textContent = resJson.message || 'لم يتم العثور على الصورة';
      return;
    }

    status.textContent = 'جلب البيانات. محاولة فك التشفير...';
    const cipherBuf = fromB64(resJson.ciphertext);
    const ivBuf = fromB64(resJson.iv);
    const saltBuf = fromB64(resJson.salt);

    // افترض أن saltBuf و ivBuf و cipherBuf هي ArrayBuffer
    const key = await deriveKey(password, new Uint8Array(saltBuf));
    try {
      const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv: new Uint8Array(ivBuf)}, key, cipherBuf);

      // قراءة metaLen (أول 4 بايت) ثم JSON ثم باقي البايتات هي الملف
      const view = new DataView(plainBuf);
      if (view.byteLength < 4) throw new Error('البيانات غير كاملة');
      const metaLen = view.getUint32(0, true); // little-endian
      if (4 + metaLen > view.byteLength) throw new Error('طول الميتا غير صحيح');

      const metaBytes = new Uint8Array(plainBuf.slice(4, 4 + metaLen));
      const fileBytes = new Uint8Array(plainBuf.slice(4 + metaLen));

      const metaJson = new TextDecoder().decode(metaBytes);
      let meta;
      try { meta = JSON.parse(metaJson); } catch (err) { meta = {}; }

      const mime = meta.mime || 'application/octet-stream';
      const origName = meta.original_filename || 'image';

      // عرض الصورة
      const blob = new Blob([fileBytes], {type: mime});
      const url = URL.createObjectURL(blob);
      currentObjectUrl = url;
      imgOut.src = url;
      downloadLink.href = url;
      downloadLink.download = origName;
      downloadLink.textContent = 'تحميل الصورة';
      preview.classList.remove('hidden');
      status.style.color = '#b7ffb2';
      status.textContent = 'تم فك التشفير. يمكنك معاينة الصورة أو تحميلها.';
    } catch (e) {
      status.style.color = '#ffb2b2';
      status.textContent = 'فشل فك التشفير — ربما كلمة المرور خاطئة أو البيانات تالفة.';
      console.error('فشل فك التشفير:', e);
    }
  } catch (err) {
    status.style.color = '#ffb2b2';
    status.textContent = 'حدث خطأ في الاتصال بالخادم';
    console.error('خطأ في fetch:', err);
  }
});