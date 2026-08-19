/**
 * KARYMERA - Worker رئيسي (Static Assets + API)
 * =================================================
 * - أي طلب لملف عادي (index.html, صور, ...) بيتخدم من ASSETS تلقائيًا
 * - /api/load  : يرجع بيانات المتجر من KV
 * - /api/login : الخطوة 1 - يتحقق من كلمة السر الأولى (ADMIN_HASH)، ويرجع توكن جزئي مؤقت
 * - /api/login-step2: الخطوة 2 - يتحقق من كلمة السر الثانية (ADMIN_HASH2) + التوكن الجزئي، ويرجع توكن الأدمن الكامل
 * - /api/save  : يحفظ بيانات المتجر (محمي بتوكن الأدمن)
 * - /api/upload: يرفع صورة إلى R2 (بديل عن الروابط الخارجية)
 * - /images/:key: يعرض صورة مخزنة في R2
 * - "/" مع ?product=ID: يبدّل صورة/عنوان/وصف المشاركة الخاصة بمنتج معيّن (Open Graph)
 * - "/" من غير product: يستخدم "صورة مشاركة الموقع العامة" (لو محفوظة) بدل الصورة الافتراضية في الكود
 *
 * الإعدادات المطلوبة في wrangler.toml (موجودة بالفعل):
 * - [assets] directory + binding = "ASSETS"
 * - kv_namespaces -> binding = "STORE_KV"
 * - r2_buckets -> binding = "STORE_IMAGES"
 * - Secrets تتضاف من الداشبورد: ADMIN_HASH (كلمة السر الأولى)، ADMIN_HASH2 (كلمة السر الثانية)
 */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

// ===== توكن أدمن له صلاحية محدودة =====
// بدل ما التوكن يكون هو نفسه الـ hash الثابت بتاع الباسورد (بيفضل صالح للأبد لو اتسرب)،
// التوكن دلوقتي عبارة عن "وقت انتهاء + توقيع" باستخدام HMAC ومفتاح ADMIN_HASH.
// الطريقة دي مش محتاجة أي تخزين إضافي في KV (stateless بالكامل) - فمفيش أي تعديل على استخدام KV/R2.
const ADMIN_TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 ساعة

async function signPayload(payload, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(sigBuf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function createAdminToken(env) {
  const expiry = Date.now() + ADMIN_TOKEN_TTL_MS;
  const sig = await signPayload(String(expiry), env.ADMIN_HASH);
  return `${expiry}.${sig}`;
}

async function verifyAdminToken(token, env) {
  if (!token || !env.ADMIN_HASH) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [expiryStr, sig] = parts;
  const expiry = Number(expiryStr);
  if (!Number.isFinite(expiry) || Date.now() > expiry) return false;
  const expectedSig = await signPayload(expiryStr, env.ADMIN_HASH);
  return timingSafeEqual(sig, expectedSig);
}

// ===== توكن جزئي مؤقت: بيتصدر بعد ما كلمة السر الأولى تتحقق لوحدها، وبيثبت إن الخطوة الأولى نجحت =====
// موقّع بـ ADMIN_HASH2 عشان محدش يقدر يزوّره حتى لو عرف كلمة السر الأولى بس (لازم يعرف الاتنين).
const PARTIAL_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 دقايق كفاية تكتب كلمة السر الثانية

async function createPartialToken(env) {
  const expiry = Date.now() + PARTIAL_TOKEN_TTL_MS;
  const sig = await signPayload(`partial.${expiry}`, env.ADMIN_HASH2);
  return `${expiry}.${sig}`;
}

async function verifyPartialToken(token, env) {
  if (!token || !env.ADMIN_HASH2) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [expiryStr, sig] = parts;
  const expiry = Number(expiryStr);
  if (!Number.isFinite(expiry) || Date.now() > expiry) return false;
  const expectedSig = await signPayload(`partial.${expiryStr}`, env.ADMIN_HASH2);
  return timingSafeEqual(sig, expectedSig);
}

// ===== Rate limiting لمحاولات تسجيل الدخول (بيستخدم نفس STORE_KV الموجود، مفيش binding جديد) =====
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_SECONDS = 10 * 60; // 10 دقايق

function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

async function isRateLimited(request, env) {
  const ip = getClientIp(request);
  const key = `login_attempts:${ip}`;
  const raw = await env.STORE_KV.get(key);
  const count = raw ? Number(raw) : 0;
  return count >= LOGIN_MAX_ATTEMPTS;
}

async function recordFailedAttempt(request, env) {
  const ip = getClientIp(request);
  const key = `login_attempts:${ip}`;
  const raw = await env.STORE_KV.get(key);
  const count = raw ? Number(raw) : 0;
  await env.STORE_KV.put(key, String(count + 1), { expirationTtl: LOGIN_WINDOW_SECONDS });
}

async function clearFailedAttempts(request, env) {
  const ip = getClientIp(request);
  await env.STORE_KV.delete(`login_attempts:${ip}`);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      // تفاصيل الخطأ الكاملة بتتسجل في الـ logs بتاعة Cloudflare (Workers -> Logs) عشان تقدر تشخّص المشكلة،
      // لكن مش بترجع للزائر عشان محدش يشوف تفاصيل داخلية عن بنية السيرفر.
      console.error('Worker error:', err && err.stack ? err.stack : String(err));
      return new Response(
        'حصل خطأ مؤقت في الموقع، جرب تاني كمان شوية.',
        { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
      );
    }
  },
};

async function handleRequest(request, env, ctx) {
    const url = new URL(request.url);

    // حماية: لو الـ KV اتفصل من المشروع (زي ما حصل بعد الـ Rename)، نوري رسالة واضحة بدل ما الموقع يقفل بالكامل
    if (!env.STORE_KV) {
      return new Response(
        'الموقع مش شغال دلوقتي: الـ KV binding (STORE_KV) مش موجود.\nروح Settings -> Bindings في الداشبورد وضيفه تاني.',
        { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
      );
    }

    // ===== تحميل بيانات المتجر =====
    if (url.pathname === '/api/load') {
      const data = await env.STORE_KV.get('store_data');
      return new Response(data || '{}', {
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }

    // ===== robots.txt: بيسمح لجوجل يزحف على الموقع وبيوجهه لمكان الـ sitemap (استجابة ثابتة، مفيش أي علاقة بالـ KV/R2) =====
    if (url.pathname === '/robots.txt') {
      const robots = `User-agent: *\nAllow: /\n\nSitemap: ${url.origin}/sitemap.xml\n`;
      return new Response(robots, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }

    // ===== sitemap.xml: بيسرد رابط كل منتج عشان جوجل يكتشفهم ويفهرسهم كلهم تلقائيًا (قراءة فقط من KV) =====
    if (url.pathname === '/sitemap.xml') {
      const raw = await env.STORE_KV.get('store_data');
      const store = raw ? JSON.parse(raw) : null;
      const products = (store && Array.isArray(store.products)) ? store.products : [];

      const escapeXml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const today = new Date().toISOString().slice(0, 10);

      const urls = [
        `<url><loc>${escapeXml(url.origin + '/')}</loc><lastmod>${today}</lastmod><changefreq>daily</changefreq><priority>1.0</priority></url>`,
        ...products.map((p) =>
          `<url><loc>${escapeXml(url.origin + '/?product=' + p.id)}</loc><lastmod>${today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>`
        ),
      ].join('');

      const xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`;
      return new Response(xml, {
        headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': 'public, max-age=3600' },
      });
    }

    // ===== الخطوة 1: التحقق من كلمة السر الأولى بس، وإصدار توكن جزئي مؤقت =====
    if (url.pathname === '/api/login' && request.method === 'POST') {
      if (!env.ADMIN_HASH || !env.ADMIN_HASH2) return json({ error: 'ADMIN_HASH أو ADMIN_HASH2 غير مضبوطين' }, 500);

      if (await isRateLimited(request, env)) {
        return json({ error: `محاولات كتير غلط، حاول تاني بعد ${Math.round(LOGIN_WINDOW_SECONDS / 60)} دقايق` }, 429);
      }

      let body;
      try { body = await request.json(); } catch (e) { return json({ error: 'invalid json' }, 400); }
      const password = body && body.password ? String(body.password) : '';
      if (!password) return json({ error: 'محتاج كلمة السر' }, 400);

      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashed = Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');

      if (!timingSafeEqual(hashed, env.ADMIN_HASH)) {
        await recordFailedAttempt(request, env);
        // تأخير بسيط عشان نصعّب محاولات التخمين المتكررة (Brute force) من نفس الطرف
        await new Promise((r) => setTimeout(r, 400));
        return json({ error: 'كلمة السر غير صحيحة' }, 401);
      }

      // كلمة السر الأولى صح - نديه توكن جزئي مؤقت (5 دقايق) يقدر يستخدمه في الخطوة الثانية بس
      const partialToken = await createPartialToken(env);
      return json({ ok: true, partialToken });
    }

    // ===== الخطوة 2: التحقق من كلمة السر الثانية + التوكن الجزئي، وإصدار توكن الأدمن الكامل =====
    if (url.pathname === '/api/login-step2' && request.method === 'POST') {
      if (!env.ADMIN_HASH2) return json({ error: 'ADMIN_HASH2 غير مضبوط' }, 500);

      if (await isRateLimited(request, env)) {
        return json({ error: `محاولات كتير غلط، حاول تاني بعد ${Math.round(LOGIN_WINDOW_SECONDS / 60)} دقايق` }, 429);
      }

      let body;
      try { body = await request.json(); } catch (e) { return json({ error: 'invalid json' }, 400); }
      const password2 = body && body.password2 ? String(body.password2) : '';
      const partialToken = body && body.partialToken ? String(body.partialToken) : '';
      if (!password2 || !partialToken) return json({ error: 'محتاج كلمة السر الثانية' }, 400);

      if (!(await verifyPartialToken(partialToken, env))) {
        return json({ error: 'الجلسة انتهت، ابدأ من كلمة السر الأولى تاني' }, 401);
      }

      const buf2 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password2));
      const hashed2 = Array.from(new Uint8Array(buf2)).map((b) => b.toString(16).padStart(2, '0')).join('');

      if (!timingSafeEqual(hashed2, env.ADMIN_HASH2)) {
        await recordFailedAttempt(request, env);
        await new Promise((r) => setTimeout(r, 400));
        return json({ error: 'كلمة السر غير صحيحة' }, 401);
      }

      await clearFailedAttempts(request, env);
      const token = await createAdminToken(env);
      return json({ ok: true, token });
    }

    // ===== حفظ بيانات المتجر (محمي بباسورد) =====
    if (url.pathname === '/api/save' && request.method === 'POST') {
      const token = request.headers.get('X-Admin-Token') || '';
      if (!(await verifyAdminToken(token, env))) {
        return json({ error: 'unauthorized' }, 401);
      }
      const body = await request.text();
      try {
        JSON.parse(body);
      } catch (e) {
        return json({ error: 'invalid json' }, 400);
      }
      await env.STORE_KV.put('store_data', body);
      return json({ ok: true });
    }

    // ===== رفع صورة إلى R2 (بديل عن الروابط الخارجية) =====
    if (url.pathname === '/api/upload' && request.method === 'POST') {
      const token = request.headers.get('X-Admin-Token') || '';
      if (!(await verifyAdminToken(token, env))) {
        return json({ error: 'unauthorized' }, 401);
      }
      if (!env.STORE_IMAGES) {
        return json({ error: 'R2 bucket غير مربوط. لازم تعمل binding اسمه STORE_IMAGES من الداشبورد.' }, 500);
      }

      const contentType = request.headers.get('Content-Type') || 'application/octet-stream';
      // ملحوظة: SVG اتشالت من القائمة المسموحة عمدًا - ملفات SVG ممكن تحتوي على <script> جواها
      // وتتنفذ في متصفح أي زائر يشوفها (XSS)، فمش آمنة نقبلها من غير تنظيف (sanitization) حقيقي.
      const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif'];
      if (!allowed.includes(contentType)) {
        return json({ error: 'صيغة الصورة غير مدعومة' }, 400);
      }

      const arrayBuffer = await request.arrayBuffer();
      if (arrayBuffer.byteLength === 0) return json({ error: 'ملف فارغ' }, 400);
      if (arrayBuffer.byteLength > 10 * 1024 * 1024) {
        return json({ error: 'الصورة أكبر من 10 ميجابايت' }, 400);
      }

      const ext = contentType.split('/')[1].replace('svg+xml', 'svg');
      const key = `img-${Date.now()}-${Math.random().toString(36).slice(2, 10)}.${ext}`;

      await env.STORE_IMAGES.put(key, arrayBuffer, {
        httpMetadata: { contentType },
      });

      const publicUrl = `${url.origin}/images/${key}`;
      return json({ ok: true, url: publicUrl, key });
    }

    // ===== قائمة كل الصور المخزّنة في R2 (لمكتبة الصور في لوحة التحكم) =====
    if (url.pathname === '/api/images' && request.method === 'GET') {
      const token = request.headers.get('X-Admin-Token') || '';
      if (!(await verifyAdminToken(token, env))) {
        return json({ error: 'unauthorized' }, 401);
      }
      if (!env.STORE_IMAGES) return json({ error: 'R2 bucket غير مربوط' }, 500);

      let images = [];
      let cursor = undefined;
      // R2 list() بترجع لحد 1000 عنصر في المرة، فبنكرر لحد ما ناخد كل الملفات
      do {
        const listed = await env.STORE_IMAGES.list({ cursor, limit: 1000 });
        for (const obj of listed.objects) {
          images.push({
            key: obj.key,
            url: `${url.origin}/images/${obj.key}`,
            size: obj.size,
            uploaded: obj.uploaded,
          });
        }
        cursor = listed.truncated ? listed.cursor : undefined;
      } while (cursor);

      images.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
      return json({ ok: true, images });
    }

    // ===== حذف صورة من R2 =====
    if (url.pathname === '/api/upload' && request.method === 'DELETE') {
      const token = request.headers.get('X-Admin-Token') || '';
      if (!(await verifyAdminToken(token, env))) {
        return json({ error: 'unauthorized' }, 401);
      }
      if (!env.STORE_IMAGES) return json({ error: 'R2 bucket غير مربوط' }, 500);

      const key = url.searchParams.get('key');
      if (!key) return json({ error: 'محتاج key' }, 400);

      await env.STORE_IMAGES.delete(key);
      return json({ ok: true });
    }

    // ===== عرض صورة من R2 =====
    if (url.pathname.startsWith('/images/')) {
      if (!env.STORE_IMAGES) return new Response('R2 bucket غير مربوط', { status: 500 });
      const key = url.pathname.replace('/images/', '');
      const object = await env.STORE_IMAGES.get(key);
      if (!object) return new Response('الصورة غير موجودة', { status: 404 });

      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set('etag', object.httpEtag);
      headers.set('Cache-Control', 'public, max-age=31536000, immutable');
      return new Response(object.body, { headers });
    }

    // ===== الصفحة الرئيسية / رابط منتج مشارك / رابط عنصر شريط متحرك مشارك =====
    const productId = url.searchParams.get('product');
    const citemId = url.searchParams.get('citem');
    if (url.pathname === '/' || url.pathname === '/index.html') {
      const assetRes = await env.ASSETS.fetch(request);
      const html = await assetRes.text();
      const htmlResponse = new Response(html, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          // مهم جدًا: من غير الهيدر ده، أي كاش (سواء Cloudflare Edge Cache أو أي CDN قدام
          // الووركر) ممكن يخزن نسخة الـ HTML بتاعت أول منتج اتفتح على مسار "/"، وبعدين
          // يرجّعها لكل الروابط التانية اللي فيها ?product=ID مختلف (لأن باقي أجزاء الرابط
          // زي بعض)، فتلاقي كل المنتجات بترجع اسم وصورة منتج واحد بس بالغلط.
          // no-store بيمنع أي تخزين مؤقت للصفحة دي تمامًا، فكل رابط منتج بيتولّد فريش كل مرة.
          'Cache-Control': 'no-store, private',
        },
      });

      const raw = await env.STORE_KV.get('store_data');
      const store = raw ? JSON.parse(raw) : null;
      const product = productId && store && store.products
        ? store.products.find((p) => String(p.id) === String(productId))
        : null;
      // عنصر الشريط المتحرك (لو الرابط ده رابط مشاركة مستقل لعنصر شريط: ?citem=ID) - بيانات مستقلة
      // تمامًا (اسم/سعر/صورة) عن المنتج الحقيقي، بغض النظر عن أي ارتباط بينهم (sourceProductId).
      const citem = citemId && store && Array.isArray(store.carouselItems)
        ? store.carouselItems.find((c) => String(c.id) === String(citemId))
        : null;
      // لو عنصر الشريط مالوش صورة خاصة بيه، برضو (زي العرض في الموقع) نرجع لصورة المنتج المرتبط
      // بيه لو موجود، بدل ما تفضل المشاركة من غير صورة خالص.
      const citemSourceProduct = citem && citem.sourceProductId != null && store && Array.isArray(store.products)
        ? store.products.find((p) => String(p.id) === String(citem.sourceProductId))
        : null;
      const citemImage = citem ? (citem.mainImg || (citemSourceProduct ? citemSourceProduct.mainImg : null)) : null;
      // كل منتجات المتجر - محتاجينها عشان نحقن نسخة أساسية من شبكة المنتجات في الصفحة الرئيسية
      // (بدون منتج محدد)، عشان أي بوت أو أداة مبتشغلش جافاسكريبت تقدر تشوف المنتجات فعليًا
      // بدل ما تلاقي متجر فاضي تمامًا - زي ما كان بيحصل قبل كده.
      const productsList = (store && Array.isArray(store.products)) ? store.products : [];

      // صورة مشاركة الموقع العامة (بتتظبط من لوحة التحكم)، بتستخدم لو مفيش منتج معيّن متشارك
      const siteShareImage = store && store.siteShareImage ? store.siteShareImage : null;

      // لو مفيش منتج محدد، ومفيش عنصر شريط محدد، ومفيش صورة مشاركة عامة، ومفيش أي منتجات أصلاً نحقنها، نسيب الصفحة زي ما هي
      if (!product && !citem && !siteShareImage && productsList.length === 0) return htmlResponse;

      const shareUrl = url.toString();
      // صورة المشاركة (لواتساب/فيسبوك) بتستخدم دايمًا صورة المنتج الرئيسية نفسها، بغض النظر
      // عن أي صورة مستقلة اتحطت للمنتج ده في "الشريط المتحرك". الشريط ممكن يتعدّل بصورة/اسم/سعر
      // مختلف تمامًا لأغراض العرض بس (زي عروض ترويجية)، وده مقصود يفضل مستقل عن صفحة المنتج
      // الحقيقية - فمينفعش نسيبه يتحكم في اللي بيظهر لما حد يشارك رابط المنتج نفسه، عشان محدش
      // يشارك رابط منتج ويطلعله صورة/بيانات حاجة تانية في المعاينة. في المقابل، رابط مشاركة عنصر
      // الشريط نفسه (?citem=) بيستخدم بيانات عنصر الشريط المستقلة هو (اسمه/سعره/صورته)، حتى لو
      // مختلفة تمامًا عن المنتج الأصلي المرتبط بيه - لأنه ده بالظبط المطلوب: استقلالية كاملة.
      const imageToUse = product ? product.mainImg : (citem ? citemImage : siteShareImage);
      const descriptionToUse = product
        ? `${product.name} - ${product.price} ج.م` + (product.oldPrice ? ` (بدل ${product.oldPrice} ج.م)` : '') + ' | KARYMERA'
        : citem
          ? `${citem.name} - ${citem.price} ج.م` + (citem.oldPrice ? ` (بدل ${citem.oldPrice} ج.م)` : '') + (citem.promoText ? ` | ${citem.promoText}` : '') + ' | KARYMERA'
          : null;

      class MetaRewriter {
        element(el) {
          const prop = el.getAttribute('property') || el.getAttribute('name');
          if (product || citem) {
            if (prop === 'og:title' || prop === 'twitter:title') {
              el.setAttribute('content', product ? product.name : citem.name);
            } else if (prop === 'og:description' || prop === 'twitter:description' || prop === 'description') {
              // بنظبط meta description كمان (مش بس og:description)، لأن جوجل بيستخدمها هي تحديدًا لعرض المقتطف في نتائج البحث
              el.setAttribute('content', descriptionToUse);
            }
          }
          if (prop === 'og:image' || prop === 'twitter:image') {
            // مهم: لو مفيش صورة منتج ولا صورة مشاركة عامة متظبطة (imageToUse = null/undefined)،
            // سيب الـ tag زي ما هو (الصورة الافتراضية og-image.png المكتوبة أصلاً في الـHTML)
            // بدل ما setAttribute يحوّل null لسترينج حرفي "null" ويكسر الصورة تمامًا.
            if (imageToUse) el.setAttribute('content', imageToUse);
          } else if ((prop === 'og:image:width' || prop === 'og:image:height') && imageToUse) {
            // نشيل الأبعاد بس لما فيه صورة فعلية بنستبدلها (منتج أو صورة مشاركة عامة)،
            // عشان منشيلش أبعاد og-image.png الافتراضية في الحالة اللي مفيش فيها استبدال أصلاً.
            el.remove();
          } else if (prop === 'og:url') {
            el.setAttribute('content', shareUrl);
          }
        }
      }
      class TitleRewriter {
        element(el) {
          if (product) el.setInnerContent(`${product.name} | KARYMERA`);
          else if (citem) el.setInnerContent(`${citem.name} | KARYMERA`);
        }
      }
      class CanonicalRewriter {
        element(el) {
          el.setAttribute('href', shareUrl);
        }
      }
      // بيانات منتج منظّمة (JSON-LD) عشان جوجل يقدر يعرض السعر وحالة التوفر جنب نتيجة البحث مباشرة
      class HeadStructuredData {
        element(el) {
          if (!product && !citem) return;
          const entity = product || citem;
          const jsonLd = {
            '@context': 'https://schema.org',
            '@type': 'Product',
            name: entity.name,
            image: [product ? product.mainImg : citemImage].filter(Boolean),
            description: descriptionToUse,
            offers: {
              '@type': 'Offer',
              url: shareUrl,
              priceCurrency: 'EGP',
              price: entity.price,
              availability: entity.available === false
                ? 'https://schema.org/OutOfStock'
                : 'https://schema.org/InStock',
            },
          };
          el.append(`<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>`, { html: true });
        }
      }

      // بيحقن محتوى المنتج الحقيقي (اسم/صورة/سعر/وصف) جوه الـ HTML نفسه لما حد يفتح رابط منتج معيّن،
      // عشان أي بوت أو متصفح ميشغلش جافاسكريبت يشوف محتوى حقيقي فورًا بدل صفحة فاضية.
      // بمجرد ما تطبيق الموقع (SPA) يشتغل، المودال الحقيقي بيتفتح فوقه ويغطيه بالكامل، وبعد شوية بيتشال من الصفحة تلقائيًا.
      const escapeHtml = (s) =>
        String(s == null ? '' : s)
          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

      class BodySsrContent {
        element(el) {
          if (product) {
            const priceHtml = `${escapeHtml(product.price)} ج.م` +
              (product.oldPrice ? ` <span style="text-decoration:line-through;color:#999;font-size:0.9rem;">${escapeHtml(product.oldPrice)} ج.م</span>` : '');
            const html = `
<div id="ssrProductContent" style="max-width:800px;margin:90px auto 20px;padding:0 20px;font-family:Tahoma,Arial,sans-serif;direction:rtl;text-align:right;color:#222;background:#fff;">
  <h1 style="font-size:1.4rem;margin:0 0 10px;">${escapeHtml(product.name)}</h1>
  ${product.mainImg ? `<img src="${escapeHtml(product.mainImg)}" alt="${escapeHtml(product.name)}" style="max-width:100%;max-height:400px;display:block;border-radius:12px;margin:0 0 12px;">` : ''}
  <p style="font-size:1.3rem;font-weight:bold;color:#e67e22;margin:0 0 10px;">${priceHtml}</p>
  ${product.desc ? `<p style="line-height:1.6;">${escapeHtml(product.desc)}</p>` : ''}
</div>
<script>setTimeout(function(){var el=document.getElementById('ssrProductContent'); if(el) el.style.display='none';}, 1500);</script>`;
            el.prepend(html, { html: true });
          } else if (citem) {
            // نفس فكرة SSR بتاعة المنتج، لكن ببيانات عنصر الشريط المستقلة (اسمه/سعره/صورته هو،
            // مش بيانات المنتج الأصلي - عشان الاستقلالية تكون كاملة حتى في المحتوى اللي البوتات بتشوفه)
            const priceHtml = `${escapeHtml(citem.price)} ج.م` +
              (citem.oldPrice ? ` <span style="text-decoration:line-through;color:#999;font-size:0.9rem;">${escapeHtml(citem.oldPrice)} ج.م</span>` : '');
            const html = `
<div id="ssrProductContent" style="max-width:800px;margin:90px auto 20px;padding:0 20px;font-family:Tahoma,Arial,sans-serif;direction:rtl;text-align:right;color:#222;background:#fff;">
  <h1 style="font-size:1.4rem;margin:0 0 10px;">${escapeHtml(citem.name)}</h1>
  ${citemImage ? `<img src="${escapeHtml(citemImage)}" alt="${escapeHtml(citem.name)}" style="max-width:100%;max-height:400px;display:block;border-radius:12px;margin:0 0 12px;">` : ''}
  <p style="font-size:1.3rem;font-weight:bold;color:#e67e22;margin:0 0 10px;">${priceHtml}</p>
  ${citem.promoText ? `<p style="line-height:1.6;">${escapeHtml(citem.promoText)}</p>` : ''}
</div>
<script>setTimeout(function(){var el=document.getElementById('ssrProductContent'); if(el) el.style.display='none';}, 1500);</script>`;
            el.prepend(html, { html: true });
          }
        }
      }

      // بيانات منظمة (ItemList) لقائمة المنتجات في الصفحة الرئيسية - بتفيد جوجل يفهم إن الصفحة فيها كتالوج منتجات حقيقي
      class HomeStructuredData {
        element(el) {
          if (product || citem || productsList.length === 0) return;
          const itemListElement = productsList.slice(0, 50).map((p, idx) => ({
            '@type': 'ListItem',
            position: idx + 1,
            item: {
              '@type': 'Product',
              name: p.name,
              image: [p.mainImg].filter(Boolean),
              offers: {
                '@type': 'Offer',
                url: `${url.origin}/?product=${p.id}`,
                priceCurrency: 'EGP',
                price: p.price,
                availability: p.available === false ? 'https://schema.org/PreOrder' : 'https://schema.org/InStock',
              },
            },
          }));
          const jsonLd = { '@context': 'https://schema.org', '@type': 'ItemList', itemListElement };
          el.append(`<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>`, { html: true });
        }
      }

      // بيحقن شبكة مبسطة من المنتجات (صورة/اسم/سعر) جوه الصفحة الرئيسية نفسها لما محدش بيفتح منتج معيّن،
      // عشان أي بوت أو أداة مبتشغلش جافاسكريبت تلاقي كتالوج حقيقي بدل متجر فاضي.
      // بمجرد ما تطبيق الموقع (SPA) يشتغل، الشبكة الحقيقية بتظهر فوقها وتغطيها، وبعد شوية بتتشال تلقائيًا.
      class HomeGridSsrContent {
        element(el) {
          if (product || citem || productsList.length === 0) return;
          const cards = productsList.slice(0, 24).map((p) => {
            const priceHtml = `${escapeHtml(p.price)} ج.م` +
              (p.oldPrice ? ` <span style="text-decoration:line-through;color:#999;font-size:0.8rem;">${escapeHtml(p.oldPrice)} ج.م</span>` : '');
            return `<a href="${escapeHtml(url.origin + '/?product=' + p.id)}" style="display:block;text-decoration:none;color:#222;border:1px solid #eee;border-radius:10px;padding:8px;">
  ${p.mainImg ? `<img src="${escapeHtml(p.mainImg)}" alt="${escapeHtml(p.name)}" style="width:100%;height:140px;object-fit:contain;display:block;margin-bottom:6px;">` : ''}
  <div style="font-size:0.85rem;margin-bottom:4px;">${escapeHtml(p.name)}</div>
  <div style="font-weight:bold;color:#e67e22;">${priceHtml}</div>
</a>`;
          }).join('');
          const html = `
<div id="ssrHomeGrid" style="max-width:1200px;margin:90px auto 20px;padding:0 16px;font-family:Tahoma,Arial,sans-serif;direction:rtl;">
  <h1 style="font-size:1.2rem;margin:0 0 14px;">منتجاتنا</h1>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;">${cards}</div>
</div>
<script>setTimeout(function(){var el=document.getElementById('ssrHomeGrid'); if(el) el.style.display='none';}, 1500);</script>`;
          el.prepend(html, { html: true });
        }
      }

      return new HTMLRewriter()
        .on('meta', new MetaRewriter())
        .on('title', new TitleRewriter())
        .on('link[rel="canonical"]', new CanonicalRewriter())
        .on('head', new HeadStructuredData())
        .on('head', new HomeStructuredData())
        .on('body', new BodySsrContent())
        .on('body', new HomeGridSsrContent())
        .transform(htmlResponse);
    }

    // ===== أي حاجة تانية: ملفات ثابتة عادية =====
    return env.ASSETS.fetch(request);
}
