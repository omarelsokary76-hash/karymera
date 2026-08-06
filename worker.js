/**
 * KARYMERA - Worker رئيسي (Static Assets + API)
 * =================================================
 * - أي طلب لملف عادي (index.html, صور, ...) بيتخدم من ASSETS تلقائيًا
 * - /api/load  : يرجع بيانات المتجر من KV
 * - /api/save  : يحفظ بيانات المتجر (محمي بباسورد عبر ADMIN_HASH)
 * - /api/upload: يرفع صورة إلى R2 (بديل عن الروابط الخارجية)
 * - /images/:key: يعرض صورة مخزنة في R2
 * - /api/visit : يزوّد عداد الزوار
 * - /api/visits: يرجع عدد الزوار من غير زيادة
 * - "/" مع ?product=ID: يبدّل صورة/عنوان/وصف المشاركة الخاصة بمنتج معيّن (Open Graph)
 * - "/" من غير product: يستخدم "صورة مشاركة الموقع العامة" (لو محفوظة) بدل الصورة الافتراضية في الكود
 *
 * الإعدادات المطلوبة في wrangler.toml (موجودة بالفعل):
 * - [assets] directory + binding = "ASSETS"
 * - kv_namespaces -> binding = "STORE_KV"
 * - r2_buckets -> binding = "STORE_IMAGES"
 * - Secret يتضاف من الداشبورد: ADMIN_HASH
 */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ===== تحميل بيانات المتجر =====
    if (url.pathname === '/api/load') {
      const data = await env.STORE_KV.get('store_data');
      return new Response(data || '{}', {
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }

    // ===== حفظ بيانات المتجر (محمي بباسورد) =====
    if (url.pathname === '/api/save' && request.method === 'POST') {
      const token = request.headers.get('X-Admin-Token') || '';
      if (!env.ADMIN_HASH || token !== env.ADMIN_HASH) {
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
      if (!env.ADMIN_HASH || token !== env.ADMIN_HASH) {
        return json({ error: 'unauthorized' }, 401);
      }
      if (!env.STORE_IMAGES) {
        return json({ error: 'R2 bucket غير مربوط. لازم تعمل binding اسمه STORE_IMAGES من الداشبورد.' }, 500);
      }

      const contentType = request.headers.get('Content-Type') || 'application/octet-stream';
      const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif', 'image/svg+xml'];
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

    // ===== حذف صورة من R2 =====
    if (url.pathname === '/api/upload' && request.method === 'DELETE') {
      const token = request.headers.get('X-Admin-Token') || '';
      if (!env.ADMIN_HASH || token !== env.ADMIN_HASH) {
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

    // ===== زيادة عداد الزوار =====
    if (url.pathname === '/api/visit') {
      let count = parseInt((await env.STORE_KV.get('visit_count')) || '0', 10);
      count++;
      ctx.waitUntil(env.STORE_KV.put('visit_count', String(count)));
      return json({ count });
    }

    // ===== قراءة عداد الزوار فقط =====
    if (url.pathname === '/api/visits') {
      const count = parseInt((await env.STORE_KV.get('visit_count')) || '0', 10);
      return json({ count });
    }

    // ===== الصفحة الرئيسية / رابط منتج مشارك =====
    const productId = url.searchParams.get('product');
    if (url.pathname === '/' || url.pathname === '/index.html') {
      const assetRes = await env.ASSETS.fetch(request);
      const html = await assetRes.text();
      const htmlResponse = new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });

      const raw = await env.STORE_KV.get('store_data');
      const store = raw ? JSON.parse(raw) : null;
      const product = productId && store && store.products
        ? store.products.find((p) => String(p.id) === String(productId))
        : null;

      // صورة مشاركة الموقع العامة (بتتظبط من لوحة التحكم)، بتستخدم لو مفيش منتج معيّن متشارك
      const siteShareImage = store && store.siteShareImage ? store.siteShareImage : null;

      // لو مفيش منتج محدد ولا صورة مشاركة عامة محفوظة، نسيب الصفحة زي ما هي بالكود الأصلي
      if (!product && !siteShareImage) return htmlResponse;

      const shareUrl = url.toString();
      const imageToUse = product ? product.mainImg : siteShareImage;

      class MetaRewriter {
        element(el) {
          const prop = el.getAttribute('property') || el.getAttribute('name');
          if (product) {
            if (prop === 'og:title' || prop === 'twitter:title') {
              el.setAttribute('content', product.name);
            } else if (prop === 'og:description' || prop === 'twitter:description') {
              const priceText = `${product.price} ج.م`;
              const description = `${product.name} - ${priceText}` +
                (product.oldPrice ? ` (بدل ${product.oldPrice} ج.م)` : '') +
                ' | KARYMERA';
              el.setAttribute('content', description);
            }
          }
          if (prop === 'og:image' || prop === 'twitter:image') {
            el.setAttribute('content', imageToUse);
          } else if (prop === 'og:url') {
            el.setAttribute('content', shareUrl);
          }
        }
      }
      class TitleRewriter {
        element(el) {
          if (product) el.setInnerContent(`${product.name} | KARYMERA`);
        }
      }

      return new HTMLRewriter()
        .on('meta', new MetaRewriter())
        .on('title', new TitleRewriter())
        .transform(htmlResponse);
    }

    // ===== أي حاجة تانية: ملفات ثابتة عادية =====
    return env.ASSETS.fetch(request);
  },
};
