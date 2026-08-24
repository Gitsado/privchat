# PrivChat təhlükəsizlik qaydaları

## Qoruma modeli

- Mesaj mətni brauzerdə AES-256-GCM ilə şifrələnir.
- Hər paket üçün ephemeral ECDH açarı, HKDF-SHA256 törətməsi və ECDSA imzası istifadə olunur.
- Şəxsi cihaz açarları export edilə bilməyən `CryptoKey` kimi IndexedDB daxilində saxlanır.
- Backend yalnız ciphertext, açar zərfi və minimum çatdırılma metadatası saxlayır.
- RLS və SECURITY DEFINER RPC-lər hər əməliyyatda istifadəçi, üzvlük, cihaz və rol yoxlaması aparır.

## Deploy qoruması

- Vercel request-time nonce yaradır və CSP-ni `'strict-dynamic'` ilə tətbiq edir.
- `'unsafe-inline'` və `'unsafe-eval'` production CSP-də yoxdur.
- `/chat` və `/admin` keşlənmir və axtarış sistemləri tərəfindən indekslənmir.
- Service worker sənəd, söhbət, admin və dinamik cavabları keşləmir.
- Production source map-ləri bağlıdır və framework identifikasiya başlığı söndürülüb.

## Secret qaydası

- Repoda yalnız publishable açar istifadə oluna bilər.
- `service_role`, database password, JWT secret, SMTP və Vercel tokenləri yalnız platforma secret store-da saxlanmalıdır.
- Secret sızarsa onu repodan silməklə kifayətlənməyin: dərhal rotate edin, sessiyaları ləğv edin və audit qeydlərini yoxlayın.

## Buraxılış qaydası

Hər production deploydan əvvəl lint, build/test və production dependency audit uğurla keçməlidir. Miqrasiyalar əvvəl staging bazasında yoxlanmalı, sonra production-a sıra ilə tətbiq edilməlidir.

## İnsident addımları

1. Vercel production deploy-u qoruyun və lazım olsa əvvəlki sağlam deploy-a rollback edin.
2. Təsirlənmiş açar və sessiyaları rotate/revoke edin.
3. Audit qeydlərini export edib dəyişdirilməyən nüsxədə saxlayın.
4. Zəifliyi bağlayın, test əlavə edin və yalnız tam yoxlamadan sonra yenidən deploy edin.
