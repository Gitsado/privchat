# PrivChat

Ucdan-uca şifrəli, Vercel üzərində işləyən şəxsi mesajlaşma tətbiqi.

## Lokal işə salma

Node.js 22.13+ və pnpm tələb olunur.

1. `.env.example` faylını `.env.local` kimi kopyalayın.
2. Öz backend URL-inizi, publishable açarınızı və sayt ünvanınızı yazın.
3. `pnpm install --frozen-lockfile` və `pnpm dev` işlədin.

Brauzer mühitində yalnız publishable açar istifadə olunur. `service_role`, verilənlər bazası parolu və JWT signing secret heç vaxt `NEXT_PUBLIC_` dəyişəninə və ya repoya yazılmamalıdır.

## Verilənlər bazası

Yeni bazada faylları bu sıra ilə işlədin:

1. `supabase/schema.sql`
2. `supabase/migrations/003_final_security_hardening.sql`
3. `supabase/migrations/004_abuse_and_privilege_hardening.sql`

Əvvəlki baza sxemi artıq tətbiq olunubsa, çatışmayan miqrasiyaları sıra ilə işlədin. `004` miqrasiyası mesaj/söhbət/şikayət limitlərini, sərt funksiya icazələrini və məlumat saxlama təmizləyicilərini əlavə edir.

İlk admin hesabı yaradıldıqdan sonra SQL redaktorunda yalnız etibarlı istifadəçinin UUID-si ilə işlədin:

```sql
update public.profiles
set role = 'admin', is_verified = true
where id = 'USER_UUID';
```

Admin səlahiyyətini istifadəçi metadatası və ya brauzer sorğusu ilə verməyin.

### Məlumat saxlama

Supabase Cron mövcuddursa, yoxa çıxmış mesajların şifrəli paketlərini tez-tez, köhnə audit qeydlərini isə gündəlik təmizləyin:

```sql
select public.purge_expired_messages(1000);
select public.purge_old_audit_logs(90, 5000);
```

Bu funksiyalar adi istifadəçi və admin API açarı üçün bağlıdır; yalnız etibarlı server/cron rolu işlədə bilər.

## Vercel deploy

Layihənin kökündəki `vercel.json` framework, build və təhlükəsizlik başlıqlarını hazır şəkildə təyin edir.

1. Layihəni öz şəxsi GitHub/GitLab/Bitbucket reposuna göndərin.
2. Vercel-də **Add New → Project** seçib həmin reponu import edin.
3. Framework preset-i **Next.js** saxlayın; build/output sahələrini əl ilə dəyişməyin.
4. Production və lazım olan Preview mühitlərinə bu dəyişənləri əlavə edin:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`
   - `NEXT_PUBLIC_SITE_URL=https://sizin-domeniniz.example`
5. Deploy başladın və sonra custom domeni qoşun.

Vercel CLI ilə deploy etmək istəsəniz, rəsmi CLI-ni quraşdırıb layihə kökündə `vercel`, production üçün isə `vercel --prod` işlədin.

## Auth konfiqurasiyası

- Site URL-i yalnız production domeninə təyin edin.
- Redirect allowlist-ə production domenini və lokal inkişaf üçün `http://localhost:3000/**` əlavə edin.
- İstifadə etmirsinizsə, `*.vercel.app` preview wildcard redirect verməyin.
- E-poçt təsdiqini, minimum 12 simvolluq parol qaydasını, leaked-password yoxlamasını və auth rate limitlərini aktiv edin.
- İctimai qeydiyyat açıqdırsa CAPTCHA aktivləşdirin.

## Vercel təhlükəsizlik ayarları

- Preview deployment-lər üçün Deployment Protection aktiv edin.
- Source və Logs görünüşünü private saxlayın.
- Hücum zamanı Attack Challenge Mode aktiv edin.
- Environment dəyişənlərinə yalnız layihə administratorlarının girişini saxlayın.
- Production domenində HTTPS-i məcburi saxlayın.

## Yoxlama

```bash
pnpm lint
pnpm test
pnpm security:audit
```

Əlavə əməliyyat qaydaları `SECURITY.md` faylındadır.
