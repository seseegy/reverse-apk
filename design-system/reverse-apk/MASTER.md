# Design System Master File

> **LOGIC:** When building a specific page, first check `design-system/pages/[page-name].md`.
> If that file exists, its rules **override** this Master file.
> If not, strictly follow the rules below.

---

**Project:** reverse-apk
**Generated:** 2026-10-10 08:33:59
**Category:** Developer Tool / IDE
**Design Dials:** Variance 3/10 (Centered / Minimal) | Motion 3/10 (Subtle) | Density 7/10 (Standard)

---

## Global Rules

### Color Palette

| Role | Hex | CSS Variable |
|------|-----|--------------|
| Primary | `#1E293B` | `--color-primary` |
| On Primary | `#FFFFFF` | `--color-on-primary` |
| Secondary | `#334155` | `--color-secondary` |
| On Secondary | `#FFFFFF` | `--color-on-secondary` |
| Accent/CTA | `#22C55E` | `--color-accent` |
| On Accent/CTA | `#0F172A` | `--color-on-accent` |
| Background | `#0F172A` | `--color-background` |
| Foreground | `#F8FAFC` | `--color-foreground` |
| Card | `#1B2336` | `--color-card` |
| Card Foreground | `#F8FAFC` | `--color-card-foreground` |
| Muted | `#272F42` | `--color-muted` |
| Muted Foreground | `#94A3B8` | `--color-muted-foreground` |
| Border | `#475569` | `--color-border` |
| Destructive | `#EF4444` | `--color-destructive` |
| On Destructive | `#000000` | `--color-on-destructive` |
| Ring | `#FFFFFF` | `--color-ring` |

**Color Notes:** Code dark + run green

### Typography

- **Heading Font:** JetBrains Mono
- **Body Font:** IBM Plex Sans
- **Mood:** code, developer, technical, precise, functional, hacker
- **Google Fonts:** [JetBrains Mono + IBM Plex Sans](https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap)

**CSS Import:**
```css
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
```

### Spacing Variables

*Density: 7/10 — Standard*

| Token | Value | Usage |
|-------|-------|-------|
| `--space-xs` | `4px` / `0.25rem` | Tight gaps |
| `--space-sm` | `8px` / `0.5rem` | Icon gaps, inline spacing |
| `--space-md` | `16px` / `1rem` | Standard padding |
| `--space-lg` | `24px` / `1.5rem` | Section padding |
| `--space-xl` | `32px` / `2rem` | Large gaps |
| `--space-2xl` | `48px` / `3rem` | Section margins |
| `--space-3xl` | `64px` / `4rem` | Hero padding |

### Shadow Depths

| Level | Value | Usage |
|-------|-------|-------|
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.05)` | Subtle lift |
| `--shadow-md` | `0 4px 6px rgba(0,0,0,0.1)` | Cards, buttons |
| `--shadow-lg` | `0 10px 15px rgba(0,0,0,0.1)` | Modals, dropdowns |
| `--shadow-xl` | `0 20px 25px rgba(0,0,0,0.15)` | Hero images, featured cards |

---

## Component Specs

### Buttons

```css
/* Primary Button */
.btn-primary {
  background: #22C55E;
  color: white;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
  cursor: pointer;
}

.btn-primary:hover {
  opacity: 0.9;
  transform: translateY(-1px);
}

/* Secondary Button */
.btn-secondary {
  background: transparent;
  color: #1E293B;
  border: 2px solid #1E293B;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
  cursor: pointer;
}
```

### Cards

```css
.card {
  background: #0F172A;
  border-radius: 12px;
  padding: 24px;
  box-shadow: var(--shadow-md);
  transition: all 200ms ease;
  cursor: pointer;
}

.card:hover {
  box-shadow: var(--shadow-lg);
  transform: translateY(-2px);
}
```

### Inputs

```css
.input {
  padding: 12px 16px;
  border: 1px solid #E2E8F0;
  border-radius: 8px;
  font-size: 16px;
  transition: border-color 200ms ease;
}

.input:focus {
  border-color: #1E293B;
  outline: none;
  box-shadow: 0 0 0 3px #1E293B20;
}
```

### Modals

```css
.modal-overlay {
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
}

.modal {
  background: white;
  border-radius: 16px;
  padding: 32px;
  box-shadow: var(--shadow-xl);
  max-width: 500px;
  width: 90%;
}
```

---

## Style Guidelines

**Style:** Minimalism & Swiss Style

**Keywords:** Clean, simple, spacious, functional, white space, high contrast, geometric, sans-serif, grid-based, essential

**Best For:** Enterprise apps, dashboards, documentation sites, SaaS platforms, professional tools

**Key Effects:** Subtle hover (200-250ms), smooth transitions, sharp shadows if any, clear type hierarchy, fast loading

### Page Pattern

**Pattern Name:** FAQ/Documentation Landing

- **Conversion Strategy:** Reduce support tickets. Track search analytics. Show related articles. Contact escalation path.
- **CTA Placement:** Search bar prominent + Contact CTA for unresolved questions
- **Section Order:** Hero with search bar > Popular categories > FAQ accordion > Contact/support CTA

---

## Motion

**Scroll Reveal** (Subtle) — Trigger: scroll (viewport enter) | Duration: 300-400ms | Easing: `power1.out`

```js
gsap.from(el, { opacity: 0, y: 12, duration: 0.35, ease: 'power1.out', scrollTrigger: { trigger: el, start: 'top 90%', toggleActions: 'play none none reverse' } });
```

**Framework notes:** Requires the ScrollTrigger plugin registered once via gsap.registerPlugin(ScrollTrigger); Use matchMedia('(prefers-reduced-motion: reduce)') to skip non-essential motion and render the final state immediately

- ✅ Keep the y offset small (8-16px) so it reads as a fade, not a slide
- ❌ Don't reveal below-the-fold content needed for SEO/crawlers as invisible-by-default without a no-JS fallback
- ⚡ toggleActions 'play none none reverse' avoids re-triggering on every scroll direction change

---

## Anti-Patterns (Do NOT Use)

- ❌ Light mode default
- ❌ Slow performance

### Additional Forbidden Patterns

- ❌ **Emojis as icons** — Use SVG icons (Heroicons, Lucide, Simple Icons)
- ❌ **Missing cursor:pointer** — All clickable elements must have cursor:pointer
- ❌ **Layout-shifting hovers** — Avoid scale transforms that shift layout
- ❌ **Low contrast text** — Maintain 4.5:1 minimum contrast ratio
- ❌ **Instant state changes** — Always use transitions (150-300ms)
- ❌ **Invisible focus states** — Focus states must be visible for a11y

---

## Pre-Delivery Checklist

Before delivering any UI code, verify:

- [ ] No emojis used as icons (use SVG instead)
- [ ] All icons from consistent icon set (Heroicons/Lucide)
- [ ] `cursor-pointer` on all clickable elements
- [ ] Hover states with smooth transitions (150-300ms)
- [ ] Light mode: text contrast 4.5:1 minimum
- [ ] Focus states visible for keyboard navigation
- [ ] `prefers-reduced-motion` respected
- [ ] Responsive: 375px, 768px, 1024px, 1440px
- [ ] No content hidden behind fixed navbars
- [ ] No horizontal scroll on mobile


---

## Penyesuaian proyek (menimpa hasil generator di atas)

> Dibuat setelah verifikasi kontras (rumus WCAG, 10 Okt 2026). Bagian ini menang atas tabel generator.

### Catatan konteks
- Ini **aplikasi** (dashboard + penampil kode + chat), bukan landing page. Bagian "Pattern" hasil generator (FAQ/Documentation Landing) **tidak dipakai**.
- Stack target: **HTMX + Jinja + Tailwind** (`html-tailwind`). Hanya mode gelap di MVP.

### Token tambahan
| Token | Hex | Kontras | Dipakai untuk |
|-------|-----|---------|---------------|
| `--color-border` | `#475569` | 2,07–2,36:1 | **Hanya** garis pemisah dekoratif (hr, tepi card) |
| `--color-border-control` | `#64748B` | 3,29:1 di card | Batas input, select, checkbox, tombol outline (wajib ≥ 3:1) |
| `--sev-info` | `#38BDF8` | 7,31:1 | Severity info |
| `--sev-low` | `#94A3B8` | 6,11:1 | Severity low |
| `--sev-medium` | `#F59E0B` | 7,30:1 | Severity medium |
| `--sev-high` | `#F87171` | 5,66:1 | Severity high |
| `--code-bg` | `#0B1220` | – | Latar penampil kode |

Severity **tidak boleh hanya warna**: selalu sertakan label teks (`HIGH`) dan ikon.

### Tipografi
- Judul, angka, nama class/path, kode: **JetBrains Mono**. Isi teks, tombol, laporan: **IBM Plex Sans**.
- Laporan AI/chat: lebar baris maks ~75 karakter (`max-w-prose`). Penampil kode boleh lebar penuh dan scroll horizontal.

### Aturan komponen (berdasarkan pencarian skill)
| Komponen | Aturan |
|----------|--------|
| Fokus | `focus-visible:ring-2` di semua kontrol; jangan `outline-none` tanpa pengganti; sticky header tidak boleh menutupi elemen yang sedang fokus |
| Progres job | Tampilkan tahap (`Langkah 3 dari 6: jadx`), bukan spinner polos; kontainer log memakai `aria-busy` saat berjalan |
| Hitungan/badge dinamis | `role="status" aria-atomic="true"` dengan teks bermakna ("12 temuan, 2 tinggi"), bukan angka saja |
| Tabel | Dibungkus `overflow-x-auto`; header kolom bisa disortir dengan tombol; baris bisa dipilih keyboard |
| Chat | Streaming token demi token; langkah tool call tampil sebagai item yang bisa dibuka |
| Upload | Dropzone **dan** tombol "Pilih berkas" (drag bukan satu-satunya cara); progres bar jelas |
| Login | `autocomplete="username"` / `"current-password"`, paste diizinkan, tombol tampilkan password |
| Form gagal | Pesan error inline per field + ringkasan error yang fokus setelah submit |
| Gerak | Hanya transisi 150–250ms (hover/fokus). Hormati `prefers-reduced-motion`. Tidak ada animasi scroll-reveal di app (itu untuk landing) |
| Ikon | SVG vektor (Phosphor atau Lucide), satu gaya dan ketebalan garis; **tanpa emoji** sebagai ikon; ikon dekoratif `aria-hidden="true"` |
| Konten dari APK/LLM | Selalu di-escape sebagai teks; jangan render HTML mentah |

### Breakpoint uji
375, 768, 1024, 1440 px. Dashboard dan penampil kode dioptimalkan untuk ≥ 1024 px; ponsel cukup terbaca.
