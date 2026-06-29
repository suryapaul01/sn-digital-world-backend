# GA Premium — Design System

**Style:** Editorial Paper Brutalism
Inspired by print editorial, swiss typography, and brutalist web — high contrast, asymmetric, ink-on-paper.

---

## 1. Color Palette ("Paper & Ink")

| Token        | Value     | Use                                  |
|--------------|-----------|--------------------------------------|
| `--paper`    | `#f5f3ee` | Primary background (warm cream)      |
| `--paper-2`  | `#e8e4dd` | Secondary surface / muted blocks     |
| `--ink`      | `#2d2d2d` | Body text, borders                   |
| `--ink-deep` | `#0d0d0d` | Headings, primary buttons, footer    |

- No gradients. No purple/indigo. No pure white.
- Borders use `color-mix(in oklab, var(--ink) 20%, transparent)` for subtle dividers; solid `--ink` for brutalist 2px frames.
- Destructive: `oklch(0.55 0.22 25)` (kept for shadcn compatibility, rarely used).

---

## 2. Typography

| Role     | Font            | Weight    | Notes                              |
|----------|-----------------|-----------|------------------------------------|
| Display  | Space Grotesk   | 700       | Headings, logo, CTAs — uppercase   |
| Body     | DM Sans         | 400 / 500 | Paragraphs, UI labels              |

- Loaded via `<link>` in `src/routes/__root.tsx` (never `@import` in CSS for Tailwind v4).
- Hierarchy: tight letter-spacing on headings, wide `tracking-widest` + uppercase on micro-labels (eyebrows, nav, badges).
- No serif fonts. No script fonts.
- Punctuation: hyphens only — no em dashes ("—") anywhere in copy.

---

## 3. Layout & Grid

- Max width: `max-w-7xl` (1280px), padded `px-4 sm:px-6`.
- Asymmetric columns (e.g., 7/5 split) on desktop; single column stack on mobile.
- Generous vertical rhythm: `py-12 sm:py-16 lg:py-24` between sections.
- Sticky header with 2px ink bottom border; backdrop blur on scroll.
- Mobile: hamburger menu, 44px min touch targets, `overflow-x: hidden` globally.

---

## 4. Brutalist Shadows & Borders

Hard offset shadows (no blur) — the defining visual signature.

```css
.shadow-brutal     → 4px 4px 0 ink  (mobile) / 8px 8px 0 ink  (≥640px)
.shadow-brutal-lg  → 6px 6px 0 ink  (mobile) / 12px 12px 0 ink (≥640px)
.shadow-glow       → 3px 3px 0 ink  (mobile) / 4px 4px 0 ink  (≥640px)
```

- Every card, button, and image frame uses a **2px solid ink border**.
- Shadows scale down on mobile to prevent horizontal overflow.
- `.glass` utility = solid paper background + 1px ink border (no actual glassmorphism — keeps the print feel).

---

## 5. Components

### Buttons
- **Primary:** `bg-ink-deep text-paper`, uppercase, bold, `tracking-widest`, 44px tall.
- **Secondary:** transparent + 2px ink border, hover inverts.
- All CTAs are rectangular (no rounded pills) — `radius: 0.25rem` max.

### Cards (plans, features, FAQ)
- White paper background, 2px ink border, brutal shadow offset.
- Highlighted card (VIP, Recommended): inverted to `bg-ink-deep text-paper` with `shadow-brutal-lg`.
- Badges: uppercase, 10–11px, tracked, sit on the border edge.

### Sections
- Eyebrow label (uppercase, tracked) → big display heading → body copy → grid.
- Section dividers are 2px solid ink lines, not subtle gradients.

---

## 6. Iconography

- **lucide-react** only, stroke-width 2.
- Icons sit inside 2px bordered square frames (e.g., logo monogram, social icons).
- Never decorative-only — every icon labels or reinforces a concrete action.

---

## 7. Imagery

- Extension screenshots framed with 2px ink border + brutal shadow.
- Logo: black ink monogram on cream square — also used as favicon, apple-touch-icon, footer mark.
- Images: `loading="lazy"`, `decoding="async"`, explicit `width`/`height`.

---

## 8. Motion

- Minimal. Hover states only: opacity shifts, color inversions, no transforms.
- `scroll-behavior: smooth` on `<html>`.
- No parallax, no scroll-jacking, no entrance animations on marketing sections.

---

## 9. Accessibility

- Min 44px touch targets on mobile.
- Focus rings via shadcn `--ring` = `--ink`.
- Semantic HTML: single `<h1>` per page, `<nav aria-label>`, `<footer>`, alt text on every image.
- Contrast: ink-deep on paper = ~17:1 (well past WCAG AAA).

---

## 10. File Map

| Concern           | File                                  |
|-------------------|---------------------------------------|
| Tokens & utilities| `src/styles.css`                      |
| Header            | `src/components/site/Header.tsx`      |
| Footer            | `src/components/site/Footer.tsx`      |
| Root head/fonts   | `src/routes/__root.tsx`               |
| Landing sections  | `src/routes/index.tsx`                |
| Blog list / post  | `src/routes/blog.index.tsx`, `blog.$slug.tsx` |
| Brand constants   | `src/lib/site.ts`                     |

---

## 11. Do / Don't

**Do**
- Use `bg-paper`, `text-ink`, `border-ink` semantic tokens.
- Stack mobile, asymmetric desktop.
- Uppercase + tracked labels for micro-copy.
- Hard offset shadows on every elevated surface.

**Don't**
- Hardcode `text-white`, `bg-black`, or hex colors in components.
- Introduce gradients, glassmorphism, or neumorphism.
- Use em dashes ("—") in copy — CI fails on forbidden strings.
- Add rounded-full pills or soft drop shadows.
- Use Inter, Poppins, or any default "AI-looking" font pair.
