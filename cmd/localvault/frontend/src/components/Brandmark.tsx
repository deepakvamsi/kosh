type BrandmarkProps = {
  /** Tailwind size + color classes, e.g. "h-7 w-7 text-[rgb(var(--accent))]". */
  className?: string
  /** Accessible label / tooltip. */
  title?: string
}

// Brandmark is Kosh's mark, drawn inline as SVG instead of shipping a raster logo.
// Benefits: it scales crisply at any size, adds no binary asset to an air-sealed and
// audited build, and themes automatically — it inherits `color` via `currentColor`, so
// set the color with a Tailwind text-* class on `className`.
//
// The glyph is a vault door with a keyhole: a single-colour, security-first mark. Swap
// the SVG body below to change the mark without touching any call site.
export default function Brandmark({
  className = 'h-7 w-7',
  title = 'Kosh',
}: BrandmarkProps) {
  return (
    <svg
      viewBox="0 0 32 32"
      role="img"
      aria-label={title}
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <title>{title}</title>
      {/* Vault door */}
      <rect x="3.5" y="3.5" width="25" height="25" rx="7" stroke="currentColor" strokeWidth="2" />
      {/* Hinge dashes */}
      <path d="M6.5 12v8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
      {/* Keyhole */}
      <circle cx="16" cy="14" r="3" fill="currentColor" />
      <path d="M14.3 16h3.4l0.9 5.8h-5.2z" fill="currentColor" />
    </svg>
  )
}
