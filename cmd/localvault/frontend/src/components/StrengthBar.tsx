import { estimateStrength } from '../lib/strength'

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#16a34a']

// StrengthBar renders a 5-segment strength indicator for a password. Renders nothing for
// an empty value so it stays out of the way until the user types.
export default function StrengthBar({ value }: { value: string }) {
  if (!value) return null
  const s = estimateStrength(value)
  return (
    <div className="flex items-center gap-2">
      <div className="flex flex-1 gap-1">
        {[0, 1, 2, 3, 4].map(i => (
          <div key={i} className="h-1 flex-1 rounded-full"
            style={{ backgroundColor: i <= s.score ? COLORS[s.score] : 'rgb(var(--border))' }} />
        ))}
      </div>
      <span className="w-20 shrink-0 text-right text-[11px] font-medium" style={{ color: COLORS[s.score] }}>
        {s.label}
      </span>
    </div>
  )
}
