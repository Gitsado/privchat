import Link from "next/link";
import { ShieldCheck } from "lucide-react";

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link className="brand" href="/" aria-label="PrivChat ana səhifə">
      <span className="brand-mark" aria-hidden="true">
        <ShieldCheck size={compact ? 17 : 20} strokeWidth={2.4} />
      </span>
      <span>PrivChat</span>
      {!compact && <span className="brand-beta">BETA</span>}
    </Link>
  );
}
