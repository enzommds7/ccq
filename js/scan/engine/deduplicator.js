/* ══════════════════════════════════════════════════════════════════
   ccq scan — DEDUPLICADOR DE EVENTOS
   - 10.000 repetições do mesmo evento contam como 1 evento único
     com occurrence_count: 10000, sem multiplicar risco ou peso
   ══════════════════════════════════════════════════════════════════ */
import { EVIDENCE_LEVEL_RANK } from './matcher.js';

export function createDeduplicator() {
  const grouped = new Map();
  let rawOccurrences = 0;

  return {
    add(event) {
      if (!event) return;
      rawOccurrences += 1;
      const key = event.dedup_key || `${event.rule_id}|${event.source?.path}|${event.observed?.object_path}`;
      const existing = grouped.get(key);
      if (!existing) {
        event.occurrence_count = event.occurrence_count || 1;
        grouped.set(key, event);
      } else {
        existing.occurrence_count += 1;
      }
    },

    finalize() {
      const events = Array.from(grouped.values()).map(ev => {
        const clone = { ...ev };
        delete clone.dedup_key;
        return clone;
      });

      events.sort((a, b) => {
        const lvlDiff = (EVIDENCE_LEVEL_RANK[b.evidence_level] || 0) - (EVIDENCE_LEVEL_RANK[a.evidence_level] || 0);
        if (lvlDiff !== 0) return lvlDiff;
        return (b.heuristic_weight || 0) - (a.heuristic_weight || 0);
      });

      return {
        events,
        rawOccurrences,
        uniqueEvents: events.length
      };
    }
  };
}
