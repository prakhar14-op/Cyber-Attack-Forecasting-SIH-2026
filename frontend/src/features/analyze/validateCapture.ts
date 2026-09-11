import { DEMO_SOURCES } from '@/demo/fixtureCaptures'
import { fileExtension, formatBytes } from '@/lib/format'
import type { CaptureKind, DemoSource } from '@/types/backend'

/** The engine reads exactly these: PCAP -> full 30 features, CSV -> flow-only. */
export const ACCEPTED_EXTENSIONS = ['.pcap', '.pcapng', '.csv'] as const

/** Guard-rail for the browser side; the engine itself streams from disk. */
export const MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024

export type CaptureValidation =
  | { ok: true; kind: CaptureKind; bundled: DemoSource | null }
  | { ok: false; error: string }

export function validateCapture(file: File): CaptureValidation {
  const extension = fileExtension(file.name)

  if (!extension) {
    return {
      ok: false,
      error: `"${file.name}" has no file extension. Provide a .pcap, .pcapng or .csv capture.`,
    }
  }

  if (!ACCEPTED_EXTENSIONS.includes(extension as (typeof ACCEPTED_EXTENSIONS)[number])) {
    return {
      ok: false,
      error: `Unsupported input type "${extension}". The pipeline reads .pcap / .pcapng (full 30-feature path) or .csv (flow-only path).`,
    }
  }

  if (file.size === 0) {
    return { ok: false, error: `"${file.name}" is empty — there is nothing to extract.` }
  }

  if (file.size > MAX_INPUT_BYTES) {
    return {
      ok: false,
      error: `"${file.name}" is ${formatBytes(file.size)}. Split captures above ${formatBytes(MAX_INPUT_BYTES)} before analysis.`,
    }
  }

  const kind: CaptureKind = extension === '.csv' ? 'csv' : 'pcap'
  return { ok: true, kind, bundled: matchBundledSource(file.name) }
}

/** A dropped copy of a repository-bundled input resolves to that known source. */
export function matchBundledSource(fileName: string): DemoSource | null {
  const name = fileName.toLowerCase()
  return (
    DEMO_SOURCES.find((source) => (source.path.split('/').pop() ?? '').toLowerCase() === name) ??
    null
  )
}
