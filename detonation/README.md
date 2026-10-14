# Detonation: CVE-2026-86950 (CoreGraphics aa_* glyph rasterizer)

Public PoC kit (trigger.ttf + trigger.pdf + render harness) detonated through
ImageIO's PDF thumbnail path (CGImageSourceCreateThumbnailAtIndex) — the same
ingest surface WhatsApp/iMessage use for PDF previews.

Goal: build a vulnerable-vs-patched characterization matrix across GitHub's
macOS runner images (macos-14 / macos-15 / macos-26), collect native crash
reports (.ips) + ASan stacks (aa_* function identification) for RCE-dev work.

Workflow: .github/workflows/detonate.yml (workflow_dispatch + push on this dir).
Artifacts: detonation-<os> (summary.txt, stdout/stderr, *.ips crash reports).
