# imageio-fuzz
libFuzzer + ASan/UBSan campaign against Apple ImageIO decode (CGImageSource), run on GitHub Actions macOS runners (M1, Xcode toolchain).
- `harness/imageio_fuzz.m` — harness (decode + properties + thumbnail paths)
- `corpus/` — 193 synthetic seeds (PNG/JPEG/GIF/BMP/TIFF/ICO/HEIC magic variety)
- Trigger: Actions → imageio-campaign → Run workflow (default 2h)
Artifacts: crash files + fuzz.log. Public-domain harness; seeds synthetic.
