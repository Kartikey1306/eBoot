# eBoot — Secure Bootloader

[![CI](https://github.com/embeddedos-org/eBoot/actions/workflows/build.yml/badge.svg)](https://github.com/embeddedos-org/eBoot/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Cryptographically Verified Boot for Any Hardware.

---

## Simulation & Analytics

### Real-Time Emulation Dashboard
Below is the real-time simulation dashboard generated from the test suite. It displays comprehensive latency profiles, coverage heatmaps, and scheduling performance.

![Emulation Dashboard](docs/screenshots/eboot_simulation.png)

### Unified Organization Health Matrix
We continuously benchmark eBoot — Secure Bootloader against the entire EmbeddedOS ecosystem to check interoperability.

![Overall Dashboard](docs/screenshots/overall_dashboard.png)

---

## Product Video

See eBoot — Secure Bootloader in action! Watch our high-fidelity product demonstration and marketing video:

> 🎥 **[Watch the eBoot — Secure Bootloader Product Video](docs/videos/eboot_marketing.mp4)**

---

## Architecture

- **Domain**: C • RSA-2048 • A/B Slots

---

## Test Suite

The suite is organised into four categories — unit, functional end-to-end,
performance, and hardware simulation.

> Coverage is not currently measured, so no coverage figure is published here.
> Live build status is the CI badge at the top of this file.

To run the entire suite locally:
```bash
python run_all_tests.py
```

---

## 📜 License & Compliance

Licensed under the MIT License. Aligned with ISO/IEC 25000 software quality standards.
