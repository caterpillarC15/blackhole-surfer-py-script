#!/usr/bin/env python3
"""
Blackhole Surfer - simple terminal simulation script.
"""

from __future__ import annotations

import random
import time


def generate_wave_reading(step: int) -> float:
    """Generate a pseudo gravity-wave reading."""
    baseline = 42.0 + (step * 0.15)
    jitter = random.uniform(-1.2, 1.2)
    return round(baseline + jitter, 2)


def run_simulation(steps: int = 12, delay_seconds: float = 0.35) -> None:
    """Print simulated readings as if surfing a blackhole edge."""
    print("Launching Blackhole Surfer...")
    print("Stabilizing event-horizon board...\n")

    for step in range(1, steps + 1):
        reading = generate_wave_reading(step)
        print(f"[{step:02d}/{steps}] gravity-wave index: {reading}")
        time.sleep(delay_seconds)

    print("\nRide complete. You made it past the photon ring.")


if __name__ == "__main__":
    run_simulation()
