"""Local file-conversion helpers for challenge assets."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import matplotlib
import numpy as np
import soundfile as sf


matplotlib.use("Agg")
import matplotlib.pyplot as plt


AudioConversionType = Literal[1, 2]
SPECTROGRAM = 1
WAVEFORM = 2


def _output_path(audio_path: Path, conversion_type: AudioConversionType) -> Path:
    """Return the default PNG path for an audio conversion."""
    suffix = "spectrogram" if conversion_type == SPECTROGRAM else "waveform"
    return audio_path.with_name(f"{audio_path.stem}_{suffix}.png")


def _mono_samples(audio_path: Path) -> tuple[np.ndarray, int]:
    """Load mono audio or down-mix stereo audio to mono."""
    samples, sample_rate = sf.read(audio_path, always_2d=False)
    if samples.size < 2:
        raise ValueError("audio file must contain at least two samples")
    if samples.ndim == 2:
        if samples.shape[1] != 2:
            raise ValueError("audio file must be mono or stereo")
        samples = samples.mean(axis=1)
    elif samples.ndim != 1:
        raise ValueError("audio file must be mono or stereo")
    return np.asarray(samples, dtype=float), sample_rate


def _spectrogram_nfft(sample_count: int) -> int:
    """Choose a bounded, power-of-two FFT size for Matplotlib's specgram.

    ``Axes.specgram`` performs the FFT internally. A power-of-two NFFT lets its
    NumPy-backed FFT implementation run efficiently. The value is capped at
    1024 samples to retain useful time resolution, and reduced for short clips.
    """
    return 2 ** int(np.floor(np.log2(min(1024, sample_count))))


def convert_audio_file(
    audio_path: str | Path,
    conversion_type: AudioConversionType,
    output_path: str | Path | None = None,
) -> Path:
    """Convert audio to a PNG spectrogram (``1``) or waveform (``2``).

    The source format must be readable by SoundFile. When ``output_path`` is
    omitted, the PNG is written beside the audio file with a descriptive name.
    The returned path is absolute.
    """
    source = Path(audio_path)
    if not source.is_file():
        raise FileNotFoundError(f"Audio file does not exist: {source}")
    if conversion_type not in {SPECTROGRAM, WAVEFORM}:
        raise ValueError("conversion_type must be 1 (spectrogram) or 2 (waveform)")

    destination = Path(output_path) if output_path is not None else _output_path(
        source, conversion_type
    )
    if destination.suffix.lower() != ".png":
        raise ValueError("output_path must use a .png extension")
    destination.parent.mkdir(parents=True, exist_ok=True)

    samples, sample_rate = _mono_samples(source)
    figure, axis = plt.subplots(figsize=(12, 4), layout="constrained")
    try:
        if conversion_type == SPECTROGRAM:
            nfft = _spectrogram_nfft(samples.size)
            axis.specgram(samples, Fs=sample_rate, NFFT=nfft, noverlap=nfft // 2)
            axis.set_ylabel("Frequency (Hz)")
            axis.set_title(f"Spectrogram: {source.name}")
        else:
            time_axis = np.arange(samples.size) / sample_rate
            axis.plot(time_axis, samples, linewidth=0.5)
            axis.set_ylabel("Amplitude")
            axis.set_title(f"Waveform: {source.name}")

        axis.set_xlabel("Time (seconds)")
        figure.savefig(destination, dpi=150)
    finally:
        plt.close(figure)

    return destination.resolve()
