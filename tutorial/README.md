# OpenPQC tutorial

A hands-on Jupyter notebook: build OpenPQC, run ML-KEM, ML-DSA and SLH-DSA interactively from Python
and C++, watch tampered ciphertexts and messages get rejected, compare sizes and speed with classical
cryptography, and see what the GPU backend changes.

**[`OpenPQC_Tutorial.ipynb`](OpenPQC_Tutorial.ipynb)** — run the cells top to bottom; each is safe to re-run.

## Run it with Docker (recommended)

One image holds the compiler, CMake, JupyterLab, and a prebuilt library, so every cell runs in
seconds. From the repository root:

```sh
docker build -f tutorial/Dockerfile -t openpqc-tutorial .
docker run --rm -p 127.0.0.1:8888:8888 openpqc-tutorial
```

Then open **http://localhost:8888/lab?token=openpqc** — the notebook opens by itself.

- The container is throwaway (`--rm`); the image keeps the built library, so restarting is instant.
- To keep changes you make to the notebook, mount this directory over the image's copy:
  `docker run --rm -p 127.0.0.1:8888:8888 -v "$PWD/tutorial":/opt/openpqc/tutorial openpqc-tutorial`
- Port 8888 taken? Use `-p 127.0.0.1:9999:8888` and open port 9999.

## Run it natively

Needed: CMake ≥ 3.20, a C++20 compiler (GCC ≥ 12 or Clang ≥ 16), Python 3.9+.

```sh
# Ubuntu/Debian example
sudo apt install cmake g++-13 python3-venv
python3 -m venv .venv && . .venv/bin/activate
pip install -r tutorial/requirements.txt
jupyter lab tutorial/OpenPQC_Tutorial.ipynb
```

The notebook finds the sources, picks the newest usable compiler, and builds the library itself
(about half a minute, once). It even works standalone: run outside the repository, it clones OpenPQC
first.

## GPU demo (native only)

The Docker image is CPU-only. The notebook's GPU section explains the SYCL backend and runs
`examples/demo_gpu` if you have built it with DPC++ or AdaptiveCpp — see
[`examples/README.md`](../examples/README.md), which also describes `live_demo`, a staged
CPU-vs-GPU race with progress bars made for presenting.

## Presenting

- Do a full dry run of the notebook beforehand (`Run → Run All Cells`); the first run builds and
  caches everything, so the live run is all fast.
- Plug the laptop in and close other builds/browsers — the benchmark numbers in sections 8 and 10
  vary with CPU clocks and load.
- For the five-minute scripted finale on a GPU machine, use `examples/live_demo` (talking points in
  [`examples/README.md`](../examples/README.md#live-demo-for-a-presentation)).
