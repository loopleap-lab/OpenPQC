# OpenPQC tutorial image: toolchain + JupyterLab, with the library already built,
# so every cell of tutorial/OpenPQC_Tutorial.ipynb runs in seconds.
#
# Build (from the repository root) and run:
#   docker build -f tutorial/Dockerfile -t openpqc-tutorial .
#   docker run --rm -p 127.0.0.1:8888:8888 openpqc-tutorial
# then open  http://localhost:8888/lab?token=openpqc

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates \
        python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir jupyterlab matplotlib numpy
ENV PATH=/opt/venv/bin:$PATH

WORKDIR /opt/openpqc
COPY . .

# Pre-build what the notebook uses (Ubuntu 24.04's default GCC 13 is C++20-capable), with the notebook's own
# configuration (section 2): the library openpqc as a shared library, which the Python bridge loads, and the
# example programs.
RUN cmake -S . -B build-tutorial -DCMAKE_BUILD_TYPE=Release \
          -DOPENPQC_BUILD_TESTS=OFF -DOPENPQC_BUILD_BENCHMARKS=OFF -DOPENPQC_SYCL=OFF -DBUILD_SHARED_LIBS=ON \
    && cmake --build build-tutorial -j"$(nproc)"

WORKDIR /opt/openpqc/tutorial
EXPOSE 8888
CMD ["jupyter", "lab", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--allow-root", \
     "--IdentityProvider.token=openpqc", \
     "--LabApp.default_url=/lab/tree/OpenPQC_Tutorial.ipynb"]
