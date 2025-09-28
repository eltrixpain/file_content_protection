# plot_stats.py
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def plot_size_distribution(csv_path: str):
    """Plot histogram of file sizes (log scale)."""
    df = pd.read_csv(csv_path)
    sizes = df["size_bytes"]

    plt.figure(figsize=(8, 5))
    bins = np.logspace(np.log10(max(1, sizes.min())), np.log10(sizes.max()+1), 50)
    plt.hist(sizes, bins=bins, edgecolor="black", alpha=0.7)

    plt.xscale("log")
    plt.xlabel("File size (bytes, log scale)")
    plt.ylabel("Count")
    plt.title("File Size Distribution")
    plt.grid(True, which="both", ls="--", alpha=0.5)
    plt.tight_layout()
    plt.show()


def plot_access_distribution(csv_path: str):
    """Plot histogram of file open hits."""
    df = pd.read_csv(csv_path)
    hits = df["open_hits"]

    plt.figure(figsize=(8, 5))
    bins = np.logspace(0, np.log10(hits.max()+1), 50)
    plt.hist(hits, bins=bins, edgecolor="black", alpha=0.7)

    plt.xscale("log")
    plt.xlabel("Open hits (log scale)")
    plt.ylabel("Count of files")
    plt.title("Access Distribution")
    plt.grid(True, which="both", ls="--", alpha=0.5)
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    # example usage
    plot_size_distribution("../sizes.csv")
    #plot_access_distribution("access.csv")
