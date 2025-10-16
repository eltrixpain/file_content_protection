# plots_separate.py
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def plot_size_histogram(sizes_csv: str, bins_count: int = 50):
    """Plot size distribution: x=size (log), y=file count."""
    df_sizes = pd.read_csv(sizes_csv)

    sizes = df_sizes["size_bytes"].astype(np.int64)
    x_min = max(1, sizes.min())
    x_max = max(x_min + 1, sizes.max())
    bins = np.logspace(np.log10(x_min), np.log10(x_max), bins_count)

    plt.figure(figsize=(9, 5))
    plt.hist(sizes, bins=bins, edgecolor="black", alpha=0.7)
    plt.xscale("log")
    plt.xlabel("File size (bytes, log scale)")
    plt.ylabel("File count")
    plt.title("File Size Distribution")
    plt.grid(True, which="both", ls="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("../statistical_result/size_histogram.png")


def plot_access_distribution_by_size(access_csv: str, sizes_csv: str, bins_count: int = 50):
    """
    Plot access distribution vs size:
    x = size bins (log), y = sum of open_hits per bin.
    """

    df_access = pd.read_csv(access_csv)
    df_sizes  = pd.read_csv(sizes_csv)

    # join per-file hits with size via (dev, ino)
    df = pd.merge(df_access, df_sizes, on=["dev", "ino"], how="inner")
    if df.empty:
        print("No overlap between access and size data.")
        return

    df["size_bytes"] = df["size_bytes"].astype(np.int64)
    df["open_hits"]  = df["open_hits"].astype(np.int64)

    sizes = df["size_bytes"]
    x_min = max(1, int(sizes.min()))
    x_max = max(x_min + 1, int(sizes.max()))
    bin_edges = np.logspace(np.log10(x_min), np.log10(x_max), bins_count + 1)

    bin_idx = np.digitize(df["size_bytes"].to_numpy(), bin_edges, right=True) - 1
    bin_idx = np.clip(bin_idx, 0, bins_count - 1)

    hits_by_bin = (
        pd.Series(df["open_hits"].to_numpy())
        .groupby(bin_idx)
        .sum()
        .reindex(range(bins_count), fill_value=0)
        .to_numpy()
    )
    bin_centers = np.sqrt(bin_edges[:-1] * bin_edges[1:])
    widths      = np.diff(bin_edges)
    plt.figure(figsize=(9, 5))
    plt.bar(bin_centers, hits_by_bin, width=widths, align="center",
            edgecolor="black", alpha=0.75)
    plt.xscale("log")
    plt.xlabel("File size (bytes, log scale)")
    plt.ylabel("Sum of open hits per size bin")
    plt.title("Access Distribution by File Size")
    plt.grid(True, which="both", ls="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("../statistical_result/access_distribution.png")


if __name__ == "__main__":
    plot_size_histogram("../statistical_result/sizes.csv")
    plot_access_distribution_by_size(
        "../statistical_result/access.csv",
        "../statistical_result/sizes.csv"
    )