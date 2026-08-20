#!/usr/bin/env python3

import argparse
from pathlib import Path
from typing import Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

MEASURED_GPU_COUNTS = [1, 2, 4, 8]
MEASURED_THROUGHPUT_BILLIONS = [16.25, 32.28, 64.15, 128.73]
DEFAULT_HOURLY_RENTAL_COSTS_EUR = [0.37, 0.75, 1.52, 3.45]

KEY_SPACE = 2**56

# Okabe-Ito-inspired colors, readable for common forms of color blindness.
BLUE = "#0072b2"
RED = "#d55e00"
GREEN = "#009e73"


def configure_common_axis(axis: plt.Axes) -> None:
    axis.set_xticks([1, 2, 4, 8])
    axis.set_xlim(0.85, 8.15)
    axis.tick_params(axis="x", labelsize=20, width=1.2, length=6)
    axis.grid(True, linestyle=":", linewidth=1.1, color="#bcbcbc", alpha=0.75)
    axis.set_axisbelow(True)
    for spine in axis.spines.values():
        spine.set_linewidth(1.2)


def save_figure(fig: plt.Figure, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def plot_scaling(output: Path) -> list[float]:
    gpu_counts = MEASURED_GPU_COUNTS
    throughput = MEASURED_THROUGHPUT_BILLIONS
    runtime_days = [
        KEY_SPACE / (measured_throughput * 1e9) / 86400
        for measured_throughput in throughput
    ]

    fig, throughput_axis = plt.subplots(figsize=(12.5, 7.5))
    time_axis = throughput_axis.twinx()

    measured_line = throughput_axis.plot(
        gpu_counts,
        throughput,
        color=BLUE,
        marker="o",
        markersize=11,
        linewidth=3.2,
        label="Measured Throughput",
        zorder=3,
    )[0]
    time_line = time_axis.plot(
        gpu_counts,
        runtime_days,
        color=GREEN,
        marker="o",
        markersize=10,
        linewidth=3.0,
        label="Worst-Case Search Time",
        zorder=3,
    )[0]

    throughput_axis.set_title(
        "56-bit Key-Recovery Performance", fontsize=26, fontweight="bold", pad=18
    )
    throughput_axis.set_xlabel(
        "Number of GPUs", fontsize=26, fontweight="bold", labelpad=12
    )
    throughput_axis.set_ylabel(
        "Throughput (Billion Keys/s)",
        color=BLUE,
        fontsize=26,
        fontweight="bold",
        labelpad=12,
    )
    time_axis.set_ylabel(
        "Time (Days)",
        color=GREEN,
        fontsize=26,
        fontweight="bold",
        labelpad=12,
    )

    configure_common_axis(throughput_axis)
    throughput_axis.set_ylim(11.5, max(throughput) * 1.05)
    time_axis.set_ylim(0, max(runtime_days) * 1.18)
    throughput_axis.tick_params(axis="y", colors=BLUE, labelsize=20)
    time_axis.tick_params(axis="y", colors=GREEN, labelsize=20)

    throughput_axis.legend(
        handles=[measured_line, time_line],
        loc="upper left",
        frameon=False,
        fontsize=20,
    )

    fig.tight_layout()
    save_figure(fig, output)
    return runtime_days


def plot_cost_and_time(
    output: Path, hourly_rental_costs: Sequence[float], runtime_days: Sequence[float]
) -> list[float]:
    gpu_counts = MEASURED_GPU_COUNTS
    runtime_hours = [days * 24 for days in runtime_days]
    full_search_cost = [
        hours * hourly_cost
        for hours, hourly_cost in zip(runtime_hours, hourly_rental_costs)
    ]

    fig, cost_axis = plt.subplots(figsize=(12.5, 7.5))
    time_axis = cost_axis.twinx()

    cost_line = cost_axis.plot(
        gpu_counts,
        full_search_cost,
        color=RED,
        marker="o",
        markersize=10,
        linewidth=3.0,
        label="Worst-Case Rental Cost",
        zorder=3,
    )[0]
    time_line = time_axis.plot(
        gpu_counts,
        runtime_days,
        color=GREEN,
        marker="o",
        markersize=10,
        linewidth=3.0,
        label="Worst-Case Search Time",
        zorder=3,
    )[0]

    cost_axis.set_title(
        "56-bit Key-Recovery Cost", fontsize=26, fontweight="bold", pad=18
    )
    cost_axis.set_xlabel("Number of GPUs", fontsize=26, fontweight="bold", labelpad=12)
    cost_axis.set_ylabel(
        "Cost (€)",
        color=RED,
        fontsize=26,
        fontweight="bold",
        labelpad=12,
    )
    time_axis.set_ylabel(
        "Time (Days)",
        color=GREEN,
        fontsize=26,
        fontweight="bold",
        labelpad=12,
    )

    configure_common_axis(cost_axis)
    cost_padding = max(5.0, (max(full_search_cost) - min(full_search_cost)) * 0.35)
    cost_axis.set_ylim(
        min(full_search_cost) - cost_padding,
        max(full_search_cost) + cost_padding,
    )
    time_axis.set_ylim(0, max(runtime_days) * 1.18)
    cost_axis.tick_params(axis="y", colors=RED, labelsize=20)
    time_axis.tick_params(axis="y", colors=GREEN, labelsize=20)

    cost_axis.legend(
        handles=[cost_line, time_line],
        loc="upper left",
        frameon=False,
        fontsize=20,
    )

    fig.tight_layout()
    save_figure(fig, output)
    return full_search_cost


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plot RTX 5090 throughput scaling, search time, and the rental cost "
            "required to exhaust a 7-byte (2^56) pairing-key space."
        )
    )
    parser.add_argument(
        "--hourly-costs",
        default=",".join(str(cost) for cost in DEFAULT_HOURLY_RENTAL_COSTS_EUR),
        help=(
            "Comma-separated total hourly rental prices for 1, 2, 4, and 8 GPUs "
            "in euros (default: 0.37,0.75,1.52,3.45)"
        ),
    )
    parser.add_argument(
        "--output",
        "--scaling-output",
        dest="output",
        type=Path,
        default=Path("figs/rtx5090_scaling.png"),
        help="Output path for the combined throughput/time figure",
    )
    parser.add_argument(
        "--cost-output",
        type=Path,
        default=Path("figs/rtx5090_bruteforce_cost_time.png"),
        help="Output path for the combined cost/time figure",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    hourly_rental_costs = [
        float(value.strip()) for value in args.hourly_costs.split(",")
    ]
    if len(hourly_rental_costs) != len(MEASURED_GPU_COUNTS) or any(
        cost <= 0 for cost in hourly_rental_costs
    ):
        raise SystemExit(
            "--hourly-costs must contain four positive values for 1, 2, 4, and 8 GPUs"
        )

    runtime_days = plot_scaling(args.output)
    full_search_cost = plot_cost_and_time(
        args.cost_output, hourly_rental_costs, runtime_days
    )

    ideal_throughput = [
        MEASURED_THROUGHPUT_BILLIONS[0] * count for count in MEASURED_GPU_COUNTS
    ]
    for count, throughput, ideal, days, hourly_cost, cost in zip(
        MEASURED_GPU_COUNTS,
        MEASURED_THROUGHPUT_BILLIONS,
        ideal_throughput,
        runtime_days,
        hourly_rental_costs,
        full_search_cost,
    ):
        efficiency = throughput / ideal * 100
        print(
            f"{count} GPU(s): {throughput:.2f} billion keys/s "
            f"({efficiency:.2f}% efficiency), {days:.2f} days, "
            f"€{cost:.2f} at €{hourly_cost:.2f}/h"
        )
    print(f"Saved {args.output}")
    print(f"Saved {args.cost_output}")


if __name__ == "__main__":
    main()
