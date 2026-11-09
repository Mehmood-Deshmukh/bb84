#!/bin/bash
#SBATCH --job-name=d5_decoy
#SBATCH --partition=cpu
#SBATCH --array=0-259
#SBATCH --cpus-per-task=1
#SBATCH --mem=12000M
#SBATCH --time=01:00:00
#SBATCH --output=experiments/results/slurm/%A_%a.out
#
# One array index = one Alice/Bob(/Eve) run. CPU partition, no GPU. Each index re-derives its
# task from the same plan (seeded), runs it, and appends a row to the run directory. A final
# reduce (run once, after the array finishes) collects the rows:
#   python scripts/decoy_cluster.py --reduce experiments/results/<exp>/<run id>
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
source .venv/bin/activate
python scripts/decoy_cluster.py --slurm-task "$SLURM_ARRAY_TASK_ID" \
    --experiments d5_decoy_honest d5_decoy_pns d5_required_n --repeats 15 --run-dir "experiments/results"
