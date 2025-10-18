from collections import defaultdict
from pathlib import Path


def analyze_mutation_results(file_path):
    total_counts = defaultdict(int)
    survived_counts = defaultdict(int)

    with open(file_path, encoding="utf-16") as f:
        # Remove empty lines
        lines = [line.strip() for line in f if line.strip()]

    for i in range(0, len(lines), 3):
        if i + 2 >= len(lines):
            continue  # skip incomplete block

        line_module = lines[i + 1]  # contains module name
        line_outcome = lines[i + 2]  # contains outcome

        # Skip last line with overall results
        module_name = line_module.split()[0]
        if "complete" in module_name:
            continue

        # Extract outcome
        if "SURVIVED" in line_outcome:
            outcome = "SURVIVED"
        elif "KILLED" in line_outcome:
            outcome = "KILLED"
        else:
            outcome = "UNKNOWN"

        total_counts[module_name] += 1
        if outcome == "SURVIVED":
            survived_counts[module_name] += 1

    # Print to screen
    # Formatting widths
    max_module_len = max(len("Module"), *(len(m) for m in total_counts))
    module_col_width = max_module_len + 2
    total_col_width = 8
    survived_col_width = 15

    # Header
    header = (
        f"{'Module':<{module_col_width}}"
        f"{'Total':>{total_col_width}}"
        f"{'Survived':>{survived_col_width}}"
        f"{'Proportion':>{survived_col_width}}"
    )
    print(header)
    print("-" * (module_col_width + total_col_width + survived_col_width * 2))

    for module in sorted(total_counts):
        total = total_counts[module]
        survived = survived_counts.get(module, 0)
        percent = survived / total
        truncated = int(percent * 100) / 100
        print(
            f"{module:<{module_col_width}}"
            f"{total:>{total_col_width}}"
            f"{survived:>{survived_col_width}}"
            f"{truncated:>{survived_col_width}}"
        )


if __name__ == "__main__":
    path_to_file = Path(__file__).parent.parent / "src" / "Mutation_Results.txt"
    analyze_mutation_results(path_to_file)
