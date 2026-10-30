
import argparse
import csv
from pathlib import Path

from secret_guard.main import SecretGuard


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_ROOT / "dataset"


def load_ground_truth(ground_truth_file):
    """Đọc nhãn thực tế từ file Ground Truth."""
    records = []

    with ground_truth_file.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            records.append({
                "filename": row["filename"].replace("\\", "/"),
                "line": int(row["line"]),
                "expected_secret": int(row["expected_secret"]),
            })

    return records


def normalize_filename(filename, dataset_dir):
    """Chuyển đường dẫn thành đường dẫn tương đối trong bộ dữ liệu."""
    path = Path(filename).resolve()

    try:
        return path.relative_to(dataset_dir.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def get_detected_lines(findings, dataset_dir):
    """Lấy danh sách các dòng đã được Secret Guard phát hiện."""
    detected = set()

    for finding in findings:
        filename = finding.get("filename")
        line = finding.get("line")

        if filename is None or line is None:
            continue

        detected.add((
            normalize_filename(filename, dataset_dir),
            int(line),
        ))

    return detected


def calculate_metrics(tp, fp, fn, tn):
    """Tính các chỉ số đánh giá."""
    total = tp + fp + fn + tn

    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
    }


def evaluate(dataset_name):
    """Đánh giá Secret Guard trên bộ Development hoặc Test."""

    if dataset_name == "development":
        dataset_dir = DATASET_DIR
        ground_truth_file = dataset_dir / "ground_truth.csv"

    else:
        dataset_dir = DATASET_DIR / "test"
        ground_truth_file = dataset_dir / "ground_truth_test.csv"

    if not ground_truth_file.exists():
        raise FileNotFoundError(
            f"Không tìm thấy Ground Truth: {ground_truth_file}"
        )

    records = load_ground_truth(ground_truth_file)

    # Khởi tạo Secret Guard và quét hai thư mục dữ liệu.
    guard = SecretGuard()

    positive_findings = guard.scan_path(
        dataset_dir / "positive"
    )

    negative_findings = guard.scan_path(
        dataset_dir / "negative"
    )

    all_findings = positive_findings + negative_findings

    detected_lines = get_detected_lines(
        all_findings,
        dataset_dir,
    )

    # Tập hợp các dòng đã được gán nhãn.
    ground_truth_lines = {
        (record["filename"], record["line"])
        for record in records
    }

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for record in records:
        key = (
            record["filename"],
            record["line"],
        )

        expected = record["expected_secret"]
        detected = key in detected_lines

        if expected == 1 and detected:
            tp += 1

        elif expected == 1 and not detected:
            fn += 1

        elif expected == 0 and detected:
            fp += 1

        else:
            tn += 1

    # Các dòng được phát hiện nhưng không có trong Ground Truth.
    extra_detections = detected_lines - ground_truth_lines
    fp += len(extra_detections)

    metrics = calculate_metrics(tp, fp, fn, tn)

    print("\n" + "=" * 60)
    print(f"       SECRET GUARD - {dataset_name.upper()} EVALUATION")
    print("=" * 60)

    print(f"Dataset directory       : {dataset_dir}")
    print(f"Ground Truth samples    : {len(records)}")
    print(f"Detected lines          : {len(detected_lines)}")

    print("\nCONFUSION MATRIX")
    print("-" * 60)
    print(f"True Positive  (TP): {tp}")
    print(f"False Positive (FP): {fp}")
    print(f"False Negative (FN): {fn}")
    print(f"True Negative  (TN): {tn}")

    print("\nEVALUATION METRICS")
    print("-" * 60)
    print(
        f"Accuracy : {metrics['accuracy']:.4f} "
        f"({metrics['accuracy'] * 100:.2f}%)"
    )
    print(
        f"Precision: {metrics['precision']:.4f} "
        f"({metrics['precision'] * 100:.2f}%)"
    )
    print(
        f"Recall   : {metrics['recall']:.4f} "
        f"({metrics['recall'] * 100:.2f}%)"
    )
    print(
        f"F1-score : {metrics['f1_score']:.4f} "
        f"({metrics['f1_score'] * 100:.2f}%)"
    )

    print("\nADDITIONAL INFORMATION")
    print("-" * 60)
    print(f"Detections outside Ground Truth: {len(extra_detections)}")

    if extra_detections:
        for filename, line in sorted(extra_detections):
            print(f"  - {filename}, line {line}")

    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate Secret Guard on Development or Test dataset."
    )

    parser.add_argument(
        "--dataset",
        choices=["development", "test"],
        default="development",
        help="Dataset to evaluate (default: development).",
    )

    args = parser.parse_args()

    try:
        evaluate(args.dataset)
    except (FileNotFoundError, ValueError, TypeError, OSError) as error:
        print(f"Evaluation error: {error}")
