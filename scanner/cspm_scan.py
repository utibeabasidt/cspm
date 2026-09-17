import subprocess
import sys


def run_module(module_name):
    print("\n" + "=" * 60)
    print(f"RUNNING: {module_name}")
    print("=" * 60)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            module_name,
        ],
        check=False,
    )

    if result.returncode != 0:
        print(
            f"\nModule failed: {module_name}"
        )

        return False

    return True


def main():
    print("\nCSPM FULL SECURITY SCAN")
    print("=======================")

    s3_success = run_module(
        "scanner.s3_scan"
    )

    if not s3_success:
        print(
            "\nCSPM scan stopped because "
            "the S3 scan failed."
        )
        return

    iam_success = run_module(
        "scanner.iam_scan"
    )

    if not iam_success:
        print(
            "\nCSPM scan stopped because "
            "the IAM scan failed."
        )
        return

    report_success = run_module(
        "scanner.report"
    )

    if not report_success:
        print(
            "\nCSPM scan completed, but "
            "report generation failed."
        )
        return

    print("\n" + "=" * 60)
    print("CSPM FULL SECURITY SCAN COMPLETED")
    print("=" * 60)

    print("\nGenerated reports:")
    print("- reports/s3_scan.json")
    print("- reports/iam_scan.json")
    print("- reports/cspm_report.json")


if __name__ == "__main__":
    main()