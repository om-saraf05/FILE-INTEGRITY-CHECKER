import os
import hashlib
import json

BASELINE_FILE = "file_hashes.json"

def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error hashing file {filepath}: {e}")
        return None


def scan_directory(directory):
    """Scan directory recursively and return dict of {filepath: hash}."""
    hashes = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            full_path = os.path.join(root, filename)
            file_hash = calculate_file_hash(full_path)
            if file_hash:
                hashes[full_path] = file_hash
    return hashes


def load_baseline():
    """Load stored file hashes."""
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_baseline(data):
    """Save file hashes to disk."""
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=4)


def compare_hashes(old_hashes, new_hashes):
    """Compare baseline and new scan results."""
    modified = []
    added = []
    deleted = []

    # Check for changed or new files
    for path, new_hash in new_hashes.items():
        if path not in old_hashes:
            added.append(path)
        elif old_hashes[path] != new_hash:
            modified.append(path)

    # Check for files removed since baseline
    for path in old_hashes:
        if path not in new_hashes:
            deleted.append(path)

    return modified, added, deleted


def main():
    directory = input("Enter directory to monitor: ").strip()
    print(f"\nScanning directory: {directory}")

    new_hashes = scan_directory(directory)
    old_hashes = load_baseline()

    if not old_hashes:
        print("No baseline found. Creating baseline...")
        save_baseline(new_hashes)
        print("Baseline saved.")
        return

    modified, added, deleted = compare_hashes(old_hashes, new_hashes)

    print("\n========== FILE INTEGRITY REPORT ==========")

    print("\nModified files:")
    for m in modified:
        print(f"  * {m}")

    print("\nNew files:")
    for a in added:
        print(f"  + {a}")

    print("\nDeleted files:")
    for d in deleted:
        print(f"  - {d}")

    print("\nUpdating baseline...")
    save_baseline(new_hashes)
    print("Baseline updated.")


if __name__ == "__main__":
    main()
