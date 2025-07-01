import os

REQUIRED_PACKAGE_DIRS = [
    "blucli",
    "core",
    "languages",
    "languages/java",
    "languages/python",
    "tests",
    "tests/positive",
    "tests/negative"
]

def ensure_init_py(directory):
    init_path = os.path.join(directory, "__init__.py")
    if not os.path.exists(init_path):
        with open(init_path, "w") as f:
            f.write("# Auto-created for package recognition\n")
        print(f"[+] Created: {init_path}")
    else:
        print(f"[✓] Exists: {init_path}")

def main():
    print("🔍 Verifying BluJay package structure...")
    for pkg_dir in REQUIRED_PACKAGE_DIRS:
        if not os.path.exists(pkg_dir):
            print(f"[!] Directory missing: {pkg_dir}")
            continue
        ensure_init_py(pkg_dir)
    print("✅ Package structure verified.")

if __name__ == "__main__":
    main()
