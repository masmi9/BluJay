#!/usr/bin/env python3
"""
Interactive Objection Test Script
Shows how to use objection programmatically and interactively
"""

import subprocess


def test_objection_connection():
    """Test objection connection to device and app."""
    print("🔍 Testing Objection Interactive Capabilities")
    print("=" * 60)

    # Test 1: List available devices
    print("\n1. 📱 Available Frida Devices:")
    try:
        result = subprocess.run(["./aods_venv/bin/frida-ls-devices"], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"❌ Error: {result.stderr}")
    except Exception as e:
        print(f"❌ Failed to list devices: {e}")

    # Test 2: Check if AndroGoat is running
    print("\n2. 🔍 Checking for running apps:")
    try:
        result = subprocess.run(["./aods_venv/bin/frida-ps", "-U"], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            print(f"Found {len(lines)-1} running processes")

            # Look for AndroGoat or other interesting apps
            for line in lines:
                if any(keyword in line.lower() for keyword in ["goat", "test", "vulnerable", "security"]):
                    print(f"  📱 {line}")
        else:
            print(f"❌ Error listing processes: {result.stderr}")
    except Exception as e:
        print(f"❌ Failed to list processes: {e}")

    # Test 3: Show objection commands for manual testing
    print("\n3. 💡 Manual Objection Commands:")
    print("   To connect to AndroGoat:")
    print("   ./aods_venv/bin/objection -g owasp.sat.agoat explore")
    print()
    print("   Common objection commands once connected:")
    print("   📋 env                    # Show environment info")
    print("   📋 android info           # Android system info")
    print("   📋 android keystore list  # List keystore entries")
    print("   📋 android sslpinning disable  # Bypass SSL pinning")
    print("   📋 android root detection disable  # Bypass root detection")
    print("   📋 memory list modules    # List loaded modules")
    print("   📋 android hooking list classes  # List available classes")
    print("   📋 android intent launch_activity <activity>  # Launch activities")
    print("   📋 file download <remote_path> <local_path>   # Download files")
    print("   📋 android clipboard monitor  # Monitor clipboard")
    print()

    # Test 4: Create sample objection script
    objection_script = """# Sample Objection Commands Script
# Save this to objection_commands.txt and use:
# ./aods_venv/bin/objection -g owasp.sat.agoat explore -c objection_commands.txt

env
android info
android keystore list
android sslpinning disable
android root detection disable
memory list modules
android hooking list classes --include-parents
android clipboard monitor --verbose
"""

    with open("sample_objection_commands.txt", "w") as f:
        f.write(objection_script)

    print("4. 📝 Created sample_objection_commands.txt")
    print("   Use it with: ./aods_venv/bin/objection -g owasp.sat.agoat explore -c sample_objection_commands.txt")

    # Test 5: Show AODS integration
    print("\n5. 🔗 AODS Integration Commands:")
    print("   Basic integration:")
    print("   ./aods_venv/bin/python dyna.py --apk apks/AndroGoat.apk --pkg owasp.sat.agoat --with-objection")
    print()
    print("   Advanced integration:")
    print("   ./aods_venv/bin/python dyna.py --apk apks/AndroGoat.apk --pkg owasp.sat.agoat \\")
    print("     --with-objection --objection-mode verify --export-objection-commands \\")
    print("     --output results_with_objection.json")


if __name__ == "__main__":
    test_objection_connection()
