import os

# A known list of ciphers that MUST appear in the file.
# If any are missing, we'll add them with a correct configuration at the end.
EXPECTED_CIPHERS = [
    "DES 56/56",
    "NULL",
    "RC2 128/128",
    "RC2 40/128",
    "RC2 56/128",
    "RC4 128/128",
    "RC4 40/128",
    "RC4 56/128",
    "RC4 64/128",
    "Triple DES 168",
    "AES 128/128",
    "AES 192/192",
    "AES 256/256",
]

CONFIG_FILE = "config_file.txt"  # The configuration file path


def load_config(filename):
    """
    Reads the configuration file line by line.
    Handles both registry-style entries and simple key-value pairs.
    Returns a dict: {cipher_name: value}
    Also returns the original lines (for rewriting in the same format).
    """
    config_dict = {}
    original_lines = []
    current_cipher = None

    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            original_lines.append(line)
            line_stripped = line.strip()

            # Skip empty lines
            if not line_stripped:
                continue

            # Check if line is a registry-style cipher header
            if line_stripped.startswith(
                "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\"
            ):
                # Extract the cipher name from the registry key
                parts = line_stripped.split("\\")
                if len(parts) > 1:
                    cipher_part = parts[-1].rstrip("]")
                    # Skip the main Ciphers key
                    if cipher_part != "Ciphers":
                        current_cipher = cipher_part

            # Check if line contains the registry-style "Enabled" value
            elif '"Enabled"=dword:' in line_stripped and current_cipher:
                value = line_stripped.split(":")[-1]
                config_dict[current_cipher] = value

            # Check if line is a simple key-value pair (non-registry style)
            elif " = " in line_stripped:
                parts = line_stripped.split(" = ", 1)
                if len(parts) == 2:
                    cipher, value = parts
                    cipher = cipher.strip()
                    value = value.strip()
                    # Store as a different format but still track it
                    config_dict[cipher + "_simple"] = value

    return config_dict, original_lines


def check_misconfigurations(config_dict):
    """
    Checks which ciphers are not set to '00000000' or 'disabled'.
    Returns a list of misconfigured ciphers.
    """
    misconfigured = []
    for cipher, value in config_dict.items():
        # Handle simple format entries
        if cipher.endswith("_simple"):
            actual_cipher = cipher[:-7]  # Remove "_simple" suffix
            if value.lower() != "00000000" and value.lower() != "disabled":
                misconfigured.append(f"{actual_cipher} (simple format)")
        # Handle registry format entries
        else:
            if value.lower() != "00000000" and value.lower() != "disabled":
                misconfigured.append(f"{cipher} (registry format)")

    return misconfigured


def rewrite_file(original_lines, config_dict, filename):
    """
    Rewrites the configuration file in the exact same format,
    but with corrected values for each cipher.
    """
    current_cipher = None
    fixed_lines = []

    for line in original_lines:
        line_stripped = line.strip()

        # Skip empty lines but preserve them
        if not line_stripped:
            fixed_lines.append(line)
            continue

        # Check if line is a registry-style cipher header
        if line_stripped.startswith(
            "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\"
        ):
            parts = line_stripped.split("\\")
            if len(parts) > 1:
                cipher_part = parts[-1].rstrip("]")
                if cipher_part != "Ciphers":
                    current_cipher = cipher_part
            fixed_lines.append(line)

        # Check if line contains the registry-style "Enabled" value
        elif '"Enabled"=dword:' in line_stripped and current_cipher:
            if (
                current_cipher in config_dict
                and config_dict[current_cipher] != "00000000"
            ):
                # Replace with fixed value
                fixed_lines.append('"Enabled"=dword:00000000\n')
            else:
                fixed_lines.append(line)

        # Check if line is a simple key-value pair
        elif " = " in line_stripped:
            parts = line_stripped.split(" = ", 1)
            if len(parts) == 2:
                cipher, value = parts
                cipher = cipher.strip()
                simple_key = cipher + "_simple"

                if simple_key in config_dict and config_dict[simple_key] != "00000000":
                    # Replace with fixed value
                    fixed_lines.append(f"{cipher} = 00000000\n")
                else:
                    fixed_lines.append(line)
        else:
            fixed_lines.append(line)

    with open(filename, "w", encoding="utf-8") as f:
        f.writelines(fixed_lines)


def append_missing_ciphers(config_dict, filename):
    """
    Checks if any cipher in EXPECTED_CIPHERS is missing from config_dict.
    If missing, append it to the file with '00000000'.
    """
    # Check both registry format and simple format
    missing_ciphers = []
    for expected in EXPECTED_CIPHERS:
        registry_found = expected in config_dict
        simple_found = expected + "_simple" in config_dict

        if not registry_found and not simple_found:
            missing_ciphers.append(expected)

    if missing_ciphers:
        with open(filename, "a", encoding="utf-8") as f:
            f.write("\n# Added missing ciphers\n")

            # Append in registry format
            for cipher in missing_ciphers:
                f.write("\n")
                key_path = f"[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\{cipher}]"
                f.write(f"{key_path}\n")
                f.write('"Enabled"=dword:00000000\n')


def print_config_file(filename):
    """
    Prints the entire config file to the terminal (for Output 2).
    """
    print("\n--- Current Configuration File ---")
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()
        print(content)
    print("----------------------------------\n")


def main():
    # 1) Load the configuration file
    config_dict, original_lines = load_config(CONFIG_FILE)

    # 2) Check for misconfigurations
    misconfigured = check_misconfigurations(config_dict)

    # Output 1: List the misconfigured ciphers
    if misconfigured:
        print("Misconfigured ciphers found:")
        for cipher in misconfigured:
            print(f" - {cipher}")
    else:
        print("No misconfigurations found.")

    # 3) If any misconfigurations exist, fix them (set to 00000000)
    if misconfigured:
        # Rewrite the file with fixed values
        rewrite_file(original_lines, config_dict, CONFIG_FILE)
        print("\n[!] The configuration file has been fixed.\n")

    # Output 2: Show the 'fixed' configuration file
    print_config_file(CONFIG_FILE)

    # 4) If there is still time, append missing ciphers
    orig_registry_ciphers = {
        cipher: value
        for cipher, value in config_dict.items()
        if not cipher.endswith("_simple")
    }
    orig_simple_ciphers = {
        cipher[:-7]: value
        for cipher, value in config_dict.items()
        if cipher.endswith("_simple")
    }

    missing_any = any(
        expected not in orig_registry_ciphers and expected not in orig_simple_ciphers
        for expected in EXPECTED_CIPHERS
    )

    if missing_any:
        append_missing_ciphers(config_dict, CONFIG_FILE)
        print("\n[!] Missing ciphers have been added to the configuration file.\n")
        print_config_file(CONFIG_FILE)


if __name__ == "__main__":
    main()
