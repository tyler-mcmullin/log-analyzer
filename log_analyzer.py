
error_lines = []
ip_counts = {}
fails_before_success = {}
flagged_ips = []
sus_threshold = 3
sus_activity = False
pot_breach = False

filename = input("Enter .log file name (without extension): ") + ".log"
try:
    with open(filename, 'r') as file:
        for line_number, line in enumerate(file, 1):
            if "Failed password" in line:
                error_lines.append(line_number)
                substrings = line.split()
                if "from" in substrings:
                    ip_index = substrings.index("from") + 1
                    ip = substrings[ip_index]
                    if ip in ip_counts:
                        ip_counts[ip] += 1
                    else:
                        ip_counts[ip] = 1
                    fails_before_success[ip] = fails_before_success.get(ip, 0) + 1
            elif "Accepted password" in line:
                substrings = line.split()
                if "from" in substrings:
                    ip_index = substrings.index("from") + 1
                    ip = substrings[ip_index]
                    if ip in fails_before_success and fails_before_success[ip] >= sus_threshold:
                        pot_breach = True
                        if ip not in flagged_ips:
                            flagged_ips.append(ip)
                    fails_before_success[ip] = 0
 
except FileNotFoundError:
    print(f"'{filename}' was not found.")

if len(error_lines) != 0:
    print(f"Total failed password attempts: {len(error_lines)}")
    print(f"Lines with failed attempts: {error_lines}\n")
    print(f"\nFailed attempts by IP: ")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")

for count in ip_counts.values():
    if count >= sus_threshold:
        sus_activity = True

if pot_breach:
    print("\nPotential breach at IP(s):")
    for ip in flagged_ips:
        print(f"{ip}: {ip_counts[ip]} failed attempts before successful login.")

if sus_activity:
    print("\nSuspicious activity detected at IP(s) (multiple failed login attempts):")
    for ip, count in ip_counts.items():
        if count >= sus_threshold:
                print(f"{ip}: {count}")






