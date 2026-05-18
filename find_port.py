"""find_port.py — prints the first free port in range 8000-8010."""
import socket
for p in range(8000, 8011):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        if s.connect_ex(("127.0.0.1", p)) != 0:
            print(p)
            break
else:
    print(8000)
