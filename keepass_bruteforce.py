import pykeepass
from itertools import product

def try_passwords(keepass_file):
    for attempt in product('0123456789', repeat=4):
        password = ''.join(attempt)
        print(password)
        try:
            kp = pykeepass.PyKeePass(keepass_file, password=password)
            print(f"Password found: {password}")
            return
        except Exception as e:
            # Incorrect password
            pass
    print("Password not found.")

keepass_file = r'D:\Philips University\IT Security\Project\databases\databases\Ahsana.kdbx'

try_passwords(keepass_file)