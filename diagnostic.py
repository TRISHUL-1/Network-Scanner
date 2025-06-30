import subprocess

print("This program can help you to view / configure your network")

while(True):

    print("Choose from the set of operations that we can perform : ")
    print("1. Get all the details\n" \
    "2. Get the self IP Address\n" \
    "3. Display the DNS Cache\n" \
    "4. Clear the DNS Cache\n" \
    "5. Clear Screen\n" \
    "6. Exit\n")
    option = int(input("> "))

    if option == 1:
        output = subprocess.check_output(["ipconfig", "/all"])
        print(output.decode())
        continue;
    if option == 2:
        output = subprocess.check_output(["ipconfig"])
        print(output.decode())
        continue;
    if option == 3:
        output = subprocess.check_output(["ipconfig", "/displaydns"])
        print(output.decode())
        continue;
    if option == 4:
        output = subprocess.check_output(["ipconfig", "/flushdns"])
        print(output.decode())
        continue;
    if option == 5:
        subprocess.call(["clear"])
    else:
        exit(1)