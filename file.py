# Test User input reading
usage = "Usage:\n\thelp\n\tupload \"[file]\"\n\tdownload \"[file]\"\n\texit"
print("Program Started")
print(usage)
fstore = "clientStore\\"
f = None
while True:
    inp = input("\n>> ")
    inp = inp.split()
    if inp[0] == "help":
        print(usage)
    elif inp[0] == "upload":
        if len(inp[1]) > 58:
            print("File name cannot be > 58 bytes in length")
            continue
        try:
            f = open(fstore+inp[1], 'rb')
        except IOError as e:
            print(e)
            continue
        contents = f.read()
        print("Upload",fstore+inp[1],"Starting...")
        print(len(contents))
    elif inp[0] == "download":
        print("Download",fstore+inp[1],"Starting...")
    elif inp[0] == "exit":
        print("Program Exiting...")
        exit(0)
    else:
        print("Error: Unrecognized command")
        print(usage)
    


# Test Files Byte Transfer
"""
with open('clientStore\\test.txt', 'rb') as f:
    contents = f.read()

f = open("serverStore\\test.txt", "wb")
bytes = contents
f.write(bytes)
f.close()
"""