'''
Class: Introduction to Computer Security
Assignment: Project - Secure File Transfer Milestones 4-5
Team 3: Eddie Tran, Alvin Tran, Joshua Hou
Date: 12/15/2021
'''

# For server
import socket
import json
import os

# First, Create the info holder for server
open("server_list.json", "a+")

# AF_INET is family of protocols. SOCK_DGRAM is a type that for connectionless protocols
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to the given ip address/port
# Binds address:(hostname,port#) to socket
hostname = socket.gethostname()
host = socket.gethostbyname(hostname)
port = 5555
s.bind((host, port))

# Run server
while True:
    print("Server is Live. Accepting Users...\n")

    # Default flag
    flag = "Idle"

    # Receives UDP message , 1024 means the # of bytes to be read from the udp socket.
    data, addr = s.recvfrom(1024)
    flag = data.decode("utf-8")

    # Testing purposes
    print("Flag: ", flag)

    # Adding user to server_list
    if flag == "Adding User":
        # Receives UDP message , 1024 means the # of bytes to be read from the udp socket.
        data, addr = s.recvfrom(1024)

        # Decodes data and sets the information to variables
        data = data.decode("utf-8")
        user_email = data
        user_port = addr[1]

        # Receives UDP message , 1024 means the # of bytes to be read from the udp socket.
        data, addr = s.recvfrom(1024)

        # Decodes data and sets and load the information to variables
        data = data.decode("utf-8")
        user_contact = json.loads(data)

        # Structure for user information
        on_server = {"email": user_email, "port": user_port}
        on_server.update(user_contact)

        file_path = "server_list.json"
        # Checks if there is anything in the server_list json file
        if os.path.getsize(file_path) == 0:
            # If there is nothing, create a new dictionary and append user
            with open("server_list.json", "a+") as f:
                file_data = {}
                file_data["server_info"] = []
                file_data["server_info"].append(on_server)
                f.seek(0)
                json.dump(file_data, f, indent=4)
                print("  User Added.")
        else:
            # If something, just append user
            with open("server_list.json", "r+") as f:
                file_data = json.load(f)
                file_data["server_info"].append(on_server)
                f.seek(0)
                json.dump(file_data, f, indent=4)
                f.truncate()
                print("  User Added.")

    # Update server_list's contact_info for users
    elif flag == "Updating Contacts":
        # Open and load file
        with open("server_list.json", "r+") as f:
            file_data = json.load(f)

            # Receive the contact that we are updating
            data, addr = s.recvfrom(1024)

            # Decodes data and sets the information to variables
            new_contact = data.decode("utf-8")
            new_contact = json.loads(data)

            # For every user on server_list
            for e in file_data["server_info"]:
                # Check if we are updating the correct user's contacts
                if addr[1] == e["port"]:
                    # Look for contact we want to change
                    for x in e["contact_info"]:
                        # If this is the contact we want to update
                        # Update contact
                        if new_contact["email"] == x["email"]:
                            print("UPDATING", new_contact)
                            x.update(new_contact)
                            f.seek(0)
                            json.dump(file_data, f, indent=4)
                            f.truncate()
                            break
                    else:
                        # Just append the contact
                        print("APPENDING", new_contact)
                        e["contact_info"].append(new_contact)
                        f.seek(0)
                        json.dump(file_data, f, indent=4)
                        f.truncate()
                        print("Contact added")

    # Listing the user's contacts
    elif flag == "Listing Contacts":
        # Receives UDP message , 1024 means the # of bytes to be read from the udp socket.
        # Decodes data and sets the information to variables
        data, addr = s.recvfrom(1024)
        user_email = data.decode("utf-8")

        # Receives UDP message , 1024 means the # of bytes to be read from the udp socket.
        # Decodes data and sets the information to variables
        data, addr = s.recvfrom(1024)
        contact_email = data.decode("utf-8")

        # Temp variable
        found = False

        # Mutual friend check
        with open("server_list.json", "r+") as f:
            file_data = json.load(f)
            for e in file_data["server_info"]:
                if contact_email == e["email"]:
                    for u in e["contact_info"]:
                        if user_email == u["email"]:
                            found = True
                            msg = "true"
                            msg = msg.encode("utf-8")
                            s.sendto(msg, (host, addr[1]))
                            break

        if found == False:
            msg = "false"
            msg = msg.encode("utf-8")
            s.sendto(msg, (host, addr[1]))

    elif flag == "File Send":
        print("Connection from: " + str(addr))
        while True:
            # file listen
            t = socket.socket(socket.AF_INET,
                              socket.SOCK_STREAM)  # AF_INET is family of protocols. SOCK_DGRAM is a type that for connectionless protocols

            thostname = socket.gethostname()
            thost = socket.gethostbyname(hostname)
            tport = 5554  # port number
            t.connect((thost, tport))
            print("Receiving file from client.")
            data = t.recv(4096)
            print("Creating file to save data.")
            with open("file.zip", 'wb') as f:
                f.write(data)
                print("File Received.")
                break

    elif flag == "Removing User":
        # this method receives UDP message , 1024 means the # of bytes to be read from the udp socket.
        data, addr = s.recvfrom(1024)
        data = data.decode("utf-8")
        user_email = data

        with open("server_list.json", "r+") as u:
            file_data2 = json.load(u)
            count = 0
            for e in file_data2["server_info"]:
                if e["email"] == user_email:
                    print("  Server User exists. ")
                    file_data2["server_info"].pop(count)
                    u.seek(0)
                    json.dump(file_data2, u, indent=4)
                    u.truncate()
                count = count + 1

    elif flag == "Idle":
        print("Server recieved nothing...")
