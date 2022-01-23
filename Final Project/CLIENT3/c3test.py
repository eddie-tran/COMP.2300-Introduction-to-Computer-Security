'''
Class: Introduction to Computer Security
Assignment: Project - Secure File Transfer Milestones 1-3
Team 3: Eddie Tran, Alvin Tran, Joshua Hou
Date: 10/24/2021
'''

# for json
import json
import os

# for registration and login
import getpass
import bcrypt

# for encryption/decryption
from Crypto import PublicKey
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes, new

# for networking
import socket

# check json if there is an existing user
def check_existing_user():
    file_path = "user.json"
    if os.path.getsize(file_path) == 0:  # checks if there is an existing user, return False if no user
        return False
    else:  # if there is an existing user, return True
        return True

# register the user
def register():
    while True: # loops until correct input
        print("No users are registered with this client.")
        choice = input("Do you want to register a new user (y\\n)? ")
        if choice == "y":
            user_data = get_user_data()  # user chooses to register, user will proceed to enter user data
            write_json(user_data, "user_info")  # after successfully getting user data, will write the data in the json file
            encryption() # encrypt the contacts json file even if there is nothing written in it
            break
        elif choice == "n":
            print("Thanks, have a good day. \nTerminating...")
            break
        else:
            print("Incorrect input.\n")

# gets user register data
def get_user_data():
    name = input("\nEnter Full Name: ")
    email = input("Enter Email Address: ")
    passwd = getpass.getpass("Enter Password: ")  # getpass makes it so password input is invisible on screen
# ***** For testing *****
#    while passwd_requirements(passwd) == False:  # will have the user input a password that satisfies the password requirements
#        passwd = getpass.getpass("Enter Password: ")
    passwd_check = getpass.getpass("Re-enter Password: ")  # have user input password again
    user_data = {}
    while True:  # loop until the user correctly inputs the intended password two times to confirm the user's password
        if passwd_check == passwd:  # match
            passwd = passwd.encode('utf-8')  # encode to bytes
            hashed_passwd = bcrypt.hashpw(passwd, bcrypt.gensalt(10))  # apply bcrypt hash
            hashed_passwd = hashed_passwd.decode('utf-8')  # decode to apply to json
            user_data = {"name": name, "email": email, "password": hashed_passwd}
            print("\nPasswords Match.\nUser Registered.\nExiting SecureDrop.")
            break
        else:
            print("Passwords did not match.\n")
            passwd = getpass.getpass("Enter Password: ")  # let user reenter password again after failing the password check
            passwd_check = getpass.getpass("Re-enter Password: ")
    return user_data

# password reqiurements for security
def passwd_requirements(passwd):
    lower, upper, digit, special = 0, 0, 0, 0
    special_char = ['`','~','!','@','#','$','%','^','&','*','(',')','_','+','-','=']
    if (len(passwd) >= 8):
        for i in passwd:
            if (i.islower()):  # counting lowercase alphabets 
                lower+=1            
            if (i.isupper()):  # counting uppercase alphabets
                upper+=1            
            if (i.isdigit()):  # counting digits
                digit+=1            
            for j in special_char:  # counting the mentioned special characters
                if (i == j):
                    special+=1           
    if (lower>=1 and upper>=1 and digit>=1 and special>=1 and lower+upper+digit+special==len(passwd)):
        return True
    else:
        print("\nInvalid Password Requirements")
        print("Must contain at least 1 lowercase")
        print("Must contain at least 1 uppercase")
        print("Must contain at least 1 digit")
        print("Must contain at least 1 special character: \n", special_char, "\n")
        return False

# write to json file
def write_json(new_data, section):
    with open("user.json", "a+") as f:
        file_data = {}
        file_data[section] = []
        file_data[section].append(new_data)
        f.seek(0)
        json.dump(file_data, f, indent=4)

# login
def login():
    is_user = False
    while (is_user == False):
        email = input("Enter Email Address: ")
        passwd = getpass.getpass("Enter Password: ")
        is_user = authenticate_user(email, passwd)  # authenticate the user by checking if email and password input matched with the user in the json file
    decryption() # decrypt the contacts json file so we can see the contents of it
    print("Welcome to SecureDrop.")

# during login, authenticate the user by checking matching email and passwords    
def authenticate_user(email, passwd):
    with open("user.json", "r") as f:  # open json file as read
        file_data = json.load(f)  # load user_info into file_data
        for user in file_data["user_info"]:
            if email == user["email"]:
                if bcrypt.checkpw(passwd.encode('utf-8'), user["password"].encode('utf-8')):  # passwords have to be encoded to check if passwords matched
                    return True
    print("Email and Password Combination Invalid\n")
    return False

# interface includes commands
def interface(s, host, port):
    print("Type \"help\" For Commands.\n")
    while True:
        command = input("secure_drop> ")
        if command == "help":
            help()
        elif command == "add":
            add(s, host, port)
        elif command == "list":
            list(s, host, port)
        elif command == "send":
            send()
        elif command == "exit":
            encryption()  # when exiting program, encrypt the contacts json file
            remove_user_from_server(s, host, port)
            break

# help function that displays all of the commands
def help():
    print("  \"add\"  -> Add a new contact")
    print("  \"list\" -> List all online contacts")
    print("  \"send\" -> Transfer file to contact")
    print("  \"exit\" -> Exit SecureDrop")

# add contacts to json
def add(s, host, port):

    #flag
    msg = "Updating Contacts"
    msg = msg.encode("utf-8")
    s.sendto(msg, (host, port))

    name = input("  Enter Full Name: ")
    email = input("  Enter Email Address: ")
    new_user = {"name": name, "email": email}
    file_path = "contacts.json"
    if os.path.getsize(file_path) == 0:  # checks if there is anything in the contacts json file
        with open("contacts.json", "a+") as f:  # if there is nothing, will create a new dictionary and append first key-value pair
            file_data = {}
            file_data["contact_info"] = []
            file_data["contact_info"].append(new_user)
            f.seek(0)
            json.dump(file_data, f, indent=4)
            print("  Contact Added.")
            
            new_contact = json.dumps(new_user)
            new_contact = new_contact.encode("utf-8")
            s.sendto(new_contact, (host, port))
            print("contact added in server")
    else:
        with open("contacts.json", "r+") as f:
            file_data = json.load(f)
            for e in file_data["contact_info"]:  # already have a contact?, check if contact exists
                if email == e["email"]:  # email address is used as the user identifier
                    print("  Contact exists. Overwriting...")
                    e.update(new_user)  # contact does exist, so overwrite the data with the new contact data
                    f.seek(0)
                    json.dump(file_data, f, indent = 4)
                    f.truncate()

                    new_contact = json.dumps(new_user)
                    new_contact = new_contact.encode("utf-8")
                    s.sendto(new_contact, (host, port))
                    print("contact added in server")
                    break
            else:  # contact does not exist, so add the new contact data
                file_data["contact_info"].append(new_user)
                f.seek(0)
                json.dump(file_data, f, indent=4)
                f.truncate()
                print("  Contact Added.") 

                new_contact = json.dumps(new_user)
                new_contact = new_contact.encode("utf-8")
                s.sendto(new_contact, (host, port))
                print("contact added in server")


# Milestone 4
def list(s, host, port):
    # Only lists if...
    # 1. The contact information has been added to this user's contacts.
    # 2. The contact has also added this user's information to their contacts
    # 3. The contact is online on the user's local network

    file_path = "contacts.json"
    if os.path.getsize(file_path) != 0:  # checks if there is anything in the server_list json file
        with open("user.json", "r") as f:
            file_data = json.load(f)
            user_email = file_data["user_info"][0]["email"]
            user_email = user_email.encode("utf-8")

        with open("contacts.json", "r") as f:
            file_data = json.load(f)
            for e in file_data["contact_info"]:
                msg = "Listing Contacts"
                msg = msg.encode("utf-8")
                s.sendto(msg, (host, port)) ## the method transmits UDP message ## sendto(bytes, address)

                s.sendto(user_email, (host, port))
                contact_email = e["email"]
                contact_email = contact_email.encode("utf-8")
                s.sendto(contact_email, (host, port)) ## the method transmits UDP message ## sendto(bytes, address)

                data, addr = s.recvfrom(1024)
                data = data.decode("utf-8")

                if data == "true":
                    print("  * " + e["name"] + " <" + e["email"] + ">")

# Milestone 5
def send(email, file):
    # print(email) test
    # print(file) test
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) ## AF_INET is family of protocols. SOCK_DGRAM is a type that for connectionless protocols

     # send flag
    hostname = socket.gethostname()
    host = socket.gethostbyname(hostname)
    port = 5555 # port number

    msg = "File Send"
    msg = msg.encode("utf-8")
    s.sendto(msg, (host, port))

    # send file
    t = socket.socket(socket.AF_INET,socket.SOCK_STREAM) ## AF_INET is family of protocols. SOCK_DGRAM is a type that for connectionless protocols
    thostname = socket.gethostname()
    host = socket.gethostbyname(hostname)
    port = 5555 # port number
    t.bind((host,port))
    t.listen()

    filename = file
    f = open(filename, "rb")
    file_data = f.read(4096)
    server,address = t.accept()
    while True:
        if file_data:
            print('Attempting to send data...')
            server.send(file_data)
            data = f.read(4096)
            print("File Sent.")
            break
        else:
            print('File sent failure.')
            break

    print(file_data)
    t.sendfile(f)
    t.close()
    # check email to see if users is online
        # if user is online search for file path


            # store file in variable
        # else return can't find file
    # send file to server using socket

    print("  send function")

# encryption function to encrypt the contacts json file
def encryption():
    plaintext_file = "contacts.json"

    # obtaining the plaintext from plaintext-file.txt
    plaintext_file = open(plaintext_file, 'rb')
    plaintext = plaintext_file.read()
    plaintext_file.close()

    # generating private and public RSA keys
    key_rsa = RSA.generate(2048)
    private_key = key_rsa.export_key()
    file_out = open("private_key.pem", 'wb')
    file_out.write(private_key)
    file_out.close()
    public_key = key_rsa.publickey().export_key()
    file_out = open("public_key.pem", 'wb')
    file_out.write(public_key)
    file_out.close()

    # generating an AES key
    key_aes = get_random_bytes(16)

    # encrypting the AES key with the public RSA key
    recipeint_key = RSA.import_key(open("public_key.pem").read())
    cipher_rsa = PKCS1_OAEP.new(recipeint_key)
    encrypted_key_aes = cipher_rsa.encrypt(key_aes)

    # encrypting all the data (encrypted aes key, aes cipher, tag, and ciphertext) using the AES key 
    file_out = open("contacts.json", 'wb')
    cipher_aes = AES.new(key_aes, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
    [file_out.write(x) for x in (encrypted_key_aes, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()

# decryption function used to decrypt contacts json file
def decryption():
    encryption_file = "contacts.json"

    # obtaining the encryption file and private key
    file_in = open(encryption_file, 'rb')
    private_key = RSA.import_key(open("private_key.pem").read())

    # extracting the encrypted data from the encryption file
    encrypted_key_aes, nonce, tag, ciphertext = [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    # decrypting the encrypted AES key using the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    key_aes = cipher_rsa.decrypt(encrypted_key_aes)
    
    # decrypting the data using the AES key
    cipher_aes = AES.new(key_aes, AES.MODE_EAX, nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    file_out = open("contacts.json", 'wb')
    file_out.write(plaintext)
    file_out.close()

def add_user_to_server(s, host, port):
    with open("user.json", "r") as f:
        file_data = json.load(f)
        msg = "Adding User"
        msg = msg.encode("utf-8")
        s.sendto(msg, (host, port)) ## the method transmits UDP message ## sendto(bytes, address)

        user_email = file_data["user_info"][0]["email"]
        user_email = user_email.encode("utf-8")
        s.sendto(user_email, (host, port)) ## the method transmits UDP message ## sendto(bytes, address)
    
    file_path = "contacts.json"
    if os.path.getsize(file_path) == 0:  # checks if there is anything in the server_list json file
        file_data = {}
        file_data["contact_info"] = []
        contact_emails = json.dumps(file_data)
        contact_emails = contact_emails.encode("utf-8")
        s.sendto(contact_emails, (host, port))
    else:
        with open("contacts.json", "r") as f:
            file_data = json.load(f)
            contact_emails = json.dumps(file_data)
            contact_emails = contact_emails.encode("utf-8")
            s.sendto(contact_emails, (host, port))

def remove_user_from_server(s, host, port):
    with open("user.json", "r") as f:
        file_data = json.load(f)
        msg = "Removing User"
        msg = msg.encode("utf-8")
        s.sendto(msg, (host, port)) ## the method transmits UDP message ## sendto(bytes, address)

        email = file_data["user_info"][0]["email"]
        email = email.encode("utf-8")
        s.sendto(email, (host, port)) ## the method transmits UDP message ## sendto(bytes, address)

# main
def main():
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) ## AF_INET is family of protocols. SOCK_DGRAM is a type that for connectionless protocols

    hostname = socket.gethostname()
    host = socket.gethostbyname(hostname)
    port = 5555 # port number

    open("user.json", "a+")
    open("contacts.json", "a+")
    if check_existing_user() == False:
        register()  # no existing user, go to register
    else:
        login()  # is existing user, go to login
        add_user_to_server(s, host, port)
        interface(s, host, port)  # after successful login, proceed to the interface

# run main
if __name__ == "__main__":
    main()