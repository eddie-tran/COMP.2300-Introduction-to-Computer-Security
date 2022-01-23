Class: Introduction to Computer Security <br />
Assignment: Project - Secure File Transfer Milestones 1-3 <br />
Team 3: Eddie Tran, Alvin Tran, Joshua Hou <br />
Date: 10/24/2021 <br />

Goals: <br />

- Milestone 1 <br />
    Registration <br />
    Check if json is empty <br />
    Encrypt password <br />

- Milestone 2 <br />
    Login <br />
    Call encrypted password <br />
    Compare encrypted password to input password <br />
    Returns true if passwords matched, false for mismatch <br />

- Milestone 3 <br />
    Adding Contacts <br />
    Encrypt contact.json using public key <br />
    Decrypt contact.json using private key <br />

- How to compile: <br />
	python main.py <br />

- When compiled: <br />
    4 files will generate in order for this program to work. <br />
        user.json <br />
        contacts.json <br />
        private.pem <br />
        public.pem <br />

    On completing registration, contacts.json will encrypt and generate an error. <br />
    This is due json files only allowing json related objects, arrays, or literals. <br />
    However, this is fine. <br />
    Encrypting the contacts.json will generate the .pem files that are needed for later use. <br />
    On login, contacts.json will decrypt showing your contacts to hopefully the 'real' user. <br />
    On exit, the contacts.json will encrypt in order to protect your data from attacks. <br />
    
    
    ---------------------------------------------------------------------------------------------- <br />
    
Class: Introduction to Computer Security <br />
Assignment: Project <br />
Group: Eddie Tran, Alvin Tran, Joshua Hou <br />
Date: 12/14/2021 <br />

Steps To Use Code: <br />
1) First have the server.py file be in its own directory. <br />
2) Next have the secure_drop.py file also be in its own directory. <br />
3) Before starting any secure_drop.py program, first start the server.py program file by typing... <br />
   	python server.py <br />
4) Start the secure_drop.py program by typing... <br />
	  python secure_drop.py <br />
5) If you want more than one client, have copies of the secure_drop.py program be in their own <br />
   new directories and start the secure_drop.py programs using the previous step. <br />
