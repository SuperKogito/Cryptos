# -*- coding: utf-8 -*-
"""
Created on Mon Sep 25 01:31:42 2017
@author: SuperKogito
"""
import hashlib
import binascii
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter.scrolledtext import *


class PageOne(tk.Frame):
    """ Page with main functionalities class """
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(background='black')
        self.notebook = ttk.Notebook(self)
        # Define tabs
        self.tab1 = tk.Frame(self.notebook, background='black')
        self.tab1.pack()
        self.tab2 = tk.Frame(self.notebook, background='black')
        self.tab2.pack()
        self.tab3 = tk.Frame(self.notebook, background='black')
        self.tab3.pack()
        self.other = tk.Frame(self.notebook, background='black')
        self.other.pack()
        # Add tabs to notebook instance
        self.notebook.add(self.tab1, text="AES-128 Encryption")
        self.notebook.add(self.tab2, text="AES-128 Decryption")
        self.notebook.add(self.tab3, text="SHA-256 Hashing")
        self.notebook.pack(expand=1, fill="both")
        self.aes_encryption_tab()
        self.aes_decryption_tab()
        self.sha_hashing_tab()
        button = tk.Button(self, text="EXit",
                           command=lambda: self.controller.show_frame("ExitPage"))
        button.configure(background="black", foreground='white',
                         activebackground='#0080ff',
                         activeforeground='white')
        button.pack(side=tk.RIGHT, padx=5, pady=5)
    # ------------------------------- tab1 ---------------------------------

    def aes_encryption_tab(self):
        self.input = tk.LabelFrame(self.tab1, text=" Input Text ",
                                   background="black", foreground='white')
        self.textvar = tk.StringVar()
        self.textbox = tk.Text(self.input, height=5, width=70,
                               wrap='word', undo=True)
        self.textbox.grid(row=0, column=0, columnspan=1)
        self.textbox.pack(expand=1, fill="both", padx=5, pady=5)
        self.input.pack(expand=1, fill="both", padx=5, pady=5)
        self.input3 = tk.LabelFrame(self.tab1, background="black",
                                    foreground='white',
                                    text=" AES-128 Key ")
        self.input3.pack(expand=1, padx=5, pady=5)
        self.verb_ent = tk.Entry(self.input3, width=55)
        self.verb_ent.pack(side=tk.LEFT, expand=1, fill="both",
                           padx=5, pady=5)
        button2 = tk.Button(self.input3, text="Encrypt",
                            command=lambda: self.encrypt_aes128())
        button2.pack(side=tk.LEFT, expand=1, fill="both", padx=5, pady=5)
        button2.configure(background="black", foreground='white',
                          activebackground='#0080ff',
                          activeforeground='white')
        self.input1 = tk.LabelFrame(self.tab1, background="black",
                                    foreground='white',
                                    text=" Output text ")
        self.aes128_encrypt_output = tk.StringVar()
        self.aes128_encrypt_output.set('\nAES 128 ciphered text\n')
        textwidget = tk.Label(self.input1,
                              textvariable=self.aes128_encrypt_output,
                              background='black', foreground="white",
                              wraplength=590)
        textwidget.pack(expand=1, fill="both", padx=5, pady=5)
        self.input1.pack(expand=1, fill="both", padx=5, pady=5)
        textwidget.configure(relief='flat', state="normal")
    # ------------------------------- tab2 ---------------------------------

    def aes_decryption_tab(self):
        self.input21 = tk.LabelFrame(self.tab2, text=" Input Text ",
                                     background="black", foreground='white')
        self.input21.pack(expand=1, fill="both", padx=5, pady=5)
        self.textvar2 = tk.StringVar()
        self.textbox2 = tk.Text(self.input21, height=5, width=70,
                                wrap='word', undo=True)
        self.textbox2.grid(row=0, column=0, columnspan=1)
        self.textbox2.pack(expand=1, fill="both", padx=5, pady=5)
        self.input22 = tk.LabelFrame(self.tab2, background="black",
                                     foreground='white',
                                     text=" AES-128 Key ")
        self.input22.pack(expand=1, padx=5, pady=5)
        self.verb_ent2 = tk.Entry(self.input22, width=55)
        self.verb_ent2.pack(side=tk.LEFT, expand=1, fill="both",
                            padx=5, pady=5)
        button22 = tk.Button(self.input22, text="Decrypt",
                             command=lambda: self.decrypt_aes128())
        button22.pack(side=tk.LEFT, expand=1, fill="both", padx=5, pady=5)
        button22.configure(background="black", foreground='white',
                           activebackground='#0080ff',
                           activeforeground='white')
        self.input23 = tk.LabelFrame(self.tab2, background="black",
                                     foreground='white',
                                     text=" Output text ")
        self.input23.pack(expand=1, fill="both", padx=5, pady=5)
        self.aes128_decrypt_output = tk.StringVar()
        self.aes128_decrypt_output.set('\nAES 128 ciphered text\n')
        textwidget3 = tk.Label(self.input23,
                               textvariable=self.aes128_decrypt_output,
                               background='black', foreground="white")
        textwidget3.pack(expand=1, fill="both", padx=5, pady=5)
    # ------------------------------- tab3 ---------------------------------

    def sha_hashing_tab(self):
        self.input31 = tk.LabelFrame(self.tab3, background="black",
                                     foreground='white',
                                     text=" SHA-256 hashing intput ")
        self.input31.pack(expand=1, fill="both", padx=5, pady=5)
        self.textbox31 = tk.Text(self.input31, height=5, width=70,
                                 wrap='word', undo=True)
        self.textbox31.grid(row=0, column=0, columnspan=1)
        self.textbox31.pack(expand=1, fill="both")
        self.SHA_output = tk.StringVar()
        self.SHA_output.set('\nHash sum\n')
        self.input32 = tk.LabelFrame(self.tab3, background="black",
                                     foreground='white',
                                     text=" SHA-256 hashing output ")
        self.input32.pack(expand=1, fill="both", padx=5, pady=5)
        self.textwidget31 = tk.Label(self.input32,
                                     textvariable=self.SHA_output,
                                     background='black',
                                     foreground="white")
        self.textwidget31.pack(expand=1, fill="both", padx=5, pady=5)
        button31 = tk.Button(self.input31, text="Generate hash",
                             command=lambda: self.hash_sha256())
        button31.pack(side=tk.LEFT, padx=5, pady=5)
        button31.configure(background="black", foreground='white',
                           activebackground='#0080ff',
                           activeforeground='white')
    # ------------------------------- logic --------------------------------

    def encrypt_aes128(self):
        from Crypto.Cipher import AES
        aes128_encrypt_input = self.textbox.get("1.0", tk.END)
        aes128_encrypt_key = self.verb_ent.get()
        # Define aes key
        if len(aes128_encrypt_key) >= 16:
            key = aes128_encrypt_key[:16]
        else:
            self.verb_ent.delete(0, tk.END)
            self.verb_ent.insert(tk.END, 'used key: 0123456789abcdef')
            key = '0123456789abcdef'
        # Data padding
        padding_value = len(aes128_encrypt_input) % 16
        for j in range(0, 16-padding_value):
            aes128_encrypt_input += " "
        # Initialization vector
        IV = 16 * '\x00'
        mode = AES.MODE_CBC
        encryptor = AES.new(key, mode, IV=IV)
        ciphertext = encryptor.encrypt(aes128_encrypt_input)
        output_ciphered_text = binascii.hexlify(ciphertext)
        # Preparing output string
        self.aes128_encrypt_output.set(output_ciphered_text.decode('utf-8'))

    def decrypt_aes128(self):
        from Crypto.Cipher import AES
        aes128_decrypt_input = self.textbox2.get("1.0", tk.END)
        aes128_decrypt_key = self.verb_ent2.get()
        # Define aes key
        if len(aes128_decrypt_key) >= 16:
            key = aes128_decrypt_key[:16]
        else:
            self.verb_ent2.delete(0, tk.END)
            self.verb_ent2.insert(tk.END, 'used key: 0123456789abcdef')
            key = '0123456789abcdef'
        # Initialization vector
        IV = 16 * '\x00'
        mode = AES.MODE_CBC
        encryptor = AES.new(key, mode, IV=IV)
        unhex_data = binascii.unhexlify(aes128_decrypt_input.strip())
        output_plain_text = encryptor.decrypt(unhex_data)
        try: 
            output = output_plain_text.decode('utf-8')
        except UnicodeDecodeError:
            output = 'Unicode decode error'
        self.aes128_decrypt_output.set(output)

    def hash_sha256(self):
        SHA_intput = self.textbox31.get("1.0", tk.END)
        hash_sum = hashlib.sha256(SHA_intput.encode('utf-8')).hexdigest()
        self.SHA_output.set(hash_sum)

    def active_tab(self):
        return self.notebook.index(self.notebook.select())
