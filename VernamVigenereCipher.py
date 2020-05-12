

from fpdf import FPDF
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=12)
pdf2 = FPDF()
pdf2.add_page()
pdf2.set_font("Arial", size=12)

# import tkinter module 
from tkinter import *
  
# import other necessery modules 
import random 
import time 
import datetime 
  
# creating root object 
root = Tk() 
  
# defining size of window 
root.geometry("1200x6000") 
  
# setting up the title of window 
root.title("Message Encryption and Decryption") 
  
Tops = Frame(root, width = 1000, relief = RAISED) 
Tops.pack(side = TOP) 
  
f1 = Frame(root, width = 35, height = 6, relief = RAISED) 
f1.pack(side = LEFT) 
  
# ============================================== 
#                  TIME 
# ============================================== 
localtime = time.asctime(time.localtime(time.time())) 
  
lblInfo = Label(Tops, font = ('helvetica', 20, 'bold'),text = "SECRET MESSAGING \n Vigenère and Vernam cipher", 
                              fg = "Black", bd = 2, anchor='w') 
                       
lblInfo.grid(row = 0, column = 0) 
lblInfo = Label(Tops, font=('arial', 15, 'bold'),  text = localtime, fg = "Steel Blue", bd = 2, anchor = 'w') 
lblInfo.grid(row = 1, column = 0) 
  

Msg = StringVar() 
key = StringVar() 
mode = StringVar() 
cipher = StringVar()
Result = StringVar() 
  
# exit function 
def qExit(): 
    pdf.output("output.pdf")
    pdf2.output("input.pdf")
    root.destroy() 
    
    
# Function to reset the window 
def Reset():  
    Msg.set("") 
    key.set("") 
    mode.set("") 
    cipher.set("")
    Result.set("") 
  
  
#Label pentru mesaj 
lblMsg = Label(f1, font = ('arial', 16, 'bold'), 
         text = "MESSAGE", bd = 16, anchor = "w") 
           
lblMsg.grid(row = 0, column = 0) 
  
txtMsg = Entry(f1, font = ('arial', 16, 'bold'), 
         textvariable = Msg, bd = 4, insertwidth = 2, 
                bg = "powder blue", justify = 'center') 
                  
txtMsg.grid(row = 0, column = 1) 

##Label pentru cheie
  
lblkey = Label(f1, font = ('arial', 16, 'bold'), 
            text = "KEY", bd = 16, anchor = "w") 
              
lblkey.grid(row = 1, column = 0) 
  
txtkey = Entry(f1, font = ('arial', 16, 'bold'), 
         textvariable = key, bd = 4, insertwidth = 2, 
                bg = "powder blue", justify = 'center') 
                  
txtkey.grid(row = 1, column = 1) 


lblmode = Label(f1, font = ('arial', 16, 'bold'), 
          text = "MODE(e for encrypt, d for decrypt)", 
                                bd = 16, anchor = "w") 
                                  
lblmode.grid(row = 2, column = 0) 
  
txtmode = Entry(f1, font = ('arial', 16, 'bold'), 
          textvariable = mode, bd = 4, insertwidth = 2, 
                  bg = "powder blue", justify = 'center') 
                    
txtmode.grid(row = 2, column = 1) 

## Cipher 
lblcipher = Label(f1, font = ('arial', 16, 'bold'), 
          text = "Cipher(Vernam(press key 1 ) or Vigenere(press key 2))", 
                                bd = 16, anchor = "w") 
                                  
lblcipher.grid(row = 3, column = 0) 
  
txtcipher = Entry(f1, font = ('arial', 16, 'bold'), 
          textvariable = cipher, bd = 4, insertwidth = 2, 
                  bg = "powder blue", justify = 'center') 
                    
txtcipher.grid(row = 3, column = 1) 

##Label pentru rezultat
lblService = Label(f1, font = ('arial', 16, 'bold'), 
             text = "The Result", bd = 16, anchor = "n") 
               
lblService.grid(row = 2, column = 2) 
  
txtService = Entry(f1, font = ('arial', 16, 'bold'),  
             textvariable = Result, bd = 4, insertwidth = 2, 
                       bg = "powder blue", justify = 'center') 
                         
txtService.grid(row = 2, column = 3) 
##

import base64 
 
def VigenereEncrypt(key, clear): 
    enc = [] 
      
    for i in range(len(clear)): 
        key_c = key[i % len(key)] 
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256) 
        enc.append(enc_c) 
          
    return base64.urlsafe_b64encode("".join(enc).encode()).decode() 
  
def VigenereDecrypt(key, enc): 
    dec = [] 
      
    enc = base64.urlsafe_b64decode(enc).decode() 
    for i in range(len(enc)): 
        key_c = key[i % len(key)] 
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256) 
        dec.append(dec_c) 
    return "".join(dec) 
  

def VernamEncrypt(key , message):
    encrypted_message = ""
    index = 0
    for char in message:
        encrypted_message = encrypted_message + chr(ord(char) ^ ord(key[index]))
        index = index + 1
        if index == len(key):
            index = 0
    return encrypted_message

def VernamDecrypt(key , message):
    decrypted_message = ""
    index = 0
    for char in message:
        decrypted_message = decrypted_message + chr(ord(char) ^ ord(key[index]))
        index = index + 1
        if index == len(key):
            index = 0
            
    return decrypted_message

  
def Ref(): 
    print("Message= ", (Msg.get())) 
    pdf2.cell(200, 10, txt=Msg.get(), ln=1, align="C")
    clear = Msg.get() 
    k = key.get() 
    m = mode.get()
    c = cipher.get()
    
    if (c == '1'):
        if (m == 'e'): 
            Result.set(VernamEncrypt(k, clear)) 
            print(Result.get())
            pdf.cell(200, 10, txt=Result.get(), ln=1, align="C")
        else: 
            Result.set(VernamDecrypt(k, clear)) 
            print(Result.get())
            pdf.cell(200, 10, txt=Result.get(), ln=1, align="C")
    else:
        if (m == 'e'): 
            Result.set(VigenereEncrypt(k, clear))
            print(Result.get())
            pdf.cell(200, 10, txt=Result.get(), ln=1, align="C")
        else: 
            Result.set(VigenereDecrypt(k, clear))
            print(Result.get())
            pdf.cell(200, 10, txt=Result.get(), ln=1, align="C")
  


 # Show message button 
btnTotal = Button(f1, padx = 16, pady = 8, bd = 16, fg = "black", 
                        font = ('arial', 16, 'bold'), width = 10, 
                       text = "Show Message", bg = "powder blue", 
                         command = Ref).grid(row = 7, column = 1) 
  
# Reset button 
btnReset = Button(f1, padx = 16, pady = 8, bd = 16, 
                  fg = "black", font = ('arial', 16, 'bold'), 
                    width = 10, text = "Reset", bg = "green", 
                   command = Reset).grid(row = 7, column = 2) 
  
# Exit button 
btnExit = Button(f1, padx = 16, pady = 8, bd = 16,  
                 fg = "black", font = ('arial', 16, 'bold'), 
                      width = 10, text = "Exit", bg = "red", 
                  command = qExit).grid(row = 7, column = 3) 

# keeps window alive 
root.mainloop() 
