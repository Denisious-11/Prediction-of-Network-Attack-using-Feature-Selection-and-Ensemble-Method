from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter import messagebox,DISABLED,NORMAL
import threading
from functools import partial
from PIL import Image, ImageTk
import time
from tkinter.scrolledtext  import ScrolledText
import joblib
import pandas as pd


my_background_color='#87608f'

# Function to load the trained model
model=joblib.load('Models/xgboost_model.joblib')
scaler_ = joblib.load('Models/minmax_scaler.joblib')

title="Network Attack Predictor"


def perform_validation():
	global uname_variable,password_variable
	uname=uname_variable.get()
	pass1=password_variable.get()
	if uname=="Anjana" and pass1=="Anjana":
		go_for_test()
	else:
		messagebox.showinfo("Warning","Wrong Credentials")   


def pred_function():
    
    alltext=input_text.get("1.0",'end')
    if alltext=='' or alltext=='\n':
        messagebox.showinfo("Alert","Fill the empty field")   
    else:

        relist=[]
        list1=alltext.split(",")
        print(list1)
        floatlist=[float(x)for x in list1]
        print(floatlist)

        # Create a DataFrame with the user input
        sample_row = pd.DataFrame([floatlist])

        # Perform standardization on the sample row
        sample_row_scaled = scaler_.transform(sample_row)


        # Predict the class label
        prediction = model.predict(sample_row_scaled)

        # Print the predicted label
        print("Predicted Label:", prediction)
        preds=prediction[0]
        print(preds)

        if preds==0:
            messagebox.showinfo("Result","Normal")
            st2.insert(INSERT,"Normal") 
        if preds==1:
            messagebox.showinfo("Result","Dos Attack")
            st2.insert(INSERT,"Dos Attack") 
        if preds==2:
           	messagebox.showinfo("Result","Probe Attack")
           	st2.insert(INSERT,"Probe Attack") 
        if preds==3:
           	messagebox.showinfo("Result","R2L Attack")
           	st2.insert(INSERT,"R2L Attack") 
        if preds==4:
           	messagebox.showinfo("Result","U2R Attack")
           	st2.insert(INSERT,"U2R Attack") 


def go_for_test():
	top.title(title)
	top.config(menu=menubar)
	global f
	f.pack_forget()
	f=Frame(top)
	f.config(bg="#8acdc1")
	f.pack(side="top", fill="both", expand=True,padx=10,pady=10)

	
	#right
	global f2
	f2=Frame(f)
	f2.pack_propagate(False)
	f2.config(bg="#8acdc1",width=500)
	f2.pack(side="right",fill="both")

	#center
	f3=Frame(f)
	f3.pack_propagate(False)
	f3.config(bg="#8acdc1",width=850)
	f3.pack(side="right",fill="both")

	f4=Frame(f3)
	f4.pack_propagate(False)
	f4.config(bg="#8acdc1",height=400)
	f4.pack(side="bottom",fill="both")

	f7=Frame(f3)
	f7.pack_propagate(False)
	f7.config(height=20)
	f7.pack(side="top",fill="both",padx="3")

	l2=Label(f7,text="Input Network Features",font="Helvetica 13 bold")
	l2.pack()


	global input_text
	input_text = Text(f4, width=50, height=10, font="Helvetica 12")
	input_text.pack(pady=10, padx=5)
	b2=Button(f4,text="Prediction",bg="#ccad51",font="Verdana 10 bold",command=pred_function)
	b2.pack(pady=2)

	
	global f6
	f6=Frame(f2)
	f6.config(bg="#8acdc1")
	f6.pack(side="top",fill="both")
	l1=Label(f6,text="Output",font="Helvetica 13 bold")
	l1.pack(side="top",fill="both")

	
	global st1,st2
	st2=ScrolledText(f6,height=15)
	st2.pack(side="bottom",fill="both",pady=7)

	

if __name__=="__main__":

	top = Tk()  
	top.title("Login Page")
	top.geometry("1200x500")
	# Set the path to your .ico file
	icon_path = "Extras/logo_icon.ico"
	# Use the iconbitmap method to set the icon
	top.iconbitmap(icon_path)
	top.resizable(False, False)

	menubar = Menu(top)  
	menubar.add_command(label="Testing",command=go_for_test)
	
   

	top.config(bg=my_background_color,relief=RAISED)  
	f=Frame(top)
	f.config(bg=my_background_color)
	f.pack(side="top", fill="both", expand=True,padx=10,pady=10)
	l=Label(f,text=title,font = "Verdana 40 bold",fg="white",bg=my_background_color)
	l.place(x=200,y=50)
	l2=Label(f,text="Username:",font="Verdana 10 bold",bg=my_background_color)
	l2.place(x=400,y=200)
	global uname_variable
	uname_variable=StringVar()
	e1=Entry(f,textvariable=uname_variable,font="Verdana 10 bold")
	e1.place(x=550,y=200)

	l3=Label(f,text="Password:",font="Verdana 10 bold",bg=my_background_color)
	l3.place(x=400,y=240)
	global password_variable
	password_variable=StringVar()
	e2=Entry(f,textvariable=password_variable,font="Verdana 10 bold",show='*')
	e2.place(x=550,y=240)

	b1=Button(f,text="Login", command=perform_validation,font="Verdana 10 bold",bg="#cdc18a")
	b1.place(x=600,y=300)

	top.mainloop() 
