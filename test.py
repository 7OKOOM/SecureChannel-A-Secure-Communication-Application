import customtkinter as ctk

# 1. Setup the main window
root = ctk.CTk()
root.title("Secure Channel Chat")
root.geometry("450x500")

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# 2. Function to handle sending text
def send_text():
    user_message = message_input.get().strip()

    if user_message:  # Make sure it's not empty
        # Enable the text box momentarily to add the message
        chat_screen.configure(state="normal")
        chat_screen.insert("end", f"You: {user_message}\n")
        chat_screen.configure(state="disabled")

        # Auto-scroll to the bottom of the screen
        chat_screen.see("end")

        # Clear the input field for the next message
        message_input.delete(0, "end")

# --- UI ELEMENTS ---

# 1. The Message Screen (Read-only so users can't randomly delete history)
chat_screen = ctk.CTkTextbox(root, width=410, height=380, state="disabled", wrap="word")
chat_screen.pack(pady=(20, 10), padx=20)

# 2. Bottom Frame to hold the Input Box and Send Button side-by-side
bottom_frame = ctk.CTkFrame(root, fg_color="transparent")
bottom_frame.pack(fill="x", padx=20, pady=(0, 20))

# 3. The Input Box (Where you type)
message_input = ctk.CTkEntry(bottom_frame, placeholder_text="Type a message...", width=290)
message_input.pack(side="left", padx=(0, 10))
# Optional: Pressing 'Enter' on the keyboard will also trigger the send button
message_input.bind("<Return>", lambda event: send_text())

# 4. The Send Button
send_button = ctk.CTkButton(bottom_frame, text="Send", width=100, command=send_text)
send_button.pack(side="right")

# Start the app loop
root.mainloop()
