from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.uix.image import Image

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import re

import qrcode
from kivy.uix.image import Image
from kivy.core.image import Image as CoreImage
from io import BytesIO
from Crypto.PublicKey import RSA

from kivy.utils import platform
from kivy.uix.popup import Popup
import os
import webbrowser
from Crypto.Cipher import PKCS1_OAEP

def decode_message(self):
    # Get the encrypted message and receiver's private key
    encrypted_message_base64 = self.message_input.text.strip()
    private_key_pem = self.private_key_receiver.text.strip()

    # Validate inputs
    if not encrypted_message_base64:
        self.result_input.text = "Error: Please enter the encrypted message."
        return

    if not private_key_pem:
        self.result_input.text = "Error: Please enter your private key."
        return

    try:
        # Decode the Base64-encoded encrypted message
        import base64
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP

        encrypted_message = base64.b64decode(encrypted_message_base64)

        # Import the private key
        private_key = RSA.import_key(private_key_pem)

        # Decrypt the message using PKCS1_OAEP
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher.decrypt(encrypted_message).decode()

        # Display the decrypted message
        self.result_input.text = f"Decrypted Message:\n{decrypted_message}"
    except ValueError as ve:
        self.result_input.text = f"Private Key Error: {ve}"
    except Exception as e:
        self.result_input.text = f"Error during decryption: {e}"

def generate_rsa_keys():
    key = RSA.generate(1024)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return public_key, private_key

class FirstScreen(Screen):
    def __init__(self, **kwrgs):
        super().__init__(**kwrgs)
        layout = BoxLayout(orientation="vertical", padding=100, spacing=20)
        label = Label(
            text="Cyber-Encrypted-Project",
            font_size=50,
            bold=True,
            color=(1, .1, 0, 1),
            size_hint=(1, 0.2),
            halign="center",
            valign="top",
        )
        layout.add_widget(label)
        receiver_label = Label(
            text="Receiver-Interface",
            font_size=30,
            bold=True,
            color=(1, .1, 0, 1),
            size_hint=(1, 0.2),
            halign="center",
            valign="top",
        )
        layout.add_widget(receiver_label)
        image=Image(source="cyber-security-quotes_silver-bullet.jpg", size_hint=(1, 0.5))
        layout.add_widget(image)
        
        button_layout = BoxLayout(size_hint=(1, 0.2), spacing=20, padding=[100, 0])

        enter_button = Button(
            text="Let's Get Started",
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(1, 0, 0, 1),
            color=(1, 1, 1, 1),
        )
        enter_button.bind(on_press=self.go_to_second_screen)

        button_layout.add_widget(enter_button)
        layout.add_widget(button_layout)

        self.add_widget(layout)

    def go_to_second_screen(self, instance):
        self.manager.current = "Second_screen"
   



class SecondScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)

        title = Label(
            text="Public RSA Key Generation", font_size=24, bold=True,
            color=(1, 1, 1, 1), size_hint=(1, 0.1), halign="center", valign="middle"
        )
        layout.add_widget(title)

        self.qr_image = Image(size_hint=(0.3, 0.3),pos_hint={'x':.25 , 'y': 0})  # Placeholder for the QR code
        layout.add_widget(self.qr_image)

        button_layout = BoxLayout(size_hint=(1, 0.2), spacing=20)

        generate_rsa_button = Button(
            text="Public-Key",
            on_press=self.generate_rsa_keys,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(1, 0, 0, 1),
            color=(1, 1, 1, 1),
            
        )
        button_layout.add_widget(generate_rsa_button)
        layout.add_widget(button_layout)
        
        send_button=Button(
            text="Send",
            on_press=self.share_public_key,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(1, 0, 0, 1),
            color=(1, 1, 1, 1),
        )
        button_layout.add_widget(send_button)
        
        self.result_input = TextInput(
            hint_text="Result will appear here",
            size_hint=(1, 0.3),
            readonly=True,
            multiline=True,
        )
        
        back_button = Button(
            text="Back",
            on_press=self.go_back,
           size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(1, 0, 0, 1),
            color=(1, 1, 1, 1),
        )
        button_layout.add_widget(back_button)
        next_button=Button(
            text="Next-->",
            on_press=self.go_next,
           size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(1, 0, 0, 1),
            color=(1, 1, 1, 1),
        )
        layout.add_widget(next_button)
        self.add_widget(layout)
        
    def generate_rsa_keys(self, instance):
        # Generate RSA keys
        try:
            public_key, private_key = generate_rsa_keys()
            self.public_key = public_key  # Initialize the public_key attribute
            self.result_input.text = f"Public Key:\n{public_key}\n\nPrivate Key:\n{private_key}"

            # Save keys to files
            with open("Receiver\public_key.pem", "w") as pub_file:
                pub_file.write(public_key)
            with open("Receiver\private_key.pem", "w") as priv_file:
                priv_file.write(private_key)
            self.result_input.text += "\n\nKeys saved to 'public_key.pem' and 'private_key.pem'"

            # Generate and display the QR code for the public key
            self.display_qr_code(public_key)
        except Exception as e:
            self.result_input.text = f"Error: {e}"

    def display_qr_code(self, data):
        # Generate a QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill="black", back_color="white")

        # Convert QR code to a format compatible with Kivy
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        texture = CoreImage(buffer, ext="png").texture
        self.qr_image.texture = texture
        
    def share_public_key(self, instance):
        if not hasattr(self, 'public_key') or not self.public_key:
            popup = Popup(title="Error", content=Label(text="No public key generated yet!"), size_hint=(0.8, 0.4))
            popup.open()
            return

        if platform == 'android':
            from jnius import autoclass
            from pythonforandroid import activity

            Intent = autoclass('android.content.Intent')
            String = autoclass('java.lang.String')

            intent = Intent(Intent.ACTION_SEND)
            intent.setType('text/plain')
            intent.putExtra(Intent.EXTRA_TEXT, String(self.public_key))

            chooser = Intent.createChooser(intent, String('Share Public Key'))
            activity.startActivity(chooser)
        else:
            file_path = os.path.abspath("Receiver\public_key.pem")
            if os.name == "posix":
                webbrowser.open(f"file://{file_path}")
            else:
                os.startfile(file_path)

    def go_back(self, instance):
        self.manager.current = "First_screen"
    def go_next(self,instance):
        self.manager.current = "Third_screen"
        
class ThirdScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)

        # Title Label
        title = Label(
            text="Decryption Process", font_size=24, bold=True,
            color=(1, 0, 0, 1), size_hint=(1, 0.1), halign="center", valign="middle"
        )
        layout.add_widget(title)

        # Input Fields
        self.message_input = TextInput(
            hint_text="Enter the encrypted message (Base64)", size_hint=(1, 0.2), multiline=True
        )
        layout.add_widget(self.message_input)

        self.private_key_receiver = TextInput(
            hint_text="Enter your Private Key (PEM format)", size_hint=(1, 0.2), multiline=True
        )
        layout.add_widget(self.private_key_receiver)

        # Button Layout
        button_layout = BoxLayout(size_hint=(1, 0.2), spacing=20)

        decrypted_button = Button(
            text="Decrypt",
            on_press=self.decrypt_message,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(1, 0, 0, 1),
            color=(1, 1, 1, 1),
        )
        reset_button = Button(
            text="Reset",
            on_press=self.reset_fields,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(0.5,0,0.8, 1),
            color=(1, 1, 1, 1),
        )
        back_button = Button(
            text="Back",
            on_press=self.go_back,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(1, 0.5, 0, 1),
            color=(1, 1, 1, 1),
        )

        button_layout.add_widget(decrypted_button)
        button_layout.add_widget(reset_button)
        button_layout.add_widget(back_button)
        layout.add_widget(button_layout)

        # Result Display
        self.result_input = TextInput(
            hint_text="Decrypted message will appear here",
            size_hint=(1, 0.3),
            readonly=True,
            multiline=True,
        )
        layout.add_widget(self.result_input)

        self.add_widget(layout)

    def decrypt_message(self, instance):
        # Pass input to `decode_message`
        self.decode_message()

    def decode_message(self):
    # Get the encrypted message and receiver's private key
      encrypted_message_base64 = self.message_input.text.strip()
      private_key_pem = self.private_key_receiver.text.strip()

    # Validate inputs
      if not encrypted_message_base64:
        self.result_input.text = "Error: Please enter the encrypted message."
        return

      if not private_key_pem:
        self.result_input.text = "Error: Please enter your private key."
        return

      try:
        # Decode the Base64-encoded encrypted message
        import base64
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP

        encrypted_message = base64.b64decode(encrypted_message_base64)

        # Import the private key
        private_key = RSA.import_key(private_key_pem)

        # Decrypt the message using PKCS1_OAEP
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher.decrypt(encrypted_message).decode()

        # Display the decrypted message
        self.result_input.text = f"Decrypted Message:\n{decrypted_message}"
      except ValueError as ve:
        self.result_input.text = f"Private Key Error: {ve}"
      except Exception as e:
        self.result_input.text = f"Error during decryption: {e}"

    def reset_fields(self, instance):
        self.message_input.text = ""
        self.private_key_receiver.text = ""
        self.result_input.text = ""

    def go_back(self, instance):
        self.manager.current = "Second_screen"

    
class ReceiverCyber(App):
      def build(self):
        sm=ScreenManager()
        sm.add_widget(FirstScreen(name="First_screen"))
        sm.add_widget(SecondScreen(name="Second_screen"))
        sm.add_widget(ThirdScreen(name="Third_screen"))
        #sm.add_widget()
        return sm
    
if __name__=="__main__":
    ReceiverCyber().run()
    
