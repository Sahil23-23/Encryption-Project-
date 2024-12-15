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

def generate_rsa_key_pair():
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
            text="Message-Sending-Encryption", font_size=24, bold=True,
            color=(1, .1, 1, 1), size_hint=(1, 0.1), halign="center", valign="middle", italic=True
        )
        layout.add_widget(title)
        self.message_input = TextInput(hint_text="Enter the message", size_hint=(1, 0.07), multiline=True)
        layout.add_widget(self.message_input)
        
        self.public_key_receiver = TextInput(hint_text="Enter the Public Key of Receiver", size_hint=(1, 0.07), multiline=True)
        layout.add_widget(self.public_key_receiver)
        
        button_layout = BoxLayout(size_hint=(1, 0.2), spacing=20)
        
        encrypt_button = Button(
            text="Encrypt",
            on_press=self.encrypt_message,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(0, 1, 0, 1),
            color=(1, 1, 1, 1),
        )

        reset_button = Button(
            text="Reset",
            on_press=self.reset_fields,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(0, 0, 1, 1),
            color=(1, 1, 1, 1),
        )

        back_button = Button(
            text="Back",
            on_press=self.go_back,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(0.5, 0.5, 0.5, 1),
            color=(1, 1, 1, 1),
        )
        send_button=Button(
            text="Send",
            on_press=self.share_message,
            size_hint=(None, None),
            size=(200, 60),
            font_size=24,
            background_normal="",
            background_color=(1, 0, 0, 1),
            color=(1, 1, 1, 1),
        )
        button_layout.add_widget(send_button)

        button_layout.add_widget(encrypt_button)
        button_layout.add_widget(reset_button)
        button_layout.add_widget(back_button)
        layout.add_widget(button_layout)

        self.result_input = TextInput(
            hint_text="Result will appear here",
            size_hint=(1, 0.2),
            readonly=True,
            multiline=True,
        )
        layout.add_widget(self.result_input)
        self.add_widget(layout)

    def reset_fields(self, instance):
        self.message_input.text = ""
        self.public_key_receiver.text = ""
        self.result_input.text = ""
        
    def encrypt_message(self, instance):
        # Get input message and public key
        message = self.message_input.text.strip()
        public_key_pem = self.public_key_receiver.text.strip()

        # Validate inputs
        if not message:
            self.result_input.text = "Error: Please enter a message to encrypt."
            return

        if not public_key_pem:
            self.result_input.text = "Error: Please enter the receiver's public key."
            return

        try:
            # Validate public key format
            if not (public_key_pem.startswith("-----BEGIN PUBLIC KEY-----") and 
                    public_key_pem.endswith("-----END PUBLIC KEY-----")):
                raise ValueError("The provided public key is not in a valid PEM format.")

            # Import the public key
            public_key = RSA.import_key(public_key_pem)

            # Encrypt the message using PKCS1_OAEP
            cipher = PKCS1_OAEP.new(public_key)
            encrypted_message = cipher.encrypt(message.encode())

            # Encode the encrypted message in base64 for readability
            self.encrypted_message = base64.b64encode(encrypted_message).decode()

            # Display the encrypted message
            self.result_input.text = f"Encrypted Message:\n{self.encrypted_message}"
        except Exception as e:
            self.result_input.text = f"Error during encryption: {e}"

    def share_message(self, instance):
      if not hasattr(self, 'encrypted_message') or not self.encrypted_message:
        popup = Popup(title="Error", content=Label(text="No encrypted message generated yet!"), size_hint=(0.8, 0.4))
        popup.open()
        return

      if platform == 'android':
        from jnius import autoclass
        from pythonforandroid import activity

        Intent = autoclass('android.content.Intent')
        String = autoclass('java.lang.String')

        intent = Intent(Intent.ACTION_SEND)
        intent.setType('text/plain')
        intent.putExtra(Intent.EXTRA_TEXT, String(self.encrypted_message))  # Use the encrypted message here

        chooser = Intent.createChooser(intent, String('Share Encrypted Message'))
        activity.startActivity(chooser)
      else:
            file_path = os.path.abspath("encrypted_message.pem")
            if os.name == "posix":
                webbrowser.open(f"file://{file_path}")
            else:
                os.startfile(file_path)

                
    def go_back(self, instance):
        self.manager.current = "First_screen"


class SenderCyber(App):
      def build(self):
        sm=ScreenManager()
        sm.add_widget(FirstScreen(name="First_screen"))
        sm.add_widget(SecondScreen(name="Second_screen"))
       # sm.add_widget()
        #sm.add_widget()
        return sm
    
if __name__=="__main__":
    SenderCyber().run()
