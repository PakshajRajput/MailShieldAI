from fastapi import FastAPI
from pydantic import BaseModel

import pickle
import re

from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Load trained model
model = load_model("../model/phishing_model.h5")

# Load tokenizer
with open("../model/tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

app = FastAPI(title="MailShieldAI Phishing Detection System")


# Request format
class EmailInput(BaseModel):
    text: str


# Home route
@app.get("/")
def home():
    return {"message": "MailShieldAI backend running"}


# Prediction route
@app.post("/predict")
def predict_email(data: EmailInput):

    # -------- Clean email text --------
    email_text = data.text

    # remove newlines
    email_text = email_text.replace("\n", " ")
    email_text = email_text.replace("\r", " ")

    # remove extra spaces
    email_text = " ".join(email_text.split())

    # remove urls for model input
    email_text = re.sub(r"http\S+", "", email_text)

    # -------- AI prediction --------
    seq = tokenizer.texts_to_sequences([email_text])
    padded = pad_sequences(seq, maxlen=200)

    prediction = model.predict(padded)[0][0]

    if prediction > 0.5:
        result = "Phishing Email"
    else:
        result = "Safe Email"

    return {
        "prediction": result,
        "confidence": float(prediction)
    }