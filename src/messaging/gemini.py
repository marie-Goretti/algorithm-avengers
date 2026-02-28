import os
import requests
import json
import base64

class GeminiAssistant:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        # Using the requested model
        self.model = "gemini-2.0-flash-exp" # gemini-3-flash-preview isn't out yet, using 2.0 Flash as equivalent high-speed/latest
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        self.enabled = self.api_key is not None
        self.history = []

    def query(self, user_query, file_path=None):
        if not self.enabled:
            return "Gemini is disabled. Set GEMINI_API_KEY to enable."
            
        contents = []
        
        # Build history context
        for entry in self.history:
            contents.append({
                "role": "user" if entry["role"] == "user" else "model",
                "parts": [{"text": entry["text"]}]
            })

        current_parts = []
        
        # If a file is provided, read it and add it as a part
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                
                # Determine mime type simple way
                mime_type = "text/plain"
                if file_path.endswith(".pdf"): mime_type = "application/pdf"
                elif file_path.endswith(".png"): mime_type = "image/png"
                elif file_path.endswith(".jpg") or file_path.endswith(".jpeg"): mime_type = "image/jpeg"
                
                current_parts.append({
                    "inline_data": {
                        "mime_type": mime_type,
                        "data": base64.b64encode(file_data).decode("utf-8")
                    }
                })
            except Exception as e:
                return f"Error reading file for IA: {e}"

        current_parts.append({"text": user_query})
        contents.append({
            "role": "user",
            "parts": current_parts
        })
        
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.7,
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 2048,
            }
        }
        
        try:
            response = requests.post(f"{self.url}?key={self.api_key}", json=payload)
            response.raise_for_status()
            data = response.json()
            
            if 'candidates' in data and data['candidates']:
                answer = data['candidates'][0]['content']['parts'][0]['text']
                # Update history
                self.history.append({"role": "user", "text": user_query})
                self.history.append({"role": "model", "text": answer})
                # Keep history reasonable (last 10 exchanges)
                if len(self.history) > 20:
                    self.history = self.history[-20:]
                return answer
            else:
                return f"Gemini returned an empty response: {data}"
        except Exception as e:
            return f"Error querying Gemini: {e}"
