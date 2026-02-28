import google.generativeai as genai
import os

# ⚠️ Configurez votre clé API ici ou via une variable d'environnement
# GOOGLE_API_KEY = "VOTRE_CLE_API"
genai.configure(api_key="AIzaSyCClHCZuLhLeBLusuyNB_7249fDZ3mYV3I")

def get_file_summary(file_content_bytes):
    """Envoie le contenu d'un fichier à Gemini pour résumé."""
    try:
        model = genai.GenerativeModel('gemini-3-flash-preview')
        
        # On suppose ici que le fichier est du texte pour cet exemple.
        # Pour des fichiers binaires, il faudrait adapter l'approche.
        text_content = file_content_bytes.decode('utf-8', errors='ignore')
        
        prompt = f"Fais un résumé très concis (2 phrases max) de ce contenu :\n\n{text_content[:2000]}"
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Erreur lors de l'analyse par Gemini : {e}"
