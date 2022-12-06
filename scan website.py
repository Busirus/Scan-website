import requests
import json

# URL de l'API de la bibliothèque de tests d'intrusion
INTRUSION_TESTING_API_URL = 'http://zap:8080/JSON/core/action/'

def scan_website(url):
  # Démarrer la bibliothèque de tests d'intrusion
  response = requests.get(INTRUSION_TESTING_API_URL + 'spider/action/scan/', params={'url': url})
  scan_id = response.json()['scan']

  # Attendre que la bibliothèque de tests d'intrusion ait terminé le scan
  while True:
    response = requests.get(INTRUSION_TESTING_API_URL + 'spider/view/status/', params={'scanId': scan_id})
    if response.json()['status'] != 'running':
      break

  # Récupérer les résultats du scan
  response = requests.get(INTRUSION_TESTING_API_URL + 'ajaxSpider/view/results/', params={'scanId': scan_id})
  results = response.json()

  # Afficher les failles de sécurité détectées
  for result in results['sites']:
    for alert in result['alerts']:
      if alert['risk'] == 'High':
        print(f"Vulnérabilité détectée : {alert['name']}")

# Exemple d'utilisation :

# Scanner un site Web pour détecter les failles de sécurité
scan_website('https://www.example.com')