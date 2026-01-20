"""
Module d'envoi de notifications par email
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional
import os
from datetime import datetime

class EmailNotifier:
    """Système de notification par email"""
    
    # Configuration par défaut (utiliser des variables d'environnement en production)
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    
    def __init__(self, sender_email: Optional[str] = None, sender_password: Optional[str] = None):
        """
        Initialise le système de notification
        
        Args:
            sender_email: Email d'envoi (sinon lire depuis variable d'environnement)
            sender_password: Mot de passe d'envoi (sinon lire depuis variable d'environnement)
        """
        self.sender_email = sender_email or os.getenv("ALERT_EMAIL")
        self.sender_password = sender_password or os.getenv("ALERT_PASSWORD")
        
        if not self.sender_email or not self.sender_password:
            print("[AVERTISSEMENT] Identifiants email non configurés")
            print("[INFO] Configurez les variables d'environnement ALERT_EMAIL et ALERT_PASSWORD")
    
    def send_email(self, to_email: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
        """
        Envoie un email
        
        Args:
            to_email: Email destinataire
            subject: Sujet du message
            html_body: Corps du message en HTML
            text_body: Corps du message en texte (fallback)
            
        Returns:
            True si succès, False sinon
        """
        if not self.sender_email or not self.sender_password:
            print("[ERREUR] Identifiants email non configurés")
            return False
        
        try:
            # Création du message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.sender_email
            msg["To"] = to_email
            
            # Corps du message
            if text_body:
                part1 = MIMEText(text_body, "plain")
                msg.attach(part1)
            
            part2 = MIMEText(html_body, "html")
            msg.attach(part2)
            
            # Connexion SMTP et envoi
            with smtplib.SMTP(self.SMTP_SERVER, self.SMTP_PORT) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, to_email, msg.as_string())
            
            print(f"[SUCCÈS] Email envoyé à: {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            print("[ERREUR] Authentification SMTP échouée")
            return False
        except smtplib.SMTPException as e:
            print(f"[ERREUR] Erreur SMTP: {e}")
            return False
        except Exception as e:
            print(f"[ERREUR] Erreur lors de l'envoi: {e}")
            return False
    
    def create_alert_email_body(self, alerts: List[Dict], alert_level: Optional[str] = None) -> tuple:
        """
        Crée le corps d'un email d'alerte
        
        Args:
            alerts: Liste des alertes
            alert_level: Niveau d'alerte spécifique (optionnel)
            
        Returns:
            Tuple (html_body, text_body)
        """
        if alert_level:
            alerts = [a for a in alerts if a["alert_level"] == alert_level]
        
        # Construction du texte
        text_body = f"""Alertes de Sécurité ANSSI
Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

Nombre d'alertes: {len(alerts)}

"""
        
        for alert in alerts:
            text_body += f"""---
CVE: {alert['cve_id']}
CVSS: {alert['cvss_score']} ({alert['base_severity']})
EPSS: {alert['epss_score']}
Produit: {alert['produit']} ({alert['vendor']})
Versions affectées: {alert['versions_affectees']}
Bulletin: {alert['titre_anssi']}
Lien: {alert['lien_bulletin']}

"""
        
        # Construction du HTML
        html_body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
        }}
        .header {{
            background-color: #d32f2f;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .alert {{
            border-left: 4px solid #d32f2f;
            background-color: #fff3e0;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 3px;
        }}
        .alert.critique {{
            border-left-color: #d32f2f;
            background-color: #ffebee;
        }}
        .alert.élevée {{
            border-left-color: #f57c00;
            background-color: #fff3e0;
        }}
        .alert.moyenne {{
            border-left-color: #fbc02d;
            background-color: #fffde7;
        }}
        .alert-level {{
            font-weight: bold;
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            margin-bottom: 10px;
        }}
        .alert-level.critique {{
            background-color: #d32f2f;
            color: white;
        }}
        .alert-level.élevée {{
            background-color: #f57c00;
            color: white;
        }}
        .alert-level.moyenne {{
            background-color: #fbc02d;
            color: black;
        }}
        .cve {{
            font-weight: bold;
            color: #1976d2;
        }}
        .severity {{
            padding: 5px;
            margin: 5px 0;
        }}
        .severity-score {{
            font-weight: bold;
        }}
        a {{
            color: #1976d2;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .footer {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Alertes de Sécurité ANSSI</h1>
            <p>Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
            <p>Nombre d'alertes: {len(alerts)}</p>
        </div>
"""
        
        for alert in alerts:
            level_class = alert['alert_level'].lower()
            html_body += f"""        <div class="alert {level_class}">
            <div class="alert-level {level_class}">{alert['alert_level']}</div>
            <p><span class="cve">{alert['cve_id']}</span></p>
            <div class="severity">
                <strong>Gravité CVSS:</strong> <span class="severity-score">{alert['cvss_score']} / 10</span> ({alert['base_severity']})
            </div>
            <div class="severity">
                <strong>Score EPSS:</strong> <span class="severity-score">{alert['epss_score']}</span>
            </div>
            <p><strong>Produit affecté:</strong> {alert['produit']} (éditeur: {alert['vendor']})</p>
            <p><strong>Versions affectées:</strong> {alert['versions_affectees']}</p>
            <p><strong>Type CWE:</strong> {alert['cwe_id']}</p>
            <p><strong>Bulletin:</strong> <a href="{alert['lien_bulletin']}">{alert['titre_anssi']}</a></p>
            <p><strong>Description:</strong> {alert['description'][:200]}...</p>
        </div>
"""
        
        html_body += """        <div class="footer">
            <p>Cet email a été généré automatiquement. Consultez le site officiel ANSSI pour plus d'informations.</p>
            <p>Lien ANSSI: <a href="https://www.cert.ssi.gouv.fr">https://www.cert.ssi.gouv.fr</a></p>
        </div>
    </div>
</body>
</html>
"""
        
        return html_body, text_body
    
    def send_alerts(self, alerts: List[Dict], recipient_email: str, alert_level: Optional[str] = None) -> bool:
        """
        Envoie un email contenant les alertes
        
        Args:
            alerts: Liste des alertes
            recipient_email: Email du destinataire
            alert_level: Niveau d'alerte spécifique (optionnel)
            
        Returns:
            True si succès
        """
        if not alerts:
            print("[AVERTISSEMENT] Aucune alerte à envoyer")
            return False
        
        html_body, text_body = self.create_alert_email_body(alerts, alert_level)
        
        subject = f"🔒 Alertes de Sécurité ANSSI - {len(alerts)} alerte(s)"
        if alert_level:
            subject = f"🔒 Alertes {alert_level} - ANSSI"
        
        return self.send_email(recipient_email, subject, html_body, text_body)
    
    def send_bulk_alerts(self, alerts: List[Dict], recipients: Dict[str, str]) -> Dict[str, bool]:
        """
        Envoie des alertes en masse à plusieurs destinataires
        
        Args:
            alerts: Liste des alertes
            recipients: Dict {email: alert_level_filter} ou {email: None} pour toutes les alertes
            
        Returns:
            Dict avec résultats d'envoi {email: succès}
        """
        results = {}
        
        for recipient_email, alert_filter in recipients.items():
            print(f"\nEnvoi des alertes à: {recipient_email}")
            success = self.send_alerts(alerts, recipient_email, alert_level=alert_filter)
            results[recipient_email] = success
        
        return results


def main():
    """Fonction principale"""
    
    print("=== Configuration du Système de Notifications ===\n")
    
    # Chargement des alertes
    try:
        alert_files = [f for f in os.listdir("output/alerts") if f.startswith("alerts_")]
        if not alert_files:
            print("[ERREUR] Aucun fichier d'alertes trouvé")
            return
        
        latest_alert_file = sorted(alert_files)[-1]
        alert_path = os.path.join("output/alerts", latest_alert_file)
        
        with open(alert_path, 'r', encoding='utf-8') as f:
            alert_data = json.load(f)
        
        alerts = alert_data.get("alerts", [])
        print(f"[INFO] {len(alerts)} alertes chargées")
        
    except FileNotFoundError:
        print("[ERREUR] Fichier d'alertes non trouvé")
        return
    
    # Création du notifier
    # NOTE: En production, utiliser des variables d'environnement
    notifier = EmailNotifier()
    
    # Configuration des destinataires
    recipients = {
        "admin@example.com": None,           # Tous les niveaux
        "security-team@example.com": "CRITIQUE",  # Seulement critiques
        "ops-team@example.com": "ÉLEVÉE"     # Seulement élevées
    }
    
    print("\n[INFO] Configuration requise pour l'envoi d'email:")
    print("1. Définir les variables d'environnement:")
    print("   - ALERT_EMAIL: email d'envoi")
    print("   - ALERT_PASSWORD: mot de passe d'application Gmail")
    print("\n2. Pour Gmail, générer un 'App Password':")
    print("   https://support.google.com/accounts/answer/185833")
    
    # Envoi des alertes (à décommenter après configuration)
    # results = notifier.send_bulk_alerts(alerts, recipients)
    # print(f"\n[RÉSULTATS] Envoi terminé: {results}")


if __name__ == "__main__":
    main()
