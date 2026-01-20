"""
Module de génération d'alertes personnalisées
"""

import pandas as pd
import json
from typing import List, Dict, Optional
import os
from datetime import datetime

class AlertGenerator:
    """Générateur d'alertes personnalisées"""
    
    # Seuils d'alerte par défaut
    DEFAULT_ALERT_RULES = {
        "critical_cvss": 9.0,           # Alerte pour CVSS >= 9
        "high_cvss": 7.0,               # Alerte pour CVSS >= 7
        "high_epss": 0.75,              # Alerte pour EPSS >= 0.75
        "monitored_vendors": [],        # Vendors à monitorer spécifiquement
        "monitored_products": []        # Produits à monitorer spécifiquement
    }
    
    def __init__(self, alert_rules: Optional[Dict] = None):
        """
        Initialise le générateur d'alertes
        
        Args:
            alert_rules: Dictionnaire des règles d'alerte personnalisées
        """
        self.alert_rules = alert_rules or self.DEFAULT_ALERT_RULES.copy()
        self.df = None
        self.alerts = []
    
    def load_dataframe(self, file_path: str = "data/processed/cves_consolidated.csv") -> bool:
        """
        Charge le DataFrame consolidé
        
        Args:
            file_path: Chemin du fichier CSV
            
        Returns:
            True si succès, False sinon
        """
        try:
            self.df = pd.read_csv(file_path)
            print(f"[INFO] DataFrame chargé: {len(self.df)} lignes")
            return True
        except FileNotFoundError:
            print(f"[ERREUR] Fichier {file_path} non trouvé")
            return False
    
    def generate_alerts(self) -> List[Dict]:
        """
        Génère les alertes en fonction des règles
        
        Returns:
            Liste des alertes générées
        """
        print("\n=== Génération des Alertes ===\n")
        
        if self.df is None:
            print("[ERREUR] Aucun DataFrame chargé")
            return []
        
        self.alerts = []
        
        # Parcours de chaque ligne du DataFrame
        for idx, row in self.df.iterrows():
            alert_level = self.evaluate_alert_level(row)
            
            if alert_level:
                alert = self.create_alert(row, alert_level)
                self.alerts.append(alert)
        
        print(f"\n[SUCCÈS] {len(self.alerts)} alerte(s) générée(s)")
        
        return self.alerts
    
    def evaluate_alert_level(self, row: pd.Series) -> Optional[str]:
        """
        Évalue le niveau d'alerte pour une vulnérabilité
        
        Args:
            row: Ligne du DataFrame
            
        Returns:
            Niveau d'alerte: "CRITIQUE", "ÉLEVÉE", "MOYENNE", None
        """
        cvss_score = row.get("cvss_score")
        epss_score = row.get("epss_score")
        vendor = row.get("vendor", "").lower()
        product = row.get("produit", "").lower()
        
        # Vérification des règles personnalisées
        monitored_vendors = [v.lower() for v in self.alert_rules.get("monitored_vendors", [])]
        monitored_products = [p.lower() for p in self.alert_rules.get("monitored_products", [])]
        
        # Alerte critique: CVSS >= 9 ou EPSS >= 0.75 + CVSS >= 7
        if cvss_score and cvss_score >= self.alert_rules["critical_cvss"]:
            return "CRITIQUE"
        
        if (cvss_score and cvss_score >= self.alert_rules["high_cvss"] and
            epss_score and epss_score >= self.alert_rules["high_epss"]):
            return "CRITIQUE"
        
        # Alerte élevée: CVSS >= 7 ou EPSS >= 0.75
        if cvss_score and cvss_score >= self.alert_rules["high_cvss"]:
            return "ÉLEVÉE"
        
        if epss_score and epss_score >= self.alert_rules["high_epss"]:
            return "ÉLEVÉE"
        
        # Vérifications des règles personnalisées
        if monitored_vendors and vendor in monitored_vendors:
            return "MOYENNE"
        
        if monitored_products and product in monitored_products:
            return "MOYENNE"
        
        return None
    
    def create_alert(self, row: pd.Series, alert_level: str) -> Dict:
        """
        Crée une alerte structurée
        
        Args:
            row: Ligne du DataFrame
            alert_level: Niveau d'alerte
            
        Returns:
            Dictionnaire de l'alerte
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "alert_level": alert_level,
            "id_anssi": row.get("id_anssi"),
            "titre_anssi": row.get("titre_anssi"),
            "cve_id": row.get("cve_id"),
            "cvss_score": row.get("cvss_score"),
            "base_severity": row.get("base_severity"),
            "epss_score": row.get("epss_score"),
            "vendor": row.get("vendor"),
            "produit": row.get("produit"),
            "versions_affectees": row.get("versions_affectees"),
            "cwe_id": row.get("cwe_id"),
            "description": row.get("description_cve"),
            "lien_bulletin": row.get("lien_bulletin")
        }
    
    def filter_alerts_by_level(self, level: str) -> List[Dict]:
        """
        Filtre les alertes par niveau
        
        Args:
            level: Niveau d'alerte ("CRITIQUE", "ÉLEVÉE", "MOYENNE")
            
        Returns:
            Liste des alertes du niveau spécifié
        """
        return [a for a in self.alerts if a["alert_level"] == level]
    
    def filter_alerts_by_vendor(self, vendor: str) -> List[Dict]:
        """
        Filtre les alertes par vendor
        
        Args:
            vendor: Nom du vendor
            
        Returns:
            Liste des alertes pour ce vendor
        """
        return [a for a in self.alerts if a["vendor"].lower() == vendor.lower()]
    
    def get_top_alerts(self, n: int = 10) -> List[Dict]:
        """
        Retourne les N alertes les plus critiques
        
        Args:
            n: Nombre d'alertes
            
        Returns:
            Liste des top N alertes (triées par CVSS desc, puis EPSS desc)
        """
        sorted_alerts = sorted(
            self.alerts,
            key=lambda x: (
                -float(x["cvss_score"] or 0),
                -float(x["epss_score"] or 0)
            )
        )
        return sorted_alerts[:n]
    
    def save_alerts_to_json(self, output_dir: str = "output/alerts") -> str:
        """
        Sauvegarde les alertes en JSON
        
        Args:
            output_dir: Répertoire de sortie
            
        Returns:
            Chemin du fichier
        """
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"alerts_{timestamp}.json")
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "total_alerts": len(self.alerts),
            "alerts_by_level": {
                "CRITIQUE": len(self.filter_alerts_by_level("CRITIQUE")),
                "ÉLEVÉE": len(self.filter_alerts_by_level("ÉLEVÉE")),
                "MOYENNE": len(self.filter_alerts_by_level("MOYENNE"))
            },
            "alerts": self.alerts
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"\n[INFO] Alertes sauvegardées dans: {output_file}")
        
        return output_file
    
    def display_summary(self) -> None:
        """Affiche un résumé des alertes"""
        
        print("\n=== Résumé des Alertes ===\n")
        print(f"Total alertes: {len(self.alerts)}")
        print(f"\nPar niveau:")
        print(f"  - CRITIQUE: {len(self.filter_alerts_by_level('CRITIQUE'))}")
        print(f"  - ÉLEVÉE: {len(self.filter_alerts_by_level('ÉLEVÉE'))}")
        print(f"  - MOYENNE: {len(self.filter_alerts_by_level('MOYENNE'))}")
        
        # Top 5 alertes par CVSS
        top_alerts = self.get_top_alerts(5)
        if top_alerts:
            print(f"\n=== Top 5 Alertes (par CVSS) ===")
            for i, alert in enumerate(top_alerts, 1):
                print(f"{i}. [{alert['alert_level']}] {alert['cve_id']} - "
                      f"{alert['produit']} ({alert['vendor']}) - "
                      f"CVSS: {alert['cvss_score']}, EPSS: {alert['epss_score']}")


def main():
    """Fonction principale"""
    
    # Règles d'alerte personnalisées
    alert_rules = {
        "critical_cvss": 9.0,
        "high_cvss": 7.0,
        "high_epss": 0.75,
        "monitored_vendors": ["Microsoft", "Apache", "Ivanti"],  # Exemples
        "monitored_products": []
    }
    
    # Génération des alertes
    generator = AlertGenerator(alert_rules=alert_rules)
    
    if generator.load_dataframe():
        alerts = generator.generate_alerts()
        
        # Sauvegarde
        generator.save_alerts_to_json()
        
        # Affichage du résumé
        generator.display_summary()


if __name__ == "__main__":
    main()
