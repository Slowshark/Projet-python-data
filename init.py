#!/usr/bin/env python3
"""
Script d'initialisation - À exécuter une seule fois pour préparer le projet
"""

import os
import subprocess
import sys

print("=" * 70)
print("   INITIALISATION DU PROJET ANSSI")
print("=" * 70)

# 1. Créer les répertoires
print("\n1. Création de la structure de répertoires...")
dirs = ["data/raw", "data/processed", "output/alerts", "notebooks"]
for d in dirs:
    os.makedirs(d, exist_ok=True)
    print(f"   ✅ {d}/")

# 2. Générer les données de test
print("\n2. Génération des données de test...")
try:
    exec(open("generate_test_data.py").read())
    print("   ✅ Données de test générées")
except Exception as e:
    print(f"   ❌ Erreur: {e}")

# 3. Exécuter la vérification
print("\n3. Vérification du projet...")
try:
    result = subprocess.run([sys.executable, "verify.py"], capture_output=True, text=True)
    if result.returncode == 0:
        print("   ✅ Toutes les vérifications réussies")
    else:
        print(f"   ⚠️  Avertissement: {result.stdout}")
except Exception as e:
    print(f"   ❌ Erreur: {e}")

print("\n" + "=" * 70)
print("✅ INITIALISATION TERMINÉE")
print("\nProchaines étapes:")
print("  1. python main.py              (lancer le pipeline)")
print("  2. jupyter notebook notebooks/analysis.ipynb  (analyses)")
print("=" * 70)
