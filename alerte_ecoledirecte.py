"""
Alerte École Directe -> notification ntfy quand un cours est annulé.

Deux façons de lancer :
  python alerte_ecoledirecte.py setup   (une seule fois, sur ton ordi, pour la question de sécurité)
  python alerte_ecoledirecte.py         (la vérification normale, lancée par GitHub toutes les 30 min)

Réglages lus dans les variables d'environnement (secrets GitHub) :
  ED_IDENTIFIANT, ED_MOTDEPASSE, NTFY_TOPIC, ED_CN, ED_CV (donnés par le mode setup)
"""

import base64
import datetime as dt
import json
import os
import sys
from urllib.parse import quote

import requests

API = "https://api.ecoledirecte.com/v3"
VERSION = os.environ.get("ED_VERSION", "4.75.0")
FICHIER_ETAT = "etat.json"
JOURS_A_SURVEILLER = 7

# Mots qui déclenchent une alerte dans le sujet d'un message
MOTS_CLES = [
    "annul", "absent", "absence", "pas cours", "pas de cours",
    "ne sera pas", "ne pourra pas", "remplac", "supprim", "libéré", "libere",
]

# Lire le contenu des messages marque ces messages comme "lus" sur École Directe.
# Par défaut on ne regarde que le sujet. Mets ED_LIRE_CONTENU=1 pour lire aussi le texte.
LIRE_CONTENU = os.environ.get("ED_LIRE_CONTENU", "0") == "1"


class DoubleAuthRequise(Exception):
    pass


class ClientED:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/130.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
        })
        self.id_eleve = None

    def _post(self, url, donnees=None):
        # Comme le site officiel : corps envoyé tel quel "data={...}" (pas ré-encodé)
        corps = "data=" + json.dumps(donnees or {}, ensure_ascii=False)
        r = self.s.post(url, data=corps.encode("utf-8"), timeout=30)
        r.raise_for_status()
        token = r.headers.get("X-Token")
        if token:
            self.s.headers["X-Token"] = token
        j = r.json()
        if j.get("token"):
            self.s.headers["X-Token"] = j["token"]
        return j

    def _recuperer_gtk(self):
        """Récupère le cookie GTK demandé par École Directe avant la connexion."""
        self.s.headers.pop("X-Gtk", None)
        self.s.headers.pop("X-Token", None)
        r = self.s.get(f"{API}/login.awp?gtk=1&v={VERSION}", timeout=30)
        gtk = None
        for c in self.s.cookies:
            if c.name == "GTK":
                gtk = c.value
        if not gtk:
            # secours : lire directement l'en-tête Set-Cookie
            for morceau in r.headers.get("Set-Cookie", "").split(";"):
                morceau = morceau.strip()
                if morceau.startswith("GTK="):
                    gtk = morceau[4:]
        if gtk:
            self.s.headers["X-Gtk"] = gtk
        print(f"[diag] GTK reçu : {'oui' if gtk else 'NON'} (HTTP {r.status_code})")
        return gtk

    def connexion(self, identifiant, mdp, cn=None, cv=None):
        identifiant = identifiant.strip()
        mdp_brut = mdp
        mdp = mdp.strip()
        print(f"[diag] identifiant : {len(identifiant)} caractères ; "
              f"mot de passe : {len(mdp)} caractères"
              f"{' (espaces en trop retirés)' if mdp != mdp_brut else ''} ; "
              f"caractères spéciaux : {'oui' if any(not ch.isalnum() for ch in mdp) else 'non'}")

        # On essaie deux formats : encodé (recommandé) puis tel quel
        essais = [
            ("encodé", quote(identifiant, safe=""), quote(mdp, safe="")),
            ("tel quel", identifiant, mdp),
        ]
        dernier = None
        for nom, ident, motdepasse in essais:
            self._recuperer_gtk()
            donnees = {"identifiant": ident, "motdepasse": motdepasse,
                       "isRelogin": False, "uuid": ""}
            if cn and cv:
                donnees["fa"] = [{"cn": cn, "cv": cv}]
            j = self._post(f"{API}/login.awp?v={VERSION}", donnees)
            code = j.get("code")
            print(f"[diag] essai '{nom}' : code {code}")
            if code == 250:
                raise DoubleAuthRequise()
            if code == 200:
                compte = j["data"]["accounts"][0]
                self.id_eleve = compte["id"]
                print("[diag] connexion réussie")
                return compte
            dernier = j

        raise RuntimeError(f"Connexion refusée (code {dernier.get('code')}) : {dernier.get('message')}")

    # --- Question de sécurité (mode setup) ---
    def question_securite(self):
        j = self._post(f"{API}/connexion/doubleauth.awp?verbe=get&v={VERSION}")
        d = j["data"]
        question = base64.b64decode(d["question"]).decode("utf-8")
        propositions = [base64.b64decode(p).decode("utf-8") for p in d["propositions"]]
        return question, d["propositions"], propositions

    def repondre_question(self, choix_b64):
        j = self._post(f"{API}/connexion/doubleauth.awp?verbe=post&v={VERSION}", {"choix": choix_b64})
        if j.get("code") != 200:
            raise RuntimeError(f"Mauvaise réponse à la question de sécurité ({j.get('message')})")
        return j["data"]["cn"], j["data"]["cv"]

    # --- Données ---
    def emploi_du_temps(self, debut, fin):
        j = self._post(
            f"{API}/E/{self.id_eleve}/emploidutemps.awp?verbe=get&v={VERSION}",
            {"dateDebut": debut, "dateFin": fin, "avecTrous": False},
        )
        return j.get("data") or []

    def messages_recus(self, annee):
        url = (f"{API}/eleves/{self.id_eleve}/messages.awp?force=false&typeRecuperation=received"
               f"&idClasseur=0&orderBy=date&order=desc&query=&onlyRead=&page=0&itemsPerPage=20"
               f"&getAll=0&verbe=get&v={VERSION}")
        j = self._post(url, {"anneeMessages": annee})
        return ((j.get("data") or {}).get("messages") or {}).get("received") or []

    def contenu_message(self, id_msg, annee):
        url = f"{API}/eleves/{self.id_eleve}/messages/{id_msg}.awp?verbe=get&mode=destinataire&v={VERSION}"
        j = self._post(url, {"anneeMessages": annee})
        contenu = (j.get("data") or {}).get("content") or ""
        try:
            return base64.b64decode(contenu).decode("utf-8", errors="ignore")
        except Exception:
            return ""


def annee_scolaire(aujourdhui):
    debut = aujourdhui.year if aujourdhui.month >= 8 else aujourdhui.year - 1
    return f"{debut}-{debut + 1}"


def notifier(titre, message):
    topic = os.environ["NTFY_TOPIC"]
    requests.post("https://ntfy.sh/", json={
        "topic": topic, "title": titre, "message": message, "tags": ["warning"],
    }, timeout=30)
    print(f"Notification envoyée : {titre} - {message}")


def charger_etat():
    try:
        with open(FICHIER_ETAT, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"deja_vu": []}


def sauver_etat(etat):
    etat["deja_vu"] = etat["deja_vu"][-500:]  # on garde seulement les 500 derniers
    with open(FICHIER_ETAT, "w", encoding="utf-8") as f:
        json.dump(etat, f, ensure_ascii=False, indent=1)


def contient_mot_cle(texte):
    t = texte.lower()
    return any(m in t for m in MOTS_CLES)


def mode_setup():
    identifiant = input("Identifiant École Directe : ").strip()
    mdp = input("Mot de passe : ").strip()
    ed = ClientED()
    try:
        ed.connexion(identifiant, mdp)
        print("\nPas de question de sécurité pour ton compte : pas besoin de ED_CN / ED_CV.")
        return
    except DoubleAuthRequise:
        pass

    question, props_b64, props = ed.question_securite()
    print(f"\nQuestion : {question}")
    for i, p in enumerate(props, 1):
        print(f"  {i}. {p}")
    n = int(input("Numéro de ta réponse : "))
    cn, cv = ed.repondre_question(props_b64[n - 1])

    ed2 = ClientED()
    ed2.connexion(identifiant, mdp, cn, cv)
    print("\nC'est bon ! Ajoute ces deux secrets dans GitHub :")
    print(f"  ED_CN = {cn}")
    print(f"  ED_CV = {cv}")


def mode_verification():
    etat = charger_etat()
    deja_vu = set(etat["deja_vu"])
    nouveaux = []

    ed = ClientED()
    try:
        ed.connexion(os.environ["ED_IDENTIFIANT"], os.environ["ED_MOTDEPASSE"],
                     os.environ.get("ED_CN"), os.environ.get("ED_CV"))
    except DoubleAuthRequise:
        if "alerte_setup" not in deja_vu:
            notifier("École Directe : action requise",
                     "La question de sécurité est revenue. Relance le mode setup sur ton ordi.")
            nouveaux.append("alerte_setup")
        etat["deja_vu"] += nouveaux
        sauver_etat(etat)
        return

    aujourdhui = dt.date.today()
    annee = annee_scolaire(aujourdhui)

    # 1. Emploi du temps : cours marqués annulés
    fin = aujourdhui + dt.timedelta(days=JOURS_A_SURVEILLER)
    for cours in ed.emploi_du_temps(aujourdhui.isoformat(), fin.isoformat()):
        if not cours.get("isAnnule"):
            continue
        cle = f"cours_{cours.get('id')}_{cours.get('start_date')}"
        if cle in deja_vu:
            continue
        debut = cours.get("start_date", "")  # ex. "2026-11-27 08:00"
        try:
            quand = dt.datetime.strptime(debut, "%Y-%m-%d %H:%M").strftime("%A %d/%m à %Hh%M")
        except ValueError:
            quand = debut
        matiere = cours.get("matiere") or cours.get("text") or "Cours"
        prof = cours.get("prof") or ""
        notifier(f"Cours annulé : {matiere}", f"{quand} {('- ' + prof) if prof else ''}".strip())
        nouveaux.append(cle)

    # 2. Messages reçus qui parlent d'annulation / d'absence
    for msg in ed.messages_recus(annee):
        cle = f"msg_{msg.get('id')}"
        if cle in deja_vu:
            continue
        sujet = msg.get("subject", "")
        expediteur = (msg.get("from") or {}).get("name", "")
        texte = sujet
        if LIRE_CONTENU and not contient_mot_cle(sujet):
            texte += " " + ed.contenu_message(msg.get("id"), annee)
        if contient_mot_cle(texte):
            notifier("Message École Directe", f"{expediteur} : {sujet}")
        nouveaux.append(cle)  # message traité, on ne le regarde plus

    etat["deja_vu"] += nouveaux
    sauver_etat(etat)
    print(f"Vérification terminée, {len(nouveaux)} nouvel(s) élément(s).")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        mode_setup()
    else:
        mode_verification()
