# StalCraft — Portfolio Kowalstwo Artystyczne

Industrialna strona portfolio z panelem admina. Stack: Python + Flask.

## Szybki start lokalnie

```bash
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

**Login admina:** `brat` / `stal2024`

---

## 🚀 Wdrożenie na Render.com (DARMOWE)

### Krok 1 — Wrzuć kod na GitHub

1. Załóż konto na github.com (jeśli nie masz)
2. Kliknij "New repository" → nadaj nazwę np. `stalcraft`
3. Wgraj wszystkie pliki:

```bash
git init
git add .
git commit -m "Stalcraft portfolio"
git remote add origin https://github.com/TWOJ_LOGIN/stalcraft.git
git push -u origin main
```

### Krok 2 — Utwórz konto na Render.com

1. Wejdź na render.com
2. Kliknij "Get Started for Free"
3. Zaloguj się przez GitHub (zalecane!)

### Krok 3 — Deploy

1. W panelu Render kliknij "New +" → "Web Service"
2. Wybierz repozytorium `stalcraft`
3. Render automatycznie wykryje ustawienia z render.yaml
4. Kliknij "Create Web Service"
5. Poczekaj ~2 minuty — gotowe!

Strona będzie pod: https://stalcraft.onrender.com

### Krok 4 — Zmień hasło (ważne!)

Render → twoja usługa → Environment:
- ADMIN_PASSWORD → zmień na swoje hasło

---

## ⚠️ Uwaga o zdjęciach (darmowy plan)

Render darmowy ma efemeryczny dysk — zdjęcia znikają po restarcie (~15 min nieaktywności).
Na płatnym planie ($7/mies.) dysk jest trwały. Na start darmowy w zupełności wystarczy.
