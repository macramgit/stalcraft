# StalCraft — Strona Portfolio

Piękna, industrialna strona portfolio dla kowala/spawacza.

## Struktura projektu

```
stalcraft/
├── app.py              # Główna aplikacja Flask
├── data.json           # Dane projektów (auto-generowany)
├── requirements.txt    # Zależności Python
├── static/
│   ├── css/style.css   # Style (industrialny design)
│   └── uploads/        # Zdjęcia projektów (auto-tworzony)
└── templates/
    ├── base.html        # Szablon bazowy
    ├── index.html       # Strona główna z galerią
    ├── project_detail.html  # Szczegóły projektu
    ├── login.html       # Logowanie
    ├── admin.html       # Panel admina
    └── add_project.html # Formularz dodawania projektu
```

## Instalacja i uruchomienie

### 1. Zainstaluj wymagania

```bash
pip install flask werkzeug
```

### 2. Uruchom aplikację

```bash
cd stalcraft
python app.py
```

Strona dostępna pod adresem: **http://localhost:5000**

## Dane logowania

- **Login:** `brat`  
- **Hasło:** `stal2024`

> ⚠️ Zmień hasło w pliku `app.py` przed wdrożeniem na serwer!
> Znajdź linie: `ADMIN_USERNAME` i `ADMIN_PASSWORD`

## Jak dodawać projekty?

1. Wejdź na stronę i kliknij **Logowanie** (prawy górny róg)
2. Zaloguj się danymi powyżej
3. Kliknij **Panel** w nawigacji
4. Kliknij **+ Nowy projekt**
5. Wypełnij formularz i dodaj zdjęcia
6. Zapisz — projekt pojawi się od razu na stronie głównej!

## Wdrożenie na serwer (produkcja)

### Opcja 1: VPS z Nginx + Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

### Opcja 2: Heroku / Railway / Render

Dodaj `Procfile`:
```
web: gunicorn app:app
```

### Ważne przed produkcją:
1. Zmień `secret_key` w `app.py` na losowy, bezpieczny klucz
2. Zmień hasło admina
3. Rozważ użycie bazy danych (SQLite/PostgreSQL) zamiast JSON

## Funkcje

✅ Galeria realizacji z filtrowaniem po kategoriach  
✅ Panel admina z logowaniem  
✅ Dodawanie projektów ze zdjęciami (drag & drop)  
✅ Usuwanie projektów  
✅ Podgląd szczegółów projektu z galerią  
✅ Responsywny design (mobile-friendly)  
✅ Formularz kontaktowy w stopce  
✅ Industrialny, ciemny design  
