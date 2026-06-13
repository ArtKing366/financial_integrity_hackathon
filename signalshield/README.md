# SignalShield PL

Проверка безопасности ссылок перед оплатой.

## Структура

```
signalshield/
├── app.py                 # Streamlit интерфейс
├── core/
│   ├── __init__.py
│   ├── blacklist.py       # Этап 1 — CERT blacklist
│   ├── whois_check.py     # Этап 2 — WHOIS
│   ├── similarity.py      # Этап 3 — схожесть с брендами
│   └── verdict.py         # Сборка финального результата
├── data/
│   ├── cert_blacklist.csv
│   └── trusted_brands.json
├── requirements.txt
└── README.md
```

## Запуск

```bash
# из корня репозитория
.venv\Scripts\activate.bat
cd signalshield
pip install -r requirements.txt
streamlit run app.py
```

## Этапы проверки

1. **blacklist** — домен в списке CERT Polska
2. **whois_check** — возраст домена
3. **similarity** — тайпосквоттинг относительно доверенных брендов
