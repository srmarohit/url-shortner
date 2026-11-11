# URL Shortener

A Python URL shortener service. It turns long URLs into short links and redirects visitors from the short link to the original address.

<!-- TODO: Confirm the framework, endpoints and storage by reading main.py, provider/ and modals/. Items marked TODO below are placeholders, not verified details. -->

---

## ✨ Features

- Create a short link for any long URL
- Redirect from a short code to the original URL
- Helper utilities for code generation and validation (`utility.py`)
- Separate layers for data models and providers
- TODO: add real features (custom aliases, expiry, click analytics, rate limiting, etc.)

---

## 🧰 Tech Stack

| Area       | Technology                                         |
| ---------- | -------------------------------------------------- |
| Language   | Python                                             |
| Framework  | TODO (for example FastAPI or Flask, see `requirements.txt`) |
| Storage    | TODO (database or in-memory, see `provider/`)      |

---

## 📁 Project Structure

```
.
├── main.py            # Application entry point
├── utility.py         # Helper functions
├── modals/            # Data models
├── provider/          # Data/service providers
├── requirements.txt   # Python dependencies
└── .gitignore
```

---

## ✅ Prerequisites

- Python 3.10 or later (TODO: confirm the minimum version)
- pip

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/srmarohit/url-shortner.git
cd url-shortner
```

### 2. Create a virtual environment

```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
python main.py
```

<!-- TODO: If main.py exposes an ASGI/WSGI app, replace the command above, for example:
     uvicorn main:app --reload      (FastAPI)
     flask --app main run           (Flask)
-->

The service starts on **http://localhost:TODO**.

---

## 🔌 API

<!-- TODO: replace with the real routes -->

| Method | Endpoint        | Description                          |
| ------ | --------------- | ------------------------------------ |
| POST   | `/shorten`      | Create a short URL from a long URL   |
| GET    | `/{short_code}` | Redirect to the original URL         |

**Example**

```bash
curl -X POST http://localhost:TODO/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/some/very/long/path"}'
```

---

## 🛠️ Troubleshooting

| Problem | Fix |
| ------- | --- |
| `ModuleNotFoundError` | Activate the virtual environment and run `pip install -r requirements.txt` again. |
| Port already in use | Stop the other process or change the port in `main.py`. |
| Short link returns 404 | Make sure the code exists in the storage used by the provider layer. |

---

## 🗺️ Roadmap

- [ ] Custom aliases
- [ ] Link expiry
- [ ] Click analytics
- [ ] Rate limiting
- [ ] Docker support

---

## 📄 License

TODO: add a license file and reference it here.
