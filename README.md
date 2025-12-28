# TikTok Full Account Insights 🔍
**by @gqpgqpg**

A powerful Python tool that gathers **deep TikTok account intelligence** using both **web scraping** and **private API behavior**, providing detailed **profile, analytics, app-level, and security information** for any public TikTok username.

---

## ✨ Features

### 🌐 Web Profile Intelligence
- User ID, secUID, short ID
- Nickname, bio, avatar
- Account creation date
- Verification status
- Follow relationship status
- Privacy & interaction settings:
  - Comments
  - Duets
  - Stitch
  - Downloads
  - Favorites
- Story status
- Organization / business flags
- Profile tab visibility (Music, Q&A, Playlists)

### 📊 Statistics
- Followers
- Following
- Likes
- Videos
- Diggs
- Friends

### 📱 App-Level Data
- Live / creator **level**
- Country & flag detection
- Creator analytics:
  - Engagement rate
  - Average views, likes, comments
  - Follower growth (90 days)
  - Posts per month
  - Hashtags & brand tags
  - Engagement percent ranges

### 🔐 Account Security Insights
- Email bound ✔️ / ❌
- Phone number bound ✔️ / ❌
- Passkey / hidden bindings detection
- OAuth / external login platforms
- Multi-host fallback system for reliability

---

## 🧠 How It Works

This tool combines:
- **TikTok Web JSON extraction**
- **Signed mobile API requests**
- **Multi-threaded host probing**
- **External analytics correlation**
- **Live account security endpoint checks**

All requests are dynamically signed and rotated to maximize success across regions.

---

## 📦 Requirements

- Python **3.9+**
- Dependencies:
  ```bash
  pip install requests SignerPy ms4
