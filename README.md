# Çizgi Stok

Çizgi Tabela Reklam'ın ürün, stok, giriş/çıkış ve katalog uygulaması.

- `server.js`: Node.js 22 sunucusu (yerleşik SQLite; dış bağımlılık yok)
- `public/index.html`: arayüz

Veriler (veritabanı, fotoğraflar, günlük yedekler) kodda değil, sunucudaki `/data` biriminde durur.
Sunucuda Docker ile çalışır; her açılışta bu daldaki kodu indirir.
