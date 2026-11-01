# Çizgi İş Takibi

Çizgi Tabela Reklam'ın günlük iş takip uygulaması (iş kayıtları, aşamalar, tahsilat, değişiklik geçmişi, Excel'e aktarma).

- `server.js`: Node.js 22 sunucusu (yerleşik SQLite; dış bağımlılık yok). Giriş yapısı Çizgi Stok ile aynıdır.
- `public/index.html`: arayüz

Yetkiler: yönetici her şeyi yapar; kullanıcı (ör. muhasebe) işleri ekler ve düzenler ama silemez.
Veriler kodda değil, sunucudaki `/data` biriminde durur; her gün otomatik yedek alınır (son 14 gün).
Sunucuda Docker ile çalışır; her açılışta bu daldaki kodu indirir.
